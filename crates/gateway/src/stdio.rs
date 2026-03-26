use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};

use crate::audit::AuditSender;

/// Errors from MCP subprocess management.
#[derive(Debug, thiserror::Error)]
pub enum StdioError {
    #[error("subprocess spawn failed: {0}")]
    SpawnFailed(String),
    #[error("subprocess crashed: {0}")]
    Crashed(String),
    #[error("subprocess timeout: {0}")]
    Timeout(String),
    #[error("JSON-RPC parse error: {0}")]
    JsonRpcParse(String),
}

/// A running MCP server subprocess communicating via STDIO.
struct McpProcess {
    child: Child,
    stdin: tokio::process::ChildStdin,
    stdout: BufReader<tokio::process::ChildStdout>,
}

/// Pool of MCP server subprocesses keyed by server name.
///
/// Uses per-process locking so that I/O to one MCP server does not block
/// concurrent requests to other servers.
pub struct StdioProcessPool {
    processes: RwLock<HashMap<String, Arc<Mutex<McpProcess>>>>,
    audit: AuditSender,
}

impl StdioProcessPool {
    pub fn new(audit: AuditSender) -> Self {
        Self {
            processes: RwLock::new(HashMap::new()),
            audit,
        }
    }

    /// Spawn an MCP server subprocess with the given command, args, and env vars.
    ///
    /// Credentials are injected as environment variables so the subprocess
    /// never reads them from a shared store.
    /// Returns the process ID (pid) of the spawned subprocess on success.
    pub async fn spawn(
        &self,
        server_name: &str,
        command: &str,
        args: &[String],
        env_vars: HashMap<String, String>,
    ) -> Result<u32, StdioError> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .envs(env_vars)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            StdioError::SpawnFailed(format!(
                "failed to spawn '{}' for server '{}': {}",
                command, server_name, e
            ))
        })?;

        let pid = child.id().unwrap_or(0);

        let stdin = child.stdin.take().ok_or_else(|| {
            StdioError::SpawnFailed(format!(
                "failed to capture stdin for server '{}'",
                server_name
            ))
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            StdioError::SpawnFailed(format!(
                "failed to capture stdout for server '{}'",
                server_name
            ))
        })?;

        let process = McpProcess {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };

        let mut processes = self.processes.write().await;
        processes.insert(server_name.to_string(), Arc::new(Mutex::new(process)));

        tracing::info!(
            server_name = server_name,
            command = command,
            pid = pid,
            "MCP subprocess spawned"
        );
        Ok(pid)
    }

    /// Send a JSON-RPC request to a running MCP server subprocess and read
    /// one line of JSON-RPC response.
    ///
    /// Only locks the individual process, allowing concurrent requests to
    /// different MCP servers.
    pub async fn send_jsonrpc(
        &self,
        server_name: &str,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, StdioError> {
        // Acquire a read lock to look up the process handle, then release it.
        let process_handle = {
            let processes = self.processes.read().await;
            processes.get(server_name).cloned().ok_or_else(|| {
                StdioError::SpawnFailed(format!("no running process for server '{}'", server_name))
            })?
        };

        // Lock only this individual process for I/O.
        let mut process = process_handle.lock().await;

        // Serialize request as a single JSON line + newline.
        let mut request_bytes = serde_json::to_vec(request)
            .map_err(|e| StdioError::JsonRpcParse(format!("failed to serialize request: {}", e)))?;
        request_bytes.push(b'\n');

        if let Err(e) = process.stdin.write_all(&request_bytes).await {
            let reason = format!("failed to write to '{}' stdin: {}", server_name, e);
            let err = StdioError::Crashed(reason.clone());
            drop(process);
            drop(process_handle);
            self.remove(server_name).await;
            self.audit.emit(
                "subprocess_crashed",
                serde_json::json!({
                    "server_name": server_name,
                    "exit_status": reason,
                }),
            );
            tracing::warn!(
                server_name = server_name,
                "removed crashed MCP subprocess from pool"
            );
            return Err(err);
        }

        if let Err(e) = process.stdin.flush().await {
            let reason = format!("failed to flush '{}' stdin: {}", server_name, e);
            let err = StdioError::Crashed(reason.clone());
            drop(process);
            drop(process_handle);
            self.remove(server_name).await;
            self.audit.emit(
                "subprocess_crashed",
                serde_json::json!({
                    "server_name": server_name,
                    "exit_status": reason,
                }),
            );
            tracing::warn!(
                server_name = server_name,
                "removed crashed MCP subprocess from pool"
            );
            return Err(err);
        }

        // Read one line from stdout with a timeout and bounded memory.
        // Uses incremental fill_buf to reject oversized lines BEFORE they
        // are fully loaded into memory.
        const MAX_LINE_BYTES: usize = 10 * 1024 * 1024; // 10 MB
        let read_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            read_line_bounded(&mut process.stdout, MAX_LINE_BYTES),
        )
        .await;

        let result = match read_result {
            Ok(Ok(line)) => {
                let response: serde_json::Value =
                    serde_json::from_str(line.trim()).map_err(|e| {
                        StdioError::JsonRpcParse(format!(
                            "invalid JSON from '{}': {}",
                            server_name, e
                        ))
                    })?;
                Ok(response)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(StdioError::Timeout(format!(
                "server '{}' did not respond within 30s",
                server_name
            ))),
        };

        // On crash (EOF, broken pipe, read error), remove the dead process from
        // the pool so the next request triggers auto-respawn.
        if let Err(StdioError::Crashed(reason)) = &result {
            // Release the per-process lock before taking the write lock.
            drop(process);
            drop(process_handle);
            self.remove(server_name).await;
            self.audit.emit(
                "subprocess_crashed",
                serde_json::json!({
                    "server_name": server_name,
                    "exit_status": reason,
                }),
            );
            tracing::warn!(
                server_name = server_name,
                "removed crashed MCP subprocess from pool"
            );
        }

        result
    }

    /// Remove and kill a server process from the pool.
    ///
    /// Returns `true` if the process existed and was removed.
    pub async fn remove(&self, server_name: &str) -> bool {
        let mut processes = self.processes.write().await;
        if let Some(process_handle) = processes.remove(server_name) {
            let mut process = process_handle.lock().await;
            let _ = process.child.kill().await;
            true
        } else {
            false
        }
    }

    /// Check if a server process is present in the pool.
    pub async fn has_process(&self, server_name: &str) -> bool {
        let processes = self.processes.read().await;
        processes.contains_key(server_name)
    }

    /// Shutdown all running subprocesses by killing them.
    pub async fn shutdown(&self) {
        let mut processes = self.processes.write().await;
        for (name, process_handle) in processes.drain() {
            tracing::info!(server_name = name, "shutting down MCP subprocess");
            let mut process = process_handle.lock().await;
            let _ = process.child.kill().await;
        }
    }
}

/// Read a single newline-terminated line from an async buffered reader,
/// aborting with an error if the line exceeds `max_bytes` BEFORE fully
/// loading it into memory.
async fn read_line_bounded<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<String, StdioError> {
    let mut buf = Vec::with_capacity(4096.min(max_bytes));
    loop {
        let available = reader.fill_buf().await.map_err(|e| {
            StdioError::Crashed(format!("read error: {}", e))
        })?;

        if available.is_empty() {
            // EOF
            if buf.is_empty() {
                return Err(StdioError::Crashed("closed stdout (process exited)".to_string()));
            }
            break;
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            break;
        }

        buf.extend_from_slice(available);
        let len = available.len();
        reader.consume(len);

        if buf.len() > max_bytes {
            return Err(StdioError::JsonRpcParse(format!(
                "response exceeded {} byte limit",
                max_bytes
            )));
        }
    }

    String::from_utf8(buf).map_err(|e| StdioError::JsonRpcParse(format!("invalid UTF-8: {}", e)))
}
