use std::io::Write;
use std::time::{Duration, Instant};

use super::client::ApiClient;

/// Poll the server for registration approval. Returns the approval code.
pub async fn poll_for_approval(
    server_url: &str,
    pk_hash: &str,
    code_challenge: &str,
    timeout: Duration,
) -> Result<String, String> {
    let client = ApiClient::new(server_url);
    let pk_hash_hex = pk_hash.strip_prefix("sha256:").unwrap_or(pk_hash);
    let path = format!(
        "/api/v1/workspaces/registration-status?pk_hash={}&cc={}",
        pk_hash_hex, code_challenge
    );

    let start = Instant::now();
    let mut delay = Duration::from_secs(1);
    let max_delay = Duration::from_secs(5);
    let spinner_chars = [
        '\u{280B}', '\u{2819}', '\u{2839}', '\u{2838}', '\u{283C}', '\u{2834}', '\u{2826}',
        '\u{2827}', '\u{2807}', '\u{280F}',
    ];
    let mut spin_idx = 0;

    loop {
        if start.elapsed() > timeout {
            // Clear spinner line before returning error
            eprint!("\r                              \r");
            return Err(
                "Timed out waiting for approval. You can resume with: agentcordon register --code <CODE>"
                    .to_string(),
            );
        }

        // Print spinner
        let elapsed = start.elapsed().as_secs();
        let mins = elapsed / 60;
        let secs = elapsed % 60;
        eprint!(
            "\r{} Polling... ({}:{:02})  ",
            spinner_chars[spin_idx % spinner_chars.len()],
            mins,
            secs
        );
        std::io::stderr().flush().ok();
        spin_idx += 1;

        tokio::time::sleep(delay).await;

        match client.get_raw(&path).await {
            Ok((200, body)) => {
                // Clear spinner line
                eprint!("\r                              \r");

                // Parse response for approval_code
                let resp: serde_json::Value = serde_json::from_str(&body)
                    .map_err(|e| format!("invalid poll response: {}", e))?;

                let code = resp
                    .get("data")
                    .and_then(|d| d.get("approval_code"))
                    .and_then(|c| c.as_str())
                    .ok_or_else(|| "poll response missing approval_code".to_string())?;

                return Ok(code.to_string());
            }
            Ok((404, _)) => {
                // Not yet approved, keep polling
            }
            Ok((status, body)) => {
                return Err(format!("unexpected poll response {}: {}", status, body));
            }
            Err(e) => {
                // Network error — keep trying
                eprintln!("\rPoll error (retrying): {}                    ", e);
            }
        }

        // Exponential backoff up to max
        delay = std::cmp::min(delay * 2, max_delay);
    }
}
