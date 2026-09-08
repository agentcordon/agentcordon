//! `agentcordon update` — replace the CLI and broker binaries with the
//! version this workspace's server is pinned to, then restart the running
//! broker with the flags it was already running.
//!
//! The version source is **server-pinned**, not GitHub `latest`: the target
//! is whatever `{server_url}/install.sh` was templated with
//! (`AGTCRDN_VERSION`). The installer is the ADR-0010 lockstep pin, so a
//! workspace can never update itself ahead of its server. (ADR-0016.)
//!
//! The binaries come from the same GitHub release the installer uses
//! (`.../releases/download/v<version>/`), are verified against that release's
//! `SHA256SUMS` — both of them, before either is installed — and are swapped
//! in atomically: each is written to a temp file in the *same directory* as
//! its target and `rename`d over it, so a crash mid-write never leaves a
//! half-written binary on `PATH`.
//!
//! The pure pieces (version parse, triple selection, checksum verification,
//! argv capture) are unit-tested; the network download and the live restart
//! are not, per the repo's seam rule.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::broker;
use crate::config;
use crate::error::CliError;

/// Where the installer publishes the binaries and their checksums.
const GITHUB_RELEASE_BASE: &str = "https://github.com/agentcordon/agentcordon/releases/download";

/// This CLI's own version — the thing being compared against the server's pin.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parsed `agentcordon update` flags.
pub struct UpdateArgs {
    /// Report current vs available and exit; change nothing.
    pub check: bool,
    /// Reinstall even when already on the pinned version.
    pub force: bool,
    /// Server URL override (same precedence as `init`/`register`).
    pub server_url: Option<String>,
    /// Skip the confirmation prompt.
    pub yes: bool,
}

/// Run `agentcordon update`.
pub async fn run(args: UpdateArgs) -> Result<(), CliError> {
    // 1. Resolve and validate the server URL (flag > env > config file).
    let resolved = config::resolve_server_url(args.server_url.as_deref())
        .ok_or_else(|| CliError::general(config::missing_server_url_hint()))?;
    let server_url = broker::validate_server_url(&resolved.url)?;

    // 2. Learn the target version from the server's own installer.
    let client = broker::http_client(Duration::from_secs(30))?;
    let target_version = fetch_target_version(&client, &server_url).await?;

    // 3. Compare with our own.
    if args.check {
        println!("Current:   v{CURRENT_VERSION}");
        println!("Available: v{target_version} (from {server_url})");
        if target_version == CURRENT_VERSION {
            println!("Up to date.");
        } else {
            println!("Run `agentcordon update` to install v{target_version}.");
        }
        return Ok(());
    }

    if target_version == CURRENT_VERSION && !args.force {
        println!("already up to date (v{CURRENT_VERSION})");
        return Ok(());
    }

    // 4. Pick the release assets for this platform.
    let triple = target_triple(std::env::consts::OS, std::env::consts::ARCH).ok_or_else(|| {
        CliError::general(format!(
            "no release binaries for this platform ({}/{}). Build from source.",
            std::env::consts::OS,
            std::env::consts::ARCH,
        ))
    })?;

    // Windows cannot rename over a running .exe; the self-replace path is not
    // implemented, so refuse before touching anything (see `replace_binary`).
    #[cfg(windows)]
    {
        return Err(CliError::general(
            "agentcordon update does not yet support Windows: a running .exe cannot be \
             replaced in place. Re-run the install one-liner (install.ps1) instead.",
        ));
    }

    // 5. Confirm, unless --yes and unless there is no TTY to ask on.
    if !args.yes && std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        let proceed = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Update agentcordon and agentcordon-broker from v{CURRENT_VERSION} to v{target_version}?"
            ))
            .default(true)
            .interact()
            .map_err(|e| CliError::general(format!("could not read your answer: {e}")))?;
        if !proceed {
            println!("Update cancelled.");
            return Ok(());
        }
    }

    // 6. Download SHA256SUMS and both binaries, verify both, THEN install.
    let cli_asset = format!("agentcordon-{triple}");
    let broker_asset = format!("agentcordon-broker-{triple}");
    let release_base = format!("{GITHUB_RELEASE_BASE}/v{target_version}");

    println!("Downloading v{target_version} for {triple}...");
    let sums = download(&client, &format!("{release_base}/SHA256SUMS")).await?;
    let sums = String::from_utf8(sums)
        .map_err(|_| CliError::general("SHA256SUMS from the release is not valid UTF-8"))?;

    let cli_bytes = download(&client, &format!("{release_base}/{cli_asset}")).await?;
    let broker_bytes = download(&client, &format!("{release_base}/{broker_asset}")).await?;

    verify_asset(&sums, &cli_asset, &cli_bytes)?;
    verify_asset(&sums, &broker_asset, &broker_bytes)?;
    println!("  verified {cli_asset} and {broker_asset} (sha256 ok)");

    // 7. Work out where the two binaries live. The CLI is `current_exe()`;
    //    the broker is its sibling.
    let cli_path = std::env::current_exe()
        .map_err(|e| CliError::general(format!("cannot locate the running binary: {e}")))?;
    let dir = cli_path
        .parent()
        .ok_or_else(|| CliError::general("the running binary has no parent directory"))?
        .to_path_buf();
    let broker_path = dir.join(broker_binary_name());

    // 8. Atomically replace both. On Unix a rename over a running binary is
    //    safe: the running process keeps the old inode.
    replace_binary(&cli_path, &cli_bytes)?;
    replace_binary(&broker_path, &broker_bytes)?;
    println!(
        "Installed agentcordon and agentcordon-broker v{target_version} in {}",
        dir.display()
    );

    // 9. Restart the running broker with the flags it was already running.
    restart_broker(&client, &broker_path, &server_url).await?;

    // 10. Report.
    println!("Now on v{target_version}. Run `agentcordon status` to verify the broker.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Version discovery
// ---------------------------------------------------------------------------

/// Fetch `{server_url}/install.sh` and read the pinned `AGTCRDN_VERSION`.
async fn fetch_target_version(
    client: &reqwest::Client,
    server_url: &str,
) -> Result<String, CliError> {
    let url = format!("{server_url}/install.sh");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CliError::general(format!("could not reach {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(CliError::general(format!(
            "GET {url} returned HTTP {}. Is the server URL correct?",
            resp.status().as_u16()
        )));
    }
    let script = resp
        .text()
        .await
        .map_err(|e| CliError::general(format!("could not read {url}: {e}")))?;
    parse_agtcrdn_version(&script).ok_or_else(|| {
        CliError::general(format!(
            "could not find AGTCRDN_VERSION in {url}; the server may be too old for \
             `agentcordon update`. Re-run the install one-liner instead."
        ))
    })
}

/// Parse `AGTCRDN_VERSION="X.Y.Z"` out of the templated installer. The line
/// the server emits is `AGTCRDN_VERSION="0.5.0"`; the un-templated source
/// still carries the `{version}` placeholder, which is not a version.
fn parse_agtcrdn_version(script: &str) -> Option<String> {
    for line in script.lines() {
        let Some(rest) = line.trim_start().strip_prefix("AGTCRDN_VERSION=") else {
            continue;
        };
        let value = rest.trim().trim_matches('"').trim_matches('\'');
        if value.is_empty() || value == "{version}" {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// Platform / asset selection
// ---------------------------------------------------------------------------

/// The release target triple for an OS/arch pair, matching the mapping in
/// `crates/server/src/install_script.sh`. `os`/`arch` are the values
/// [`std::env::consts::OS`]/[`ARCH`](std::env::consts::ARCH) report.
fn target_triple(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

/// The on-disk name of the broker binary beside the CLI.
fn broker_binary_name() -> &'static str {
    if cfg!(windows) {
        "agentcordon-broker.exe"
    } else {
        "agentcordon-broker"
    }
}

// ---------------------------------------------------------------------------
// Download + verification
// ---------------------------------------------------------------------------

/// GET a release asset as bytes.
async fn download(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, CliError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| CliError::general(format!("could not download {url}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        if status == 404 {
            return Err(CliError::general(format!(
                "no published release asset at {url} (HTTP 404). A server built from `main` \
                 ahead of a release has no matching binaries; build from source."
            )));
        }
        return Err(CliError::general(format!(
            "downloading {url} returned HTTP {status}"
        )));
    }
    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| CliError::general(format!("could not read {url}: {e}")))
}

/// Verify one asset's bytes against its `SHA256SUMS` entry, or abort.
fn verify_asset(sums: &str, asset: &str, bytes: &[u8]) -> Result<(), CliError> {
    let expected = expected_sum_for(sums, asset).ok_or_else(|| {
        CliError::general(format!(
            "SHA256SUMS has no entry for {asset}; refusing to install it."
        ))
    })?;
    if verify_sha256(bytes, &expected) {
        Ok(())
    } else {
        Err(CliError::general(format!(
            "SHA-256 mismatch for {asset}! Expected {expected}, got {}. \
             Nothing was installed.",
            sha256_hex(bytes)
        )))
    }
}

/// The expected hex digest for `asset` from a `SHA256SUMS` file. Handles both
/// the `<hash>  <name>` (text) and `<hash> *<name>` (binary) forms that
/// `sha256sum` writes and the installer reads.
fn expected_sum_for(sums: &str, asset: &str) -> Option<String> {
    for line in sums.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        let name = name.strip_prefix('*').unwrap_or(name);
        if name == asset {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

/// The lowercase hex SHA-256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Whether `data` hashes to `expected_hex` (case-insensitive).
fn verify_sha256(data: &[u8], expected_hex: &str) -> bool {
    sha256_hex(data).eq_ignore_ascii_case(expected_hex.trim())
}

// ---------------------------------------------------------------------------
// Atomic install
// ---------------------------------------------------------------------------

/// Write `bytes` to a temp file in the same directory as `target`, make it
/// executable, and `rename` it over `target`.
///
/// The rename is atomic within one filesystem, which is why the temp file has
/// to be a sibling of the target rather than in `/tmp`. On Unix, renaming
/// over a binary that is *currently running* is safe: the running process
/// holds the old inode open and only new `exec`s see the replacement — this
/// is what lets `update` replace its own binary and the live broker's.
///
/// On Windows a running `.exe` is locked and cannot be renamed over; the fix
/// is the rename-self-aside pattern (move the running exe to a `.old` name,
/// then write the new one). That is not implemented — `run` refuses on
/// Windows before reaching here.
#[cfg(unix)]
fn replace_binary(target: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    let dir = target
        .parent()
        .ok_or_else(|| CliError::general("target binary has no parent directory"))?;
    let tmp = tmp_sibling(target);

    std::fs::write(&tmp, bytes).map_err(|e| {
        CliError::general(format!(
            "cannot write {} (is {} writable?): {e}",
            tmp.display(),
            dir.display()
        ))
    })?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        CliError::general(format!("cannot chmod {}: {e}", tmp.display()))
    })?;
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        CliError::general(format!("cannot replace {}: {e}", target.display()))
    })?;
    Ok(())
}

/// Windows placeholder: the self-replace pattern is not implemented, and
/// `run` refuses on Windows before it would be called. Kept so the module
/// compiles on Windows rather than failing to build.
#[cfg(windows)]
fn replace_binary(_target: &Path, _bytes: &[u8]) -> Result<(), CliError> {
    Err(CliError::general(
        "in-place binary replacement is not implemented on Windows",
    ))
}

/// A unique sibling temp path for `target`, in the same directory so the
/// rename stays within one filesystem.
fn tmp_sibling(target: &Path) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agentcordon".to_string());
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(".{name}.{}.new", std::process::id()))
}

// ---------------------------------------------------------------------------
// Broker restart
// ---------------------------------------------------------------------------

/// Restart the running broker with the flags it was already running.
///
/// Discovers the broker through `~/.agentcordon/broker.port` (the same path
/// the CLI uses), reads its argv (`/proc/<pid>/cmdline`), stops it, and
/// starts the freshly-installed binary with the *same* argv. If no broker is
/// running, there is nothing to restart and we say so. If argv cannot be
/// recovered, we fall back to `--server-url <resolved> --port <same>` and
/// warn which flags may need re-applying.
async fn restart_broker(
    client: &reqwest::Client,
    broker_path: &Path,
    server_url: &str,
) -> Result<(), CliError> {
    let Some(base_url) = discover_running_broker(client).await else {
        println!("No running broker to restart (start one with `agentcordon-broker`).");
        return Ok(());
    };

    let pid = running_broker_pid();
    let captured = pid.and_then(read_proc_argv);

    let port = port_from_url(&base_url);
    let (args, warn) = match &captured {
        Some(argv) if argv.len() > 1 => (argv[1..].to_vec(), None),
        _ => {
            let mut fallback = vec!["--server-url".to_string(), server_url.to_string()];
            if let Some(p) = port {
                fallback.push("--port".to_string());
                fallback.push(p.to_string());
            }
            (
                fallback,
                Some(
                    "! Could not read the running broker's command line; restarted it with \
                     --server-url and --port only.\n  Re-apply any other flags it needs \
                     (--bind, --shared-secret, --proxy-allow-loopback, --tls-cert/--tls-key).",
                ),
            )
        }
    };

    // Stop the old broker and wait for it to release its single-instance lock
    // before starting the new one.
    if let Some(pid) = pid {
        stop_broker(pid);
    }
    wait_until_down(client, &base_url).await;

    println!("Restarting broker...");
    let mut cmd = std::process::Command::new(broker_path);
    cmd.args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // A plain spawn: the broker must OUTLIVE this `update` process, unlike the
    // autostart path, which binds the broker to the CLI's lifetime.
    cmd.spawn()
        .map_err(|e| CliError::general(format!("failed to start the new broker: {e}")))?;

    if let Some(warn) = warn {
        eprintln!("{warn}");
    }

    // Wait for the new broker's /health to come up.
    let new_url = port
        .map(|p| format!("http://localhost:{p}"))
        .unwrap_or(base_url);
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if client.get(format!("{new_url}/health")).send().await.is_ok() {
            println!("Broker restarted.");
            return Ok(());
        }
    }
    Err(CliError::general(
        "the new broker did not report healthy within 5 seconds; check its logs.",
    ))
}

/// The broker's base URL if one is running and answering `/health`, via the
/// port file (the CLI's discovery path).
async fn discover_running_broker(client: &reqwest::Client) -> Option<String> {
    let port_path = agentcordon_dir()?.join("broker.port");
    let contents = std::fs::read_to_string(&port_path).ok()?;
    let base_url = broker::broker_url_from_port_file(&contents).ok()?;
    if client
        .get(format!("{base_url}/health"))
        .send()
        .await
        .is_ok()
    {
        Some(base_url)
    } else {
        None
    }
}

/// The running broker's pid, from `~/.agentcordon/broker.pid` (written by the
/// broker daemon), falling back to a `ps` scan.
fn running_broker_pid() -> Option<u32> {
    if let Some(dir) = agentcordon_dir() {
        if let Ok(text) = std::fs::read_to_string(dir.join("broker.pid")) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                return Some(pid);
            }
        }
    }
    pid_from_ps()
}

/// Last-resort pid discovery: ask `ps` for a process named
/// `agentcordon-broker`. Unix only; returns `None` on Windows or when `ps`
/// is unavailable.
#[cfg(unix)]
fn pid_from_ps() -> Option<u32> {
    let out = std::process::Command::new("ps")
        .args(["-eo", "pid=,comm="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(pid), Some(comm)) = (parts.next(), parts.next()) else {
            continue;
        };
        if comm.contains("agentcordon-broker") {
            if let Ok(pid) = pid.parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(not(unix))]
fn pid_from_ps() -> Option<u32> {
    None
}

/// Read a process's argv from `/proc/<pid>/cmdline` (NUL-separated). Unix
/// only; `None` on any platform without procfs.
#[cfg(target_os = "linux")]
fn read_proc_argv(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = argv_from_cmdline(&raw);
    if argv.is_empty() {
        None
    } else {
        Some(argv)
    }
}

#[cfg(not(target_os = "linux"))]
fn read_proc_argv(_pid: u32) -> Option<Vec<String>> {
    // macOS has no procfs; the config-derived fallback + warning covers it.
    None
}

/// Split a NUL-separated `/proc/<pid>/cmdline` into argv, dropping the
/// trailing empty field the kernel leaves after the last NUL.
fn argv_from_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Send the broker a termination signal. Unix: `kill -TERM`, which the broker
/// handles with a graceful shutdown that removes its port/pid/lock files.
#[cfg(unix)]
fn stop_broker(pid: u32) {
    let _ = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
}

#[cfg(not(unix))]
fn stop_broker(_pid: u32) {}

/// Poll `/health` until the broker stops answering (it has released its
/// single-instance lock), or a few seconds pass.
async fn wait_until_down(client: &reqwest::Client, base_url: &str) {
    for _ in 0..40 {
        if client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .is_err()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `~/.agentcordon`.
fn agentcordon_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".agentcordon"))
}

/// The port a broker base URL names, for the config-derived restart fallback.
fn port_from_url(base_url: &str) -> Option<u16> {
    url::Url::parse(base_url).ok()?.port()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- version parse ------------------------------------------------------

    /// The line the server templates into `install.sh`.
    #[test]
    fn parses_the_templated_version() {
        let script = "#!/bin/sh\nset -eu\nAGTCRDN_VERSION=\"0.5.0\"\nGITHUB_RELEASE=\"...\"\n";
        assert_eq!(parse_agtcrdn_version(script).as_deref(), Some("0.5.0"));
    }

    /// An indented assignment (defensive) still parses.
    #[test]
    fn parses_an_indented_version() {
        let script = "    AGTCRDN_VERSION='1.2.3'\n";
        assert_eq!(parse_agtcrdn_version(script).as_deref(), Some("1.2.3"));
    }

    /// The un-templated source still carries the `{version}` placeholder,
    /// which is not a version and must not be treated as one.
    #[test]
    fn refuses_the_untemplated_placeholder() {
        let script = "AGTCRDN_VERSION=\"{version}\"\n";
        assert!(parse_agtcrdn_version(script).is_none());
    }

    #[test]
    fn a_script_without_the_key_yields_nothing() {
        assert!(parse_agtcrdn_version("#!/bin/sh\necho hi\n").is_none());
    }

    // -- triple selection ---------------------------------------------------

    /// Every pair `install_script.sh` maps, mapped the same way.
    #[test]
    fn triple_selection_matches_the_installer() {
        assert_eq!(
            target_triple("linux", "x86_64"),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(
            target_triple("linux", "aarch64"),
            Some("aarch64-unknown-linux-gnu")
        );
        assert_eq!(
            target_triple("macos", "x86_64"),
            Some("x86_64-apple-darwin")
        );
        assert_eq!(
            target_triple("macos", "aarch64"),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(
            target_triple("windows", "x86_64"),
            Some("x86_64-pc-windows-msvc")
        );
    }

    #[test]
    fn an_unsupported_platform_has_no_triple() {
        assert!(target_triple("linux", "riscv64").is_none());
        assert!(target_triple("freebsd", "x86_64").is_none());
    }

    // -- checksum verification ---------------------------------------------

    /// A SHA256SUMS in the exact shape `sha256sum` writes and the installer
    /// (`$2 == a || $2 == "*" a`) reads: two-space text form, and the
    /// `*`-prefixed binary form.
    const SUMS: &str = "\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  agentcordon-x86_64-unknown-linux-gnu
1111111111111111111111111111111111111111111111111111111111111111 *agentcordon-broker-x86_64-unknown-linux-gnu
";

    #[test]
    fn finds_a_sum_in_the_two_space_text_form() {
        assert_eq!(
            expected_sum_for(SUMS, "agentcordon-x86_64-unknown-linux-gnu").as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn finds_a_sum_in_the_star_prefixed_binary_form() {
        assert_eq!(
            expected_sum_for(SUMS, "agentcordon-broker-x86_64-unknown-linux-gnu").as_deref(),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
    }

    #[test]
    fn an_asset_absent_from_the_sums_has_no_entry() {
        assert!(expected_sum_for(SUMS, "agentcordon-aarch64-apple-darwin").is_none());
    }

    /// The empty input hashes to the well-known empty SHA-256, so a verify of
    /// empty bytes against that digest passes.
    #[test]
    fn a_matching_digest_verifies() {
        let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(verify_sha256(b"", empty_sha));
    }

    #[test]
    fn a_mismatched_digest_fails() {
        let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(!verify_sha256(b"not empty", empty_sha));
    }

    /// The end-to-end verify used before install: a match passes, a mismatch
    /// aborts, and an asset with no entry aborts.
    #[test]
    fn verify_asset_gates_on_the_digest() {
        // "abc" -> known SHA-256.
        let sums = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  agentcordon-x86_64-unknown-linux-gnu\n";
        assert!(verify_asset(sums, "agentcordon-x86_64-unknown-linux-gnu", b"abc").is_ok());
        assert!(verify_asset(sums, "agentcordon-x86_64-unknown-linux-gnu", b"xyz").is_err());
        assert!(verify_asset(sums, "agentcordon-broker-x86_64-unknown-linux-gnu", b"abc").is_err());
    }

    // -- argv capture -------------------------------------------------------

    /// The kernel serves argv NUL-separated with a trailing NUL after the
    /// last field. This is the exact byte shape of a broker started with
    /// `--server-url ... --port ... --proxy-allow-loopback`.
    #[test]
    fn argv_parses_a_proc_style_cmdline() {
        let raw = b"agentcordon-broker\0--server-url\0https://cordon.example.com\0--port\09876\0--proxy-allow-loopback\0";
        assert_eq!(
            argv_from_cmdline(raw),
            vec![
                "agentcordon-broker",
                "--server-url",
                "https://cordon.example.com",
                "--port",
                "9876",
                "--proxy-allow-loopback",
            ]
        );
    }

    /// A bare program with no arguments yields a single-element argv, which
    /// `restart_broker` treats as "no flags to preserve" and falls back.
    #[test]
    fn argv_of_a_bare_program_is_one_element() {
        assert_eq!(
            argv_from_cmdline(b"agentcordon-broker\0"),
            vec!["agentcordon-broker"]
        );
    }

    #[test]
    fn argv_of_empty_cmdline_is_empty() {
        assert!(argv_from_cmdline(b"").is_empty());
    }

    // -- misc ---------------------------------------------------------------

    #[test]
    fn a_port_is_read_from_a_broker_url() {
        assert_eq!(port_from_url("http://localhost:9876"), Some(9876));
        assert_eq!(port_from_url("https://127.0.0.1:4490"), Some(4490));
    }

    #[test]
    fn the_temp_file_is_a_sibling_of_its_target() {
        let tmp = tmp_sibling(Path::new("/home/u/.local/bin/agentcordon"));
        assert_eq!(tmp.parent(), Some(Path::new("/home/u/.local/bin")));
        assert!(tmp
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".agentcordon."));
    }
}
