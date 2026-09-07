//! The user-level CLI config file, `~/.agentcordon/config.toml`.
//!
//! One key lives here: `server_url`, written by `install.sh` / `install.ps1`
//! from the origin the installer was fetched from. It is what makes
//! `--server-url` optional — the installer already knows which server this
//! machine belongs to, so neither `agentcordon init` nor broker autostart
//! should have to be told again.
//!
//! Precedence, everywhere a server URL is needed: the `--server-url` flag,
//! then `AGTCRDN_SERVER_URL`, then this file. `status` reports which of the
//! three answered, because "the CLI is talking to the wrong server" is
//! otherwise invisible.

use std::path::{Path, PathBuf};

use crate::error::CliError;

/// The environment override, second in precedence.
pub const SERVER_URL_ENV: &str = "AGTCRDN_SERVER_URL";

/// The file name inside `~/.agentcordon/`.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Where a resolved server URL came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerUrlSource {
    /// `--server-url` on the command line.
    Flag,
    /// The `AGTCRDN_SERVER_URL` environment variable.
    Env,
    /// `server_url` in `~/.agentcordon/config.toml`.
    ConfigFile,
}

impl ServerUrlSource {
    /// How `agentcordon status` names this source.
    pub fn describe(self) -> &'static str {
        match self {
            ServerUrlSource::Flag => "--server-url",
            ServerUrlSource::Env => SERVER_URL_ENV,
            ServerUrlSource::ConfigFile => "~/.agentcordon/config.toml",
        }
    }
}

/// A server URL and the answer to "why this one".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    pub url: String,
    pub source: ServerUrlSource,
}

/// The one-line hint printed when no server URL is configured anywhere.
pub fn missing_server_url_hint() -> String {
    format!(
        "No server URL configured. Pass --server-url <URL>, set {SERVER_URL_ENV}, \
         or re-run your server's installer (it writes ~/.agentcordon/{CONFIG_FILE_NAME})."
    )
}

/// `~/.agentcordon/config.toml`.
pub fn config_path() -> Result<PathBuf, CliError> {
    config_path_from(dirs::home_dir())
}

/// Inner form of [`config_path`], taking the home-dir lookup as a parameter so
/// the error branch is testable without touching the host's passwd database.
fn config_path_from(home: Option<PathBuf>) -> Result<PathBuf, CliError> {
    let home = home.ok_or_else(|| {
        CliError::general(
            "could not resolve user home directory; \
             set HOME (Unix/macOS) or USERPROFILE (Windows)",
        )
    })?;
    Ok(home.join(".agentcordon").join(CONFIG_FILE_NAME))
}

/// The `server_url` recorded in a config file, if the file exists, parses, and
/// carries a non-empty string there.
///
/// Every failure is `None`: a malformed config written by a future installer
/// must not make the CLI unusable, because the flag and the environment
/// variable still work and the hint names both.
pub fn server_url_in(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    server_url_in_toml(&text)
}

/// The parse half of [`server_url_in`], separated so the file-format rules can
/// be tested without a filesystem.
fn server_url_in_toml(text: &str) -> Option<String> {
    let value: toml::Value = toml::from_str(text).ok()?;
    let raw = value.get("server_url")?.as_str()?;
    normalise(raw)
}

/// Trim whitespace and any trailing `/`, and treat the empty string as absent.
/// A trailing slash on the origin would produce `https://host//register` in
/// every URL the CLI builds from it.
fn normalise(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Resolve the server URL from the flag, the environment and the config file,
/// in that order.
pub fn resolve_server_url(flag: Option<&str>) -> Option<ServerUrl> {
    let env = std::env::var(SERVER_URL_ENV).ok();
    let file = config_path().ok().and_then(|p| server_url_in(&p));
    resolve_from(flag, env.as_deref(), file.as_deref())
}

/// The precedence rule itself, with all three inputs supplied.
fn resolve_from(flag: Option<&str>, env: Option<&str>, file: Option<&str>) -> Option<ServerUrl> {
    for (raw, source) in [
        (flag, ServerUrlSource::Flag),
        (env, ServerUrlSource::Env),
        (file, ServerUrlSource::ConfigFile),
    ] {
        if let Some(url) = raw.and_then(normalise) {
            return Some(ServerUrl { url, source });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_wins_over_everything() {
        let resolved = resolve_from(
            Some("https://flag.example"),
            Some("https://env.example"),
            Some("https://file.example"),
        )
        .expect("a flag is a server URL");
        assert_eq!(resolved.url, "https://flag.example");
        assert_eq!(resolved.source, ServerUrlSource::Flag);
    }

    #[test]
    fn the_environment_wins_over_the_config_file() {
        let resolved = resolve_from(
            None,
            Some("https://env.example"),
            Some("https://file.example"),
        )
        .expect("the environment is a server URL");
        assert_eq!(resolved.url, "https://env.example");
        assert_eq!(resolved.source, ServerUrlSource::Env);
    }

    /// The whole point of the installer writing the file: with neither a flag
    /// nor an environment variable, the machine still knows its server.
    #[test]
    fn the_config_file_answers_when_nothing_else_does() {
        let resolved = resolve_from(None, None, Some("https://file.example"))
            .expect("the file is a server URL");
        assert_eq!(resolved.url, "https://file.example");
        assert_eq!(resolved.source, ServerUrlSource::ConfigFile);
    }

    #[test]
    fn nothing_configured_resolves_to_nothing() {
        assert!(resolve_from(None, None, None).is_none());
    }

    /// An exported-but-empty `AGTCRDN_SERVER_URL` is how a shell profile that
    /// sets the variable conditionally looks. It must fall through to the
    /// file rather than resolve to "".
    #[test]
    fn an_empty_value_is_not_a_server_url() {
        let resolved = resolve_from(Some("  "), Some(""), Some("https://file.example"))
            .expect("the file still answers");
        assert_eq!(resolved.url, "https://file.example");
        assert_eq!(resolved.source, ServerUrlSource::ConfigFile);
    }

    /// `https://host/` would build `https://host//register`.
    #[test]
    fn a_trailing_slash_is_trimmed_from_every_source() {
        let flag = resolve_from(Some("https://flag.example/"), None, None).unwrap();
        assert_eq!(flag.url, "https://flag.example");
        let env = resolve_from(None, Some("https://env.example/"), None).unwrap();
        assert_eq!(env.url, "https://env.example");
    }

    #[test]
    fn the_config_file_is_toml_with_a_top_level_server_url() {
        let parsed = server_url_in_toml("server_url = \"https://cordon.example.com\"\n");
        assert_eq!(parsed.as_deref(), Some("https://cordon.example.com"));
    }

    /// The installer writes a comment above the key; a hand-edited file may
    /// carry anything else. Neither may change what `server_url` means.
    #[test]
    fn other_keys_and_comments_do_not_disturb_the_lookup() {
        let text = "# written by install.sh\nserver_url = \"http://127.0.0.1:4490\"\nother = 1\n";
        assert_eq!(
            server_url_in_toml(text).as_deref(),
            Some("http://127.0.0.1:4490")
        );
    }

    /// A config the CLI cannot parse must not make the CLI unusable: the flag
    /// and the environment variable still work, and the hint names both.
    #[test]
    fn a_malformed_config_is_absent_rather_than_fatal() {
        assert!(server_url_in_toml("this is not toml = = =").is_none());
        assert!(server_url_in_toml("other = 1").is_none());
        assert!(server_url_in_toml("server_url = 7").is_none());
        assert!(server_url_in_toml("server_url = \"\"").is_none());
    }

    #[test]
    fn a_missing_file_is_absent_rather_than_fatal() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(server_url_in(&dir.path().join("nope.toml")).is_none());
    }

    #[test]
    fn the_config_lives_next_to_the_brokers_state() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = config_path_from(Some(dir.path().to_path_buf())).unwrap();
        assert_eq!(path, dir.path().join(".agentcordon").join("config.toml"));
    }

    #[test]
    fn no_home_is_an_error_not_a_fallback_path() {
        let err = config_path_from(None).expect_err("missing home must error");
        assert!(err.message.contains("home directory"), "{}", err.message);
    }

    /// `status` has to be able to say which of the three answered.
    #[test]
    fn every_source_names_itself() {
        assert_eq!(ServerUrlSource::Flag.describe(), "--server-url");
        assert_eq!(ServerUrlSource::Env.describe(), "AGTCRDN_SERVER_URL");
        assert_eq!(
            ServerUrlSource::ConfigFile.describe(),
            "~/.agentcordon/config.toml"
        );
    }

    /// The error a user sees when nothing is configured has to name all three
    /// ways out on one line.
    #[test]
    fn the_hint_names_the_flag_the_variable_and_the_file() {
        let hint = missing_server_url_hint();
        assert!(hint.contains("--server-url"), "{hint}");
        assert!(hint.contains("AGTCRDN_SERVER_URL"), "{hint}");
        assert!(hint.contains("config.toml"), "{hint}");
        assert_eq!(hint.lines().count(), 1, "the hint is one line: {hint}");
    }
}
