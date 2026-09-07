//! Integration tests for `GET /install.sh`.
//!
//! Two properties a new user depends on and neither of which the script had:
//!
//! 1. **It runs under `sh`.** The documented invocation, in the README and in
//!    `docs/upgrading.md`, is `curl -fsSL <server>/install.sh | sh`. The script
//!    used to re-exec itself with
//!    `exec bash -c "$(curl -fsSL <AGTCRDN_BASE_URL>/install.sh)"`, so under a
//!    `sh` that is not bash it fetched itself again from the server's
//!    *configured* base URL rather than from the URL the user actually used.
//!    On any deployment where those differ — a container network, a tunnel, a
//!    reverse proxy the server does not know its own name behind — the
//!    documented command died on a connection error. The script must not
//!    re-fetch itself.
//! 2. **It verifies what it downloads.** README advertises SHA-256
//!    verification for the Windows installer; the Unix one installed two
//!    binaries straight from the GitHub release with no check at all.
//!
//! Both are asserted against the served bytes, because the served bytes are
//! what a user pipes into a shell.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use agent_cordon_server::test_helpers::TestAppBuilder;

async fn setup_test_app() -> Router {
    TestAppBuilder::new().build().await.app
}

/// `GET /install.sh` with an optional `Host`, returning status, content type
/// and the script body as text.
async fn get_install_script(app: &Router, host: Option<&str>) -> (StatusCode, String, String) {
    let mut builder = Request::builder().method(Method::GET).uri("/install.sh");
    if let Some(h) = host {
        builder = builder.header(header::HOST, h);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn install_script_is_served_as_a_shell_script() {
    let app = setup_test_app().await;
    let (status, content_type, body) = get_install_script(&app, None).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.contains("shellscript"),
        "unexpected content-type: {content_type}"
    );
    assert!(
        body.starts_with("#!/bin/sh"),
        "the documented invocation is `| sh`, so the script must be POSIX sh; \
         first line was: {:?}",
        body.lines().next()
    );
}

#[tokio::test]
async fn install_script_does_not_re_fetch_itself() {
    let app = setup_test_app().await;
    let (_, _, body) = get_install_script(&app, Some("agentcordon.example.com")).await;

    // The old guard was:
    //   if [ -z "${BASH_VERSION:-}" ]; then
    //       exec bash -c "$(curl -fsSL <base>/install.sh)"
    // which re-downloads from the templated base URL, not from the URL the
    // user piped from. No executable line may both curl and name install.sh;
    // a comment showing the documented invocation is fine.
    for (n, line) in body.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with('#') {
            continue;
        }
        assert!(
            !(code.contains("curl") && code.contains("install.sh")),
            "line {} re-fetches the script instead of running as served: {line}",
            n + 1
        );
    }
    assert!(
        !body.contains("exec bash"),
        "the script must not re-exec under bash; it has to run as served"
    );
    assert!(
        !body.contains("BASH_VERSION"),
        "no bash-only guard: the script is POSIX sh and runs as served"
    );
}

#[tokio::test]
async fn install_script_verifies_sha256_before_installing() {
    let app = setup_test_app().await;
    let (_, _, body) = get_install_script(&app, None).await;

    assert!(
        body.contains("SHA256SUMS"),
        "the script must fetch the release's SHA256SUMS"
    );
    // At least one real digest tool, and a comparison that can fail the run.
    assert!(
        body.contains("sha256sum") || body.contains("shasum") || body.contains("openssl dgst"),
        "the script must actually compute a SHA-256 digest"
    );
    assert!(
        body.contains("mismatch"),
        "the script must abort on a checksum mismatch"
    );
}

#[tokio::test]
async fn install_script_installs_both_binaries() {
    let app = setup_test_app().await;
    let (_, _, body) = get_install_script(&app, None).await;

    assert!(body.contains("agentcordon-${TARGET}"), "CLI asset missing");
    assert!(
        body.contains("agentcordon-broker-${TARGET}"),
        "broker asset missing"
    );
}

#[tokio::test]
async fn install_script_is_templated_with_the_request_host_when_no_base_url_is_set() {
    let app = setup_test_app().await;
    let (_, _, body) = get_install_script(&app, Some("agentcordon.example.com")).await;

    assert!(
        body.contains("agentcordon.example.com"),
        "the served script should reference the host the client reached"
    );
    assert!(
        !body.contains("{server_url}"),
        "the placeholder must be substituted"
    );
}

/// `GET /install.ps1` serves the Windows installer the README's one-liner
/// (`irm https://<server>/install.ps1 | iex`) depends on, with the server URL
/// the client used substituted in. The route was documented and shipped in
/// `tools/install.ps1` but never registered, so the one-liner was a 404.
#[tokio::test]
async fn install_ps1_is_served_with_the_reaching_origin_substituted() {
    let app = setup_test_app().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/install.ps1")
                .header(header::HOST, "cordon.example.test")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("text/plain"),
        "PowerShell must be served as text so `irm | iex` treats it as a script, got {content_type}"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(
        body.starts_with("#Requires -Version 5.1"),
        "body must start with the PowerShell header, got {:?}",
        &body[..body.len().min(60)]
    );
    assert!(
        body.contains("$ServerUrl = \"https://cordon.example.test\""),
        "the reaching origin must be substituted for the {{SERVER_URL}} placeholder"
    );
    assert!(
        !body.contains("{SERVER_URL}"),
        "no placeholder may survive substitution"
    );
    assert!(
        body.contains("LOCALAPPDATA"),
        "install target must be %LOCALAPPDATA%"
    );
}

/// The served installer pins the release to the server's own version.
///
/// It used to fetch `releases/latest/download`, which is the last *published*
/// release. A server built from `main` therefore handed every new user a CLI
/// and broker from an older release — 0.3.3 against a 0.4.0 server, across
/// the v0.4.0 signing-format change that `docs/cli-reference.md` says in bold
/// the two sides cannot talk over. The one install command in the README
/// produced a mismatched pair, and nothing said so.
#[tokio::test]
async fn install_script_pins_the_release_to_the_server_version() {
    let app = setup_test_app().await;
    let (_, _, body) = get_install_script(&app, None).await;

    let expected = format!(
        "https://github.com/agentcordon/agentcordon/releases/download/v{}",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        body.contains(&expected),
        "the script must download from this server's own release tag ({expected})"
    );
    assert!(
        !body.contains("releases/latest/download"),
        "`latest` is the last published release, not this server's version"
    );
    assert!(
        !body.contains("{version}"),
        "the version placeholder must be substituted"
    );
}

/// When no release exists for this version yet — the normal state of `main`
/// between releases — the script has to say so and point at building from
/// source, rather than fail on a bare 404 from a URL the user did not choose.
#[tokio::test]
async fn install_script_explains_a_missing_release_for_this_version() {
    let app = setup_test_app().await;
    let (_, _, body) = get_install_script(&app, None).await;

    assert!(
        body.contains(env!("CARGO_PKG_VERSION")),
        "the failure message must name the version it looked for"
    );
    assert!(
        body.contains("Building from Source") || body.contains("build from source"),
        "the failure message must point at building from source"
    );
}

/// The Windows installer is pinned the same way, for the same reason.
#[tokio::test]
async fn install_ps1_pins_the_release_to_the_server_version() {
    let app = setup_test_app().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/install.ps1")
                .header(header::HOST, "cordon.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);

    let expected = format!(
        "https://github.com/agentcordon/agentcordon/releases/download/v{}",
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        body.contains(&expected),
        "the PowerShell installer must pin the same tag ({expected})"
    );
    assert!(
        !body.contains("releases/latest/download"),
        "`latest` is the last published release, not this server's version"
    );
    assert!(
        !body.contains("{VERSION}"),
        "the version placeholder must be substituted"
    );
}

// ---------------------------------------------------------------------------
// The scheme of the fallback SERVER_URL
// ---------------------------------------------------------------------------

/// `GET /install.sh` with a `Host` and an explicit `X-Forwarded-Proto`.
async fn get_install_script_forwarded(
    app: &Router,
    host: &str,
    forwarded_proto: Option<&str>,
) -> String {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri("/install.sh")
        .header(header::HOST, host);
    if let Some(proto) = forwarded_proto {
        builder = builder.header("x-forwarded-proto", proto);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn server_url_line(body: &str) -> &str {
    body.lines()
        .find(|l| l.trim_start().starts_with("SERVER_URL="))
        .unwrap_or_else(|| panic!("the script sets SERVER_URL: {body}"))
        .trim()
}

/// The server never terminates TLS itself, so a request that arrives without
/// `X-Forwarded-Proto` arrived over plain HTTP. Guessing `https` emitted an
/// installer pointing at a URL that does not answer, and the documented
/// symptom of a missing `AGTCRDN_BASE_URL` (`0.0.0.0`) never appeared, so a
/// user had no way to recognise the situation.
#[tokio::test]
async fn a_plain_http_request_gets_an_http_fallback_url() {
    let app = setup_test_app().await;

    let body = get_install_script_forwarded(&app, "localhost:4140", None).await;

    assert_eq!(
        server_url_line(&body),
        r#"SERVER_URL="http://localhost:4140""#
    );
}

/// A reverse proxy that terminates TLS says so, and that is the only way the
/// server can know.
#[tokio::test]
async fn a_forwarded_https_request_gets_an_https_fallback_url() {
    let app = setup_test_app().await;

    let body = get_install_script_forwarded(&app, "cordon.example.test", Some("https")).await;

    assert_eq!(
        server_url_line(&body),
        r#"SERVER_URL="https://cordon.example.test""#
    );
}

/// A proxy chain sends a comma-separated list; the first entry is the client's
/// own hop, which is the one that matters.
#[tokio::test]
async fn a_forwarded_proto_list_uses_the_first_entry() {
    let app = setup_test_app().await;

    let body = get_install_script_forwarded(&app, "cordon.example.test", Some("https, http")).await;

    assert_eq!(
        server_url_line(&body),
        r#"SERVER_URL="https://cordon.example.test""#
    );
}

/// `AGTCRDN_BASE_URL` still wins over everything the request carries -- it is
/// the operator's answer, and the reason the fallback exists at all is that
/// it is unset.
#[tokio::test]
async fn a_configured_base_url_beats_the_request_headers() {
    let app = TestAppBuilder::new()
        .with_config(|c| c.base_url = Some("https://agentcordon.example.com/".to_string()))
        .build()
        .await
        .app;

    let body = get_install_script_forwarded(&app, "internal:3140", Some("http")).await;

    assert_eq!(
        server_url_line(&body),
        r#"SERVER_URL="https://agentcordon.example.com""#
    );
}

// ---------------------------------------------------------------------------
// What the installer leaves the user with
// (uat/artifacts/reviews/ONBOARDING-empirical.md F3, F6, F7)
// ---------------------------------------------------------------------------

/// `GET /install.ps1` body, for the assertions that are about the served text.
async fn get_install_ps1(app: &Router) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/install.ps1")
                .header(header::HOST, "cordon.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The closing message is the only instruction most people read, so it names
/// exactly one command.
///
/// It used to also explain what `init` does ("choose your agent runtimes").
/// `init` now picks the runtimes, installs the skill *and* enrols the
/// workspace, which is more than a trailing comment can carry — and `init`
/// itself says what it did. What the installer owes the reader is the name of
/// the next command.
#[tokio::test]
async fn the_installers_name_agentcordon_init_as_the_next_command() {
    let app = setup_test_app().await;
    let sh = get_install_script(&app, None).await.2;
    let ps1 = get_install_ps1(&app).await;

    for (name, body) in [("install.sh", &sh), ("install.ps1", &ps1)] {
        assert!(
            body.contains("agentcordon init"),
            "{name}: the closing message must name `agentcordon init`"
        );
    }
}

/// `export PATH="…:$PATH"` is ephemeral — the next terminal has no
/// `agentcordon` — and it does not parse in nushell at all. The script reads
/// `$SHELL` and writes the file that shell actually reads.
///
/// `config.nu` was the file the old *printed hint* named; the block goes in
/// `env.nu`, which is nushell's own place for environment setup and the one
/// that is sourced before `config.nu`.
#[tokio::test]
async fn the_unix_installer_covers_every_shell_it_can_name() {
    let app = setup_test_app().await;
    let (_, _, body) = get_install_script(&app, None).await;

    assert!(body.contains("$SHELL"), "the script must look at $SHELL");
    for expected in [
        ".bashrc",
        ".bash_profile",
        ".zshrc",
        "fish_add_path",
        "$env.PATH",
        "env.nu",
    ] {
        assert!(
            body.contains(expected),
            "PATH guidance must cover {expected}"
        );
    }
}

/// `install.sh` refuses an asset with no `SHA256SUMS` entry; `install.ps1`
/// warned and installed it anyway, so the two documented one-liners had
/// different security postures while `docs/installation.md` described them
/// identically (F6).
#[tokio::test]
async fn the_windows_installer_refuses_an_asset_with_no_checksum_entry() {
    let app = setup_test_app().await;
    let body = get_install_ps1(&app).await;

    assert!(
        !body.contains("skipping verification"),
        "install.ps1 must not install an unverified asset"
    );
    assert!(
        body.contains("refusing to install"),
        "install.ps1 must refuse an asset with no SHA256SUMS entry, as install.sh does"
    );
}

/// A proxy, a DNS blip or a rate-limit produced "No published release for
/// AgentCordon vX" and a "build from source" instruction — a confidently wrong
/// diagnosis (F7). Only a 404 means there is no release.
#[tokio::test]
async fn both_installers_tell_a_missing_release_apart_from_a_failed_fetch() {
    let app = setup_test_app().await;
    let sh = get_install_script(&app, None).await.2;
    let ps1 = get_install_ps1(&app).await;

    assert!(
        sh.contains("404"),
        "install.sh must check for a 404 before blaming a missing release"
    );
    assert!(
        sh.contains("Could not reach") || sh.contains("could not reach"),
        "install.sh needs a separate message for a transport failure"
    );
    assert!(
        ps1.contains("404") && ps1.contains("StatusCode"),
        "install.ps1 must inspect the HTTP status before blaming a missing release"
    );
    assert!(
        ps1.contains("Could not reach"),
        "install.ps1 needs a separate message for a transport failure"
    );
}

// ---------------------------------------------------------------------------
// What the installer *writes*: the server URL, and PATH that survives the
// terminal (uat/artifacts/reviews/ONBOARDING-empirical.md F3, P5)
// ---------------------------------------------------------------------------

/// Run the served `install.sh` under a throwaway `HOME`, with the download
/// skipped.
///
/// `AGENTCORDON_SKIP_DOWNLOAD=1` is the seam these tests need and the escape
/// hatch a build-from-source user needs: it stops before the GitHub fetch and
/// still does everything the installer does *locally* — write the config file,
/// persist PATH, print the closing message. Without it there is no way to
/// exercise the two things a new user actually depends on without reaching the
/// public internet from a unit test.
struct InstallerRun {
    home: tempfile::TempDir,
    stdout: String,
    status: std::process::ExitStatus,
}

impl InstallerRun {
    fn file(&self, relative: &str) -> Option<String> {
        std::fs::read_to_string(self.home.path().join(relative)).ok()
    }
}

async fn run_installer(shell: &str, extra_env: &[(&str, &str)]) -> InstallerRun {
    run_installer_in(setup_test_app().await, shell, extra_env).await
}

async fn run_installer_in(app: Router, shell: &str, extra_env: &[(&str, &str)]) -> InstallerRun {
    let (_, _, body) = get_install_script(&app, Some("cordon.example.test")).await;

    let home = tempfile::TempDir::new().expect("temp HOME");
    let script = home.path().join("install.sh");
    std::fs::write(&script, &body).expect("write the served script");

    let mut cmd = std::process::Command::new("sh");
    cmd.arg(&script)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("SHELL", shell)
        .env("AGENTCORDON_SKIP_DOWNLOAD", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("the served script must run under sh");
    InstallerRun {
        home,
        stdout: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        status: out.status,
    }
}

/// The installer knows the origin it was fetched from. Writing it to the CLI's
/// config is what makes `--server-url` optional on `register` and on
/// `agentcordon init` — the difference between a two-command enrolment and a
/// user copying a URL out of a terminal.
#[tokio::test]
async fn the_installer_records_the_server_it_came_from() {
    let run = run_installer("/bin/bash", &[]).await;
    assert!(run.status.success(), "installer failed: {}", run.stdout);

    let config = run
        .file(".agentcordon/config.toml")
        .expect("the installer must write ~/.agentcordon/config.toml");
    assert!(
        config.contains(r#"server_url = "http://cordon.example.test""#),
        "config must record the origin the script was fetched from: {config}"
    );
    assert!(
        run.stdout.contains(".agentcordon/config.toml"),
        "the installer must say it wrote the config: {}",
        run.stdout
    );
}

/// The config directory holds nothing but the broker's own key material next
/// to it, so it is created `0700` like every other directory the broker owns.
#[cfg(unix)]
#[tokio::test]
async fn the_config_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let run = run_installer("/bin/bash", &[]).await;
    let mode = std::fs::metadata(run.home.path().join(".agentcordon"))
        .expect(".agentcordon must exist")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "~/.agentcordon must be 0700, was {mode:o}");
}

/// Re-running the installer from a *different* server silently repointing the
/// machine is the failure this guards: the change is made, and it is
/// announced with both URLs.
#[tokio::test]
async fn changing_the_recorded_server_is_announced() {
    let app = setup_test_app().await;
    let run = run_installer_in(app, "/bin/bash", &[]).await;

    std::fs::write(
        run.home.path().join(".agentcordon/config.toml"),
        "server_url = \"https://old.example.com\"\n",
    )
    .unwrap();

    let mut cmd = std::process::Command::new("sh");
    let second = cmd
        .arg(run.home.path().join("install.sh"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", run.home.path())
        .env("SHELL", "/bin/bash")
        .env("AGENTCORDON_SKIP_DOWNLOAD", "1")
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&second.stdout).into_owned();

    assert!(
        out.contains("https://old.example.com") && out.contains("http://cordon.example.test"),
        "a changed server_url must name both the old and the new value: {out}"
    );
    let config = run.file(".agentcordon/config.toml").unwrap();
    assert!(
        config.contains("http://cordon.example.test"),
        "the newly fetched installer's origin wins: {config}"
    );
}

/// `export PATH=…` printed to a terminal is gone when that terminal closes,
/// and it does not parse in nushell at all (F3). rustup and uv both write the
/// user's shell startup file; so does this.
#[tokio::test]
async fn the_installer_persists_path_for_each_shell() {
    // (login shell, file it must write, line it must contain)
    let cases: &[(&str, &str, &str)] = &[
        ("/bin/bash", ".bashrc", "export PATH="),
        ("/usr/bin/zsh", ".zshrc", "export PATH="),
        (
            "/usr/bin/fish",
            ".config/fish/conf.d/agentcordon.fish",
            "fish_add_path",
        ),
        ("/usr/bin/nu", ".config/nushell/env.nu", "$env.PATH"),
    ];

    for (shell, file, line) in cases {
        let run = run_installer(shell, &[]).await;
        assert!(run.status.success(), "{shell}: {}", run.stdout);
        let written = run
            .file(file)
            .unwrap_or_else(|| panic!("{shell} must have its PATH persisted in {file}"));
        assert!(
            written.contains(line),
            "{shell}: {file} must contain {line}, got: {written}"
        );
        assert!(
            written.contains(".local/bin"),
            "{shell}: {file} must add the install dir: {written}"
        );
        assert!(
            run.stdout.contains(file),
            "{shell}: the installer must name the file it changed: {}",
            run.stdout
        );
        assert!(
            run.stdout.to_lowercase().contains("remove"),
            "{shell}: the installer must say how to undo the change: {}",
            run.stdout
        );
    }
}

/// A second install must not append a second block. Marker-delimited, checked
/// before writing.
#[tokio::test]
async fn persisting_path_twice_changes_the_file_once() {
    let app = setup_test_app().await;
    let run = run_installer_in(app, "/bin/bash", &[]).await;
    let after_first = run.file(".bashrc").expect("bashrc written");

    let mut cmd = std::process::Command::new("sh");
    cmd.arg(run.home.path().join("install.sh"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", run.home.path())
        .env("SHELL", "/bin/bash")
        .env("AGENTCORDON_SKIP_DOWNLOAD", "1")
        .output()
        .unwrap();

    assert_eq!(
        run.file(".bashrc").unwrap(),
        after_first,
        "a rerun must leave the startup file byte-identical"
    );
}

/// Editing a user's dotfiles is the kind of thing that must be refusable, and
/// refusing it must still leave them able to finish by hand.
#[tokio::test]
async fn the_path_edit_can_be_declined() {
    let run = run_installer("/bin/bash", &[("AGENTCORDON_NO_MODIFY_PATH", "1")]).await;

    assert!(
        run.file(".bashrc").is_none(),
        "AGENTCORDON_NO_MODIFY_PATH=1 must write no startup file"
    );
    assert!(
        run.stdout.contains("export PATH="),
        "declining the edit must still print the line to add by hand: {}",
        run.stdout
    );
}

/// The closing message is the only instruction most people read. After this
/// change it has one instruction in it, and no `--server-url`: the server is
/// already remembered.
#[tokio::test]
async fn the_closing_message_is_what_was_installed_and_one_next_step() {
    let run = run_installer("/bin/bash", &[]).await;

    assert!(
        run.stdout
            .contains("Next: cd into a project and run `agentcordon init`"),
        "the closing message must be the single next step: {}",
        run.stdout
    );
    let tail: Vec<&str> = run
        .stdout
        .lines()
        .filter(|l| l.contains("agentcordon register"))
        .collect();
    assert!(
        tail.is_empty(),
        "`register` is no longer a step a new user takes: {tail:?}"
    );
}

/// The same promise on Windows: the installer knows its origin and records it.
#[tokio::test]
async fn the_windows_installer_records_the_server_and_ends_with_init() {
    let app = setup_test_app().await;
    let body = get_install_ps1(&app).await;

    assert!(
        body.contains("config.toml"),
        "install.ps1 must write the CLI config file"
    );
    assert!(
        body.contains(".agentcordon"),
        "install.ps1 must write it under the user's .agentcordon directory"
    );
    assert!(
        body.contains("Next: cd into a project and run `agentcordon init`"),
        "install.ps1's closing message must be the single next step"
    );
    assert!(
        !body.contains("agentcordon register"),
        "`register` is no longer a step a new user takes"
    );
    assert!(
        body.contains("AGENTCORDON_NO_MODIFY_PATH"),
        "the PATH edit must be declinable on Windows too"
    );
}
