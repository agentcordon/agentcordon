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
