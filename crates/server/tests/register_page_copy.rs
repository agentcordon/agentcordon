//! `/register` is the first page a new user reads, and its copy is the
//! product's instructions — so it has to describe what the CLI and the
//! installer actually do.
//!
//! Two fresh-user walkthroughs followed it and were misled three times: the
//! page promised the CLI would open a browser (it deliberately never does —
//! `docs/cli-reference.md § agentcordon register`), it printed a different
//! `curl` spelling from the README's, and it told the reader to move the
//! binary onto their PATH when `install.sh` installs it to `~/.local/bin`
//! and prints the `export PATH` line itself.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_server::test_helpers::TestAppBuilder;

use crate::common;

/// Render `/register` with no query parameters: the instructions page.
async fn register_page() -> String {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    common::create_test_user(
        &*ctx.store,
        "copy-admin",
        common::TEST_PASSWORD,
        UserRole::Admin,
    )
    .await;
    let cookie = common::login_user_combined(&ctx.app, "copy-admin", common::TEST_PASSWORD).await;
    let resp = ctx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/register")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// The CLI does not launch a browser, by design: the broker usually runs on
/// a different host, container or SSH session than the browser, so an
/// `xdg-open` would open the page on the wrong machine. A user who is told
/// to wait for a window waits forever.
#[tokio::test]
async fn register_page_does_not_promise_the_cli_opens_a_browser() {
    let html = register_page().await;

    assert!(
        !html.contains("opens\n            <a href=\"/activate\">/activate</a> in your browser"),
        "the page must not claim the CLI opens a browser"
    );
    assert!(
        html.contains("does not open a browser"),
        "the page must say the CLI leaves opening the page to the reader: {html}"
    );
}

/// One spelling of the install command across the product. The README uses
/// `curl -fsSL`; the page used `curl -sSfL`, and a reader comparing the two
/// has to work out whether the difference matters.
#[tokio::test]
async fn register_page_prints_the_same_curl_flags_as_the_readme() {
    let html = register_page().await;

    assert!(
        html.contains("curl -fsSL "),
        "the page must use the README's flag spelling: {html}"
    );
    assert!(
        !html.contains("curl -sSfL"),
        "the page must not use a second spelling of the same command"
    );
}

/// `install.sh` installs to `~/.local/bin` itself and prints the `export
/// PATH` line when that directory is not on the reader's PATH. Telling the
/// reader to move the binary describes a step that does not exist.
#[tokio::test]
async fn register_page_describes_what_the_installer_actually_does() {
    let html = register_page().await;

    assert!(
        !html.contains("move it somewhere on your PATH"),
        "the installer installs the binaries itself; the page must not ask for a move"
    );
    assert!(
        html.contains("~/.local/bin"),
        "the page must name where the installer puts the binaries: {html}"
    );
}

/// Install-to-use is three commands, and this page is where a new user reads
/// what the third one is. It used to print
/// `agentcordon init && agentcordon register --server-url <origin>` — two
/// commands, one of them carrying a URL the reader had to keep hold of. The
/// installer now records the server and `init` finishes enrollment, so the
/// page shows one command with nothing to copy into it.
#[tokio::test]
async fn register_page_shows_init_as_the_whole_of_step_two() {
    let html = register_page().await;

    assert!(
        html.contains("'agentcordon init'"),
        "step 2 must be `agentcordon init` on its own: {html}"
    );
    assert!(
        !html.contains("agentcordon register --server-url"),
        "the server URL is recorded by the installer; the page must not ask for it again"
    );
    assert!(
        html.contains("config.toml"),
        "the page must say the installer records the server: {html}"
    );
}
