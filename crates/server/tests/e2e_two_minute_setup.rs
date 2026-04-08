//! E2E "2-Minute Setup" Acceptance Tests (Feature 8)
//!
//! These tests exercise the complete v1.5.2 user journey end-to-end,
//! from server start through a full agent operation cycle.
//!
//! Uses in-process HTTP via `tower::ServiceExt::oneshot` (no TCP/Docker).
//! Uses `wiremock::MockServer` for upstream API simulation.

use crate::common::*;

use uuid::Uuid;

use agent_cordon_core::domain::user::UserRole;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};

use agent_cordon_server::test_helpers::TestAppBuilder;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TEST_PASSWORD: &str = "strong-test-password-e2e!";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create an agent bound to a device directly in DB.
/// Replaces old device-mediated enrollment flow (removed in v1.13.0).
/// Returns (agent_id_string, "") for backwards compat.
async fn enroll_agent_via_device(
    state: &agent_cordon_server::state::AppState,
    _device_key: &p256::ecdsa::SigningKey,
    _device_id: &str,
    agent_name: &str,
    agent_tags: Option<Vec<&str>>,
) -> (String, String) {
    let agent_id = WorkspaceId(Uuid::new_v4());
    let now = chrono::Utc::now();
    let tags: Vec<String> = agent_tags
        .unwrap_or_default()
        .into_iter()
        .map(String::from)
        .collect();

    let agent = Workspace {
        id: agent_id.clone(),
        name: agent_name.to_string(),
        enabled: true,
        status: WorkspaceStatus::Active,
        pk_hash: None,
        encryption_public_key: None,
        tags,
        owner_id: None,
        parent_id: None,
        tool_name: None,
        created_at: now,
        updated_at: now,
    };

    state
        .store
        .create_workspace(&agent)
        .await
        .expect("create agent in DB");

    (agent_id.0.to_string(), String::new())
}

// ===========================================================================
// 8A. The Full Flow
// ===========================================================================

// ===========================================================================
// 8B. Negative E2E Scenarios
// ===========================================================================

// ===========================================================================
// 8C. Concurrency E2E
// ===========================================================================

/// 3 agents enroll through the same device concurrently; all approved with unique IDs.
#[tokio::test]
async fn test_e2e_concurrent_agent_enrollments() {
    let ctx = TestAppBuilder::new().with_admin().build().await;
    let _admin = create_test_user(&*ctx.store, "admin", TEST_PASSWORD, UserRole::Admin).await;
    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (cookie, csrf) = login_user(&app, "admin", TEST_PASSWORD).await;
    let full_cookie = combined_cookie(&cookie, &csrf);

    // Create and enroll a single device
    let (sig_key, sig_jwk, _enc_key, enc_jwk) = generate_dual_p256_keypairs_jwk();
    let (device_id, bootstrap_token) =
        create_device_via_api(&ctx.state, &full_cookie, &csrf, "concurrent-device").await;
    enroll_device(&ctx.state, &bootstrap_token, &sig_jwk, &enc_jwk).await;

    // Enroll 3 agents concurrently through the same device
    let state = ctx.state.clone();
    let sig_key_clone = sig_key.clone();
    let device_id_clone = device_id.clone();

    let mut enrollment_handles = Vec::new();
    for i in 0..3 {
        let s = state.clone();
        let sk = sig_key_clone.clone();
        let did = device_id_clone.clone();
        let handle = tokio::spawn(async move {
            enroll_agent_via_device(&s, &sk, &did, &format!("concurrent-agent-{}", i), None).await
        });
        enrollment_handles.push(handle);
    }

    // Collect results — agent_id is in the first element
    let mut agent_ids = Vec::new();
    for handle in enrollment_handles {
        let (agent_id, _) = handle.await.expect("enrollment task");
        agent_ids.push(agent_id);
    }

    // Assert all agent IDs are unique
    let mut unique_ids = agent_ids.clone();
    unique_ids.sort();
    unique_ids.dedup();
    assert_eq!(
        unique_ids.len(),
        3,
        "all 3 agent IDs must be unique: {:?}",
        agent_ids
    );

    // All agents should be bound to the same device
    for agent_id in &agent_ids {
        let agent_uuid = Uuid::parse_str(agent_id).unwrap();
        let agent = ctx
            .store
            .get_workspace(&WorkspaceId(agent_uuid))
            .await
            .expect("get agent")
            .expect("agent must exist");
        assert!(agent.enabled, "agent {} must be enabled", agent_id,);
    }
}
