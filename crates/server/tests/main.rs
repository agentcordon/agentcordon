// All integration tests consolidated into a single binary.
//
// Previously, each .rs file in this directory compiled as a separate ~294MB
// test binary. With 28 files that meant ~8.3GB of disk and 27 redundant
// link steps. By re-exporting every file as a module of this single crate,
// we compile and link once.
//
// Each module is its own namespace so duplicate helper function names
// (e.g. `setup_test_app`, `create_user_in_db`) across modules do not conflict.

mod common;

mod cedar_policy_routes;
mod credential_bugs;
mod csrf;
mod docs;
mod e2e_two_minute_setup;
mod lifecycle_cross_principal;
mod mcp_tests;
mod metrics;
mod oauth2_refresh_rotation;
mod oidc;
mod permission_grants;
mod phase2_tags_status;
mod policy_templates;
mod user_auth;
mod v014_features;
mod v015_features;
mod v016_crypto;
mod v016_oauth2;
mod v1100_cross_feature;
mod v1100_curated_policies;
mod v1100_features;
mod v1100_policy_list;
mod v1100_policy_tester;
mod v1100_rsop_api;
mod v1100_statement_editor;
mod v1110_affected_principals;
mod v1110_agent_upload;
mod v1110_cedar_schema;
mod v1110_cross_feature;
mod v1110_dashboard;
mod v1110_device_scoped_mcps;
mod v1110_migration;
mod v1110_permissions_audit;
mod v1110_policy_link_fix;
mod v1110_policy_tester_attrs;
mod v1140_cleanup_permissions;
mod v1140_jwt_issuer;
mod v1140_jwt_validation;
mod v1140_mcp_permissions;
mod v1140_sse_merge;
mod v1150_audit_policy_reasoning;
mod v1150_credential_history_ui;
mod v1150_migration_consolidation;
mod v1150_nonce_tracking;
mod v1150_workspace_identity_tag;
mod v153_openapi;
mod v153_server_defaults;
mod v154_e2e;
mod v154_manage_tags;
mod v154_ownership;
mod v154_policy_test;
mod v16_hardening;
mod v170_cross_feature;
mod v170_features;
mod v170_proxy_name_resolution;
mod v171_credential_display;
mod v171_display_names;
mod v171_jwt_nbf;
mod v171_proxy_validation;
mod v180_agent_store;
mod v180_llm_exposed;
mod v180_stats;
mod v190_migration;
mod v190_pages;
mod v190_routing;
mod v190_sse;
mod v190_templates;
mod v191_argon2_async;
mod v191_credential_list;
mod v191_page_auth;
mod v191_policy_detail;
mod v191_sqlite_pool;
mod v191_sse_limits;
mod v192_features;
mod v192_permission_names;
mod v193_credential_templates;
mod v193_features;
mod v194_features;
mod v194_login_form;
mod v194_policy_route;
mod v194r2_features;
mod v200_audit_stream;
mod v200_workspace_mcp_sync;
mod v200_workspace_policy_sync;
mod v200_workspace_tags;
mod v201_credential_fields;
mod v201_mcp_authorize;
mod v300_oauth_as;
mod v300_security;
mod v310_mcp_marketplace;
mod v311_credential_name_scoping;
mod v312_mcp_config_sync;
mod v330_oauth_dcr;
mod vaults;
mod workspace_delete;
