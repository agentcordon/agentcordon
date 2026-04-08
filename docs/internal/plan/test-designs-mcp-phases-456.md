# Test Designs: MCP Marketplace Phases 4-6

## Phase 4: Enhanced Config Sync with Encrypted Credentials

### Context

Extends `GET /api/v1/workspaces/mcp-servers` to accept `?include_credentials=true&broker_public_key=<base64url>`. When present, for each MCP server's `required_credentials`, the server ECIES-encrypts the credential material to the broker's public key and includes it in the response.

### Integration Tests

File: `crates/server/tests/v320_encrypted_config_sync.rs`

Pattern: follows `v200_workspace_mcp_sync.rs` and `v310_mcp_marketplace.rs` structure with `TestAppBuilder`, `send_json`, and workspace JWT auth.

#### 4.1 `test_sync_without_credentials_unchanged`

**Setup:** Create workspace + MCP server with `required_credentials` linking to a stored credential. Provision via Phase 3 flow.

**Action:** `GET /api/v1/workspaces/mcp-servers` (no query params) with workspace JWT.

**Assert:**
- Response shape identical to existing sync (no `encrypted_credentials` field).
- Backward-compatible: no regression from Phase 4 changes.

#### 4.2 `test_sync_with_credentials_includes_envelopes`

**Setup:** Create workspace, create credential ("github-pat"), provision MCP server with `required_credentials: [cred_id]`. Generate a P-256 keypair for the "broker" (use `p256::SecretKey::random`).

**Action:** `GET /api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key=<base64url-uncompressed>` with workspace JWT.

**Assert:**
- 200 OK.
- Each server entry has an `encrypted_credentials` array.
- Each entry in `encrypted_credentials` contains: `credential_id`, `credential_type`, `transform_name`, `encrypted_envelope` with fields: `version`, `ephemeral_public_key`, `ciphertext`, `nonce`, `aad`.
- `version` is `1`.
- `ephemeral_public_key` is valid base64 decoding to 65 bytes (uncompressed P-256 point).

#### 4.3 `test_sync_encrypted_credential_decryptable`

**Setup:** Same as 4.2. Keep the broker's P-256 private key.

**Action:** Fetch sync with `include_credentials=true`. ECIES-decrypt the envelope using the broker's private key.

**Assert:**
- Decrypted plaintext is valid JSON matching `{"value": "<original_secret>"}`.
- AAD validates correctly (contains workspace_id, credential_id).

#### 4.4 `test_sync_credentials_excluded_when_no_policy_grant`

**Setup:** Create workspace A and workspace B. Create credential owned by workspace A. Create MCP server referencing that credential. Do NOT create a Cedar grant policy for workspace B.

**Action:** Workspace B calls `GET /api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key=<key>`.

**Assert:**
- Server entry is returned (MCP servers are a global catalog).
- `encrypted_credentials` is empty or null for credentials workspace B cannot vend.
- No 500 error — the server gracefully skips unauthorized credentials.

#### 4.5 `test_sync_credentials_invalid_public_key_rejected`

**Setup:** Standard workspace + MCP server.

**Action:** `GET /api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key=AAAA` (malformed key).

**Assert:**
- 400 Bad Request.
- Error message references `broker_public_key`.

#### 4.6 `test_sync_credentials_wrong_key_length_rejected`

**Setup:** Standard workspace.

**Action:** Call with `broker_public_key` that decodes to 32 bytes (not 65).

**Assert:** 400 Bad Request with message about 65-byte uncompressed point.

#### 4.7 `test_sync_credentials_expired_credential_excluded`

**Setup:** Create credential with `expires_at` in the past. Link to MCP server.

**Action:** Sync with `include_credentials=true`.

**Assert:** Expired credential is not included in `encrypted_credentials`.

#### 4.8 `test_sync_credentials_multiple_servers_multiple_creds`

**Setup:** Create 3 MCP servers, each with different `required_credentials` (some overlapping). Create 4 credentials total.

**Action:** Sync with `include_credentials=true`.

**Assert:**
- Each server's `encrypted_credentials` array matches its `required_credentials` list (minus any the workspace can't vend).
- No credential appears under a server that doesn't require it.

#### 4.9 `test_sync_credentials_no_secret_in_response_outside_envelope`

**Setup:** Provision MCP server with known secret `"ghp_phase4_leak_check"`.

**Action:** Sync with credentials.

**Assert:** Serialized response body does NOT contain the plaintext secret string anywhere outside the ECIES envelope ciphertext.

#### 4.10 `test_sync_credentials_audit_events`

**Setup:** Provision MCP server with credential.

**Action:** Sync with `include_credentials=true`.

**Assert:**
- Audit log contains a vend event for each credential encrypted in the response.
- Audit events do NOT contain the secret value.
- Audit events include the correlation_id.

---

## Phase 5: Broker MCP Config Cache + Credential Injection

### Context

The broker adds:
- `mcp_configs: RwLock<HashMap<String, Vec<CachedMcpServer>>>` to BrokerState.
- Background sync task (every 60s) calling the Phase 4 enhanced sync endpoint.
- `call_tool` uses cached config + decrypted credentials, injecting via `credential_transform::apply()`.
- MCP OAuth token refresh integrated into the existing 30-second loop.

### Integration Tests

File: `crates/broker/tests/mcp_cache_injection.rs` (or within existing broker test structure)

These tests require a mock server or the real server in test mode. Pattern: spin up test server + broker, use `reqwest` to exercise broker endpoints.

#### 5.1 `test_broker_cache_populated_on_startup`

**Setup:** Start server with provisioned MCP servers (2 servers, 3 credentials). Start broker pointing at server.

**Action:** Wait for initial sync (poll broker state or use a test hook).

**Assert:**
- `broker.mcp_configs` contains entries for the workspace.
- Each `CachedMcpServer` has `name`, `url`, `transport`, `decrypted_credentials`.
- Credentials are decrypted (not still in ECIES envelope form).

#### 5.2 `test_broker_cache_refreshes_periodically`

**Setup:** Start server + broker. Wait for initial sync. Then add a new MCP server via admin API.

**Action:** Wait for next sync cycle (up to 60s in real time, or reduce interval for tests).

**Assert:** New server appears in broker's `mcp_configs` cache.

#### 5.3 `test_broker_call_tool_injects_bearer_credential`

**Setup:** Provision MCP server "github" with a bearer-type credential (`value: "ghp_test123"`). Start a mock MCP HTTP server that echoes received headers. Start broker with cache populated.

**Action:** `POST /mcp/call` via broker with `{"server": "github", "tool": "some_tool", "arguments": {}}`.

**Assert:**
- Mock MCP server received `Authorization: Bearer ghp_test123` header.
- Broker response is 200 with tool result.

#### 5.4 `test_broker_call_tool_injects_api_key_header`

**Setup:** Provision MCP server with `api_key_header` credential (header_name: `X-Api-Key`, value: `key-abc`). Mock MCP server.

**Action:** `POST /mcp/call` via broker.

**Assert:** Mock received `X-Api-Key: key-abc` header.

#### 5.5 `test_broker_call_tool_injects_api_key_query`

**Setup:** Provision MCP server with `api_key_query` credential (param_name: `api_key`, value: `key-xyz`). Mock MCP server.

**Action:** `POST /mcp/call` via broker.

**Assert:** Mock received `?api_key=key-xyz` in the request URL.

#### 5.6 `test_broker_call_tool_no_credential_still_works`

**Setup:** Provision MCP server with `auth_method: none` and no `required_credentials`. Mock MCP server.

**Action:** `POST /mcp/call` via broker.

**Assert:**
- No `Authorization` header injected.
- Tool call succeeds.

#### 5.7 `test_broker_call_tool_server_not_in_cache`

**Setup:** Broker with empty cache (no sync yet or server returns empty).

**Action:** `POST /mcp/call` with a nonexistent server name.

**Assert:** 404 or appropriate error (falls back to current server-fetch behavior or returns cache miss error).

#### 5.8 `test_broker_cache_handles_server_unavailable`

**Setup:** Start broker. Make the server unreachable (stop it or point at wrong URL).

**Action:** Wait for sync cycle.

**Assert:**
- Broker logs a warning but doesn't crash.
- Previous cache entries (if any) are retained (stale-while-revalidate).
- Broker health endpoint still returns ok (degraded, not down).

#### 5.9 `test_broker_oauth_token_refresh_for_mcp_credential`

**Setup:** Provision MCP server with an `oauth2_client_credentials` type credential. Set the credential's token TTL to be very short (or mock token expiry).

**Action:** Wait for the 30-second refresh loop to fire. Then call the MCP tool.

**Assert:**
- The refreshed token is used in the injected `Authorization` header.
- The old (expired) token is not sent.

#### 5.10 `test_broker_credential_decryption_uses_broker_key`

**Setup:** Start broker (which generates its own P-256 keypair). Verify the sync endpoint was called with the broker's public key.

**Action:** Inspect the sync request (via mock or server audit log).

**Assert:**
- `broker_public_key` in the sync request matches the broker's `encryption_key` public component.
- Decrypted credentials in cache are valid (not garbled from key mismatch).

#### 5.11 `test_broker_ssrf_protection_still_applies`

**Setup:** Provision MCP server with URL pointing to `http://169.254.169.254/latest/meta-data/` (cloud metadata). Cache populated.

**Action:** `POST /mcp/call` via broker.

**Assert:** Blocked by SSRF protection (existing `validate_proxy_target_resolved`).

---

## Phase 6: Marketplace UI

### Context

New page at `/mcp-marketplace` showing a template grid. API key templates show a credential picker. OAuth templates show a "Connect" button. Uses the same template picker pattern as `credentials/new.html`.

### Integration Tests

File: `crates/server/tests/v330_marketplace_ui.rs`

Pattern: follows existing UI page tests — HTTP GET for the page, check 200 and key HTML fragments.

#### 6.1 `test_marketplace_page_loads_authenticated`

**Setup:** Create admin user, log in (get session cookie).

**Action:** `GET /mcp-marketplace` with session cookie.

**Assert:**
- 200 OK.
- Response body contains `<title>` with "Marketplace" or "MCP Marketplace".
- Response body contains the Alpine.js `x-data` attribute for the marketplace page component.

#### 6.2 `test_marketplace_page_redirects_unauthenticated`

**Setup:** No login.

**Action:** `GET /mcp-marketplace` without session cookie.

**Assert:** 302 redirect to `/login` (or 401, depending on middleware behavior).

#### 6.3 `test_marketplace_page_contains_template_grid`

**Setup:** Log in as admin.

**Action:** `GET /mcp-marketplace`.

**Assert:**
- HTML contains `template-grid` class (the grid container).
- HTML contains at least one `template-card` element (indicating templates are rendered or Alpine.js will populate them).

#### 6.4 `test_marketplace_page_references_templates_api`

**Setup:** Log in as admin.

**Action:** `GET /mcp-marketplace`.

**Assert:**
- JavaScript/Alpine init function references `/api/v1/mcp-templates` (the data source for the grid).
- This confirms the page will fetch templates on load.

#### 6.5 `test_marketplace_page_has_credential_picker_for_api_key`

**Setup:** Log in as admin.

**Action:** `GET /mcp-marketplace`.

**Assert:**
- HTML contains credential picker UI elements (select/dropdown for choosing existing credentials or input for new secret).
- This should be conditionally shown for `auth_method: api_key` templates.

#### 6.6 `test_marketplace_page_has_oauth_connect_button`

**Setup:** Log in as admin.

**Action:** `GET /mcp-marketplace`.

**Assert:**
- HTML contains a "Connect" button or link element associated with OAuth templates.
- The button references an OAuth authorization URL or a provision endpoint with OAuth flow.

#### 6.7 `test_marketplace_install_flow_provisions_server`

**Setup:** Log in as admin. Create a credential. Note the workspace ID.

**Action:** Simulate the install flow by calling `POST /api/v1/mcp-servers/provision` (which the UI form submits to) with `template_key`, `workspace_id`, `credential_id`.

**Assert:**
- 200 OK with server ID in response.
- MCP server appears in `GET /api/v1/mcp-servers` list.
- This is essentially the Phase 3 provisioning test but confirms the UI flow's backend works.

#### 6.8 `test_marketplace_search_filters_templates`

**Setup:** Log in. Fetch `/mcp-marketplace`.

**Action:** Verify the page HTML includes a search/filter input (matching the credential `new.html` pattern with `templateSearch` model).

**Assert:**
- Search input exists with appropriate `x-model` binding.
- Filter logic is present in the Alpine.js component.

---

## E2E DAG Node Specs

File: `tests/e2e/nodes/mcp_marketplace.py`

Pattern: follows `tests/e2e/nodes/mcp.py` and `tests/e2e/nodes/broker.py` — each node is a function + `DagNode` declaration with `depends_on`, `produces`, `consumes`.

### Node: `mcp_marketplace.sync_with_credentials`

**depends_on:** `["setup.login", "broker.start", "mcp.provision_github"]`

**consumes:** `["base_url", "broker_url", "broker_pem_key_path", "admin_session_cookie"]`

**produces:** `["mcp_sync_with_creds_response"]`

**Logic:**
1. Generate a P-256 keypair (or use broker's key from context).
2. Call `GET /api/v1/workspaces/mcp-servers?include_credentials=true&broker_public_key=<key>` via workspace JWT.
3. Assert 200, assert `encrypted_credentials` present for provisioned server.
4. ECIES-decrypt one envelope, assert plaintext contains `{"value": ...}`.
5. Store response in context.

### Node: `mcp_marketplace.broker_cache_populated`

**depends_on:** `["broker.start", "mcp.provision_github"]`

**consumes:** `["broker_url", "broker_pem_key_path"]`

**produces:** `[]`

**Logic:**
1. Wait up to 90s for broker cache to populate (poll `POST /mcp/list-servers` via broker, check the provisioned server appears).
2. Assert the server has credential info available (broker can call tools with it).

### Node: `mcp_marketplace.broker_injects_credential`

**depends_on:** `["mcp_marketplace.broker_cache_populated"]`

**consumes:** `["broker_url", "broker_pem_key_path"]`

**produces:** `[]`

**Logic:**
1. Start a simple mock HTTP MCP server on a free port that echoes received headers.
2. Update the provisioned MCP server's URL to point at the mock (via admin API).
3. Wait for broker cache refresh.
4. `POST /mcp/call` via broker for a tool on that server.
5. Assert the mock received the credential in the `Authorization` header.
6. Tear down mock.

**Note:** This node is `critical: False` because it requires a mock server setup that may be fragile in CI.

### Node: `mcp_marketplace.ui_page_loads`

**depends_on:** `["setup.login"]`

**consumes:** `["base_url", "admin_session_cookie"]`

**produces:** `[]`

**Logic:**
1. `GET /mcp-marketplace` with session cookie.
2. Assert 200.
3. Assert response contains "template-grid" and "template-card" strings.
4. Assert response contains a reference to `/api/v1/mcp-templates`.

### Node: `mcp_marketplace.provision_from_ui`

**depends_on:** `["mcp_marketplace.ui_page_loads", "credential.create"]`

**consumes:** `["base_url", "admin_session_cookie", "test_credential_id", "test_workspace_id"]`

**produces:** `["marketplace_provisioned_server_id"]`

**Logic:**
1. `POST /api/v1/mcp-servers/provision` with `template_key: "github"`, `workspace_id`, `credential_id`.
2. Assert 200, extract server ID.
3. `GET /api/v1/mcp-servers` and assert the new server appears.
4. Store server ID in context.

### Node: `mcp_marketplace.no_secret_leak`

**depends_on:** `["mcp_marketplace.provision_from_ui"]`

**consumes:** `["base_url", "admin_session_cookie", "marketplace_provisioned_server_id"]`

**produces:** `[]`

**Logic:**
1. Fetch the provisioned MCP server detail via admin API.
2. Assert response body does not contain the credential secret in plaintext.
3. Fetch audit log, assert no audit entry contains the secret value.

---

## Test Priority

| Priority | Tests | Rationale |
|----------|-------|-----------|
| P0 | 4.2, 4.3, 4.4, 5.3, 5.4 | Core functionality: encryption works, policy exclusion works, credential injection works |
| P0 | 4.9, 4.10 | Security: no secret leakage |
| P1 | 4.1, 4.5, 4.6, 5.1, 5.6, 5.8 | Backward compat, input validation, graceful degradation |
| P1 | 6.1, 6.2, 6.7 | UI loads, auth enforced, install flow works end-to-end |
| P2 | 4.7, 4.8, 5.2, 5.7, 5.9, 5.10, 5.11 | Edge cases and refresh behavior |
| P2 | 6.3-6.6, 6.8 | UI content verification |
