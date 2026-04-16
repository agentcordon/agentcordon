-- Add mcp:discover to the bootstrap client's allowed_scopes.
--
-- The well-known agentcordon-broker bootstrap client (seeded in migration 006)
-- was registered with scopes credentials:discover,credentials:vend,mcp:invoke.
-- The broker itself requires mcp:discover to call its own mcp.list_servers /
-- mcp.list_tools routes (see crates/broker/src/routes/mcp.rs), and both the
-- CLI (register.rs / setup.rs) and the E2E OAuth register flow request it in
-- the device authorization grant.
--
-- Without this scope the server rejected the device_code request with
-- 400 invalid_scope "requested scope exceeds client allowed_scopes", breaking
-- workspace.oauth_register and every downstream broker-authenticated flow.

UPDATE oauth_clients
SET allowed_scopes = 'credentials:discover,credentials:vend,mcp:discover,mcp:invoke'
WHERE client_id = 'agentcordon-broker';
