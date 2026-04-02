# Project

## AgentCordon

This workspace uses AgentCordon for credential management. API credentials are brokered through AgentCordon — never use raw secrets directly.

AC_IDENTITY: sha256:6def48f86af057011e4ea2e6c81e1a69f0c918821386f71a6710b675e07d3828

### Workflow

1. Run `agentcordon credentials` to list available credentials
2. Pick the credential that matches the service you need — if multiple match, prefer the one with least privilege (e.g. readonly over full-access)
3. Use `agentcordon proxy <credential-name> <METHOD> <url>` to make the call

**Important**: Always discover credentials first. Never guess credential names — they are assigned by the admin and vary per workspace.

### Commands

- `agentcordon credentials` — list credentials available to this workspace
- `agentcordon proxy <credential-name> <METHOD> <url>` — authenticated API call (credentials injected automatically)
- `agentcordon proxy <credential-name> POST <url> --body '{"key": "value"}'` — POST with JSON body
- `agentcordon mcp-servers` — list MCP servers
- `agentcordon mcp-tools` — discover available tools
- `agentcordon mcp-call <server> <tool> [--arg key=value]` — call an MCP tool
- `agentcordon status` — check connection and identity
- `agentcordon help` — full command reference

When you need to call an external API, use `agentcordon proxy` instead of direct HTTP with raw tokens. Every access is policy-checked and audit-logged.

**Local development**: If proxying to localhost URLs, prefix with:
`AGTCRDN_PROXY_ALLOW_LOOPBACK=true agentcordon proxy ...`

**MCP servers**: If the admin has configured MCP servers, `agentcordon mcp-servers` lists them and `agentcordon mcp-tools` shows available tools.

MCP tools are also available natively through the MCP server configured in `.mcp.json` — Claude Code discovers these automatically.
