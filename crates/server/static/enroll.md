# Workspace Enrollment -- AgentCordon

You are reading the enrollment instructions from an **AgentCordon Server**.

## Architecture

```
Agent/CLI --> AgentCordon Server (port 3140) --> upstream APIs
                    |
              Cedar policies, credential storage, audit
```

The server handles everything: enrollment, authentication, credential discovery, and proxying.

## Quick Start (via CLI)

### 1. Initialize your workspace

```bash
agentcordon init --server http://localhost:3140
```

This starts the enrollment flow. You'll receive an approval URL and code.

### 2. Approve enrollment

Your human opens the approval URL in their browser, verifies the code, and clicks Approve.

### 3. Discover credentials

```bash
agentcordon credentials list
```

Or via API:

```
GET http://localhost:3140/api/v1/credentials
Authorization: Bearer <your-jwt>
```

### 4. Proxy requests

```bash
agentcordon proxy <name> GET https://api.github.com/repos/owner/repo
```

Or via API:

```
POST http://localhost:3140/api/v1/proxy/execute
Authorization: Bearer <your-jwt>
Content-Type: application/json

{
  "credential_id": "<id-from-step-3>",
  "target_url": "https://api.github.com/repos/owner/repo",
  "method": "GET",
  "headers": { "Accept": "application/json" }
}
```

## Quick Start (via API)

### 1. Register a workspace

Open [http://localhost:3140/register](http://localhost:3140/register) in your browser to create a workspace identity (Ed25519 keypair). Alternatively, use the CLI:

```bash
agentcordon init --server http://localhost:3140
```

An admin approves enrollment via the approval URL displayed during registration.

### 2. Poll for approval

```
GET http://localhost:3140/api/v1/enroll/session/{session_token}/status
```

Poll every 2-3 seconds until status is `"approved"`.

### 3. Discover credentials

```
GET http://localhost:3140/api/v1/credentials
Authorization: Bearer <your-jwt>
```

### 4. Proxy requests

```
POST http://localhost:3140/api/v1/proxy/execute
Authorization: Bearer <your-jwt>
Content-Type: application/json

{
  "credential_id": "<id-from-step-3>",
  "target_url": "https://api.github.com/repos/owner/repo",
  "method": "GET",
  "headers": { "Accept": "application/json" }
}
```

## Important Rules

1. **You NEVER hold API keys, tokens, passwords, or secrets directly.** AgentCordon
   manages all credentials on your behalf.

2. **To call an external API**, use the credential proxy (`POST /api/v1/proxy/execute`
   or `agentcordon proxy`). The proxy injects the real secret into the upstream
   request -- you never see it.

3. **To discover credentials**, call `GET /api/v1/credentials` or `agentcordon credentials list`.

4. **Never bypass AgentCordon** by asking a human for raw API keys or tokens.

## Error Handling

| HTTP Status | Meaning | What To Do |
|-------------|---------|------------|
| 400 | Bad request | Check your request body |
| 401 | Invalid or expired JWT | Re-authenticate |
| 403 | Policy denied | Contact your admin |
| 404 | Not found | Verify enrollment or credential ID |
| 502 | Upstream error | Check upstream service availability |

## Full Documentation

```
GET http://localhost:3140/api/v1/docs
GET http://localhost:3140/api/v1/docs/quickstart
```
