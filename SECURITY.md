# Security Policy

AgentCordon holds credentials on behalf of other people's agents. A flaw here is
a flaw in the thing it exists to prevent, so security reports get priority over
everything else.

## Supported versions

AgentCordon is pre-1.0. **Only the latest minor version is supported.** Fixes
land on the newest minor and ship in a patch release of it; older minors get
nothing, including security fixes.

| Version | Supported |
|---|:---:|
| 0.4.x | Yes |
| < 0.4 | No |

There is no long-term-support line and no backporting. If you are running an
older minor, the fix is to upgrade — see [`docs/upgrading.md`](docs/upgrading.md),
and note that server, broker and CLI move together.

## Reporting a vulnerability

**Report privately. Do not open a public issue, discussion or pull request.**

Use GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/agentcordon/agentcordon/security/advisories/new)**
— or, in the repository, **Security → Advisories → Report a vulnerability**.

That opens a draft advisory visible only to you and the maintainer. It is where
the whole exchange happens: the discussion, the fix, a CVE if one is warranted,
and the published advisory when the fix ships.

Please include:

- The version, and whether it is the container image or a native binary.
- What an attacker gains — read a credential, bypass a policy, escalate a role,
  reach a network the broker should refuse.
- A reproduction: the smallest sequence of requests, config or CLI commands that
  shows it. Redact real secrets; a fingerprint or a canary string is enough.
- Whether you believe it is exploitable with default settings or needs a
  particular misconfiguration.

## What to expect

| | |
|---|---|
| Acknowledgement | Within 3 working days |
| Initial assessment | Within 7 working days: confirmed or not, with severity |
| Fix for a confirmed high or critical issue | Targeted within 30 days, in a patch release of the current minor |
| Disclosure | Advisory published with the release that fixes it |

This is a small project, not a vendor with a response team. Those are honest
targets rather than a contractual SLA, and you will be told if one is going to
slip.

You will be credited in the advisory unless you ask not to be. There is no bug
bounty.

## Scope

**In scope** — the code in this repository and the artifacts it publishes:

- Credential disclosure: a secret reaching the agent, the CLI, a log, an audit
  row, a template or an error body.
- Authorization: any way to obtain a vend, a tool call or an admin operation
  that the Cedar policy should have denied, including privilege escalation
  between users, workspaces or vaults.
- The trust boundaries: CLI→broker request signing and nonce replay, the broker
  key pin, the ECIES vend envelope, the target-bound URL pattern check, the SSRF
  guard, the response leak scanner.
- Cryptography and key handling: the master key ring, rotation and re-sealing,
  encryption at rest.
- Authentication and sessions: the device-code flow, OAuth 2.0 as issued and as
  consumed, OIDC sign-in, the admin session cookie, CSRF.
- The published container image and release binaries, and the `install.sh` /
  `install.ps1` the server serves.

**Out of scope:**

- Vulnerabilities in dependencies with no AgentCordon-specific exploit path.
  Those belong upstream; `cargo deny check advisories` already tracks the tree,
  and `deny.toml` records why each ignored advisory is ignored.
- Deployments that ignore the documentation: a server without
  `AGTCRDN_BASE_URL`, a broker started with `--proxy-allow-loopback` or
  `AGTCRDN_PROXY_ALLOW_LOOPBACK` (which disables the SSRF check by design), an
  admin console served over plain HTTP on a routable address, or
  `AGTCRDN_REPLICA_MODE=unsafe-shared`.
- Anything requiring an attacker who already has root on the server host, the
  contents of the `/data` volume, or the master secret.
- A malicious *admin*: an admin can read and write credentials by design.
- Denial of service by ordinary request volume, missing security headers with no
  demonstrated impact, and the output of automated scanners without a working
  proof of concept.

Security *hardening* ideas and low-severity issues that are safe to discuss in
the open are welcome as a
[Security Concern issue](https://github.com/agentcordon/agentcordon/issues/new?template=security_report.yml).
If you are unsure which a finding is, report it privately and it will be moved.

## Where the security model is written down

[Authorization & Cedar Policy](docs/authorization-and-cedar-policy.md),
[Credential Encryption](docs/credential-encryption.md),
[Master Key](docs/master-key.md), and
[System Architecture](docs/system-architecture.md) describe what AgentCordon
claims to guarantee. A report is strongest when it names the claim it breaks.
