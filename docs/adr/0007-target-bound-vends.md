# 7. Target-bound vends, with a structural URL pattern enforced at both server and broker

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

AgentCordon promised that agents call APIs without seeing the keys, and that every access is
policy-checked. As built, the promise held for the *secret* but not for the *request*. The
server decided whether a workspace could have a credential; the broker decided where that
credential went, with only a loopback check. A prompt-injected agent could ask for a legitimate
credential and send it anywhere.

A credential already carried an `allowed_url_pattern`. The admin UI displayed it as an
enforced restriction. Nothing read it. The broker's vend request did not say where the
credential was going, so the server had nothing to check it against — the field was decorative.
This is also how a CI check for enforcement modules with no callers came to exist: the URL
matcher sat unused for an entire release.

The pattern's original matcher was also a plain glob over the whole URL string, which is not a
safe way to compare URLs: `https://*.github.com/*` matched any URL whose *query string* merely
contained `.github.com/`.

## Decision

**A vend names its target, and the target is checked twice.**

1. **The vend request carries the target.** `POST /api/v1/credentials/vend-device/{name}` (and
   the by-id form) accept `method` and `target_url`
   (`crates/broker/src/server_client.rs`, `crates/server/src/routes/admin_api/credentials/vend.rs`).
2. **The server checks first, before any secret leaves it.** A credential with a pattern is
   vended only for a target inside it; a non-`generic` credential is never vended without one.
   The target goes into the Cedar context as `target_url` and into the vend audit row.
3. **The vend response carries `allowed_url_pattern` back**, and the broker re-checks the
   target against it **in the process that will inject**, failing closed with 403 when it does
   not match, or when a non-`generic` credential arrives with no pattern at all
   (`crates/broker/src/routes/proxy.rs`).

The matcher is **structural**, not textual (`crates/core/src/proxy/url_match.rs`): scheme, host
and port are compared as parsed values, a `*` in the host stands for exactly one label, and the
glob applies to path and query only.

Supporting rules that make the check meaningful:

- A refusal has its own error code, **`url_pattern_denied`**, with a message naming the pattern
  and the target, relayed verbatim by the broker. `forbidden` / "access denied by server
  policy" sent users to Cedar and `/policies` for a mismatch that lives on the credential.
- A URL-pattern refusal writes a `credential_vend_denied` audit row naming the workspace, the
  credential, the target URL and method, and the pattern — because the check returns before
  Cedar runs, and Cedar is what self-audits denials.
- The pattern is validated **when it is written**, not only when it is used: create and update
  answer 400 naming what is wrong.
- Redirects are never followed by the broker's outbound client. A 3xx is returned to the CLI
  with its status and headers, because following one would carry the injected credential to
  wherever the upstream pointed — outside the pattern that was just checked.
- The same reasoning extends to MCP: tool-list probes pass the same resolving SSRF check as
  tool calls, and the leak scanner runs over tool results and probe responses as well as proxy
  responses.

## Consequences

- Double enforcement is deliberate, not redundant. The server's check is the authority and is
  what refuses before a secret is released; the broker's check is what stops an envelope
  obtained for one target being used for another in the process that holds the plaintext.
- A `generic` credential with no pattern is still unrestricted. That is the compatibility
  escape hatch, and it is why the CLI's success line now says whether a credential is fenced or
  unrestricted, and why `agentcordon credentials create` accepts `--allowed-url-pattern`.
- Structural matching is stricter than the old glob, so a pattern written against the old
  behaviour may now refuse a URL it used to allow. That is the fix, not a regression.
- Every vend is now attributable: the audit log records *what an agent did with a credential*,
  not merely that it received one.
- Binary and streaming bodies through the proxy remain out of scope; bodies are forwarded byte
  for byte under the caller's Content-Type, with a 10 MiB response cap.
