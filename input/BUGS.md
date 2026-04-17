# BUGS — AgentCordon source-code audit

**Scope:** ~55k LOC Rust across `crates/core/`, `crates/server/`, `crates/broker/`, `crates/cli/`, plus `policies/default.cedar`, 9 SQL migrations, and ~120 integration test files.

**Date:** 2026-04-17.

**Methodology:** Four parallel read-only reviewers, one per crate scope, each returning a structured finding list. Consolidated here by prefix. IDs are reviewer-local — not globally unique across prefixes.

**Already fixed (not in this list):**
- BRK-1 (prior audit) — OAuth2 per-credential lock landed: `OAuth2RefreshManager` and `OAuth2TokenManager` both use `DashMap<K, Arc<tokio::sync::Mutex<Option<V>>>>` with per-key single-flight.
- BRK-15 — misleading `OAuth2RefreshManager` docstring was corrected to describe DashMap deep-clone semantics.

**Severity legend:**

| Tag | Meaning |
|-----|---------|
| High | Exploitable flaw, missing control, or production blocker. Address before next release. |
| Medium | Hardening opportunity, latent risk, or robustness gap. |
| Low | Code quality, edge case, or documentation. |
| Info | Observation or design choice worth noting — not a defect. |

---

## Headline priorities

Address these eight items before the next release, in order:

1. **SRV-1** — no Content-Security-Policy / X-Frame-Options / X-Content-Type-Options / HSTS response headers on any route. Single-patch XSS-class mitigation.
2. **CLI-2 / BRK-2** — the Ed25519-signed payload at [crates/cli/src/signing.rs:127](crates/cli/src/signing.rs#L127) and the broker-side reconstruction at [crates/broker/src/auth.rs:109](crates/broker/src/auth.rs#L109) both omit the URL query string. Two requests that differ only in query params sign identically — latent signature-reuse vector.
3. **CLI-1** — `agentcordon init` keypair write is not TOCTOU-safe. An attacker with write access to `~/.agentcordon/` could race between the existence-check and the `write`. Fix with `OpenOptions::create_new(true)`.
4. **CORE-1** — three `.unwrap()` calls on JSON metadata mutation in [crates/core/src/domain/audit.rs](crates/core/src/domain/audit.rs) (lines 161, 186, 380) can panic the audit subsystem on malformed input.
5. **CLI-3** — trailing-slash ambiguity between CLI signing and server path normalisation produces spurious signature mismatches. Canonicalise the path both ways, or reject trailing slashes.
6. **CLI-4** — Windows `HOME` fallback to `/tmp` breaks Windows entirely. Use `dirs::home_dir()` or `USERPROFILE`.
7. **MIG-1** — migration `007_credential_name_unique.sql` fails destructively on any deployment with duplicate `(workspace_id, owner_id, name)` triples. No pre-flight scanner.
8. **SRV-2** — no app-level HTTPS enforcement. The `Secure` cookie attribute is set but an HTTP-served deployment silently sends session cookies in cleartext.

**Not a bug (design decision, do not refile):** root-user bypass. `user.is_root` short-circuits Cedar at [crates/core/src/policy/cedar/mod.rs:86-95](crates/core/src/policy/cedar/mod.rs#L86-L95) intentionally — root is the control-plane admin and has unrestricted access. No dedicated audit event, counter, or log-level escalation is wanted. See [wiki/decisions/root-user-is-unrestricted.md](wiki/decisions/root-user-is-unrestricted.md) for the authoritative decision record. The earlier CORE-2 ("root bypass auditability") and CORE-14 ("root bypass breadth") rows have been removed.

---

## CORE-* findings (12)

*(CORE-2 and CORE-14 were the root-bypass entries. Both removed — this is intentional by design, not a bug. See [wiki/decisions/root-user-is-unrestricted.md](wiki/decisions/root-user-is-unrestricted.md). IDs left with a gap so audit trail stays stable.)*

| ID | Severity | Title | Location | Fix sketch |
|----|----------|-------|----------|-----------|
| CORE-1 | High | Panicking `unwrap()` in audit metadata handling | crates/core/src/domain/audit.rs:161 (also 186, 380) | Replace `metadata.as_object_mut().unwrap()` with `.ok_or()` or pattern match |
| ~~CORE-2~~ | — | **Removed — design decision.** Root-user bypass is intentional | crates/core/src/policy/cedar/mod.rs:86-95 | See [wiki/decisions/root-user-is-unrestricted.md](wiki/decisions/root-user-is-unrestricted.md) |
| CORE-3 | Medium | Enrollment-code RNG comment could be clearer about modulo bias rejection | crates/core/src/crypto/aes_gcm.rs:159-168 | The rejection loop is correct; add a comment stating the intent explicitly |
| CORE-4 | Medium | Legacy `hash_session_token_sha256` still in codebase with `#[allow(dead_code)]` | crates/core/src/crypto/session.rs:46-52 | Delete the function; add an assertion-test forbidding any SHA-256 session path |
| CORE-5 | Medium | AES-GCM atomic-counter rollback has documentation gap | crates/core/src/crypto/aes_gcm.rs:69-74 | Document the `fetch_add`+`fetch_sub` rollback pattern; note that `Ordering::Relaxed` is correct for a monotonic counter |
| CORE-6 | Medium | HKDF called with `None` salt on ECIES derivation — safe but unexplicit | crates/core/src/crypto/ecies/mod.rs:138 | Pass an explicit empty-salt literal with a comment citing RFC 5869 §3.1 |
| CORE-7 | Medium | DNS-resolution timeout during SSRF check could leak timing | crates/core/src/proxy/url_safety.rs:82-88 | 5s timeout is fine; emit a slow-resolve audit event to catch patterns |
| CORE-8 | Medium | Policy validation merges warnings and errors without severity distinction | crates/core/src/policy/cedar/mod.rs:239-246 | Return `Vec<(Severity, Message)>` or split into two vecs; preserve per-diagnostic classification |
| CORE-9 | Low | No integration test verifies `test-crypto` Argon2 params are not compiled into release artifacts | crates/core/src/crypto/mod.rs:18-35 | CI matrix should assert release builds reject `--features test-crypto` |
| CORE-10 | Low | `enr_` prefix on enrollment codes is generated but never validated on decode | crates/core/src/crypto/aes_gcm.rs:172-177 | Add a matching validator; weak defense-in-depth otherwise |
| CORE-11 | Low | Credential-leak scanner silently skips values shorter than `MIN_SCAN_LENGTH=4` | crates/core/src/proxy/leak_scanner.rs:20-38 | Make the floor configurable; emit an audit event when a value is skipped |
| CORE-12 | Low | OIDC clock-skew tolerance hardcoded to 60 s | crates/core/src/auth/oidc.rs:121 | Make configurable via env var; align default with session/OAuth windows |
| CORE-13 | Info | AES-GCM nonces via `OsRng`; counter threshold correctly enforced | crates/core/src/crypto/aes_gcm.rs:84-86 | No defect — documents a strength |
| ~~CORE-14~~ | — | **Removed — design decision.** Root-bypass breadth is intentional | crates/core/src/policy/cedar/mod.rs:88 | See [wiki/decisions/root-user-is-unrestricted.md](wiki/decisions/root-user-is-unrestricted.md) |

---

## SRV-* findings (11)

| ID | Severity | Title | Location | Fix sketch |
|----|----------|-------|----------|-----------|
| SRV-1 | High | No CSP / X-Frame-Options / X-Content-Type-Options / HSTS headers on any response | crates/server/src/lib.rs (router build) | Add middleware emitting `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security: max-age=31536000; includeSubDomains` |
| SRV-2 | High | No app-level HTTPS enforcement; HTTP deployment silently leaks session cookies | crates/server/src/routes/admin_api/user_auth.rs:198-207 | Middleware rejects non-HTTPS unless `AGTCRDN_ALLOW_HTTP=true`; loud startup warning in HTTP mode |
| SRV-3 | Medium | `AuditingPolicyEngine::evaluate()` writes audit events fire-and-forget | crates/server/src/auditing_policy_engine.rs:164-172 | Buffered on-disk WAL for outages; synchronous audit-write for sensitive operations (vend, policy change, `is_root` toggle) |
| SRV-4 | Medium | `X-Forwarded-For` trusted unconditionally in device-approve rate limiter | crates/server/src/middleware/rate_limit_device_approve.rs:19-21 | Add `AGTCRDN_TRUSTED_PROXIES` CIDR allow-list; only parse `X-Forwarded-For` from trusted proxy IPs |
| SRV-5 | Medium | Session `last_seen_at` touch is fire-and-forget; DB errors swallowed | crates/server/src/extractors/authenticated_user.rs:73-74 | Log touch failures at `warn`; circuit-breaker on consecutive failures |
| SRV-6 | Medium | Default login lockout is 30 s (dev-friendly) with no production floor | crates/server/src/config.rs:313-314 | Reject `AGTCRDN_LOGIN_LOCKOUT_SECONDS < 300` in production mode |
| SRV-7 | Low | Verify PKCE `code_verifier` validation lives on the token-exchange endpoint, not consent | crates/server/src/routes/oauth/consent.rs:142-148 | If missing on `POST /token`, add per RFC 7636 §4.5 |
| SRV-8 | Low | Startup MCP-policy-rename migration silently skips ambiguous server names | crates/server/src/migrations.rs:38-44 | Warn at startup; refuse to start if critical policies are skipped |
| SRV-9 | Low | Open-redirect risk on consent-form `next` parameter if attacker-controlled | crates/server/src/routes/oauth/authorize.rs:99-127 | Require `next` to be a relative path starting with `/api/`; reject `://` and `//` |
| SRV-10 | Info | Session cleanup runs every 300 s | crates/server/src/main.rs:323-368 | Reasonable default; document that stale sessions can persist up to the interval |
| SRV-11 | Info | Device-side audit events carry client-supplied timestamps | crates/server/src/routes/control_plane/audit_stream.rs:293-295 | Store server `received_at` in metadata for forensic reconciliation |

---

## BRK-* findings (9)

The broker reviewer skipped BRK-1 (already fixed) and started at BRK-2.

| ID | Severity | Title | Location | Fix sketch |
|----|----------|-------|----------|-----------|
| BRK-2 | High | **Signed payload omits URL query string — request reuse across query params** | crates/broker/src/auth.rs:109 | Append `uri().query()` to the signed payload; update CLI canonicalisation to match. Dual-sided with CLI-2. **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 28973d8) |
| BRK-3 | Medium | Plaintext credential values held in `String` (no zeroise on drop) | crates/broker/src/credential_transform.rs:31; vend.rs:23; state.rs:108 | Wrap in `zeroize::Zeroizing<Vec<u8>>` or a custom `Drop` type; `&str` only at moment of use |
| BRK-4 | Medium | Timestamp parsing accepts negative / overflow values | crates/broker/src/auth.rs:48 | `if timestamp < 0 \|\| now.saturating_sub(timestamp).abs() > MAX_CLOCK_SKEW { reject }` |
| BRK-5 | Medium | Registration-error surfacing races between `/register` and `/status` | crates/broker/src/auth.rs:145-151 | Atomic CAS on `registration_errors`; single-op remove scoped to pk_hash |
| BRK-6 | Medium | 401 responses on proxy/MCP leak detailed OAuth2 provider error text to the CLI | crates/broker/src/routes/proxy.rs:192; mcp.rs:173 | Log full error server-side; return generic "failed to acquire credential" to CLI |
| BRK-7 | Medium | `--proxy-allow-loopback` is global; no per-CIDR / per-credential override; no scheme allow-list | crates/broker/src/routes/proxy.rs:73-81 | Add `--proxy-allow-cidr` list; prod-only scheme allow-list (https) |
| BRK-8 | Medium | Token-store atomic-rename failures have no retry or surfacing | crates/broker/src/token_store.rs:64-65 | 3× retry with backoff; abort with clear error if all fail |
| BRK-9 | Low | MCP server URLs cached from 60 s sync; no revalidation at tool-invoke time | crates/broker/src/mcp_sync.rs:105-127 | Re-run the proxy URL-safety check at `call_tool`, not just at sync |
| BRK-10 | Low | `block_in_place` for ECIES decrypt; `spawn_blocking` is friendlier to the runtime | crates/broker/src/vend.rs:60 | Switch to `spawn_blocking` for decryption-heavy paths |

Also noted: no explicit zeroise of `new_refresh: String` after the rotation callback in [crates/broker/src/oauth2_refresh.rs](crates/broker/src/oauth2_refresh.rs). Overlaps with BRK-3; folded.

---

## CLI-* findings (10)

| ID | Severity | Title | Location | Fix sketch |
|----|----------|-------|----------|-----------|
| CLI-1 | High | Keypair file creation is not TOCTOU-safe | crates/cli/src/commands/init.rs:30-63 | `OpenOptions::new().create_new(true).write(true).mode(0o600)`; retry on `EEXIST` with user confirmation; `CreateFileW` + `CREATE_NEW` on Windows **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 31ccd67) |
| CLI-2 | High | **Query strings silently dropped from signed payload** | crates/cli/src/commands/proxy.rs:35; signing.rs:127 | Append canonicalised query string to signed path. Dual-sided with BRK-2 **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 28973d8) |
| CLI-3 | High | Trailing-slash disagreement with server path normalisation produces signature mismatches | crates/cli/src/signing.rs:127 | Canonicalise path on both ends, or reject trailing slashes at sign time **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 28973d8) |
| CLI-4 | High | Windows `HOME` fallback to `/tmp` instead of `USERPROFILE` | crates/cli/src/broker.rs:311; commands/setup.rs:109 | Use `dirs::home_dir()` crate or `USERPROFILE`; last-resort fallback to current dir, never `/tmp` **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit c6b9f5b) |
| CLI-5 | Medium | `.unwrap()` on JSON mutation can panic | crates/cli/src/commands/init.rs:355, 362 | `.ok_or_else(CliError::…)` |
| CLI-6 | Medium | HTTP method case not normalised before signing | crates/cli/src/commands/proxy.rs:65 | Reject anything not uppercase `{GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH}` |
| CLI-7 | Medium | `Content-Type` is assumed `application/json` but not covered by the signature | crates/cli/src/broker.rs:105-106, 131 | Either include `Content-Type` in the signed payload or reject non-JSON bodies on signed routes |
| CLI-8 | Low | `broker.port` file read has no advisory lock | crates/cli/src/broker.rs:270-276 | `flock()` on `setup`; read with a timeout |
| CLI-9 | Low | `SystemTime` error surfacing is vague; skew tolerance not documented | crates/cli/src/signing.rs:121-123 | Log "system clock error (check NTP); max 30 s skew"; test at 31 s in the past |
| CLI-10 | Info | Contract not documented: Ed25519 seed must be exactly 32 bytes per RFC 8032 | crates/cli/src/signing.rs:63-66 | Add a doc comment stating the invariant |

---

## POLICY-* findings (3)

| ID | Severity | Title | Location | Fix sketch |
|----|----------|-------|----------|-----------|
| POLICY-1 | Medium | Cedar comparison at line 138 mixes a `User` principal with a resource owner whose type isn't enforced by the schema | policies/default.cedar:138 | Verify `resource.owner` is typed as a principal-ref, not a string; a type mismatch would silently never match |
| POLICY-2 | Medium | Two `forbid` rules for disabled MCP (lines 238-254) repeat the same `!resource.enabled` check | policies/default.cedar:240-246 | Consolidate into one `forbid` over `[mcp_list_tools, mcp_tool_call]` |
| POLICY-3 | Low | Admin-workspace permit (line 46-51) is textually before the narrowing `forbid` (line 232-236) | policies/default.cedar | Cedar semantics evaluate all `forbid` first, so this is correct; add a comment documenting that convention |

---

## TEST-* findings (3)

| ID | Severity | Title | Location | Fix sketch |
|----|----------|-------|----------|-----------|
| TEST-1 | High | **No integration test asserts workspace-attempts-`access` → 403 + audit event** | crates/server/tests/ | `workspace_access_forbidden` test: log in as workspace, call raw-credential endpoint, assert 403, assert `PolicyEvaluated { action=access, decision=forbid }` in the audit store |
| TEST-2 | Medium | No concurrent-vend test (nonce collision, DB-row-lock deadlock, per-key-lock regression) | crates/server/tests/ | `tokio::spawn` 5 concurrent `vend_credential` calls from the same workspace on the same credential; assert no nonce collision, no deadlock |
| TEST-3 | Low | No backup/restore round-trip test for credential decryption across master-secret changes | crates/server/tests/ | Create credential → back up DB → rotate master secret → restore → verify decryption |

---

## MIG-* findings (2)

| ID | Severity | Title | Location | Fix sketch |
|----|----------|-------|----------|-----------|
| MIG-1 | High | **Migration 007 fails destructively on duplicate `(workspace_id, owner_id, name)` rows with no pre-flight scanner** | migrations/007_credential_name_unique.sql | Pre-check script: `SELECT workspace_id, owner_id, name, COUNT(*) FROM credentials GROUP BY 1,2,3 HAVING COUNT(*) > 1`. Document dedup path before upgrading **Resolved by plan 2026-04-17-high-cli-and-mig-1** (commit 2fe5700) |
| MIG-2 | Low | Migration 009 `pk_hash_prefill` nullable semantics undocumented | migrations/009_device_code_pk_hash.sql | Make the column `NOT NULL DEFAULT ''`; document that empty means "pre-existing device code, no binding" |

---

## Cross-cutting observations

1. **CLI-2 ⇔ BRK-2** describe the same defect from opposite sides — the CLI generates a signature over a payload that excludes the query string, and the broker reconstructs its verification payload the same way. Both sides must change together; don't merge one side without the other.

2. **BRK-3** (plaintext credentials not zeroised) and **BRK-6** (error chains echoing provider text that might include credential material) together form a memory-hygiene cluster. Fix BRK-3 first with `Zeroizing<Vec<u8>>` on `CredentialMaterial.value`, then audit every `{err:?}` / `{err:#?}` formatter on the vend and MCP paths.

3. ~~**CORE-2** (root bypass auditability) and **CORE-14** (breadth of the bypass)~~ — removed from the finding set. Root-user bypass is intentional by design; see [wiki/decisions/root-user-is-unrestricted.md](wiki/decisions/root-user-is-unrestricted.md). Future audits must not refile this.

---

## Prior audit findings not resurfaced by this pass

The following were surfaced in the 2026-04-17 ad-hoc review that seeded the wiki, but none of the four agent reviewers refiled them this pass. Code has not changed in these areas — each is worth explicit re-verification before the next release:

- **CSRF `SameSite=Lax` / session cookie not `HttpOnly`** — was SRV-3 / CROSS-8. Verify [crates/server/src/middleware/csrf.rs](crates/server/src/middleware/csrf.rs) still uses `SameSite=Lax` and the CSRF cookie is still JS-readable for Alpine. If so, consider `SameSite=Strict`.
- **OAuth access-token hashing uses plain SHA-256 (not HMAC)** — was SRV-4. Session tokens use HMAC-SHA256 keyed with a master-secret-derived key. OAuth tokens would benefit from symmetry.
- **Audit-stream SSE: per-user cap but no per-IP / global cap** — was SRV-6. Global ceiling + per-IP limiter on the WebSocket upgrade would close this.
- **Workspace-policy sync uses substring match on UUIDs** — was SRV-10. Structured per-workspace filter (a column, or parsed entity references) is more robust.
- **Master-secret rotation unaudited and multi-step** — was CROSS-2. Warn at startup when env var and `.secret` disagree; emit audit events around `POST /api/v1/admin/rotate-key`.
- **No rotation path for workspace Ed25519 keys** — was CROSS-3. `agentcordon rotate-key` command that self-signs with the old key and atomically swaps server-side.
- **Unresolved `TODO` in DCR path** — was SRV-9. `crates/server/src/oauth_discovery/client.rs:90` falls back to a hardcoded `client_name`.
- **`PolicyEngine` silent deny-all on `RwLock` poisoning** — was CORE-3 in the prior audit. `crates/core/src/policy/cedar/mod.rs:142-143` swallows a poisoned lock; log at `error` level or panic to prompt restart.
- **No failure coalescing for concurrent upstream failures on the same OAuth2 credential** — was BRK-16. Each follower re-runs HTTP + rotation callback after the leader fails. Partial fix would be a short-lived negative cache in the slot.
- **AWS SigV4 silent error discard + lossy UTF-8 percent-decode** — were CORE-8 / CORE-9 in the prior audit. `crates/core/src/transform/builtins/aws_sigv4.rs:111` and `:281-297`.

---

## Strengths

- **Crypto fundamentals are solid.** HKDF-SHA256 with unique domain-separation labels (tested at [crates/core/src/crypto/key_derivation.rs:305-352](crates/core/src/crypto/key_derivation.rs#L305-L352)); AES-256-GCM with nonce-exhaustion counter; Ed25519 with domain-separated challenge payload; P-256 ECIES with per-vend ephemeral keypair + AAD binding to `device_id ‖ credential_id ‖ vend_id ‖ timestamp`.
- **Zero `unsafe`** anywhere in the workspace.
- **Deny-by-default enforced at three layers** — Cedar semantics, `PolicyDecisionResult::Forbid` as the default variant, and `middleware/policy.rs:with_policy()` converting any non-`Permit` to 403.
- **Timing-safe auth primitives.** `PasswordAuthenticator` uses a dummy-hash padding pattern to prevent user enumeration. OAuth access tokens, CSRF tokens, and client secrets all use `subtle::ConstantTimeEq`.
- **Rhai sandbox is defensible.** `new_raw()` engine, safe-only packages, operation / call-stack / string-size caps, error-message scrubbing against secret exfiltration.
- **SSRF controls on the proxy path** block loopback, RFC 1918, link-local, CGNAT, multicast, and reserved ranges.
- **Credential-leak scanner** runs on outbound responses before they reach the agent; tagged in audit events when a leak is detected.
- **Per-credential OAuth2 locking** (chunk-01 of plan `2026-04-17-brk-1-oauth-per-cred-lock`) — concurrent refreshes for different credentials now proceed in parallel; single-flight per credential preserved.
- **Versioned integration tests.** ~120 files named `v<MAJOR><MINOR><PATCH>_*.rs` serve as release gates; RFC 8628 conformance tests cite spec sections explicitly.
- **Three-tier defence-in-depth.** Credentials never cross the server → broker boundary in plaintext; the broker is the only party that can decrypt a vend envelope.

---

## Methodology note

Four parallel `Explore` agents with "very thorough" thoroughness: one per crate (`core`, `server`, `broker`) and one covering `cli` + `policies/` + `tests/` + `migrations/`. Each returned a structured Markdown table; this file consolidates them verbatim with cross-cuts and prior-audit gaps annotated. No code was modified during the review.

Counts: **45 findings** (8 High, 18 Medium, 17 Low, 2 Info) + **10 prior-audit items** awaiting re-verification. CORE-2 and CORE-14 removed per design decision — see [wiki/decisions/root-user-is-unrestricted.md](wiki/decisions/root-user-is-unrestricted.md).
