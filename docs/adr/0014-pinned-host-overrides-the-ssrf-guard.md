# 14. A credential fenced to one literal host is forwarded to it past the SSRF guard; `**` is one or more host labels

- **Status:** Accepted
- **Date:** 2026-09-07

## Context

The first real use of AgentCordon against services a person actually runs failed twice on the
same afternoon, and neither failure was a policy decision.

A Home Assistant on a Tailscale network resolves to a `100.64/10` address. The admin had
fenced its credential to `https://homeassistant.<tailnet>.ts.net/*`: the exact host, nothing
else. The broker's SSRF guard refused the address anyway. The only escape was
`AGTCRDN_PROXY_ALLOW_LOOPBACK`, which switches the whole guard off for every credential and
every MCP upstream, and which needs the broker restarted. Nobody hosting a service on a tailnet
or a LAN — the common case for a personal deployment — will accept "disable the protection to
reach the thing I explicitly configured".

The AWS credential type auto-defaulted its fence to `https://*.amazonaws.com/*`. Under the
structural matcher (ADR-0007) a `*` in the host is exactly one DNS label, so that fence covers
`sts.amazonaws.com` and nothing regional: `ssm.us-east-1.amazonaws.com` is two labels in front
of the tail and can never match. The pattern reads as "any AWS host" to every human who writes
it, and there was no way to write what they meant.

The SSRF guard ran before the vend, on the principle that a target the broker will not call is
a target whose credential should never leave the server. That ordering meant the guard decided
with no knowledge of the credential's fence.

## Decision

**A fence that names one literal host is the admin's statement of where the credential goes,
and the SSRF guard defers to it.**

1. `pattern_pins_host(pattern)` in `crates/core/src/proxy/url_match.rs` is true when the
   pattern's host contains no wildcard label. The path may still carry wildcards; the pin is
   about *where*, not *which paths*.
2. On `POST /proxy` the broker still runs the resolving guard first, but holds the verdict.
   After the vend and the broker's own pattern check, a refusal is overridden when the vended
   `allowed_url_pattern` pins the target's host. An unrestricted credential, or one fenced with
   a wildcard host, leaves the refusal standing; the upstream receives nothing.
3. The refusal names both ways out: the exact pattern an admin would write to pin this host
   (`scheme://host[:port]/*`, ready to copy) and, for local development with an unfenced
   credential, the broker flag and where it is read.
4. **`**` as the leftmost host label stands for one or more DNS labels.** It is refused
   anywhere else and refused as the whole host. `https://**.amazonaws.com/*` covers every
   regional endpoint and never the apex. The AWS auto-default fence is now this form.

`AGTCRDN_PROXY_ALLOW_LOOPBACK` is unchanged: it still turns the guard off entirely and is still
development-only.

## Consequences

- **The guard's verdict is decided after the vend.** For a target the server's pattern check
  refuses, nothing changes: the server refuses first and no secret leaves it. For a target
  inside a wildcard or absent fence that the guard then refuses, the credential was vended to
  the broker and not used. The broker is the process trusted to hold every vended credential,
  and the vend audit row records the target, so this is a narrower guarantee than "never
  vended", not a weaker boundary. The alternative — a second round trip to fetch the fence
  before vending — would have cost every private-target call a request to buy back a property
  the server's own check already provides.
- **The pin is exactly what the SSRF guard was protecting against, deliberately.** The guard
  exists so a prompt-injected agent cannot aim a credential at the cloud metadata endpoint or an
  internal admin panel. With a pinned fence the agent cannot aim it anywhere but the pinned
  host, which the admin chose. An admin who pins a credential to `http://169.254.169.254/*` has
  made that choice on purpose, and the audit row says so.
- **DNS rebinding of a pinned host is out of scope.** The guard resolved once and the outbound
  client resolves again, so rebinding was never fully closed; a pinned host is one the admin
  trusts, and an attacker who controls its DNS controls the service anyway.
- **MCP upstreams are not covered.** Their URL is admin-configured too, but the broker's MCP
  route and the server's discovery keep the unconditional guard for now. Extending the same
  reasoning there is a separate decision.
- A `*.amazonaws.com` fence written before this change still means one label. That is the
  documented grammar; the console's hint, the CLI reference and the auto-default now show the
  `**` form, and the error an agent sees names the pattern so the mismatch is visible.
