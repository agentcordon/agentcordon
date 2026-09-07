# 8. CLI↔broker channel hardening: nonce, key pin, and a shared secret or TLS off loopback

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The CLI authenticates to the broker by signing each request with the workspace's Ed25519 key.
The channel around that signature was weaker than the signature itself:

- The signed payload was `METHOD\nPATH\nTIMESTAMP\nBODY`, replayable for the whole 30-second
  skew window. `/register` signed no timestamp at all.
- The CLI had no idea *which* broker it was talking to. Anything answering on the discovered
  port could receive signed requests and, having them, act as the workspace.
- `--bind 0.0.0.0` exposed the signed API to the network with no further requirement. TLS flags
  existed but were validated and then rejected at startup, so the only real option was a
  reverse proxy in front of every non-loopback bind.
- The broker's port file recorded only a port, so discovery assumed plaintext on localhost.

## Decision

Harden the channel on three axes, and require an explicit choice before the broker leaves
loopback.

**Replay.** The signed payload is `METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY` with a fresh 16-byte
`X-AC-Nonce`; `/register` signs `NAME\nPK\nSCOPES\nTIMESTAMP\nNONCE`. The broker keeps a
bounded seen-set of `(key, nonce)` for the skew window and answers a second presentation with
401 (`crates/identity/src/request.rs`, `crates/identity/src/register.rs`,
`crates/broker/src/auth.rs`).

**Identity of the broker.** `GET /health` returns `encryption_public_key` and
`key_fingerprint`. `agentcordon register` writes `.agentcordon/broker.fingerprint` (0600) and
every later connection refuses a broker whose fingerprint differs, naming both values.
`register --force` re-pins; pre-existing workspaces are pinned on first use with a notice.
`AGTCRDN_BROKER_URL` is accepted only for loopback or `https://`, and is refused before any
request is made.

**Non-loopback binds.** The broker exits at startup on a non-loopback bind unless one of two
things is configured:

- `--shared-secret` / `AGTCRDN_BROKER_SHARED_SECRET`, after which every route except `/health`
  requires `X-AgentCordon-Broker-Secret` (constant-time compare) and the CLI sends it from the
  same variable; or
- `--tls-cert` / `--tls-key`, and the broker **terminates TLS itself** with rustls (HTTP/1.1 and
  HTTP/2), rather than telling the operator to put a proxy in front of it
  (`crates/broker/src/tls.rs`). Unusable material stops the broker before the data directory is
  created, naming the flag at fault.

`AGTCRDN_BROKER_CA` names a PEM file whose certificates become **extra** trust anchors for the
CLI's broker connection — verification is never disabled — and an untrusted broker is refused
with a message naming the variable. The port file now records a full URL (`http://` or
`https://`, loopback or the single bound interface, and the port); the CLI still accepts the
bare-port form older brokers wrote.

**Local artifacts.** One broker per `--data-dir` (advisory `flock` on `broker.lock`); the data
directory is 0700 and key, token store, port, pid and lock files are created 0600 *at open*
rather than chmod'ed afterwards.

## Consequences

- **CLI and broker must be upgraded together.** The identity test vectors are re-frozen, so the
  signed bytes changed; a 0.3.x CLI cannot drive a 0.4.0 broker and vice versa. See ADR-0010.
- The seen-set is in memory and bounded to the skew window, so a broker restart forgets nonces.
  That is acceptable: the timestamp window bounds the exposure either way.
- A TLS broker must be reached with `AGTCRDN_BROKER_URL=https://…`. Local port-file discovery
  now carries the scheme, but a broker bound off loopback is not discoverable from a plain
  `~/.agentcordon/broker.port` on another host by design.
- Fingerprint pinning means a deliberately re-keyed broker breaks every workspace until
  `register --force`. The error names both fingerprints so the operator can tell a re-key from
  an impostor.
- Non-loopback deployment is now a decision an operator makes explicitly, with a secret or a
  certificate, instead of one they make by typing `--bind 0.0.0.0`.
