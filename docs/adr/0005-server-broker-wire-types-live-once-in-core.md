# 5. Server↔broker wire types live once in `agent-cordon-core`

- **Status:** Accepted
- **Date:** 2026-09-04

## Context

The broker's picture of the server was hand-written. Vend bodies and MCP sync bodies were built
with `serde_json::json!`, query strings were concatenated, and responses were parsed into
broker-local structs that restated the server's fields from memory. The server's own request
and response types lived in its route modules.

Nothing connected the two. A field renamed on the server compiled cleanly, passed the server's
tests, passed the broker's tests, and broke in production — which is exactly what happened once:
renaming `VendResponse.transform_name` on the server alone left both suites green while every
credential transform was silently lost. The independent test-suite review (`uat/artifacts/reviews/REVIEW.md`,
item 3) called this out as a high-priority structural risk rather than a bug.

## Decision

The server↔broker wire contract is a set of shared types in `crates/core/src/wire/`, organised
as `wire::{credentials, mcp, oauth}`, and both sides use them:

- the credential vend request and response;
- MCP sync query, sync entries and credential envelopes;
- MCP tool entries;
- the MCP authorization request and response;
- the OAuth device-code and token forms and responses;
- the `{"data": …}` envelope.

The broker no longer hand-writes request bodies or hand-builds query strings. A field renamed
on the server is a **compile error in both crates**.

The wire format itself is unchanged by this decision; it is a refactor of where the definitions
live, not of what goes over the socket.

Serialization details that shared types alone cannot pin — form encoding, query-string bytes,
the exact JSON a real handler emits — are pinned by wire-contract tests at both HTTP seams
(`crates/server/tests/wire_contract.rs`, `crates/broker/tests/wire_contract.rs`): the bytes the
broker emits are read back into the server's own request types, and the server's real responses
are read back into the broker's.

Two things deliberately stay separate:

- **The broker's agent-facing credential listing is an explicit projection**, not a
  re-serialisation of the server's `CredentialSummary`. Transform scripts, metadata, tags,
  descriptions and ownership stay on the control plane. Sharing a type here would have leaked
  control-plane fields to agents by default.
- The CLI↔broker channel is not covered by this ADR; its shape is owned by the broker's routes
  and the `agentcordon-identity` crate.

## Consequences

- `agent-cordon-core` is now a dependency the broker cannot drop, and a wire change is a
  workspace-wide change. That is the point.
- The compiler enforces field *names and types*. It does not enforce that a value means the
  same thing on both sides, nor the encoding at the boundary — hence the contract tests.
- Because the shape is shared, server and broker must be upgraded together across a wire
  change. 0.4.0 changes the vend shape and removes routes; see ADR-0010.
- The same reasoning produced `agentcordon-identity` for the CLI↔broker signing payloads: one
  definition, frozen test vectors, both sides call it.
