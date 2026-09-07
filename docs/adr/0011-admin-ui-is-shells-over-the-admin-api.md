# 11. The admin UI is shells over the admin API, with one primitives module and one placement grammar

- **Status:** Accepted
- **Date:** 2026-09-06

## Context

The admin console had grown by copy-and-paste, and two independent reviews
(`uat/artifacts/reviews/UI-REVIEW.md`, `uat/artifacts/reviews/DESIGN-REVIEW.md`) found the same root cause three times over.

**Scoping lived twice.** Page handlers fetched credentials, workspaces, MCP servers, policies,
users, audit events and OIDC providers themselves, Cedar-filtered them, and seeded them into
the template as JSON. The admin API did the same work independently. A page and its API could
therefore disagree about what a user may see — and did.

**Every interaction pattern existed several times.** Four confirmation patterns coexisted
(a slide-in partial, an inline modal, native `confirm`, native `alert`/`prompt`); 21 hand-written
error reporters against 14 uses of the shared one; 63 mutating fetches with no response
handling at all, so deleting an OIDC provider toasted success on a 403. Modals did not trap
focus and opened with focus on the destructive button.

**Every surface existed twice.** The credential and workspace detail pages were each ~950
duplicated lines between a split-pane partial and a standalone page, and they had drifted: a
missing History tab on one side, contradictory 403 wording, a Restore modal that ignored
Escape on one side, fields silently dropped on save.

**There was no placement rule**, so Enable/Disable appeared as a row button, a header button
and an edit-form checkbox; destructive actions appeared wherever there was room; and a page
could have two primary buttons or none.

## Decision

Three rules, applied across the console.

**1. Pages are shells; the admin API is the only source of data.** A page handler renders the
user context, a `<meta name="csrf-token">`, and the entity id from the URL. Every list is
fetched by the page's script from the admin API. The page-side filters and JSON seeding are
deleted (`crates/server/src/routes/admin_ui/pages/`). Non-admin scoping therefore follows the
API exactly: audit and dashboard activity for a non-admin is the user's own events and needs
`view_audit`; the users page needs `manage_users`. The unreferenced panel fragments
(`/credentials/{id}/partial`, `/workspaces/{id}/partial`, `/security/{id}/partial`) are removed.

**2. One shared primitives module, `window.AC`** (`crates/server/static/js/ac.js`):
`AC.confirm`, `AC.prompt`, `AC.modal`, `AC.fetch`, `AC.reportError`, `AC.toast`. Every modal
overlay traps focus, marks the page behind `inert`, starts on the safe control and restores
focus on close. `AC.fetch` adds the CSRF header and handles 401 by redirecting to
`/login?next=` with a message. `partials/delete_modal.html` is retired; `showToast` and
`reportApiError` remain as aliases. **A template test fails the suite if a mutating fetch or a
toast bypasses the primitives**, which is what keeps the rule true over time. The same
technique pins other single-definition rules: one `eventTypeLabel` / `eventPrincipal` pair in
`base.html` used by the Dashboard, the Audit page and all four History tabs, and a guard
against pairing `x-data="component()"` with `x-init="init()"` on one element.

**3. One placement grammar** (`uat/artifacts/reviews/DESIGN-REVIEW.md` §2):

- Page header: title (count), search, secondary buttons, then **exactly one primary** at the
  right end.
- Detail header: name, status pill, Enable/Disable as a secondary button **here and nowhere
  else**, then an overflow menu (`⋯`) holding every destructive action — Revoke, Delete,
  Unshare — each confirming through `AC.confirm`.
- Tabs carry tab-level actions as outlined buttons at the tab's top right; the page still has
  exactly one primary button, in the header.
- List rows are links (a stretched anchor), with no row buttons, except Settings tables, which
  have no detail page.
- Each entity has **one detail surface**: the standalone pages are shells that include the
  pane partials, so `/credentials/{id}` and `/workspaces/{id}` are full pages on every
  viewport and `/{entity}/{id}/view` redirects to the canonical path.

Alongside these, the visual system is enforced by global selectors rather than page by page:
one type and spacing scale, four radius tokens, resting surfaces with a border and no shadow
(only modals, menus and toasts float), and one palette definition covering light and dark.

## Consequences

- The console is now a client of its own API, so "what an operator sees" has one answer and
  the UI cannot be more permissive than the API by accident. It also means a page renders
  nothing until its fetches return, which is the trade.
- The guard tests are load-bearing. Without them the primitives rule decays back to
  hand-written fetches within a release; that is exactly how the four dialog patterns arose.
- Because Enable/Disable lives only in a detail header, bulk enable/disable from a list is not
  possible. That is a deliberate omission, not an oversight.
- Console feature work deliberately left out of this pass: pagination UI, audit retention and
  sinks, policy versioning, time-bound grants, MFA, custom roles, admin API tokens.
- The specs are driven in Chromium only; Firefox and WebKit projects exist in the Playwright
  config but have no recorded full pass, and there is no automated accessibility check. Both
  are tracked separately.
