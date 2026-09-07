> [Home](index.md) · Admin UI

# Admin UI

A map of the browser console at `AGTCRDN_BASE_URL`: one section per screen --
what it is for, its primary action, what is behind the overflow menu, and which
roles see it. Sign in at `/login`; every page below requires a session and
redirects to `/login` without one.

---

**On this page:**
[Chrome](#chrome-top-bar-and-user-menu) · [Dashboard](#dashboard) · [Credentials](#credentials) · [Workspaces](#workspaces) · [Policies](#policies) · [MCP Servers](#mcp-servers) · [Audit Log](#audit-log) · [Settings](#settings) · [Enrollment pages](#enrollment-pages) · [Conventions](#conventions) · [Path reference](#path-reference)

---

## Conventions

The same grammar holds on every page, so a control is where you expect it:

- **One primary action per page**, filled orange, at the right end of the page
  header. Everything else in the header is outlined.
- **Detail pages** put status beside the title, then `[Disable] [Edit] [⋯]`.
  Every destructive action -- Delete, Revoke -- is inside that **⋯** overflow
  menu, never loose beside Edit, and each still confirms in a dialog that names
  the object and the consequence.
- **Enable/Disable is a header button** on a detail page and nowhere else: not a
  toggle on a list row, and not a checkbox you reach through Edit.
- **Rows are links.** A list row navigates to the record, and the **whole row**
  is the click target -- the anchor on the name cell is stretched over the row,
  so the last cell works as well as the first. This holds on Credentials,
  Workspaces, Policies and MCP Servers alike. List rows carry no action buttons.
  Settings tables are the exception -- they have no detail page, so they carry
  their own row controls.
- **A tab-level action** (Share with workspace, Rediscover tools, Grant) is an
  outlined button at the top-right of the tab, not in the page header.
- **Tab bars are tabs, not anonymous buttons.** A tab bar is a `role="tablist"`
  and each tab is a real `<button>` with `role="tab"` and `aria-selected`, so a
  screen reader announces it as a tab and says which one is current, and the
  keyboard works without a mouse: Tab reaches the bar, Enter or Space switches
  tab.
- Colour means state. Green/amber/red are Active, Disabled, Revoked, permit,
  forbid. Categories -- credential type, transform, auth mode, transport, role,
  tag -- are neutral grey.

---

## Chrome: top bar and user menu

The top bar carries six links: **Dashboard**, **Workspaces**, **Credentials**,
**Policies**, **MCP Servers**, **Audit Log**. (The Policies item is at
`/security`; `/policies` redirects there.)

At the right end, your name is a **menu**, not a label. It shows your role and
opens onto three items:

| Item | What it does |
|------|--------------|
| **Settings** | `/settings` |
| **Light theme** / **Dark theme** | Flips the theme; the label names what you will get |
| **Sign Out** | Ends the session and returns to `/login` |

Below 768px the six links, Settings, the theme item and Sign Out all move into
the hamburger drawer.

**Under 768 px, tables scroll sideways rather than shrink.** Every table on
every page -- including the ones a detail pane fetches later -- sits in a
horizontal scroll container, so a wide table (the dashboard's Recent activity,
the audit log) keeps its columns at a readable width and you swipe or drag to
reach the ones past the right edge. Nothing is dropped; the header row sticks to
the top of its own scroll box.

---

## Dashboard

`/dashboard` (and `/`). The landing page. Under the title is a health line --
*Server responding · v{version}*.

- **Three tiles**, each a link: Workspaces (with the active count), Credentials,
  and MCP servers (with the disabled count, when any are disabled).
- **Get started** -- a first-run checklist, shown only while the instance has no
  workspace: *Store a credential*, *Register a workspace*, *Install an MCP
  server*. Each step links to the page that does it and ticks itself off from
  the live counts.
- **Recent activity** -- one table of the eight newest credential vends and MCP
  tool calls, permitted and denied, each row a link into `/audit/{id}`, with
  **View audit log →** beside the heading. Timestamps are relative (`1m ago`),
  as on the audit log, with the exact time on hover. It is empty until a
  workspace does something; the full log is at `/audit`.

There is no primary action here, by design. Every role sees the page; the tiles
and the table show only what that role's policies allow.

---

## Credentials

**List -- `/credentials`.** A table: Name, Service, Type, Vault, Tags. For a
`generic` credential the Type cell also names its transform (`generic ·
basic-auth`), which is the only thing that separates a bearer credential from
a basic-auth one. Search sits
in the header; a filter row underneath carries the **Vault:** select (when you can
see more than one vault), the tag chips, and a **Manage vaults →** link into
Settings.

- Primary action: **Add Credential**. Hidden for viewers, who hold no `create`.

**New -- `/credentials/new`.** A template picker that opens on eight cards with a
search box and **Show all N templates**; once you pick one it collapses to a
single line, *Template: <name>* with **Change**. Then Name, Service, and
**Allowed URL pattern** directly beneath Service -- it is the security-relevant
field, so it sits with the field that describes the same thing. Type, and for the
`generic` type a **Transform** select. Tags, then **Vault** with an inline **New
vault** button beside it. **Description** and **Target Identity** are behind an
**Advanced** disclosure at the foot. Submit is **Store Credential**.

**Detail -- `/credentials/{id}`.** A full page, and the record's only URL
(`/credentials/{id}/view` redirects here). The header is
`[Edit] [⋯ Delete]`, with created/owner/id on one meta line under the title.
Above the tabs: the identity and security rows, including **Reveal Secret** →
**Copy** / **Hide** with a countdown, and the URL Restriction.

| Tab | What is on it |
|-----|---------------|
| **Permissions** (default) | Effective Access per principal with **View** into a modal, the Permission Grants table with per-row revoke, and the **Grant Permission** form -- a workspace select, a Grant/Deny segmented control, and the four action checkboxes |
| **History** | Secret Rotations (a row opens Rotation Detail; **Restore** is offered per version) and Audit Events |

Roles: a viewer, or someone reading through a vault read-share, sees the record
and no secret, no Edit, no Delete and no grant form. For a read-share the
Permissions tab explains the share instead of showing Effective Access, and the
page makes no request the recipient would be refused.

---

## Workspaces

**List -- `/workspaces`.** A table: Name, Status, Owner, Tags, with a search box.

- Primary action: **Register Workspace** → `/register`. Hidden for viewers.

**Detail -- `/workspaces/{id}`.** A full page (`/workspaces/{id}/view` redirects
here). Header: `[Disable | Enable] [⋯]`.

| In the ⋯ overflow | Effect |
|-------------------|--------|
| **Revoke** | Final. Kills the workspace's OAuth clients and every access and refresh token in one transaction. Hidden once the workspace is revoked |
| **Delete** | Removes the record |

**Disable** stays a header button because it is the reversible one, and it is
disabled outright on a revoked workspace.

| Tab | What is on it |
|-----|---------------|
| **Details** (default) | Status, owner, tags (**Edit** → **Save** / **Cancel**), and the meta rows |
| **Access** | *MCP servers this workspace can reach*, and *Consent grants* with a **Revoke consent** per row. One tab, because both answer the same question |
| **History** | The workspace's audit events, each a link into `/audit/{id}` |

---

## Policies

The nav item is **Policies**; the paths are under `/security`.

**List -- `/security`.** Search, one filter select (*All except grants* / *Grants
only* / *System only* / *Custom only*), and sortable Name, Enabled and Updated
headers. Each row is a link -- the whole row, not just the name cell, as
everywhere else in the console -- and there is no per-row enable/disable.

- Primary action: **New Policy**; beside it, outlined, **Open tester**. Both are
  admin-only.

**Detail -- `/security/{id}`.** Header: `[Disable | Enable] [Edit] [⋯ Delete]`.
Enabling and disabling never needs edit mode. The last enabled policy refuses
both disable and delete and says why -- with none enabled, everything but the
root user is denied. Below the statements are the **Affected Principals** card
(loaded on demand with **Load** / **Refresh**) and a **Test this policy →** link
into the tester, prefilled.

**New -- `/security/new`.** Name, Description, the Cedar source, an **Enabled**
checkbox, **Create Policy**, and template cards that preview into the editor with
**Use this template**.

**Tester -- `/security/tester`.** The only policy tester in the product; there is
no second one embedded in a policy page. Pick a Principal (workspaces, and users
carrying their role), an Action, and a Resource -- a concrete credential or MCP
server, or *Any credential* / *Any MCP server* / *Any workspace* / *Any policy*.
A Role select appears for a user principal and a Tags field for a workspace, so
you can ask what a different role or tag set would decide. **Test** (or
Ctrl+Enter) gives the decision chain; **Test All Workspaces** gives the access
matrix and needs a concrete resource. The header's **Scenarios** menu saves the
current form, reloads a saved one, and clears the list; scenarios live in your
browser's local storage, so they are per-browser and unshared.

---

## MCP Servers

**List -- `/mcp-servers`.** A table: Server, Auth, Status, Workspaces, Tools, with
one search box.

- Primary action: **Add server** → the marketplace. Hidden for viewers.

**Marketplace -- `/mcp-servers/marketplace`.** Its own page, titled *Add a
server*; it is no longer a section of the list. (`/marketplace` and
`/mcp-marketplace` redirect here.) A search box, category chips, and one card per
template showing its auth mode. Clicking a card opens the **install modal**: pick
the workspace, then supply what the auth mode asks for -- nothing for *No Auth*,
nothing for OAuth, and for *API Key* a **Credential** select with two options,
**Create new credential** (the default: one password box, *API Key / Secret*,
with a hint under it naming where the key will be sent -- the template's header,
its query parameter, or `Authorization: Bearer`) and **Use existing credential**
(a second select of your vault credentials). It is one select, not two named
panels. The confirm button is **Install**, or **Connect with <name>** for an
OAuth template. Installing needs `create`, so a viewer gets a permission message
instead of the grid.

**Detail -- `/mcp-servers/{id}`.** Header: `[Disable | Enable] [Edit] [⋯ Delete]`.
The Enabled state is the header button, not a checkbox inside Edit -- a disabled
server is refused every `mcp_tool_call` and `mcp_list_tools` by the default
policy.

| Tab | What is on it |
|-----|---------------|
| **Tools** (default) | The discovered tools, with **Rediscover tools** at the top-right -- the retry for an install whose discovery failed |
| **Access** | *Workspaces with access* (**Share with workspace**, and an unshare per row) and *Permission grants* (Effective Access, an *Available Cedar Actions* disclosure, the grants table, and the **Grant Access** form with its Grant/Deny segmented control). One tab, because bindings and grants are the same question |
| **History** | The server's audit events |

---

## Audit Log

`/audit`, and `/audit/{id}` to open one event.

- Header: a search box and an **Export** menu offering **CSV**, **JSONL** and
  **Syslog**. Whatever filters you have set travel with the export.
- Filter bar: a **Type:** dropdown listing every event type present in the
  events loaded (it used to be a row of pills that reflowed on every load), and
  **Decision:** as three pills -- All decisions, Permit, Forbid.
- Rows expand in place to the full event -- principal, action, resource,
  decision and reason, timestamp, correlation and event ids, a link to the
  deciding policy, and **Show JSON**. **Load more** pages further back.

Every role reaches the page; Cedar filters what is in it.

---

## Settings

`/settings`. One page with a sticky **section rail** on the left: **Account**,
**Vaults**, then under *Admin* **Users**, **Sign-in (SSO)**, **Master key**, and
under *MCP* **OAuth clients**. The server version sits at the rail's foot. Each
link is an anchor into the section below.

| Section | Rail label | Who sees it | What is on it |
|---------|-----------|-------------|---------------|
| Change Password | Account | everyone | Current and new password, **Change Password** |
| Vaults | Vaults | everyone (create: not viewers) | The vault table. Per row: **Rename**, **Share** (or **Shares**, when you may audit but not grant), and **Delete** in the row's **⋯** overflow -- disabled, with the reason, while the vault still holds credentials. Sharing expands a sub-row: pick a user, **Share**, and **Revoke** per existing share |
| SSO / OIDC Providers | Sign-in (SSO) | admin | **Add Provider** opens an inline form; each row has a toggle and **Delete** |
| User Management | Users | admin | **Add User** (opens `/settings/users/new`). Each row carries a **Role** select, **Disable** / **Enable**, and **Reset password**. Root's role and account are read-only, and you cannot disable the account you are signed in as |
| Master Key | Master key | admin | **Re-seal credentials** -- an outlined button whose confirm dialog carries the weight. The report renders inline. See [Master Key](master-key.md#issuing-the-call) |
| OAuth Provider Clients | OAuth clients | admin + operator (read-only for an operator) | **Add Client** opens an inline form. An admin gets an enabled toggle per row, **Re-register** on an auto-registered client, and **Delete**. See [Granting MCP Server Access](granting-mcp-server-access.md#oauth-provider-clients) |

The standalone Users page is gone, and user management is a section of this page and
nowhere else: both `/users` and `/settings/users` redirect to
`/settings#users-section`, which is the **Users** rail link. `/settings/users/new` is
the one user page that is still its own screen -- the create form **Add User** opens --
and `/users/new` redirects to it.

---

## Enrollment pages

- **`/register`** -- *Workspace Registration*. Instructions, not a form: the
  install command per OS, then `agentcordon register`. When the CLI passes a
  fingerprint it also shows *Approve Workspace Registration*.
- **`/activate`** -- *Activate a new device*. Names the workspace and the device
  key, warns when that key is already registered, lists the scopes being asked
  for, and offers **Deny** and **Approve**. It accepts `?user_code=` to prefill.
  Approving lands on `/activate/success`; the other outcomes are
  `/activate/denied` and `/activate/expired`.

See [Workspace Enrollment](workspace-enrollment.md) for the flow behind them.

---

## Path reference

| Path | Page |
|------|------|
| `/dashboard` | Dashboard (`/` redirects here) |
| `/credentials`, `/credentials/new`, `/credentials/{id}` | Credentials |
| `/workspaces`, `/workspaces/{id}` | Workspaces |
| `/security`, `/security/new`, `/security/{id}`, `/security/tester` | Policies |
| `/mcp-servers`, `/mcp-servers/marketplace`, `/mcp-servers/{id}` | MCP servers |
| `/audit`, `/audit/{id}` | Audit log |
| `/settings` (the **Users** section is `/settings#users-section`), `/settings/users/new` | Settings |
| `/register`, `/activate` | Enrollment |

Redirects kept for older links: `/policies*` → `/security*`, `/users` and
`/settings/users` → `/settings#users-section`, `/users/new` →
`/settings/users/new`, `/marketplace` and
`/mcp-marketplace` → `/mcp-servers/marketplace`, `/credentials/{id}/view` and
`/workspaces/{id}/view` → the record's page, `/agents` and `/devices` →
`/workspaces`, `/mcp` → `/mcp-servers`.
