# 13. `agentcordon init` installs the AgentCordon skill per runtime; the MCP server surface is deferred

- **Status:** Accepted
- **Date:** 2026-09-06

## Context

AgentCordon integrates with a coding-agent runtime in exactly one way: the runtime reads
prose that tells it to shell out to `agentcordon proxy` and `agentcordon mcp-call`. Two
reviews at v0.4.0 measured how well that worked.

The empirical review ran blind tasks against Claude Code with no mention of AgentCordon.
With the files `init` wrote, six out of six runs discovered credentials before guessing,
never reached for `curl`, read a tool's schema before calling it, and refused a prompt
injection. Without them, the agent made the raw call, succeeded, and reported success —
no error, no warning, no audit row. **The instruction file is what makes the product
work at all**, so where it lives is a product decision, not a packaging detail.

The landscape review then checked seventeen runtimes against their own documentation and
found that what `init` wrote did not match what they read:

- `.codex/instructions.md` and `.openclaw/instructions.md` were written on every
  `--agent codex` / `--agent openclaw` run. Codex reads `AGENTS.md` and `.agents/skills`;
  OpenClaw is a self-hosted gateway whose workspace is `~/.openclaw/workspace`, not a
  project directory. Neither file has ever been read by anything, and both asserted in
  their first line that they were loaded automatically.
- `init --agent codex` and `--agent openclaw` wrote no `CLAUDE.md`, and a probe proved
  Claude Code 2.1.263 does not read `AGENTS.md` on its own. A user who typed
  `agentcordon init --agent codex` and later opened Claude Code in that directory was
  silently uncordoned.
- The generated `AGENTS.md` block was ~5.5 KB and always on, in every session of every
  runtime, whether or not the task touched a credential. Windsurf caps a workspace rule
  file at 12,000 characters and Codex caps the concatenated instruction chain at 32 KiB,
  so a pre-existing `AGENTS.md` could push the block past a ceiling. Zed loads only the
  *first* of `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
  `.github/copilot-instructions.md`, `AGENT.md`, `AGENTS.md` — any repo with one of the
  five earlier files never saw the block at all.
- Thirteen of the surveyed runtimes read `.agents/skills/<name>/SKILL.md`, the
  [Agent Skills](https://agentskills.io/specification) open standard. `init` wrote no
  skill, and two of the files it did write named `.agents/skills/` as a discovery path
  that did not exist.

The obvious third option — a real MCP server, `agentcordon mcp-serve`, making the proxy
and the brokered tools native typed tools in sixteen of seventeen runtimes — is the only
change that stops depending on a model following prose. It is also one to two weeks of
work, a new protocol surface, and a new ADR of its own about why the surface belongs in
the CLI rather than on the broker.

## Decision

**The Agent Skill is the integration. `init` writes one `SKILL.md` into the skill
directory each selected runtime documents, and writes no always-on instruction file.
The MCP server surface is deferred.**

### Three tiers, in this order

1. **The skill** (this ADR). One file, progressive disclosure: a runtime loads its
   ~100 tokens of frontmatter at startup and reads the body only when the task is about
   credentials or MCP. It survives Zed's first-match rule and Windsurf's character cap
   because it is not a rules file.
2. **A pointer file, only where there is no skill discovery at all.** Exactly one
   runtime qualifies: Aider, which auto-loads nothing and has no skills, so it gets a
   `read:` entry in `.aider.conf.yml` naming the skill.
3. **`agentcordon mcp-serve`** — deferred. The specification is
   `uat/artifacts/reviews/ONBOARDING-landscape.md` § 5.2: a stdio JSON-RPC server in the
   CLI, reusing `BrokerClient` unchanged, exposing `agentcordon_status`,
   `agentcordon_credentials`, `agentcordon_proxy` and `agentcordon_mcp_servers` plus one
   tool per brokered upstream tool, with `correlation_id` in each result's `_meta`. It
   belongs in the CLI and not on the broker: the broker authenticates by workspace
   signature (ADR-0008) and a runtime's MCP client cannot sign, so an HTTP MCP endpoint
   would need a bearer secret held by the runtime — exactly the class of secret
   ADR-0006 keeps out of the agent's hands. When it lands it gets its own ADR, and the
   skill's body gains one paragraph saying "prefer the `agentcordon_*` tools; fall back
   to the CLI only if they are absent".

### What that means concretely

- `.agents/skills/agentcordon/SKILL.md` is always written. It is the open-standard path,
  thirteen runtimes read it, and it is the file Aider's `read:` entry names.
- `.claude/skills/agentcordon/SKILL.md` for Claude Code and Cline, `.kiro/skills/` for
  Kiro — the three runtimes whose documentation does not list `.agents/skills`.
- **No `AGENTS.md`, no `CLAUDE.md`, no `GEMINI.md`, no `.github/copilot-instructions.md`,
  no `.cursor/rules`, no `.goosehints`, no Zed rules file.** Every runtime that would
  have taken one has skill discovery, so the pointer would be duplicated context that
  costs every session.
- The skill does not carry the workspace identity. It is derived from the key and changes
  when the key does; a file holding a copy goes stale, which is how `AGENTS.md` and
  `CLAUDE.md` once came to name two different workspaces. The skill tells the agent to
  run `agentcordon status`.
- No detection marker may be a path `init` writes, or a runtime that detects on its own
  installed skill can never be deselected.

Claude Code was the case that decided whether tier 2 needed to cover it. A headless trial
of Claude Code 2.1.263, in a fresh directory containing nothing but
`.claude/skills/agentcordon/SKILL.md` and run with `--allowedTools ""`, answered
"What tools do I have for calling internal APIs safely? Answer from the project
instructions only." with the skill's content, opening: *"The project's only instruction
file is the AgentCordon skill."* The same question in an empty directory answered
*"There are no project instructions to answer from."* A project skill is discovered
without an import file, so Claude Code takes no `CLAUDE.md`.

## Install-to-use is three commands

*Added after the v0.4.0 onboarding review's Part 1 (`uat/artifacts/reviews/ONBOARDING-empirical.md`).*

Part 1 measured the documented path at under fifteen seconds of machine time and found the
friction was all in what the human had to carry between steps. Two things stood out. PATH was
left entirely to the reader (F3): the installer printed `export PATH="…:$PATH"`, which is
gone when the terminal closes and does not parse in nushell at all. And the server URL was
carried by hand: the installer's closing message ended with
`agentcordon register --server-url <URL>`, so a URL the *server itself* had just templated
into the script had to be copied out of a terminal into a later command.

**The decision: install-to-use is three commands.**

1. The admin starts the server.
2. The developer runs the one-liner the server serves.
3. In a project, `agentcordon init` does everything else.

Concretely:

- **The installer remembers the server.** `install.sh` and `install.ps1` are served *by* the
  server and already know the origin they were fetched from. They write it to
  `~/.agentcordon/config.toml` as `server_url` (`0600`, in a `0700` directory), rewriting
  only that key so anything else in the file survives, and naming both URLs when replacing a
  different one — re-running a second server's installer must not silently repoint a machine.
- **The installer persists PATH.** Like rustup and uv: read `$SHELL`, append a
  marker-delimited block to the file that shell actually reads (`~/.bashrc`, or
  `~/.bash_profile` on macOS whose terminals are login shells; `~/.zshrc`;
  `~/.config/fish/conf.d/agentcordon.fish` with `fish_add_path`;
  `~/.config/nushell/env.nu` with `$env.PATH`), print what changed and how to undo it, and
  do nothing on a rerun.
- **`init` completes enrollment.** After the runtime picker and the skill, `init` starts a
  broker if none is running and runs the device flow — the same function `register` runs, so
  the code, the link, the expiry and the polling cannot drift apart — and ends on two lines.
  `register` is unchanged and is the re-enrolment command.

### Precedence

`init` and `register` are the only commands that need a server URL. One order, everywhere:

| # | Source | Set by |
|---|---|---|
| 1 | `--server-url <URL>` | the caller |
| 2 | `AGTCRDN_SERVER_URL` | the shell or CI environment |
| 3 | `server_url` in `~/.agentcordon/config.toml` | the installer |

First one set wins; an empty value is unset and a trailing `/` is trimmed. A missing or
malformed config file is *absent*, never fatal — the flag and the environment variable still
work, and the error names all three. `agentcordon status` reports which source answered,
because a leftover `AGTCRDN_SERVER_URL` silently beating the config file is otherwise
invisible.

### The opt-outs

Every step this adds writes something the user did not ask for by name, so each has one:

| Opt-out | Effect |
|---|---|
| `AGENTCORDON_NO_MODIFY_PATH=1` | The installer changes no startup file and prints the line instead. Honoured by both installers. |
| `AGENTCORDON_SKIP_DOWNLOAD=1` | The installer skips the GitHub fetch and does the local setup only — for a source build against a server with no matching release. |
| `agentcordon init --no-register` | `init` sets the directory up and stops: no broker, no device flow, and no error when no server is configured. |

Being off a terminal is deliberately **not** an opt-out from enrollment. The runtime picker
needs a human and is skipped without one; the device flow is not a prompt — it prints a code
and polls — so a pipe still enrolls, and `--no-register` is the way to say otherwise. Making
a tty change what `init` *does* would mean a script and a terminal set up different
workspaces from the same command.

### Consequence

`agentcordon init` can now fail where it used to succeed: a workspace with no server URL
from any of the three sources is an error rather than a half-finished setup. The skill is
written first, so nothing is lost, and the message names the flag, the variable, the
installer and `--no-register`.

## Consequences

- The always-on context cost drops from ~5.5 KB in every session to the skill's
  frontmatter. Windsurf's and Codex's caps stop being a risk, and Zed's first-match rule
  stops being able to shadow AgentCordon.
- One file to keep truthful instead of one per runtime. The two files that were read by
  nothing are gone, and so is the class of bug where a generated file asserts something
  false about how it is loaded.
- **Skill activation is model-decided.** An always-on block was guaranteed to be in
  context; a skill is loaded when the model judges the description to match. That is the
  real cost of this decision, and it is why the `description` frontmatter carries explicit
  trigger phrases, and why tier 3 exists: native tools are the only integration that does
  not depend on a model's judgement. The trial above is evidence for one runtime at one
  version, not proof for all of them.
- Aider is prose-only, permanently: no MCP client, no skills. Its shell commands are
  user-approved, which is acceptable for a human-in-the-loop tool.
- A runtime that adds skill discovery later needs a registry entry and nothing else. A
  runtime that drops it needs a pointer writer, and the `Writer` enum has the shape for
  one.
- Until tier 3 lands, the runtime's permission model still sees `agentcordon proxy …` as
  one more Bash command: it cannot show a typed argument list, cannot allow-list per
  tool, and the CLI's JSON error envelope still has to be parsed out of shell output.
  That is the gap `mcp-serve` closes and this ADR does not.
