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
