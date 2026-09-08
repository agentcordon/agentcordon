> [Home](index.md) > Roadmap

# Roadmap

Where AgentCordon is going, and why. This page is the list of directions, ranked, each
with the reason it belongs to this project rather than to a secrets manager or an MCP
proxy. It is not a schedule. A direction becomes work when it has a spec in the issue
tracker, and a decision when it has an ADR.

The thread through all of them: AgentCordon sits on the one chokepoint every agent action
passes through, with a real policy engine behind it and a graph of effective access that
cannot disagree with enforcement. The directions worth pursuing are the ones only that
position makes possible.

| # | Direction | Status |
|---|-----------|--------|
| 1 | [Step-up approval with a passkey or security key](#1-step-up-approval-with-a-passkey-or-security-key) | Spec: #60 |
| 2 | [Impact preview before a change is saved](#2-impact-preview-before-a-change-is-saved) | Idea |
| 3 | [Capability attenuation for sub-agents](#3-capability-attenuation-for-sub-agents) | Idea |
| 4 | [Secretless cloud access through workload identity federation](#4-secretless-cloud-access-through-workload-identity-federation) | Idea |
| 5 | [Policy replay against history](#5-policy-replay-against-history) | Idea |
| 6 | [An MCP firewall: policy on arguments and results](#6-an-mcp-firewall-policy-on-arguments-and-results) | Idea |
| 7 | [Cross-credential data-flow policy](#7-cross-credential-data-flow-policy) | Idea |
| 8 | [Budgets and rate governance per workspace](#8-budgets-and-rate-governance-per-workspace) | Idea |
| 9 | [A shippable red-team suite](#9-a-shippable-red-team-suite) | Idea |
| — | [The authorization graph in BloodHound](bloodhound-opengraph.md) | Spec: #59, schema on `feat/bloodhound-opengraph` |

---

## 1. Step-up approval with a passkey or security key

**What.** A policy can hold a request for a human. An agent asks to vend a credential or
call a tool; the policy says this one needs a person; the server parks the request, the
agent's terminal says so and waits, and the people allowed to approve see it in the
console. Approving is a touch on a security key or a passkey, with user verification,
signing a challenge the server bound to that exact request. The approval is single-use,
consumed by the call it authorised, and every step is audited with the approver and the
device.

**Why it sets the project apart.** Permit or deny is the wrong shape for paying an
invoice, merging to `main`, deleting a resource or revealing a secret. Holding those for
a human is what makes an agent deployable against real money and real infrastructure,
and binding the yes to a hardware key is what makes a stolen session or a leaked
password unable to give it. No secrets manager has the vantage point to hold the call,
and no MCP proxy has the policy engine to decide which calls to hold.

**Shape.** The hold is an ordinary Cedar forbid with an approval annotation that an
`approved` context flag lifts, so approval can never widen access beyond what policy
already permits. WebAuthn for the ceremony; the request digest is what the signature
attests to. Spec: #60. Follow-ups once it lands: approving from the terminal by touching a
locally attached key, notifications, and step-up for the console's own dangerous actions.

## 2. Impact preview before a change is saved

**What.** When an admin is about to add a grant, share a vault, bind an MCP server or edit
a policy, show what the change does before the save: which agents can now reach which
secrets and tools that they could not before, and which paths close. A plan before an
apply.

**Why.** The engine can already evaluate every principal against every action and
resource; that is what the BloodHound export does. Turned inward at save time, it answers
the question every reviewer actually has, "what does this let happen", with a number and
a list instead of a reading of Cedar. Nothing in the space does this because nothing else
holds both the model and the engine.

**Shape.** Reuse the graph builder from the BloodHound work to compute the set of
capability edges before and after the proposed change, and render the difference on the
form. The difference is small and fast at the scale of one install.

## 3. Capability attenuation for sub-agents

**What.** A workspace can spawn a child workspace whose access is a strict subset of its
own, chosen at spawn time and enforced by the engine. An orchestrator hands a sub-agent
only what the task needs.

**Why.** Orchestrators delegating to sub-agents is the dominant agent pattern, and nobody
governs the delegation. Workspaces already have a `parent_id` that nothing uses. Making
parentage mean attenuation, macaroon-style, turns a fleet of agents into a tree with a
least-privilege invariant, and the graph shows the tree.

**Shape.** A child's policy evaluation is the parent's, intersected with the child's own
grant. Enrollment of a child is a signed act of the parent workspace, so no human is in
the loop for each spawn. `AC_ParentOf` in the BloodHound schema becomes a traversable
edge in the child-to-parent direction.

## 4. Secretless cloud access through workload identity federation

**What.** Instead of storing a cloud key and injecting it, the workspace's own Ed25519
identity federates: AWS OIDC, Azure federated credentials, GCP workload identity. The
broker mints a short-lived token, scoped by a session policy to the target call, and
stores nothing long-lived at all.

**Why.** "We store no cloud secrets" is a stronger sentence than "we encrypt them". Entra
now has first-class agent identities, and mapping a workspace onto one is timely. A token
scoped per call is also the ultimate URL fence: the credential cannot be used outside the
call it was minted for.

**Shape.** AgentCordon becomes an OIDC issuer for workspace identities, and a credential
type per cloud that names the role or app to assume. The vend path exchanges the
workspace's assertion for the cloud token and injects that. Fits ADR-0006 exactly: the
long-lived trust stays on the server, the broker holds only what is short-lived.

## 5. Policy replay against history

**What.** The policy tester evaluates one hypothetical. Extend it to replay the last day or
week of real audit rows against a proposed policy set and show what would have been
denied, held or newly permitted.

**Why.** Policy changes are guesses without this. With it, an operator tightens a policy
knowing exactly which of last week's calls it would have stopped, and loosens one
knowing what it would have let through. Time-travel simulation is the difference between
authoring policy and testing it.

**Shape.** Audit rows already carry principal, action, resource and context. Replay is
evaluation of those tuples against a candidate policy set, batched, with a diff against
the recorded decisions.

## 6. An MCP firewall: policy on arguments and results

**What.** Cedar on tool calls at the argument level: permit `create_issue` but forbid
`merge_pull_request` when the base is `main`; constrain a `repo` argument to a pattern.
Then data-loss prevention on tool results: redact or block a result that matches a
pattern before it reaches the model.

**Why.** Tool-level allowlists and `mcp-serve` make AgentCordon an MCP gateway. Policy on
what goes into a tool and what comes back makes it a control, which is the whole
difference. The leak scanner already scans results for injected secrets; extending it to
operator-defined patterns is the same machinery pointed at a wider target.

**Shape.** Tool arguments enter the Cedar context as a record so ordinary predicates can
constrain them; result scanning reuses the scanner with configurable needles and a
block-or-redact decision. Schemas from discovery let the console offer argument names.

## 7. Cross-credential data-flow policy

**What.** Track, within a session, which upstream a piece of response data came from, and
let policy forbid data obtained with one credential from leaving through another's fence.

**Why.** The prompt-injection attack that actually happens is read with credential A,
exfiltrate with credential B. The broker sees both calls and both responses, which is a
vantage point nothing else in the pipeline has. Containing that attack at the broker is
the strongest runtime claim the project could make.

**Shape.** Taint at the granularity of response bodies and their fingerprints, carried in
the broker's session state, checked against outbound bodies before injection. Starts as
detection and audit, becomes enforcement once false positives are understood.

## 8. Budgets and rate governance per workspace

**What.** Ceilings per workspace and per credential: calls per hour, calls per day, and
where an upstream reports cost, spend. A runaway agent hits a wall, not a bill.

**Why.** "The agent can do everything except spend money" is the instinct every operator
has, and it is currently unexpressible. Rate limits at the broker are cheap and
immediately useful; spend limits are the same control with a price attached.

**Shape.** Counters in the broker keyed by workspace and credential, limits in the
credential's grant, an audit event on the wall, and a Cedar context value so policy can
also express "no more than N".

## 9. A shippable red-team suite

**What.** Package the release harness's blind-agent scenario, the one that tries to make
an agent leak a secret, so an operator can run it against their own deployment and get a
report: which secrets reached a model context, which fences held, which approvals fired.

**Why.** "Your model never sees a secret" is the project's central claim. A claim with a
test a customer can run is worth more than the claim, and nobody else ships one.

**Shape.** The existing S15 scenario and its checker, parameterised by server URL and
credentials, with a report in the style of the UAT summary.

---

## How a direction moves

1. **Idea.** A section on this page, with the what, the why and a sketch of the shape.
2. **Spec.** An issue in the tracker in the spec format, with user stories, implementation
   and testing decisions, and the seams named. The row above links it.
3. **Decision.** The design choices that will outlive the code go in an ADR when the
   implementation lands.
4. **Done.** The row moves to the changelog and the section is trimmed to a pointer.
