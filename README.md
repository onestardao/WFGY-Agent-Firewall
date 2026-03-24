# WFGY-Agent-Firewall

Pre-execution firewall for autonomous agents.

Phase 1 is an MVP focused on one thing only:

stop dangerous tool calls before execution, require human approval for high-risk actions, and leave a readable audit trail.

## What this repo is

WFGY-Agent-Firewall is an agent firewall layer designed to intercept tool calls before they execute.

The first implementation target is OpenClaw-style agent loops with a `before_tool_call` interception point.

This repository is currently in Phase 1 Alpha.
The goal of Phase 1 is not to build a full reasoning engine or a full governance stack.
The goal is to prove that dangerous actions can be blocked before damage happens.

## Phase 1 scope

Phase 1 includes:

- `before_tool_call` interception
- rule-based Security Critic
- lightweight Alignment Critic
- synchronous human review in terminal
- structured audit logging
- 3 reproducible demos

## Not in Phase 1

The following are explicitly out of scope for the first sprint:

- full WFGY runtime control loop
- full Scar Ledger field mechanics
- full semantic residue processing
- OOC override protocol
- full Atlas telemetry automation
- multi-channel approval integrations

These may be added later, but they are not required for the first working MVP.

## Design idea

The firewall separates intent from execution.

When an agent requests a tool call, the firewall evaluates that action before the tool runs.

Phase 1 uses two simple critic layers:

- **Security Critic**
  Checks hard policy violations such as recursive delete, secret access, unsafe shell patterns, and outbound calls to non-allowlisted domains.

- **Alignment Critic**
  Checks whether the requested action still matches the current task scope.

If an action is clearly unsafe, it is denied.
If an action is high-risk but potentially legitimate, execution pauses and asks the human operator for approval.
If an action is safe and in-scope, it is allowed.

## Decision contract

Every intercepted tool call must resolve to one of:

- `ALLOW`
- `REVIEW`
- `DENY`

Phase 1 keeps this contract intentionally small and stable.

## Minimum threat classes for Phase 1

Phase 1 must detect or escalate at least these classes:

- bulk or recursive delete
- secret or credential file access
- outbound requests to non-allowlisted domains
- dangerous shell execution patterns
- production config writes
- obvious task-scope mismatch

## MVP demos

Phase 1 is considered successful if these demos are reproducible:

1. **Bulk Delete Blocked**  
   A destructive delete attempt is denied before execution.

2. **Secret / Exfil Blocked**  
   A secret read or outbound exfil attempt is denied before execution.

3. **Human Review for Risky Config Change**  
   A risky but plausible config write is paused for explicit human approval.

## Repository layout

```text
/src
  /plugins
    beforeToolCall.ts
  /critics
    securityCritic.ts
    alignmentCritic.ts
  /hitl
    terminalReview.ts
  /logging
    auditLogger.ts
  /types
    firewallTypes.ts
  decisionEngine.ts

/config
  firewall.policy.json
  allowlist.domains.json
  wfgy.config.json

/demos
  demo-bulk-delete.md
  demo-secret-exfil.md
  demo-human-review.md

/docs
  SPEC_PHASE1.md
  ROADMAP.md
````

## Contribution model

For now, the project uses a simple contribution flow:

1. pick or open an issue
2. create a branch or fork
3. keep changes narrow and reviewable
4. open a PR
5. maintainer reviews and merges

Please avoid broad refactors during Phase 1.
The sprint goal is to get the first working firewall gate online.

## Current sprint priority

The current priority order is:

1. wire interception into the execution loop
2. implement Security Critic
3. implement terminal review loop
4. implement audit logging
5. implement lightweight Alignment Critic
6. lock the 3 demos

## Future direction

Later phases may add:

* `tool_result_persist` post-execution checks
* WFGY semantic drift scoring
* simplified scar memory
* structured failure tagging
* richer policy layers

But the first milestone is simpler:

**block first, review second, log everything.**

## Status

Alpha sprint.
MVP first.
Keep it small.
Keep it testable.
Keep it reviewable.
