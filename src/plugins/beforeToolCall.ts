import { Decision, FirewallDecision, ToolCallContext } from "../types/firewallTypes";
import { evaluateSecurity } from "../critics/securityCritic";

/**
 * Primary interception hook for the WFGY-Agent-Firewall.
 *
 * Responsibilities:
 *   1. Receive the tool-call context from the agent runtime.
 *   2. Delegate to the Security Critic for evaluation.
 *   3. Enforce the decision (ALLOW / REVIEW / DENY) by blocking bad tool calls via Error exceptions.
 *   4. Return the FirewallDecision to continue the execution if allowed.
 */
export async function beforeToolCall(
  context: ToolCallContext
): Promise<FirewallDecision> {
  console.log(
    `[Firewall] Intercepting tool call: ${context.toolName} (id: ${context.metadata?.toolCallId ?? "n/a"})`
  );

  let decision: FirewallDecision;

  // ── Evaluate with Fail-Closed check ───────────────────────────────────────
  try {
    decision = await evaluateSecurity(context);
  } catch (err: any) {
    console.error(`[Firewall] CRITICAL ERROR during evaluation: ${err.message}`);
    // Industry standard fail-closed pattern: If the enforcement mechanism errors, DENY the action.
    throw new Error(`[FIREWALL_ERROR] Blocking execution due to failure in enforcement layer.`);
  }

  // ── Enforce ───────────────────────────────────────────────────────────────
  switch (decision.decision) {
    case Decision.DENY:
      console.warn(
        `[Firewall] ✖ DENIED  | category: ${decision.category} | reason: ${decision.reason}`
      );
      throw new Error(`[FIREWALL_DENY] ${decision.reason}`);

    case Decision.REVIEW:
      console.info(
        `[Firewall] ⚠ REVIEW | category: ${decision.category} | reason: ${decision.reason}`
      );
      // TEMP: block (since HITL is not implemented yet or is handled out-of-band for #3 MVP)
      throw new Error(`[FIREWALL_REVIEW] ${decision.reason}`);

    case Decision.ALLOW:
      console.log(
        `[Firewall] ✔ ALLOW  | category: ${decision.category} | reason: ${decision.reason}`
      );
      return decision;
  }

  throw new Error(`[FIREWALL_ERROR] Unhandled decision type: ${(decision as any).decision}`);
}
