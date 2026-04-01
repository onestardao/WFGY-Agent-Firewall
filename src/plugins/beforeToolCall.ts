import { Decision, FirewallDecision, ToolCallContext } from "../types/firewallTypes";
import { evaluateSecurity } from "../critics/securityCritic";
import { writeAuditLog } from "../logging/auditLogger";

/**
 * Primary interception hook for the WFGY-Agent-Firewall.
 *
 * Responsibilities:
 *   1. Receive the tool-call context from the agent runtime.
 *   2. Delegate to the Security Critic for evaluation.
 *   3. Enforce the decision (ALLOW / REVIEW / DENY) by blocking bad tool calls via Error exceptions.
 *   4. Log every interception to the structured audit trail.
 *   5. Return the FirewallDecision to continue the execution if allowed.
 */
export async function beforeToolCall(
  context: ToolCallContext
): Promise<FirewallDecision> {
  console.log(
    `[Firewall] Intercepting tool call: ${context.toolName} (id: ${context.toolCallId ?? context.metadata?.toolCallId ?? "n/a"})`
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
        `[Firewall] \u2716 DENIED  | category: ${decision.category} | reason: ${decision.reason}`
      );
      writeAuditLog(context, decision);
      throw new Error(`[FIREWALL_DENY] ${decision.reason}`);

    case Decision.REVIEW:
      console.info(
        `[Firewall] \u26A0 REVIEW | category: ${decision.category} | reason: ${decision.reason}`
      );
      writeAuditLog(context, decision);
      // TEMP: block (HITL not implemented yet — see No.4)
      throw new Error(`[FIREWALL_REVIEW] ${decision.reason}`);

    case Decision.ALLOW:
      console.log(
        `[Firewall] \u2714 ALLOW  | category: ${decision.category} | reason: ${decision.reason}`
      );
      writeAuditLog(context, decision);
      return decision;
  }

  throw new Error(`[FIREWALL_ERROR] Unhandled decision type: ${(decision as any).decision}`);
}
