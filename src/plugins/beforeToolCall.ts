import {
  Decision,
  FirewallDecision,
  HumanReviewResult,
  ToolCallContext,
} from "../types/firewallTypes";
import { evaluateSecurity } from "../critics/securityCritic";
import { requestTerminalReview } from "../hitl/terminalReview";
import { writeAuditLog } from "../logging/auditLogger";

/**
 * Primary interception hook for the WFGY-Agent-Firewall.
 *
 * Evaluation order:
 *   1. Security Critic  — hard policy checks (DENY / REVIEW / ALLOW)
 *   2. Terminal Review   — if critic returns REVIEW, pause for human (No.4)
 *   3. Audit Logger      — every interception is logged (No.5)
 *   4. Return the FirewallDecision to continue the execution if allowed.
 *
 * Fail-closed: any unexpected error during evaluation results in DENY.
 */
export async function beforeToolCall(
  context: ToolCallContext
): Promise<FirewallDecision> {
  console.log(
    `[Firewall] Intercepting tool call: ${context.toolName} (id: ${context.toolCallId ?? context.metadata?.toolCallId ?? "n/a"})`
  );

  let decision: FirewallDecision;
  let humanReview: HumanReviewResult | null = null;

  // ── 1. Security Critic (fail-closed) ────────────────────────────────────
  try {
    decision = await evaluateSecurity(context);
  } catch (err: any) {
    console.error(`[Firewall] CRITICAL ERROR during evaluation: ${err.message}`);
    throw new Error(`[FIREWALL_ERROR] Blocking execution due to failure in enforcement layer.`);
  }

  // ── 2. Enforce ──────────────────────────────────────────────────────────
  switch (decision.decision) {
    case Decision.DENY:
      console.warn(
        `[Firewall] \u2716 DENIED  | category: ${decision.category} | reason: ${decision.reason}`
      );
      writeAuditLog(context, decision, null);
      throw new Error(`[FIREWALL_DENY] ${decision.reason}`);

    case Decision.REVIEW:
      console.info(
        `[Firewall] \u26A0 REVIEW | category: ${decision.category} | reason: ${decision.reason}`
      );
      // ── No.4: Terminal human review ──────────────────────────────────
      humanReview = await requestTerminalReview(context, decision);
      writeAuditLog(context, decision, humanReview);

      if (humanReview.outcome === "REJECTED") {
        throw new Error(
          `[FIREWALL_REVIEW_REJECTED] Operator rejected: ${humanReview.reviewerNote ?? decision.reason}`
        );
      }
      // Operator approved — fall through to return
      console.log(`[Firewall] \u2714 APPROVED by operator \u2014 proceeding.`);
      return decision;

    case Decision.ALLOW:
      console.log(
        `[Firewall] \u2714 ALLOW  | category: ${decision.category} | reason: ${decision.reason}`
      );
      writeAuditLog(context, decision, null);
      return decision;
  }

  throw new Error(`[FIREWALL_ERROR] Unhandled decision type: ${(decision as any).decision}`);
}
