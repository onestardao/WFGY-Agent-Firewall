import {
  Decision,
  FirewallDecision,
  HumanReviewResult,
  ToolCallContext,
} from "../types/firewallTypes";
import { evaluateSecurity } from "../critics/securityCritic";
import { evaluateAlignment } from "../critics/alignmentCritic";
import { requestTerminalReview } from "../hitl/terminalReview";
import { writeAuditLog } from "../logging/auditLogger";

/**
 * Primary interception hook for the WFGY-Agent-Firewall.
 *
 * Evaluation order:
 *   1. Security Critic  — hard policy checks (DENY / REVIEW / ALLOW)
 *   2. Alignment Critic — task-scope mismatch check (REVIEW / ALLOW)  (No.6)
 *   3. Terminal Review   — if either critic returns REVIEW, pause for human (No.4)
 *   4. Audit Logger      — every interception is logged regardless of outcome (No.5)
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
    console.error(`[Firewall] CRITICAL ERROR during security evaluation: ${err.message}`);
    // Record the fail-closed event in audit trail before rethrowing
    const failClosedDecision: FirewallDecision = {
      decision: Decision.DENY,
      category: "ENFORCEMENT_FAILURE",
      reason: `Security evaluation crashed: ${err.message}`,
      toolName: context.toolName,
      toolCallId: context.toolCallId ?? `call-${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
    writeAuditLog(context, failClosedDecision, null);
    throw new Error(`[FIREWALL_ERROR] Blocking execution due to failure in enforcement layer.`);
  }

  // ── 2. Alignment Critic (only if security passed with ALLOW) ────────────
  if (decision.decision === Decision.ALLOW) {
    try {
      const alignmentResult = await evaluateAlignment(context);
      if (alignmentResult.decision === Decision.REVIEW) {
        // Alignment escalated — override to REVIEW
        decision = alignmentResult;
      }
    } catch (err: any) {
      console.error(`[Firewall] ERROR during alignment evaluation: ${err.message}`);
      // Fail-closed: treat alignment failure as REVIEW, not silent ALLOW
      decision = {
        decision: Decision.REVIEW,
        category: "ALIGNMENT_ERROR",
        reason: `Alignment check failed: ${err.message}`,
        toolName: context.toolName,
        toolCallId: context.toolCallId ?? `call-${Date.now()}`,
        timestamp: new Date().toISOString(),
      };
    }
  }

  // ── 3. Enforce ──────────────────────────────────────────────────────────
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
