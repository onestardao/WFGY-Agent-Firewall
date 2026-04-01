import * as readline from "readline";
import {
  FirewallDecision,
  HumanReviewResult,
  ToolCallContext,
} from "../types/firewallTypes";

/**
 * Synchronous terminal-based human review flow.
 * Phase 1 (Issue No.4)
 *
 * When the firewall returns REVIEW, execution pauses here.
 * The operator sees a summary and must explicitly approve or reject.
 *
 * Phase 1 scope: terminal only. No Slack / Telegram / webhook.
 */

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Format tool arguments into a short readable summary (max ~300 chars). */
function formatParamsSummary(args: Record<string, any>): string {
  const raw = JSON.stringify(args, null, 2);
  if (raw.length <= 300) return raw;
  return raw.slice(0, 300) + "\n  ...(truncated)";
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Prompt the operator in the terminal and wait for approve / reject.
 *
 * Returns a `HumanReviewResult` that should be passed to the audit logger.
 * This function is async because it waits for stdin input.
 */
export async function requestTerminalReview(
  context: ToolCallContext,
  firewallDecision: FirewallDecision
): Promise<HumanReviewResult> {
  const border = "=".repeat(60);

  // ── Display review panel ────────────────────────────────────────────────
  console.log();
  console.log(border);
  console.log("  FIREWALL REVIEW REQUIRED");
  console.log(border);
  console.log();
  console.log(`  Tool:      ${context.toolName}`);
  console.log(`  Call ID:   ${context.toolCallId ?? "n/a"}`);
  console.log(`  Category:  ${firewallDecision.category}`);
  console.log(`  Reason:    ${firewallDecision.reason}`);
  console.log();
  console.log("  Params:");
  formatParamsSummary(context.arguments)
    .split("\n")
    .forEach((line) => console.log(`    ${line}`));
  console.log();
  console.log(border);

  // ── Wait for operator input ─────────────────────────────────────────────
  const answer = await promptUser(
    "  Approve this action? [y/N]: "
  );

  const approved = answer.trim().toLowerCase() === "y";

  // Optional: let operator add a note on rejection
  let reviewerNote: string = "";
  if (!approved) {
    const note = await promptUser("  Reason for rejection (optional, Enter to skip): ");
    if (note.trim()) reviewerNote = note.trim();
  }

  const result: HumanReviewResult = {
    outcome: approved ? "APPROVED" : "REJECTED",
    ...(reviewerNote ? { reviewerNote } : {}),
    reviewedAt: new Date().toISOString(),
  };

  console.log();
  console.log(
    approved
      ? "  >> Action APPROVED by operator."
      : `  >> Action REJECTED by operator.${reviewerNote ? ` (${reviewerNote})` : ""}`
  );
  console.log(border);
  console.log();

  return result;
}

// ── Internal readline wrapper ───────────────────────────────────────────────

function promptUser(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<string>((resolve) => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}
