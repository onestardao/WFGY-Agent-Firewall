import * as fs from "fs";
import * as path from "path";
import {
  AuditLogEntry,
  Decision,
  FirewallDecision,
  HumanReviewResult,
  ToolCallContext,
} from "../types/firewallTypes";

/**
 * Structured audit logger for the WFGY-Agent-Firewall.
 * Phase 1 (Issue No.5)
 *
 * Every intercepted tool call writes one JSON-lines entry.
 * Output: console + append to `logs/firewall-audit.jsonl`.
 */

// ── Config ──────────────────────────────────────────────────────────────────

const LOG_DIR = path.resolve(__dirname, "../../logs");
const LOG_FILE = path.join(LOG_DIR, "firewall-audit.jsonl");

/**
 * Best-effort log directory creation.
 * If filesystem is read-only or permissions are restricted, degrade
 * gracefully to console-only logging instead of crashing the firewall.
 */
let fileLoggingEnabled = true;

function ensureLogDir(): void {
  try {
    if (!fs.existsSync(LOG_DIR)) {
      fs.mkdirSync(LOG_DIR, { recursive: true });
    }
  } catch (err: any) {
    console.warn(`[AuditLog] Cannot create log directory (${err.message}). File logging disabled, console-only.`);
    fileLoggingEnabled = false;
  }
}

ensureLogDir();

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Summarize tool-call arguments for the audit trail.
 * Truncates long values to avoid bloating the log.
 */
function summarizeParams(args: Record<string, any>, maxLen = 200): string {
  const raw = JSON.stringify(args);
  if (raw.length <= maxLen) return raw;
  return raw.slice(0, maxLen) + "...(truncated)";
}

/**
 * Derive the final outcome label from the firewall decision + human review.
 */
function deriveFinalOutcome(
  decision: Decision,
  humanReview: HumanReviewResult | null
): AuditLogEntry["finalOutcome"] {
  if (decision === Decision.ALLOW) return "EXECUTED";
  if (decision === Decision.DENY) return "BLOCKED";
  // REVIEW path
  if (humanReview) {
    return humanReview.outcome === "APPROVED" ? "EXECUTED" : "BLOCKED_BY_HUMAN";
  }
  return "BLOCKED";
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Build and persist an audit log entry.
 *
 * Call this AFTER the firewall decision is finalized.
 * Returns the entry for downstream use / testing.
 */
export function writeAuditLog(
  context: ToolCallContext,
  firewallDecision: FirewallDecision,
  humanReview: HumanReviewResult | null = null
): AuditLogEntry {
  const entry: AuditLogEntry = {
    // Identity
    timestamp: new Date().toISOString(),
    sessionId: context.sessionId ?? context.metadata?.sessionId ?? "unknown",
    agentId: context.agentId ?? context.metadata?.agentId ?? "unknown",

    // Tool metadata
    toolName: context.toolName,
    toolCallId:
      context.toolCallId ??
      context.metadata?.toolCallId ??
      firewallDecision.toolCallId,
    paramsSummary: summarizeParams(context.arguments),

    // Firewall decision
    decision: firewallDecision.decision,
    category: firewallDecision.category,
    reason: firewallDecision.reason,

    // Human review
    humanReview,

    // Final outcome
    finalOutcome: deriveFinalOutcome(firewallDecision.decision, humanReview),
  };

  // ── Persist ─────────────────────────────────────────────────────────────
  const line = JSON.stringify(entry);

  // 1. Console (always)
  const icon =
    entry.finalOutcome === "EXECUTED"
      ? "\u2714"
      : entry.finalOutcome === "BLOCKED_BY_HUMAN"
      ? "\u26A0"
      : "\u2716";
  console.log(`[AuditLog] ${icon} ${entry.toolName} | ${entry.decision} | ${entry.category}`);

  // 2. File (append, best-effort — skip if file logging was disabled at init)
  if (fileLoggingEnabled) {
    try {
      fs.appendFileSync(LOG_FILE, line + "\n", "utf-8");
    } catch (err: any) {
      console.error(`[AuditLog] Failed to write log file: ${err.message}`);
    }
  }

  return entry;
}

/**
 * Read all audit log entries from the current log file.
 * Useful for demos and testing.
 */
export function readAuditLog(): AuditLogEntry[] {
  if (!fs.existsSync(LOG_FILE)) return [];
  const raw = fs.readFileSync(LOG_FILE, "utf-8").trim();
  if (!raw) return [];
  return raw.split("\n").map((line) => JSON.parse(line) as AuditLogEntry);
}
