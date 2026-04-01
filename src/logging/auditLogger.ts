import * as fs from "fs";
import * as path from "path";
import {
  AuditLogEntry,
  Decision,
  FirewallDecision,
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

/** Ensure the log directory exists (created once on module load). */
function ensureLogDir(): void {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
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
 * Derive the final outcome label from the firewall decision.
 * (No.4 human review will extend this in a subsequent commit.)
 */
function deriveFinalOutcome(decision: Decision): AuditLogEntry["finalOutcome"] {
  if (decision === Decision.ALLOW) return "EXECUTED";
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
  firewallDecision: FirewallDecision
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

    // Human review — not yet implemented (see No.4)
    humanReview: null,

    // Final outcome
    finalOutcome: deriveFinalOutcome(firewallDecision.decision),
  };

  // ── Persist ─────────────────────────────────────────────────────────────
  const line = JSON.stringify(entry);

  // 1. Console (always)
  const icon = entry.finalOutcome === "EXECUTED" ? "\u2714" : "\u2716";
  console.log(`[AuditLog] ${icon} ${entry.toolName} | ${entry.decision} | ${entry.category}`);

  // 2. File (append, best-effort — don't crash the firewall if disk fails)
  try {
    fs.appendFileSync(LOG_FILE, line + "\n", "utf-8");
  } catch (err: any) {
    console.error(`[AuditLog] Failed to write log file: ${err.message}`);
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
