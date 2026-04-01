/**
 * Shared firewall decision contract and types.
 * Defined for Phase 1 as per Issue #3.
 */

export enum Decision {
  ALLOW = "ALLOW",
  REVIEW = "REVIEW",
  DENY = "DENY",
}

export interface FirewallDecision {
  // Required Phase 1 fields
  decision: Decision;
  category: string;
  reason: string;
  toolName: string;
  toolCallId: string;
  timestamp: string; // ISO 8601 string

  // Reserved fields for future phases
  riskScore?: number;
  semanticDriftScore?: number;
  scarPressure?: number;
  expectedEffect?: string;
  observedEffect?: string;
  failureCode?: string;
}

export interface ToolCallContext {
  toolName: string;
  toolCallId?: string;
  arguments: Record<string, any>;
  metadata?: Record<string, any>;
  /** Session identifier for audit trail. */
  sessionId?: string;
  /** Agent identifier for audit trail. */
  agentId?: string;
}

// ── No.5: Audit Logging ─────────────────────────────────────────────────────

export interface AuditLogEntry {
  // Identity
  timestamp: string;
  sessionId: string;
  agentId: string;

  // Tool metadata
  toolName: string;
  toolCallId: string;
  paramsSummary: string;

  // Firewall decision
  decision: Decision;
  category: string;
  reason: string;

  // Human review (null if not applicable)
  humanReview: null;

  // Final outcome after all checks
  finalOutcome: "EXECUTED" | "BLOCKED";

  // Reserved Phase 2 fields
  riskScore?: number;
  semanticDriftScore?: number;
  expectedEffect?: string;
  observedEffect?: string;
  failureCode?: string;
}
