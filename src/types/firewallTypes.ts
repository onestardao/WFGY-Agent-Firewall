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
  arguments: Record<string, any>;
  metadata?: Record<string, any>;
}
