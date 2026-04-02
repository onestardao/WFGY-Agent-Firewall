import {
  Decision,
  FirewallDecision,
  ToolCallContext,
} from "../types/firewallTypes";

/**
 * Lightweight Alignment Critic for Phase 1 (Issue No.6).
 *
 * Compares the current tool-call action against the stated task scope.
 * If there is an obvious mismatch, escalates to REVIEW.
 *
 * This is intentionally simple for MVP:
 *   - Categorize the tool call by action type
 *   - Categorize the task scope by keywords
 *   - Flag when the action category is clearly outside the task category
 *
 * Phase 2 will replace this with WFGY semantic drift scoring.
 */

// ── Action categories ───────────────────────────────────────────────────────

/**
 * Each category maps to keywords that would appear in tool names or arguments.
 */
const ACTION_SIGNALS: Record<string, string[]> = {
  DESTRUCTIVE: ["rm ", "rm -", "delete", "drop", "truncate", "destroy", "purge", "unlink", "shred"],
  NETWORK_OUT: ["curl", "wget", "fetch", "http", "https", "ssh", "scp", "rsync", "upload", "post"],
  FILE_WRITE:  ["write", "create", "mkdir", "mv ", "cp ", "rename", "append", "overwrite"],
  FILE_READ:   ["read", "cat ", "ls ", "find ", "grep", "search", "head", "tail", "list"],
  CONFIG:      ["config", "settings", "env", "setup", "install", "enable", "disable"],
  EXECUTE:     ["exec", "run", "bash", "sh ", "cmd", "spawn", "subprocess", "eval"],
};

/**
 * Task-scope keywords that suggest what the operator actually wants.
 */
const TASK_SIGNALS: Record<string, string[]> = {
  READING:     ["read", "review", "check", "inspect", "look", "find", "search", "list", "show", "print", "debug", "log"],
  WRITING:     ["write", "create", "add", "implement", "build", "generate", "make"],
  REFACTORING: ["refactor", "rename", "move", "reorganize", "restructure", "clean"],
  TESTING:     ["test", "spec", "assert", "verify", "validate", "check"],
  DEPLOYING:   ["deploy", "push", "release", "publish", "ship"],
  DELETING:    ["delete", "remove", "clean up", "purge", "drop"],
};

// ── Mismatch matrix ─────────────────────────────────────────────────────────

/**
 * Which action categories are suspicious when the task does NOT belong
 * to that action's natural scope.
 *
 * Key: action category. Value: task categories where this action is expected.
 * If the current task does NOT fall into any of the expected categories,
 * the critic flags it as a scope mismatch.
 */
const EXPECTED_SCOPE: Record<string, string[]> = {
  DESTRUCTIVE: ["DELETING", "REFACTORING"],
  NETWORK_OUT: ["DEPLOYING"],
  CONFIG:      ["DEPLOYING", "WRITING"],
  EXECUTE:     ["TESTING", "DEPLOYING", "WRITING"],
  // FILE_WRITE and FILE_READ are generally acceptable in most tasks
};

// ── Helpers ─────────────────────────────────────────────────────────────────

function detectActionCategory(context: ToolCallContext): string | null {
  const blob = (
    context.toolName + " " + JSON.stringify(context.arguments)
  ).toLowerCase();

  for (const [category, signals] of Object.entries(ACTION_SIGNALS)) {
    for (const signal of signals) {
      if (blob.includes(signal)) return category;
    }
  }
  return null;
}

function detectTaskCategory(taskScope: string): string | null {
  const lower = taskScope.toLowerCase();

  for (const [category, signals] of Object.entries(TASK_SIGNALS)) {
    for (const signal of signals) {
      if (lower.includes(signal)) return category;
    }
  }
  return null;
}

function makeDecision(
  decision: Decision,
  category: string,
  reason: string,
  context: ToolCallContext
): FirewallDecision {
  const toolCallId =
    context.toolCallId ?? context.metadata?.toolCallId ?? `call-${Date.now()}`;
  return {
    decision,
    category,
    reason,
    toolName: context.toolName,
    toolCallId,
    timestamp: new Date().toISOString(),
  };
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Evaluate whether the requested tool call aligns with the current task scope.
 *
 * - If no `taskScope` is provided in the context, alignment cannot be checked — returns ALLOW.
 * - If the action category is not in the suspicious set, returns ALLOW.
 * - If the action is suspicious but the task category matches, returns ALLOW.
 * - Otherwise, escalates to REVIEW with a human-readable reason.
 */
export async function evaluateAlignment(
  context: ToolCallContext
): Promise<FirewallDecision> {
  const taskScope = context.taskScope ?? context.metadata?.taskScope;

  // No task scope → can't check alignment → allow
  if (!taskScope || typeof taskScope !== "string" || !taskScope.trim()) {
    return makeDecision(
      Decision.ALLOW,
      "ALIGNMENT_SKIP",
      "No task scope provided; alignment check skipped.",
      context
    );
  }

  const actionCategory = detectActionCategory(context);

  // Action not in any known category → nothing to flag
  if (!actionCategory) {
    return makeDecision(
      Decision.ALLOW,
      "ALIGNMENT_UNKNOWN_ACTION",
      "Tool call does not match any known action category.",
      context
    );
  }

  // If this action category has no scope restrictions, allow
  const expectedScopes = EXPECTED_SCOPE[actionCategory];
  if (!expectedScopes) {
    return makeDecision(
      Decision.ALLOW,
      "ALIGNMENT_OK",
      `Action category "${actionCategory}" has no scope restrictions.`,
      context
    );
  }

  const taskCategory = detectTaskCategory(taskScope);

  // Task matches one of the expected scopes → aligned
  if (taskCategory && expectedScopes.includes(taskCategory)) {
    return makeDecision(
      Decision.ALLOW,
      "ALIGNMENT_OK",
      `Action "${actionCategory}" is expected for task scope "${taskCategory}".`,
      context
    );
  }

  // ── Scope mismatch → escalate to REVIEW ───────────────────────────────
  return makeDecision(
    Decision.REVIEW,
    "SCOPE_MISMATCH",
    `Action "${actionCategory}" seems outside the stated task scope "${taskScope}". ` +
      `Expected task types: [${expectedScopes.join(", ")}], detected: "${taskCategory ?? "NONE"}".`,
    context
  );
}
