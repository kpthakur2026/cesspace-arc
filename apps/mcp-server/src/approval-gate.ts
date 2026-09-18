/**
 * CesSpace ARC — RC-04 Task 4 Approval Gate
 *
 * All Task-4 approval logic lives here so the single authoritative dispatch
 * pipeline in ./index.ts stays readable and its security ordering stays visible.
 *
 * Frozen redemption precedence (rc04 §4.1):
 *   1. control-object schema admission
 *   2. business-parameter schema admission
 *   3. workspace resolution
 *   4. Layer 1 permanent SecurityKernel
 *   5. Layer 2 current DeclarativePolicyEngine
 *   6. mutation approval floor
 *   7. approval record/token/binding validation
 *   8. atomic APPROVED -> CONSUMED
 *   9. strip _arcApproval
 *  10. invoke subsystem
 *
 * Token lookup, comparison, and consumption NEVER happen before the current
 * Layer-1 and Layer-2 DENY decisions have been determined.
 */

import path from 'node:path';

import { z } from 'zod';

import { type AdminApprovalSummary } from '@cesspace-arc/protocol';
import { PolicyOutcome, type PolicyEffect, type PolicyMatchTarget } from '@cesspace-arc/policy';
import { canonicalJson, sha256Hex } from '@cesspace-arc/policy';
import {
  MAX_REVIEW_SUMMARY_PATHS,
  type ApprovalActorBinding,
  type ApprovalRequestSnapshot,
  type ApprovalReviewSummary,
} from '@cesspace-arc/protocol';
import { parseUnifiedPatch } from '@cesspace-arc/filesystem';

/** Reserved top-level MCP control object key. */
export const ARC_APPROVAL_KEY = '_arcApproval';

/** Canonical approval request identifier shape. */
export const APPROVAL_REQUEST_ID_REGEX = /^[0-9a-f]{32}$/;

/** Maximum raw token size in UTF-8 bytes (rc04 §15). */
export const MAX_ARC_APPROVAL_TOKEN_BYTES = 128;

/**
 * Strict reserved control-object schema.
 *
 * `.strict()` rejects any additional property, and the token bound is applied
 * on UTF-8 BYTE length rather than JavaScript character count.
 */
export const ArcApprovalControlSchema = z
  .object({
    requestId: z
      .string()
      .regex(APPROVAL_REQUEST_ID_REGEX, 'requestId must be 32 lowercase hexadecimal characters'),
    token: z
      .string()
      .min(1, 'token must be a non-empty string')
      .refine(
        (value) => Buffer.byteLength(value, 'utf8') <= MAX_ARC_APPROVAL_TOKEN_BYTES,
        `token must not exceed ${MAX_ARC_APPROVAL_TOKEN_BYTES} UTF-8 bytes`,
      ),
  })
  .strict();

export type ArcApprovalControl = z.infer<typeof ArcApprovalControlSchema>;

/**
 * Shared JSON-schema fragment advertising `_arcApproval` on every registered
 * tool, since Layer 2 may elevate any tool to REQUIRE_APPROVAL.
 */
export const ARC_APPROVAL_JSON_SCHEMA = {
  type: 'object',
  description:
    'Reserved approval control object. Only required when a previous call returned APPROVAL_REQUIRED.',
  properties: {
    requestId: {
      type: 'string',
      pattern: '^[0-9a-f]{32}$',
      description: 'Approval request identifier returned by a previous APPROVAL_REQUIRED response.',
    },
    token: {
      type: 'string',
      description: 'One-time approval token issued by the trusted operator workflow.',
    },
  },
  required: ['requestId', 'token'],
  additionalProperties: false,
} as const;

/** Adds the reserved control object to a tool input schema. */
export function withArcApprovalSchema<T extends Record<string, unknown>>(schema: T): T {
  const properties = (schema.properties ?? {}) as Record<string, unknown>;
  return {
    ...schema,
    properties: { ...properties, [ARC_APPROVAL_KEY]: ARC_APPROVAL_JSON_SCHEMA },
  };
}

// ---------------------------------------------------------------------------
// 1. Reserved control extraction and admission
// ---------------------------------------------------------------------------

export interface ExtractedArcApproval {
  /** Business parameters with the reserved control object removed. */
  businessParameters: Record<string, unknown>;
  /** Present only when the control object was structurally VALID. */
  control: ArcApprovalControl | null;
  /** True when `_arcApproval` was supplied but failed schema admission. */
  malformed: boolean;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Extracts and validates the reserved `_arcApproval` control object.
 *
 * The control object is validated SEPARATELY and removed before the remaining
 * business parameters are validated against the existing strict tool schemas.
 * The subsystem therefore never sees it.
 */
export function extractArcApproval(parameters: unknown): ExtractedArcApproval {
  if (!isPlainObject(parameters)) {
    return { businessParameters: {}, control: null, malformed: false };
  }
  if (!Object.prototype.hasOwnProperty.call(parameters, ARC_APPROVAL_KEY)) {
    return { businessParameters: { ...parameters }, control: null, malformed: false };
  }

  const businessParameters = { ...parameters };
  delete businessParameters[ARC_APPROVAL_KEY];

  const parsed = ArcApprovalControlSchema.safeParse(parameters[ARC_APPROVAL_KEY]);
  if (!parsed.success) {
    return { businessParameters, control: null, malformed: true };
  }
  return { businessParameters, control: parsed.data, malformed: false };
}

/**
 * Bounded, non-sensitive audit facts about a supplied control object.
 *
 * A malformed control object is untrusted input, so it is never serialized
 * wholesale: only these coarse booleans are recorded.
 */
export function safeApprovalAuditMetadata(
  raw: unknown,
  control: ArcApprovalControl | null,
): Record<string, string | number | boolean> {
  if (raw === undefined) {
    return {};
  }
  const requestIdValue = isPlainObject(raw) ? raw.requestId : undefined;
  const tokenValue = isPlainObject(raw) ? raw.token : undefined;
  return {
    approvalControlProvided: true,
    requestIdShapeValid:
      typeof requestIdValue === 'string' && APPROVAL_REQUEST_ID_REGEX.test(requestIdValue),
    tokenProvided: typeof tokenValue === 'string' && tokenValue.length > 0,
    approvalControlValid: control !== null,
  };
}

// ---------------------------------------------------------------------------
// 2. Execution payload hash (rc04 §18, §22)
// ---------------------------------------------------------------------------

export interface ExecutionPayloadInput {
  toolName: string;
  /** EXACT post-schema validated business parameters, excluding `_arcApproval`. */
  businessParameters: Record<string, unknown>;
  actor: ApprovalActorBinding;
  workspaceId: string;
  workspaceRootHash: string;
  policyHash: string;
}

/**
 * Builds the exact object that is hashed for approval binding.
 *
 * `canonicalJson` and `sha256Hex` come from @cesspace-arc/policy; the sanitized
 * audit payload hash is a DIFFERENT value and is never substituted here.
 */
export function buildPayloadToSign(input: ExecutionPayloadInput): Record<string, unknown> {
  const actor: Record<string, unknown> = {
    clientId: input.actor.clientId,
    clientType: input.actor.clientType,
  };
  // Exact presence semantics: optional identity components are included only
  // when present. `authenticated` is deliberately NOT bound; Layer 1 re-evaluates
  // authentication on every request.
  if (input.actor.sessionId !== undefined) {
    actor.sessionId = input.actor.sessionId;
  }
  if (input.actor.deviceId !== undefined) {
    actor.deviceId = input.actor.deviceId;
  }

  return {
    schemaVersion: '1.0',
    toolName: input.toolName,
    parameters: input.businessParameters,
    actor,
    workspaceId: input.workspaceId,
    workspaceRootHash: input.workspaceRootHash,
    policyHash: input.policyHash,
  };
}

/** SHA-256 over canonical JSON of the exact payload-to-sign. */
export function computeExecutionPayloadHash(input: ExecutionPayloadInput): string {
  return sha256Hex(canonicalJson(buildPayloadToSign(input)));
}

// ---------------------------------------------------------------------------
// 3. Layer-2 target extraction (rc04 §15)
// ---------------------------------------------------------------------------

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Windows-style absolute path, e.g. `C:/x`. Backslashes are rejected separately. */
const WINDOWS_ABSOLUTE_PATH = /^[a-zA-Z]:[\\/]/;

/**
 * Normalizes a caller-supplied target path into canonical workspace-relative
 * form for Layer-2 matching (rc04 §15: Task 4 provides the normalized path).
 *
 * The policy grammar is a strict subset of what the filesystem accepts: it has
 * no notation for `.` segments, `//`, or a trailing slash, and the workspace
 * root itself has no valid representation. Feeding a non-canonical spelling to
 * the matcher would make it fail closed, and silently dropping the path would
 * let a `paths` rule miss — a real bypass, since the filesystem happily accepts
 * `./secret/key.txt` while a `secret/**` rule would not match it.
 *
 * Returns:
 * - a non-empty canonical relative path (e.g. `a/b.txt`) when the target
 *   resolves inside the workspace root,
 * - `''` when the candidate safely denotes the WORKSPACE ROOT itself,
 * - `undefined` when the caller supplied no path at all,
 * - `null` when the path is unsafe or unrepresentable (traversal, absolute,
 *   NUL, backslash). The caller MUST treat null as fail-closed.
 */
export function normalizeTargetPathForPolicy(
  workspaceRoot: string,
  candidate: unknown,
): string | undefined | null {
  if (candidate === undefined || candidate === null) {
    return undefined;
  }
  if (typeof candidate !== 'string' || candidate.length === 0) {
    return null;
  }
  // Reject NUL and Windows-style separators outright.
  if (candidate.includes('\u0000') || candidate.includes('\\')) {
    return null;
  }
  if (workspaceRoot.length === 0) {
    return null;
  }
  // An ABSOLUTE path must never be reinterpreted into an approvable relative
  // target, even when it happens to point inside the workspace root. Otherwise
  // an approval could be created for an operation the RC-03 filesystem will
  // later reject as an absolute path, and review metadata could expose the host
  // path. Checked BEFORE any resolution.
  if (path.isAbsolute(candidate) || WINDOWS_ABSOLUTE_PATH.test(candidate)) {
    return null;
  }

  const resolved = path.resolve(workspaceRoot, candidate);
  const relative = path.relative(workspaceRoot, resolved);
  if (relative.length === 0) {
    // A safe workspace-root selector. The frozen v1 policy grammar has no
    // representation for the root, so the caller decides per policy mode.
    return '';
  }
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return null;
  }
  return relative.split(path.sep).join('/');
}

/**
 * Normalizes an executable to the basename form the policy matcher expects.
 * Mirrors RC-02 normalization: path separators are impossible past Layer 1, and
 * comparison is on the lowercase bare name.
 */
export function executableBasename(executable: unknown): string | undefined {
  const value = asString(executable);
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  return trimmed.toLowerCase();
}

/**
 * Maps validated business parameters into deterministic policy match targets.
 *
 * Multi-target operations return one target per affected path; the caller
 * reduces them with the same most-restrictive precedence.
 */
export function extractPolicyTargets(
  toolName: string,
  params: Record<string, unknown>,
  workspaceRoot: string,
  patchTargetPaths?: readonly string[],
  policyMode: 'BUILTIN' | 'EXTERNAL' = 'EXTERNAL',
): PolicyMatchTarget[] {
  const base: PolicyMatchTarget = { toolName };

  /**
   * Adds a normalized path target.
   *
   * `null` means the path has no safe canonical relative form at all; the whole
   * request fails closed, signalled by returning `null` here.
   *
   * `''` means the candidate safely denotes the WORKSPACE ROOT. The frozen v1
   * external grammar cannot represent the root, so an EXTERNAL policy keeps
   * failing it closed; the BUILTIN compatibility policy falls back to the
   * tool-only base target, preserving the verified RC-01 behaviour.
   */
  const withPath = (candidate: unknown): PolicyMatchTarget | null | undefined => {
    const normalized = normalizeTargetPathForPolicy(workspaceRoot, candidate);
    if (normalized === null) return null;
    if (normalized === undefined) return undefined;
    if (normalized === '') {
      return policyMode === 'BUILTIN' ? base : null;
    }
    return { ...base, path: normalized };
  };

  switch (toolName) {
    case 'create_file':
    case 'write_file':
    case 'delete_file':
    case 'read_file': {
      const target = withPath(params.path);
      return target === null || target === undefined ? [] : [target];
    }

    case 'move_file': {
      const source = withPath(params.sourcePath);
      const destination = withPath(params.destinationPath);
      const targets: PolicyMatchTarget[] = [];
      if (source !== null && source !== undefined) targets.push(source);
      if (destination !== null && destination !== undefined) targets.push(destination);
      return targets;
    }

    case 'apply_patch': {
      const paths = patchTargetPaths ?? [];
      if (paths.length === 0) return [base];
      const targets: PolicyMatchTarget[] = [];
      for (const rawPath of paths) {
        const target = withPath(rawPath);
        if (target === null || target === undefined) return [];
        targets.push(target);
      }
      return targets;
    }

    case 'run_command': {
      const executableBasenameValue = executableBasename(params.executable);
      const target: PolicyMatchTarget = { ...base };
      if (executableBasenameValue !== undefined) {
        target.executableBasename = executableBasenameValue;
      }
      const cwdTarget = withPath(params.cwd);
      if (cwdTarget === null) return [];
      if (cwdTarget !== undefined) target.path = cwdTarget.path;
      return [target];
    }

    case 'list_directory': {
      const target = withPath(params.path);
      return target === null ? [] : target === undefined ? [base] : [target];
    }

    case 'search_files': {
      const target = withPath(params.subPath);
      return target === null ? [] : target === undefined ? [base] : [target];
    }

    case 'search_text': {
      const filePattern = asString(params.filePattern);
      return filePattern === undefined ? [base] : [{ ...base, path: filePattern }];
    }

    case 'git_status':
      return [{ ...base, gitAction: 'status' }];

    case 'git_diff': {
      const target = withPath(params.path);
      return target === null
        ? []
        : [
            target === undefined
              ? { ...base, gitAction: 'diff' }
              : { ...target, gitAction: 'diff' },
          ];
    }

    case 'git_log': {
      const target = withPath(params.path);
      return target === null
        ? []
        : [target === undefined ? { ...base, gitAction: 'log' } : { ...target, gitAction: 'log' }];
    }

    default:
      // Process/system tools have no synthetic policy target: revision strings
      // are never reinterpreted as branches merely to make a matcher match.
      return [base];
  }
}

// ---------------------------------------------------------------------------
// 4. Decision reduction (rc04 §16, §20)
// ---------------------------------------------------------------------------

const EFFECT_RANK: Record<PolicyEffect, number> = {
  DENY: 0,
  REQUIRE_APPROVAL: 1,
  ALLOW: 2,
};

export interface ReducedDecision {
  effect: PolicyEffect;
  outcome: PolicyOutcome;
  matchingRuleId: string;
  reason: string;
}

/**
 * Reduces per-target decisions with DENY > REQUIRE_APPROVAL > ALLOW.
 *
 * Equal winning effects are broken by lexicographically smallest matchingRuleId,
 * so the result is independent of target order.
 */
export function reduceDecisions(
  decisions: readonly {
    effect: PolicyEffect;
    matchingRuleId: string;
    reason: string;
  }[],
): ReducedDecision | null {
  let winner: ReducedDecision | null = null;

  for (const decision of decisions) {
    if (winner === null) {
      winner = {
        effect: decision.effect,
        outcome: effectToOutcome(decision.effect),
        matchingRuleId: decision.matchingRuleId,
        reason: decision.reason,
      };
      continue;
    }
    const candidateRank = EFFECT_RANK[decision.effect];
    const winnerRank = EFFECT_RANK[winner.effect];
    if (
      candidateRank < winnerRank ||
      (candidateRank === winnerRank && decision.matchingRuleId < winner.matchingRuleId)
    ) {
      winner = {
        effect: decision.effect,
        outcome: effectToOutcome(decision.effect),
        matchingRuleId: decision.matchingRuleId,
        reason: decision.reason,
      };
    }
  }

  return winner;
}

function effectToOutcome(effect: PolicyEffect): PolicyOutcome {
  if (effect === 'DENY') return PolicyOutcome.DENY;
  if (effect === 'REQUIRE_APPROVAL') return PolicyOutcome.REQUIRE_APPROVAL;
  return PolicyOutcome.ALLOW;
}

/** Most restrictive of two effects. */
export function mostRestrictive(a: PolicyEffect, b: PolicyEffect): PolicyEffect {
  return EFFECT_RANK[a] <= EFFECT_RANK[b] ? a : b;
}

// ---------------------------------------------------------------------------
// 5. Review material and safe review summary (rc04 §31, §32)
// ---------------------------------------------------------------------------

export interface ReviewMaterialAndSummary {
  reviewMaterial: string | undefined;
  reviewSummary: ApprovalReviewSummary | undefined;
}

function sha256OfText(value: string): string {
  return sha256Hex(value);
}

function boundTargetPaths(paths: readonly string[]): string[] {
  return paths.slice(0, MAX_REVIEW_SUMMARY_PATHS);
}

/**
 * Builds operator review material plus safe structured metadata.
 *
 * Raw material is the EXACT business payload (file content, patch text) and is
 * never wrapped in a JSON envelope carrying metadata — doing so would push a
 * legal 1 MiB mutation over the per-record review byte limit.
 */
export function buildReviewPayload(
  toolName: string,
  params: Record<string, unknown>,
  patchTargetPaths?: readonly string[],
): ReviewMaterialAndSummary {
  switch (toolName) {
    case 'create_file': {
      const content = typeof params.content === 'string' ? params.content : '';
      const path = asString(params.path);
      return {
        reviewMaterial: content,
        reviewSummary: {
          ...(path === undefined ? {} : { targetPaths: boundTargetPaths([path]) }),
          contentBytes: Buffer.byteLength(content, 'utf8'),
          contentHash: sha256OfText(content),
        },
      };
    }

    case 'write_file': {
      const content = typeof params.content === 'string' ? params.content : '';
      const path = asString(params.path);
      const expectedHash = asString(params.expectedHash);
      return {
        reviewMaterial: content,
        reviewSummary: {
          ...(path === undefined ? {} : { targetPaths: boundTargetPaths([path]) }),
          contentBytes: Buffer.byteLength(content, 'utf8'),
          contentHash: sha256OfText(content),
          ...(expectedHash === undefined ? {} : { expectedHash: expectedHash.toLowerCase() }),
          overwrite: params.overwrite === true,
        },
      };
    }

    case 'delete_file': {
      const path = asString(params.path);
      const expectedHash = asString(params.expectedHash);
      // A delete has no body to review; the safe summary is sufficient.
      return {
        reviewMaterial: undefined,
        reviewSummary: {
          ...(path === undefined ? {} : { targetPaths: boundTargetPaths([path]) }),
          ...(expectedHash === undefined ? {} : { expectedHash: expectedHash.toLowerCase() }),
        },
      };
    }

    case 'move_file': {
      const sourcePath = asString(params.sourcePath);
      const destinationPath = asString(params.destinationPath);
      const expectedSourceHash = asString(params.expectedSourceHash);
      const paths = [sourcePath, destinationPath].filter((p): p is string => p !== undefined);
      return {
        reviewMaterial: undefined,
        reviewSummary: {
          ...(paths.length === 0 ? {} : { targetPaths: boundTargetPaths(paths) }),
          ...(expectedSourceHash === undefined
            ? {}
            : { expectedSourceHash: expectedSourceHash.toLowerCase() }),
        },
      };
    }

    case 'apply_patch': {
      const patch = typeof params.patch === 'string' ? params.patch : '';
      const paths = patchTargetPaths ?? [];
      return {
        reviewMaterial: patch,
        reviewSummary: {
          ...(paths.length === 0 ? {} : { targetPaths: boundTargetPaths(paths) }),
          patchBytes: Buffer.byteLength(patch, 'utf8'),
          patchHash: sha256OfText(patch),
          dryRun: params.dryRun === true,
          ...(typeof params.fuzz === 'number' ? { fuzz: params.fuzz } : {}),
        },
      };
    }

    case 'run_command': {
      const executable = executableBasename(params.executable);
      const rawArgs = Array.isArray(params.args) ? params.args : [];
      return {
        // Bounded canonical representation of validated business parameters,
        // excluding raw environment values.
        reviewMaterial: canonicalJson({
          executable: asString(params.executable) ?? '',
          args: rawArgs.filter((a): a is string => typeof a === 'string'),
          cwd: asString(params.cwd) ?? null,
        }),
        reviewSummary: {
          ...(executable === undefined ? {} : { executable }),
          argumentCount: rawArgs.length,
        },
      };
    }

    default: {
      // Non-mutation approvals: bounded canonical representation of the
      // validated business parameters.
      return {
        reviewMaterial: canonicalJson(params),
        reviewSummary: undefined,
      };
    }
  }
}

/**
 * Parses an apply_patch body with the authoritative RC-03 parser.
 * Throws before any approval creation or consumption when malformed.
 */
export function parsePatchTargetPaths(patch: unknown): string[] {
  if (typeof patch !== 'string') {
    return [];
  }
  const parsed = parseUnifiedPatch(patch);
  return parsed.files.map((file) => file.targetPath);
}

// ---------------------------------------------------------------------------
// 6. Admin surface projection
// ---------------------------------------------------------------------------

/**
 * The ONE authoritative projection from an approval snapshot to the bounded
 * admin summary shape. Used by the admin IPC list method; there is deliberately
 * no second, divergent projection.
 *
 * Raw review material is never included. The safe `reviewSummary` is included so
 * an operator can see the target parameters being approved.
 */
export function toAdminSummary(snapshot: ApprovalRequestSnapshot): AdminApprovalSummary {
  return {
    requestId: snapshot.requestId,
    toolName: snapshot.toolName,
    state: snapshot.state,
    workspaceId: snapshot.binding.workspace.workspaceId,
    clientId: snapshot.binding.actor.clientId,
    clientType: snapshot.binding.actor.clientType,
    sessionId: snapshot.binding.actor.sessionId,
    deviceId: snapshot.binding.actor.deviceId,
    createdAt: snapshot.createdAt,
    expiresAt: snapshot.expiresAt,
    remainingSeconds: snapshot.remainingSeconds,
    reviewMaterialBytes: snapshot.reviewMaterialBytes,
    reviewSummary: snapshot.reviewSummary,
  };
}
