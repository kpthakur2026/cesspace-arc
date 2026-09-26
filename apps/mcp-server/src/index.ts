#!/usr/bin/env node
import { platform, arch, cpus, totalmem, freemem } from 'node:os';
import { statfsSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

import {
  ArcError,
  type AuditRecord,
  type AuditLifecycleMetadata,
  type HealthResponse,
  type SystemStatusResponse,
  type PolicyEvaluationContext,
  type RunCommandRequest,
  type ArcCiStatusRequest,
  type ArcStageEvidenceRequest,
} from '@cesspace-arc/protocol';
import {
  ApprovalStateManager,
  DeclarativePolicyEngine,
  SecurityKernel,
  WorkspaceRegistry,
  getApprovalFailureReason,
  sha256Hex,
  type PolicyEffect,
  type PolicyMatchTarget,
  type WorkspaceRecord,
  RC03_MUTATION_TOOLS,
  RC07_COMPOSITE_TOOLS,
  type CompositePlanSecurityFacts,
} from '@cesspace-arc/policy';
import { EnrollmentManager, SessionManager } from '@cesspace-arc/auth';
import { AdminIpcError, AdminIpcServer } from './admin-ipc.js';
import {
  RemoteExecutionBridge,
  RemoteRequestAdmission,
  createAuthenticatedRequestLimiter,
  type CompleteActor,
} from './remote-execution.js';
import type { BoundedRequestLimiter } from './remote-resource-limits.js';
import { ApprovalAuditSink, getApprovalAuditSink } from './approval-audit.js';
import { getAuditWriteAuthority, type AuditWriteAuthority } from './audit-write-authority.js';
import { getGatewayAuditSink } from './gateway-audit.js';
import { RemoteGateway, type RemoteGatewayStatus } from './remote-gateway.js';
import { readRemoteRequestContext, RemoteMcpSurface } from './remote-mcp-surface.js';
import { GatewayDeviceAdministration } from './device-administration.js';
import type { RemoteConfig } from './remote-config.js';
import {
  ARC_APPROVAL_KEY,
  computeExecutionPayloadHash,
  deriveCanonicalPathTargets,
  extractArcApproval,
  extractPolicyTargets,
  buildReviewPayload,
  mostRestrictive,
  parsePatchTargetPaths,
  reduceDecisions,
  safeApprovalAuditMetadata,
  withArcApprovalSchema,
} from './approval-gate.js';
import {
  type CanonicalCompositePlan,
  computePlanHash,
  deepFreezePlan,
  validateStepAgainstRegistry,
  enterCompositeInvocation,
  executeCompositePlan,
  type DeterministicExecutionRegistry,
  createProductionDeterministicRegistry,
  createServerCompositeAdmissionTicket,
  runWithCompositeAdmissionTicket,
} from './composite-framework.js';
import { SERVER_INTERNAL_ACCESS } from './internal/server-seam.js';
import { createServerDeterministicExecutor } from './internal/execution-authority.js';
import type { TestCompositeHarness } from './internal/composite-testing.js';
import {
  handleArcRepoStatus,
  handleArcWorktreeStatus,
  DEFAULT_TASK2_TIMEOUT_MS,
} from './internal/repo-worktree-status.js';
import { handleArcReviewDiff, DEFAULT_TASK3_TIMEOUT_MS } from './internal/review-diff.js';
import {
  DEFAULT_TASK4_STEP_TIMEOUT_MS,
  DEFAULT_TASK4_AGGREGATE_TIMEOUT_MS,
  materializeArcVerifyPlan,
  projectArcVerifyResponse,
} from './internal/verify.js';
import {
  materializeArcTestPlan,
  projectArcTestResponse,
  validateTestFilter,
} from './internal/test.js';
import { handleArcCiStatus } from './internal/ci-status.js';
import { handleArcStageEvidence } from './internal/stage-evidence.js';
import {
  AuditLogger,
  computeSha256,
  canonicalJson,
  openAuditRuntime,
  type AuditConfig,
  type AuditHealthMetadata,
  type AuditRuntime,
} from '@cesspace-arc/audit';
import { FilesystemSubsystem } from '@cesspace-arc/filesystem';
import { GitSubsystem, MAX_DIFF_BYTES } from '@cesspace-arc/git';
import {
  ProcessRegistry,
  type IProcessLifecycleSink,
  type ProcessLifecycleEvent,
} from '@cesspace-arc/processes';
import {
  ControlledProcessRunner,
  type ITerminalSubsystem,
  type IInternalDeterministicExecutor,
} from '@cesspace-arc/terminal';
import { z } from 'zod';

export interface ArcServerConfig {
  /**
   * The single active transport mode for this process (§4 L-4).
   *
   * stdio and remote are MUTUALLY EXCLUSIVE: selecting 'remote' does not add a
   * listener beside stdio, it replaces it. RC-04 stdio semantics are unchanged
   * when 'stdio' is selected.
   */
  transport: 'stdio' | 'remote';
  /**
   * Remote gateway configuration. Required when transport is 'remote' and
   * ignored (never implicitly activated) when it is 'stdio'.
   */
  remote?: RemoteConfig;
  authorizedRoots: Array<{ id: string; path: string }>;
  defaultWorkspaceId?: string;
  stage?: string;
  /**
   * Trusted operator admin channel configuration.
   *
   * Both fields must be supplied together. Supplying exactly one fails server
   * startup rather than silently starting a partially configured admin access
   * path. When absent entirely, no admin listener is created.
   *
   * The endpoint is a local IPC path only; the operator public key is not a
   * secret and grants no authority without the corresponding private key.
   */
  admin?: {
    endpoint?: string;
    operatorPublicKeyB64?: string;
  };
  /**
   * Trusted external declarative policy configuration (RC-04 Task 4).
   *
   * The format is explicit and never sniffed from content. When supplied and
   * INVALID, the server fails closed: there is no fallback to the built-in
   * compatibility policy, and every non-health operation is refused.
   */
  policy?: {
    sourceText: string;
    format: 'json' | 'yaml';
  };
  /**
   * The durable RC-06 audit runtime configuration (rc06 §24.2).
   *
   * Auditing is MANDATORY in production: there is no `enabled` flag, and a
   * server composed without this field fails startup closed rather than serving
   * privileged work with no durable evidence.
   *
   * This is TRUSTED LAUNCH CONFIGURATION ONLY. It is supplied by the process
   * that constructs the server; it is never read from a command-line argument,
   * an environment variable, an MCP parameter, a remote header, or a request
   * body. It carries a PATH to the checkpoint signing key and never the key
   * itself.
   */
  audit?: AuditConfig;
}

/** Safe, non-sensitive reason the Layer-2 engine is unavailable. */
export interface PolicyInitializationFailure {
  /** Coarse category only. Never raw policy text, paths, or parser detail. */
  reason: 'POLICY_PARSE_ERROR' | 'POLICY_LOAD_ERROR';
}

const WorkspaceIdSchema = z
  .string()
  .max(128, 'workspaceId exceeds maximum allowed length of 128 characters')
  .trim()
  .min(1, 'workspaceId must not be empty or whitespace-only');

const WorkspaceRootSchema = z
  .string()
  .max(1024, 'workspaceRoot exceeds maximum allowed length of 1024 characters')
  .trim()
  .min(1, 'workspaceRoot must not be empty or whitespace-only');

const RelativePathSchema = z
  .string()
  .max(1024, 'path exceeds maximum allowed length of 1024 characters')
  .trim()
  .min(1, 'path must not be empty or whitespace-only');

const OptionalPathSchema = z
  .string()
  .max(1024, 'path exceeds maximum allowed length of 1024 characters')
  .trim()
  .min(1, 'path must not be empty or whitespace-only');

const SubPathSchema = z
  .string()
  .max(1024, 'subPath exceeds maximum allowed length of 1024 characters')
  .trim()
  .min(1, 'subPath must not be empty or whitespace-only');

const QuerySchema = z
  .string()
  .max(500, 'query exceeds maximum allowed length of 500 characters')
  .trim()
  .min(1, 'query must not be empty or whitespace-only');

const PatternSchema = z
  .string()
  .max(256, 'pattern exceeds maximum allowed length of 256 characters')
  .trim()
  .min(1, 'pattern must not be empty or whitespace-only');

const FilePatternSchema = z
  .string()
  .max(256, 'filePattern exceeds maximum allowed length of 256 characters')
  .trim()
  .min(1, 'filePattern must not be empty or whitespace-only');

const RevisionTargetSchema = z
  .string()
  .max(128, 'revision or target exceeds maximum allowed length of 128 characters')
  .trim()
  .min(1, 'revision or target must not be empty or whitespace-only');

const ExecutableSchema = z
  .string()
  .max(128, 'executable exceeds maximum allowed length of 128 characters')
  .trim()
  .min(1, 'executable must not be empty or whitespace-only');

const ProcessIdSchema = z
  .string()
  .max(128, 'processId exceeds maximum allowed length of 128 characters')
  .trim()
  .min(1, 'processId must not be empty or whitespace-only');

const CommandArgSchema = z
  .string()
  .max(1024, 'command argument exceeds maximum allowed length of 1024 characters');

const EnvKeySchema = z
  .string()
  .max(128, 'env key exceeds maximum allowed length of 128 characters')
  .trim()
  .min(1, 'env key must not be empty');

const EnvValueSchema = z
  .string()
  .max(512, 'env value exceeds maximum allowed length of 512 characters');

const FileContentSchema = z
  .string()
  .refine(
    (val) => Buffer.byteLength(val, 'utf8') <= 1024 * 1024,
    'content exceeds maximum allowed size of 1 MiB (1,048,576 bytes)',
  );

const PatchContentSchema = z
  .string()
  .refine((val) => val.trim().length > 0, 'patch must not be empty or whitespace-only')
  .refine(
    (val) => Buffer.byteLength(val, 'utf8') <= 512 * 1024,
    'patch exceeds maximum allowed size of 512 KiB (524,288 bytes)',
  );

const Sha256HashSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{64}$/, 'expectedHash must be a 64-character hexadecimal SHA-256 hash');

/**
 * Advertises the reserved `_arcApproval` control object on every registered MCP
 * tool, because Layer 2 may elevate ANY tool to REQUIRE_APPROVAL.
 *
 * The JSON schema is advisory to the client; the runtime Zod control schema in
 * approval-gate.ts remains authoritative, including the UTF-8 byte bound.
 */
function withArcApprovalSchemaOnTools(tools: Tool[]): Tool[] {
  return tools.map((tool) => ({
    ...tool,
    inputSchema: withArcApprovalSchema(
      tool.inputSchema as Record<string, unknown>,
    ) as Tool['inputSchema'],
  }));
}

/**
 * Strict Zod validation schemas for all permitted tools (RC-01 read-only + RC-02 controlled execution + RC-03 mutation).
 * Enforces runtime schema pre-admission rejection and audit logging.
 */
export const TOOL_SCHEMAS = {
  health: z.object({}).strict(),
  system_status: z.object({}).strict(),
  list_directory: z
    .object({
      path: OptionalPathSchema.optional(),
      recursive: z.boolean().optional(),
      maxDepth: z.number().int().min(1).max(5).optional(),
      includeHidden: z.boolean().optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  read_file: z
    .object({
      path: RelativePathSchema,
      offset: z.number().int().min(0).optional(),
      length: z.number().int().min(0).max(1048576).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  search_files: z
    .object({
      pattern: PatternSchema,
      subPath: SubPathSchema.optional(),
      maxResults: z.number().int().min(1).max(200).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  search_text: z
    .object({
      query: QuerySchema,
      isRegex: z.boolean().optional(),
      filePattern: FilePatternSchema.optional(),
      maxMatches: z.number().int().min(1).max(200).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  git_status: z
    .object({
      workspaceRoot: WorkspaceRootSchema.optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  git_diff: z
    .object({
      target: RevisionTargetSchema.optional(),
      path: OptionalPathSchema.optional(),
      cached: z.boolean().optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  git_log: z
    .object({
      maxCount: z.number().int().min(1).max(100).optional(),
      revision: RevisionTargetSchema.optional(),
      path: OptionalPathSchema.optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  run_command: z
    .object({
      executable: ExecutableSchema,
      args: z.array(CommandArgSchema).max(100).optional(),
      cwd: OptionalPathSchema.optional(),
      timeoutMs: z.number().int().min(100).max(300000).optional(),
      env: z.record(EnvKeySchema, EnvValueSchema).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
      runInBackground: z.boolean().optional(),
    })
    .strict(),
  process_status: z
    .object({
      processId: ProcessIdSchema,
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  process_output: z
    .object({
      processId: ProcessIdSchema,
      offset: z.number().int().min(0).optional(),
      stdoutCursor: z.number().int().min(0).optional(),
      stderrCursor: z.number().int().min(0).optional(),
      maxBytes: z.number().int().min(1).max(131072).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  terminate_process: z
    .object({
      processId: ProcessIdSchema,
      signal: z.enum(['SIGTERM', 'SIGKILL']).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  create_file: z
    .object({
      path: RelativePathSchema,
      content: FileContentSchema,
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  write_file: z
    .object({
      path: RelativePathSchema,
      content: FileContentSchema,
      expectedHash: Sha256HashSchema,
      overwrite: z.literal(true),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  delete_file: z
    .object({
      path: RelativePathSchema,
      expectedHash: Sha256HashSchema,
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  move_file: z
    .object({
      sourcePath: RelativePathSchema,
      destinationPath: RelativePathSchema,
      expectedSourceHash: Sha256HashSchema,
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  apply_patch: z
    .object({
      patch: PatchContentSchema,
      dryRun: z.boolean().optional(),
      fuzz: z.literal(0).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  arc_repo_status: z
    .object({
      workspaceId: WorkspaceIdSchema.optional(),
      workspaceRoot: WorkspaceRootSchema.optional(),
    })
    .strict(),
  arc_worktree_status: z
    .object({
      workspaceId: WorkspaceIdSchema.optional(),
      workspaceRoot: WorkspaceRootSchema.optional(),
    })
    .strict(),
  arc_review_diff: z
    .object({
      mode: z.enum(['staged', 'unstaged', 'target']).optional(),
      targetRevision: z.string().min(1).max(256).optional(),
      path: z.string().min(1).optional(),
      maxBytes: z.number().int().positive().max(MAX_DIFF_BYTES).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  arc_verify: z
    .object({
      suite: z.enum(['all', 'format', 'lint', 'typecheck', 'test']).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  arc_test: z
    .object({
      testPath: z.string().min(1).max(1024).optional(),
      filter: z.string().min(1).max(512).optional(),
      testRunner: z.literal('node').optional(),
      maxDurationMs: z.number().int().min(100).max(60000).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  arc_ci_status: z
    .object({
      workflowName: z.string().min(1).max(256).optional(),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
  arc_stage_evidence: z
    .object({
      targetStage: z.string().min(1).max(64),
      workspaceId: WorkspaceIdSchema.optional(),
    })
    .strict(),
} as const;

/**
 * Definition of the 4 RC-02 MCP Tools (controlled terminal & process execution).
 */
export const RC02_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'run_command',
    description:
      'Execute an approved command within an authorized workspace under policy control (executable allowlist, output bounded at 512 KiB, default-deny security kernel).',
    inputSchema: {
      type: 'object',
      properties: {
        executable: {
          type: 'string',
          description:
            'Basename of the executable to run (no path separators). Must be on the allowlist.',
        },
        args: {
          type: 'array',
          description: 'Array of argument strings (max 100). Each argument max 1024 characters.',
          items: { type: 'string' },
          maxItems: 100,
        },
        cwd: {
          type: 'string',
          description: 'Working directory relative path within the workspace root.',
        },
        timeoutMs: {
          type: 'integer',
          description: 'Execution timeout in milliseconds (100–300000, default: 30000).',
          minimum: 100,
          maximum: 300000,
        },
        env: {
          type: 'object',
          description: 'Optional extra environment variables (allowlisted keys only).',
          additionalProperties: { type: 'string' },
        },
        workspaceId: {
          type: 'string',
          description: 'Registered workspace ID.',
        },
        runInBackground: {
          type: 'boolean',
          description: 'If true, returns a processId immediately without waiting for completion.',
        },
      },
      required: ['executable'],
      additionalProperties: false,
    },
  },
  {
    name: 'process_status',
    description: 'Query the status of an ARC-managed process by its opaque process ID.',
    inputSchema: {
      type: 'object',
      properties: {
        processId: {
          type: 'string',
          description: 'Opaque ARC process identifier (arc-proc-*).',
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['processId'],
      additionalProperties: false,
    },
  },
  {
    name: 'process_output',
    description:
      'Read buffered stdout/stderr output from an ARC-managed process (max 128 KiB per read, 512 KiB total buffer).',
    inputSchema: {
      type: 'object',
      properties: {
        processId: {
          type: 'string',
          description: 'Opaque ARC process identifier (arc-proc-*).',
        },
        offset: {
          type: 'integer',
          description: 'Byte offset into the combined output buffer (legacy/fallback).',
          minimum: 0,
        },
        stdoutCursor: {
          type: 'integer',
          description: 'Independent byte cursor for the stdout stream.',
          minimum: 0,
        },
        stderrCursor: {
          type: 'integer',
          description: 'Independent byte cursor for the stderr stream.',
          minimum: 0,
        },
        maxBytes: {
          type: 'integer',
          description: 'Maximum bytes to return (max 131072).',
          minimum: 1,
          maximum: 131072,
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['processId'],
      additionalProperties: false,
    },
  },
  {
    name: 'terminate_process',
    description:
      'Send a termination signal to an ARC-managed process. Defaults to SIGTERM with a SIGKILL escalation after 1 second.',
    inputSchema: {
      type: 'object',
      properties: {
        processId: {
          type: 'string',
          description: 'Opaque ARC process identifier (arc-proc-*).',
        },
        signal: {
          type: 'string',
          description: 'Signal to send: SIGTERM (default) or SIGKILL.',
          enum: ['SIGTERM', 'SIGKILL'],
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['processId'],
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 5 RC-03 MCP Tools (file mutation primitives).
 * All invocations require explicit human approval and remain non-executable in RC-03.
 */
export const RC03_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'create_file',
    description:
      'Registered RC-03 file mutation capability to create a new regular file. Invocation requires explicit human approval and remains fail-closed until the approval execution workflow is available.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Workspace-relative path of the new file (max 1024 characters).',
        },
        content: {
          type: 'string',
          description: 'UTF-8 content of the file (max 1 MiB / 1,048,576 bytes).',
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['path', 'content'],
      additionalProperties: false,
    },
  },
  {
    name: 'write_file',
    description:
      'Registered RC-03 file mutation capability to update an existing regular file with hash-guarded overwrite. Invocation requires explicit human approval and remains fail-closed until the approval execution workflow is available.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Workspace-relative path of the file to overwrite (max 1024 characters).',
        },
        content: {
          type: 'string',
          description: 'New UTF-8 content for the file (max 1 MiB / 1,048,576 bytes).',
        },
        expectedHash: {
          type: 'string',
          description:
            'Required 64-character hexadecimal SHA-256 pre-modification hash of the file.',
        },
        overwrite: {
          type: 'boolean',
          description: 'Explicit overwrite acknowledgment (must be true).',
          enum: [true],
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['path', 'content', 'expectedHash', 'overwrite'],
      additionalProperties: false,
    },
  },
  {
    name: 'apply_patch',
    description:
      'Registered RC-03 file mutation capability to apply a bounded unified diff patch across existing workspace files. Invocation requires explicit human approval and remains fail-closed until the approval execution workflow is available.',
    inputSchema: {
      type: 'object',
      properties: {
        patch: {
          type: 'string',
          description:
            'Unified diff patch content in standard format (max 512 KiB / 524,288 bytes).',
        },
        dryRun: {
          type: 'boolean',
          description:
            'If true, simulates the patch in memory without modifying any files on disk.',
        },
        fuzz: {
          type: 'integer',
          description: 'Fuzz tolerance factor (must be exactly 0; fuzz matching is not supported).',
          enum: [0],
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['patch'],
      additionalProperties: false,
    },
  },
  {
    name: 'delete_file',
    description:
      'Registered RC-03 file mutation capability to remove an existing regular file with pre-deletion hash verification. Invocation requires explicit human approval and remains fail-closed until the approval execution workflow is available.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Workspace-relative path of the file to delete (max 1024 characters).',
        },
        expectedHash: {
          type: 'string',
          description: 'Required 64-character hexadecimal SHA-256 pre-deletion hash of the file.',
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['path', 'expectedHash'],
      additionalProperties: false,
    },
  },
  {
    name: 'move_file',
    description:
      'Registered RC-03 file mutation capability to perform a no-replace move/rename with source hash verification. Invocation requires explicit human approval and remains fail-closed until the approval execution workflow is available.',
    inputSchema: {
      type: 'object',
      properties: {
        sourcePath: {
          type: 'string',
          description:
            'Workspace-relative path of the existing file to move (max 1024 characters).',
        },
        destinationPath: {
          type: 'string',
          description: 'Workspace-relative destination path (must not exist; max 1024 characters).',
        },
        expectedSourceHash: {
          type: 'string',
          description: 'Required 64-character hexadecimal SHA-256 hash of the source file.',
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['sourcePath', 'destinationPath', 'expectedSourceHash'],
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 9 RC-01 MCP Tools.
 */
export const RC01_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'health',
    description: 'Check control plane readiness, active stage, and subsystem health.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'list_directory',
    description:
      'List entries within an authorized workspace directory (bounded depth, hides blacklisted secrets).',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Relative path within the workspace root (defaults to root).',
        },
        recursive: {
          type: 'boolean',
          description: 'Whether to traverse subdirectories recursively (default: false).',
        },
        maxDepth: {
          type: 'integer',
          description: 'Maximum recursion depth (1 to 5, default: 1).',
          minimum: 1,
          maximum: 5,
        },
        includeHidden: {
          type: 'boolean',
          description: 'Whether to include non-blacklisted hidden files (default: false).',
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'read_file',
    description:
      'Read file content within authorized workspace (max 1 MiB single read, pagination support, secret protection).',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Relative path of the file to read within the workspace.',
        },
        offset: {
          type: 'integer',
          description: 'Byte offset to begin reading from (default: 0).',
          minimum: 0,
        },
        length: {
          type: 'integer',
          description: 'Number of bytes to read (max: 1048576, default: 65536).',
          minimum: 0,
          maximum: 1048576,
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['path'],
      additionalProperties: false,
    },
  },
  {
    name: 'search_files',
    description:
      'Find file paths matching pattern within authorized workspace roots (max 200 matches).',
    inputSchema: {
      type: 'object',
      properties: {
        pattern: {
          type: 'string',
          description: 'Filename pattern or glob to search for.',
        },
        subPath: {
          type: 'string',
          description: 'Optional sub-directory to restrict search within.',
        },
        maxResults: {
          type: 'integer',
          description: 'Maximum number of results to return (default: 50, max: 200).',
          minimum: 1,
          maximum: 200,
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['pattern'],
      additionalProperties: false,
    },
  },
  {
    name: 'search_text',
    description:
      'Search text or regex within workspace files (ReDoS protected, skips binaries and secrets).',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Text string or regex pattern to search for.',
        },
        isRegex: {
          type: 'boolean',
          description: 'Treat query as a regular expression (default: false).',
        },
        filePattern: {
          type: 'string',
          description: 'Optional file glob pattern to filter searched files.',
        },
        maxMatches: {
          type: 'integer',
          description: 'Maximum number of matches to return (default: 50, max: 200).',
          minimum: 1,
          maximum: 200,
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    name: 'git_status',
    description:
      'Inspect Git working tree status (branch, clean/dirty, staged/unstaged/untracked).',
    inputSchema: {
      type: 'object',
      properties: {
        workspaceRoot: {
          type: 'string',
          description: 'Optional workspace path or ID.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'git_diff',
    description: 'Inspect Git diff with buffer bounds (max 512 KiB) and secret masking.',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'Target commit or ref (e.g. HEAD, HEAD~1). Must not begin with "-".',
        },
        path: {
          type: 'string',
          description: 'Optional relative path to filter diff.',
        },
        cached: {
          type: 'boolean',
          description: 'Inspect staged changes only (--cached).',
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'git_log',
    description:
      'Read recent commit history with parameter injection protection (max 100 commits).',
    inputSchema: {
      type: 'object',
      properties: {
        maxCount: {
          type: 'integer',
          description: 'Maximum number of commits to retrieve (default: 10, max: 100).',
          minimum: 1,
          maximum: 100,
        },
        revision: {
          type: 'string',
          description: 'Starting commit ref/branch. Must not begin with "-".',
        },
        path: {
          type: 'string',
          description: 'Optional relative path to filter log.',
        },
        workspaceId: {
          type: 'string',
          description: 'Optional registered workspace ID.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'system_status',
    description:
      'Inspect host runtime health and sanitized OS metrics (no hostnames, IPs, or env vars).',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 2 RC-07 Task-2 MCP Tools (repository and worktree status).
 * Only these two tools are advertised from RC-07; the other 5 remain unexposed until their owning tasks.
 */
export const RC07_TASK2_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'arc_repo_status',
    description:
      'Provide a bounded, structured repository status summary for the active workspace, including branch identity, HEAD commit details, clean/dirty state, file change counts, and protected-branch awareness.',
    inputSchema: {
      type: 'object',
      properties: {
        workspaceId: {
          type: 'string',
          description: 'Authorized workspace identifier (optional).',
        },
        workspaceRoot: {
          type: 'string',
          description: 'Authorized workspace root directory path (optional).',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'arc_worktree_status',
    description:
      'Provide bounded worktree status for isolated agent environments, confirming worktree isolation, main repository linkage, branch binding, and lock state without arbitrary filesystem traversal.',
    inputSchema: {
      type: 'object',
      properties: {
        workspaceId: {
          type: 'string',
          description: 'Authorized workspace identifier (optional).',
        },
        workspaceRoot: {
          type: 'string',
          description: 'Authorized workspace root directory path (optional).',
        },
      },
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 1 RC-07 Task-3 MCP Tool (review diff).
 * Advertised as tool #21 in production tool discovery.
 */
export const RC07_TASK3_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'arc_review_diff',
    description:
      'Provide a bounded, structured review diff for the active workspace, including changed file summaries, insertions/deletions, and automatic redaction of sensitive credentials and private keys.',
    inputSchema: {
      type: 'object',
      properties: {
        mode: {
          type: 'string',
          enum: ['staged', 'unstaged', 'target'],
          description:
            "Review diff mode ('staged', 'unstaged', or 'target'). Defaults to 'unstaged'.",
        },
        targetRevision: {
          type: 'string',
          description:
            'Target Git revision to compare against (required in target mode, optional in staged mode).',
        },
        path: {
          type: 'string',
          description: 'Authorized workspace-relative path filter (optional).',
        },
        maxBytes: {
          type: 'integer',
          minimum: 1,
          maximum: 524288,
          description: 'Maximum diff payload size budget in bytes (up to 524,288 bytes / 512 KiB).',
        },
        workspaceId: {
          type: 'string',
          description: 'Authorized workspace identifier (optional).',
        },
      },
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 1 RC-07 Task-4 MCP Tool (verification).
 * Advertised as tool #22 in production tool discovery.
 */
export const RC07_TASK4_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'arc_verify',
    description:
      'Execute deterministic engineering verification suite (format, lint, typecheck, test) in an isolated, check-only environment.',
    inputSchema: {
      type: 'object',
      properties: {
        suite: {
          type: 'string',
          enum: ['all', 'format', 'lint', 'typecheck', 'test'],
          description:
            "Verification suite to run ('all', 'format', 'lint', 'typecheck', 'test'). Defaults to 'all'.",
        },
        workspaceId: {
          type: 'string',
          description: 'Authorized workspace identifier (optional).',
        },
      },
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 1 RC-07 Task-5 MCP Tool (testing).
 * Advertised as tool #23 in production tool discovery.
 */
export const RC07_TASK5_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'arc_test',
    description:
      'Execute tests using the kernel-bound Node test runner with deterministic arguments and structured TAP reporting under policy control.',
    inputSchema: {
      type: 'object',
      properties: {
        testPath: {
          type: 'string',
          description:
            'Workspace-relative path to a test file or directory (optional, defaults to workspace test discovery).',
        },
        filter: {
          type: 'string',
          description: 'Test name pattern filter (optional).',
        },
        testRunner: {
          type: 'string',
          enum: ['node'],
          description: "Test runner to execute (strictly 'node', defaults to 'node').",
        },
        maxDurationMs: {
          type: 'integer',
          minimum: 100,
          maximum: 60000,
          description:
            'Maximum execution duration in milliseconds (100 to 60000, defaults to 60000).',
        },
        workspaceId: {
          type: 'string',
          description: 'Authorized workspace identifier (optional).',
        },
      },
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 1 RC-07 Task-6 MCP Tool (CI status inspection).
 * Advertised as tool #24 in production tool discovery.
 */
export const RC07_TASK6_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'arc_ci_status',
    description:
      'Inspect local CI workflow definitions and repository readiness without network access or remote CI queries.',
    inputSchema: {
      type: 'object',
      properties: {
        workflowName: {
          type: 'string',
          description: 'Logical workflow name to filter by (optional).',
        },
        workspaceId: {
          type: 'string',
          description: 'Authorized workspace identifier (optional).',
        },
      },
      additionalProperties: false,
    },
  },
]);

/**
 * Definition of the 1 RC-07 Task-7 MCP Tool (stage evidence aggregation).
 * Advertised as tool #25 in production tool discovery.
 */
export const RC07_TASK7_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  {
    name: 'arc_stage_evidence',
    description:
      'Aggregate local machine-verifiable evidence for a release stage without synthesizing human or governance approval.',
    inputSchema: {
      type: 'object',
      properties: {
        targetStage: {
          type: 'string',
          description: 'Target development or release stage name (e.g., RC-00 through RC-07).',
        },
        workspaceId: {
          type: 'string',
          description: 'Authorized workspace identifier (optional).',
        },
      },
      required: ['targetStage'],
      additionalProperties: false,
    },
  },
]);

/**
 * Authoritative complete list of all 25 registered tools (RC-01 + RC-02 + RC-03 + RC-07 Tasks 2, 3, 4, 5, 6, 7).
 * Used directly by the ListTools handler.
 */
export const ALL_TOOL_DEFINITIONS: Tool[] = withArcApprovalSchemaOnTools([
  ...RC01_TOOL_DEFINITIONS,
  ...RC02_TOOL_DEFINITIONS,
  ...RC03_TOOL_DEFINITIONS,
  ...RC07_TASK2_TOOL_DEFINITIONS,
  ...RC07_TASK3_TOOL_DEFINITIONS,
  ...RC07_TASK4_TOOL_DEFINITIONS,
  ...RC07_TASK5_TOOL_DEFINITIONS,
  ...RC07_TASK6_TOOL_DEFINITIONS,
  ...RC07_TASK7_TOOL_DEFINITIONS,
]);

/**
 * The authoritative set of REGISTERED MCP tool names.
 *
 * Derived from {@link ALL_TOOL_DEFINITIONS} rather than maintained beside it, so
 * the catalog a caller sees from `tools/list` and the catalog this process will
 * execute are the same object. There is no second list to drift and no
 * name-specific rule anywhere: a name is executable if and only if it is in
 * this set.
 */
const REGISTERED_TOOL_NAMES: ReadonlySet<string> = new Set(
  ALL_TOOL_DEFINITIONS.map((tool) => tool.name),
);

/**
 * True when `name` is a registered MCP tool.
 *
 * Deliberately GENERIC. This is not a denylist of administrative or otherwise
 * sensitive names: it is the positive membership test against the one
 * registered catalog, so a name that is not a tool is not callable regardless
 * of what it is called or who calls it.
 */
function isRegisteredToolName(name: string): boolean {
  return REGISTERED_TOOL_NAMES.has(name);
}

/**
 * The single JSON-RPC error for a `tools/call` naming an unregistered tool.
 *
 * Identical — code AND message — to the error the SDK itself returns for an
 * unregistered JSON-RPC METHOD. An unknown tool name is therefore
 * indistinguishable from an unknown method name: a caller cannot probe which
 * names exist, and no administrative or otherwise sensitive name is confirmed
 * or denied by the shape of the answer.
 *
 * Thrown from the `CallToolRequestSchema` boundary, BEFORE the shared execution
 * pipeline is entered, so no policy evaluation, approval state, or subsystem
 * call is ever reached for such a call. The HTTP admission a remote request
 * already paid for at the transport is unaffected and is not refunded: the gate
 * adds no accounting of its own and changes no rate or concurrency semantics.
 */
function unknownToolError(): McpError {
  return new McpError(ErrorCode.MethodNotFound, 'Method not found');
}

/**
 * Rebuilds one MCP tool result as a fresh object.
 *
 * The SDK's `CallToolResult` union is only assignable from an anonymous object
 * type, because an `interface` does not receive an implicit index signature.
 * Normalizing here keeps the remote tool path returning exactly the same shape
 * the shared stdio pipeline returns, with no cast anywhere.
 */
function remoteToolResult(result: {
  isError?: boolean;
  content: Array<{ type: 'text'; text: string }>;
}): { isError?: boolean; content: Array<{ type: 'text'; text: string }> } {
  return result.isError === undefined
    ? { content: result.content }
    : { isError: result.isError, content: result.content };
}

export interface IArcMcpServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  flushAudit(): Promise<void>;
  dispatchToolCall(
    toolName: string,
    parameters: Record<string, unknown>,
    actorOverride?: Partial<PolicyEvaluationContext['actor']>,
  ): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }>;
}

/**
 * Raised when a denial could not be made durable.
 *
 * Module-private on purpose. It is never exported, so no subsystem, transport,
 * CLI path or test can construct one, and `instanceof` at the single conversion
 * point in {@link ArcMcpServer.executeAuthenticatedToolCall} cannot be satisfied
 * by anything but a real failed durable `DENIED` append.
 *
 * It carries the already-bounded refusal. It never carries the raw cause: an
 * `fs` error, a directory, a key path, an inode or a device number added to it,
 * or read out of it, would be a leak with no security value.
 */
class AuditPersistenceFailure extends Error {
  constructor(public readonly refusal: ArcError) {
    super('a durable audit denial could not be recorded');
    this.name = 'AuditPersistenceFailure';
  }
}

export class ProcessAuditSink implements IProcessLifecycleSink {
  /**
   * The ONE production write authority for this chain.
   *
   * It is derived from the logger the composition root handed in, so a process
   * lifecycle record lands in the same persistent primary sequence as the tool
   * invocation that spawned it — rather than appearing only on the historical
   * in-memory chain, where it would vanish on restart.
   */
  private readonly authority: AuditWriteAuthority;

  constructor(
    auditLogger: AuditLogger,
    private workspaceRegistry: WorkspaceRegistry,
  ) {
    this.authority = getAuditWriteAuthority(auditLogger);
  }

  public async onProcessEvent(event: ProcessLifecycleEvent): Promise<void> {
    const ws = this.workspaceRegistry.getWorkspace(event.workspaceId);
    const workspacePath = ws ? ws.rootPath : '';

    const isFailure = event.eventType === 'PROCESS_SPAWN_FAILED';
    const isTimeout = event.eventType === 'PROCESS_TIMEOUT';

    await this.authority.write({
      timestamp: event.timestamp,
      actor: {
        clientId: event.actor.clientId,
        clientType: event.actor.clientType || 'mcp-client',
        deviceId: event.actor.deviceId || 'local-machine',
        sessionId: event.actor.sessionId,
      },
      target: {
        workspaceId: event.workspaceId,
        workspacePath,
      },
      invocation: {
        toolName: event.eventType,
        parametersRedacted: {
          eventType: event.eventType,
          processId: event.processId,
          executable: event.executable,
          ...(event.signal ? { signal: event.signal } : {}),
          ...(typeof event.exitCode === 'number' ? { exitCode: event.exitCode } : {}),
          ...(typeof event.durationMs === 'number' ? { durationMs: event.durationMs } : {}),
          ...(event.error ? { error: event.error } : {}),
        },
        payloadHash: computeSha256(
          canonicalJson({ processId: event.processId, eventType: event.eventType }),
        ),
      },
      policy: {
        decision: 'ALLOW',
        ruleId: 'process-lifecycle-event',
        evaluationDurationMs: 0,
      },
      execution: {
        status: isFailure ? 'ERROR' : isTimeout ? 'TIMEOUT' : 'SUCCESS',
        startTime: event.timestamp,
        endTime: event.timestamp,
        durationMs: event.durationMs || 0,
        exitCode: typeof event.exitCode === 'number' ? event.exitCode : undefined,
      },
      error: event.error ? { code: 'PROCESS_ERROR', message: event.error } : undefined,
    });
  }
}

/**
 * Safely sanitizes path parameters for audit logging.
 * Rejects hostile paths (absolute paths, traversals, null bytes) and records only safe metadata.
 */
export function sanitizePathForAudit(candidate: unknown): unknown {
  if (typeof candidate !== 'string') {
    return { pathType: typeof candidate, pathOmitted: true };
  }
  const trimmed = candidate.trim();
  if (
    trimmed.includes('\0') ||
    trimmed.startsWith('/') ||
    trimmed.startsWith('\\') ||
    /^[a-zA-Z]:[/\\]/.test(trimmed) ||
    trimmed.split(/[/\\]/).includes('..') ||
    trimmed.length > 1024
  ) {
    return {
      pathLength: candidate.length,
      pathOmitted: true,
    };
  }
  return trimmed;
}

/**
 * Authoritative mutation audit sanitizer implementing strict data minimization.
 * Ensures raw content, raw patches, patch context, and hostile paths NEVER enter audit records.
 */
export function sanitizeMutationAuditParameters(
  toolName: string,
  parameters: Record<string, unknown>,
): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};

  if (toolName === 'create_file') {
    sanitized.path = sanitizePathForAudit(parameters.path);
    sanitized.contentBytes =
      typeof parameters.content === 'string'
        ? Buffer.byteLength(parameters.content, 'utf8')
        : parameters.content !== undefined
          ? { contentType: typeof parameters.content }
          : undefined;
    if (typeof parameters.workspaceId === 'string') {
      sanitized.workspaceId = parameters.workspaceId;
    }
  } else if (toolName === 'write_file') {
    sanitized.path = sanitizePathForAudit(parameters.path);
    sanitized.contentBytes =
      typeof parameters.content === 'string'
        ? Buffer.byteLength(parameters.content, 'utf8')
        : parameters.content !== undefined
          ? { contentType: typeof parameters.content }
          : undefined;
    if (
      typeof parameters.expectedHash === 'string' &&
      /^[0-9a-fA-F]{64}$/.test(parameters.expectedHash)
    ) {
      sanitized.expectedHash = parameters.expectedHash;
    } else if (parameters.expectedHash !== undefined) {
      sanitized.expectedHashProvided = true;
    }
    if (parameters.overwrite !== undefined) {
      sanitized.overwrite = parameters.overwrite;
    }
    if (typeof parameters.workspaceId === 'string') {
      sanitized.workspaceId = parameters.workspaceId;
    }
  } else if (toolName === 'delete_file') {
    sanitized.path = sanitizePathForAudit(parameters.path);
    if (
      typeof parameters.expectedHash === 'string' &&
      /^[0-9a-fA-F]{64}$/.test(parameters.expectedHash)
    ) {
      sanitized.expectedHash = parameters.expectedHash;
    } else if (parameters.expectedHash !== undefined) {
      sanitized.expectedHashProvided = true;
    }
    if (typeof parameters.workspaceId === 'string') {
      sanitized.workspaceId = parameters.workspaceId;
    }
  } else if (toolName === 'move_file') {
    sanitized.sourcePath = sanitizePathForAudit(parameters.sourcePath);
    sanitized.destinationPath = sanitizePathForAudit(parameters.destinationPath);
    if (
      typeof parameters.expectedSourceHash === 'string' &&
      /^[0-9a-fA-F]{64}$/.test(parameters.expectedSourceHash)
    ) {
      sanitized.expectedSourceHash = parameters.expectedSourceHash;
    } else if (parameters.expectedSourceHash !== undefined) {
      sanitized.expectedSourceHashProvided = true;
    }
    if (typeof parameters.workspaceId === 'string') {
      sanitized.workspaceId = parameters.workspaceId;
    }
  } else if (toolName === 'apply_patch') {
    sanitized.patchBytes =
      typeof parameters.patch === 'string'
        ? Buffer.byteLength(parameters.patch, 'utf8')
        : parameters.patch !== undefined
          ? { patchType: typeof parameters.patch }
          : undefined;
    if (typeof parameters.dryRun === 'boolean') {
      sanitized.dryRun = parameters.dryRun;
    }
    if (typeof parameters.fuzz === 'number') {
      sanitized.fuzz = parameters.fuzz;
    }
    if (typeof parameters.workspaceId === 'string') {
      sanitized.workspaceId = parameters.workspaceId;
    }
  }

  // Record extra property count if any were supplied (no attacker keys stored)
  const knownPropertyMap: Record<string, Set<string>> = {
    create_file: new Set(['path', 'content', 'workspaceId']),
    write_file: new Set(['path', 'content', 'expectedHash', 'overwrite', 'workspaceId']),
    delete_file: new Set(['path', 'expectedHash', 'workspaceId']),
    move_file: new Set(['sourcePath', 'destinationPath', 'expectedSourceHash', 'workspaceId']),
    apply_patch: new Set(['patch', 'dryRun', 'fuzz', 'workspaceId']),
  };
  const knownKeys = knownPropertyMap[toolName];
  if (knownKeys) {
    const extraKeys = Object.keys(parameters).filter((k) => !knownKeys.has(k));
    if (extraKeys.length > 0) {
      sanitized.extraPropertyCount = extraKeys.length;
    }
  }

  return sanitized;
}

/**
 * Dedicated pre-validation mutation sanitizer for audit logging.
 * When a mutation request fails schema admission, this ensures arbitrary raw user strings
 * (malformed paths, unknown property names, content, patches, workspace IDs, hash strings)
 * are NEVER stored in audit logs.
 * Records ONLY safe facts: property counts and metadata types/lengths.
 */
export function sanitizePreValidationMutationParameters(
  toolName: string,
  parameters: Record<string, unknown>,
): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {
    propertyCount: Object.keys(parameters).length,
  };

  const knownPropertyMap: Record<string, Set<string>> = {
    create_file: new Set(['path', 'content', 'workspaceId']),
    write_file: new Set(['path', 'content', 'expectedHash', 'overwrite', 'workspaceId']),
    delete_file: new Set(['path', 'expectedHash', 'workspaceId']),
    move_file: new Set(['sourcePath', 'destinationPath', 'expectedSourceHash', 'workspaceId']),
    apply_patch: new Set(['patch', 'dryRun', 'fuzz', 'workspaceId']),
  };

  const knownKeys = knownPropertyMap[toolName] || new Set();
  const extraPropertyCount = Object.keys(parameters).filter((k) => !knownKeys.has(k)).length;
  if (extraPropertyCount > 0) {
    sanitized.extraPropertyCount = extraPropertyCount;
  }

  if (parameters.path !== undefined) {
    sanitized.pathType = typeof parameters.path;
    if (typeof parameters.path === 'string') {
      sanitized.pathLength = parameters.path.length;
    }
  }

  if (parameters.sourcePath !== undefined) {
    sanitized.sourcePathType = typeof parameters.sourcePath;
    if (typeof parameters.sourcePath === 'string') {
      sanitized.sourcePathLength = parameters.sourcePath.length;
    }
  }

  if (parameters.destinationPath !== undefined) {
    sanitized.destinationPathType = typeof parameters.destinationPath;
    if (typeof parameters.destinationPath === 'string') {
      sanitized.destinationPathLength = parameters.destinationPath.length;
    }
  }

  if (parameters.content !== undefined) {
    sanitized.contentType = typeof parameters.content;
    if (typeof parameters.content === 'string') {
      sanitized.contentBytes = Buffer.byteLength(parameters.content, 'utf8');
    }
  }

  if (parameters.patch !== undefined) {
    sanitized.patchType = typeof parameters.patch;
    if (typeof parameters.patch === 'string') {
      sanitized.patchBytes = Buffer.byteLength(parameters.patch, 'utf8');
    }
  }

  if (parameters.expectedHash !== undefined) {
    sanitized.expectedHashType = typeof parameters.expectedHash;
    if (typeof parameters.expectedHash === 'string') {
      sanitized.expectedHashLength = parameters.expectedHash.length;
    }
  }

  if (parameters.expectedSourceHash !== undefined) {
    sanitized.expectedSourceHashType = typeof parameters.expectedSourceHash;
    if (typeof parameters.expectedSourceHash === 'string') {
      sanitized.expectedSourceHashLength = parameters.expectedSourceHash.length;
    }
  }

  if (parameters.overwrite !== undefined) {
    sanitized.overwriteType = typeof parameters.overwrite;
  }

  if (parameters.dryRun !== undefined) {
    sanitized.dryRunType = typeof parameters.dryRun;
  }

  if (parameters.fuzz !== undefined) {
    sanitized.fuzzType = typeof parameters.fuzz;
  }

  if (parameters.workspaceId !== undefined) {
    sanitized.workspaceIdType = typeof parameters.workspaceId;
    if (typeof parameters.workspaceId === 'string') {
      sanitized.workspaceIdLength = parameters.workspaceId.length;
    }
  }

  return sanitized;
}

/**
 * Sanitizes parameters prior to schema validation for audit logging.
 * Ensures raw arguments, environment values, and secrets are never stored in audit logs.
 */
export function sanitizePreValidationParameters(
  toolName: string,
  parameters: Record<string, unknown>,
): Record<string, unknown> {
  if (toolName === 'run_command') {
    const sanitized: Record<string, unknown> = {};

    // Executable: retain only safe alphanumeric/dash string without path separators
    if (
      typeof parameters.executable === 'string' &&
      /^[a-zA-Z0-9_.-]+$/.test(parameters.executable)
    ) {
      sanitized.executable = parameters.executable;
    } else if (parameters.executable !== undefined) {
      sanitized.executable = `[UNSAFE_OR_NON_STRING_EXECUTABLE: ${typeof parameters.executable}]`;
    }

    // Args: retain ONLY argCount, argument types, and recognized safe flags (--version, -v, --help, -h)
    // Never store raw argument values!
    if (Array.isArray(parameters.args)) {
      const safeFlags = parameters.args.filter(
        (a) => typeof a === 'string' && /^(-v|--version|-h|--help)$/.test(a),
      );
      sanitized.args = {
        argCount: parameters.args.length,
        argTypes: parameters.args.map((a) => typeof a),
        safeFlags,
      };
    } else if (parameters.args !== undefined) {
      sanitized.args = { argType: typeof parameters.args };
    }

    // Env: env key names only, NEVER env values
    if (parameters.env && typeof parameters.env === 'object' && !Array.isArray(parameters.env)) {
      sanitized.envKeys = Object.keys(parameters.env);
    } else if (parameters.env !== undefined) {
      sanitized.env = `[INVALID_ENV_TYPE: ${typeof parameters.env}]`;
    }

    // Safe metadata
    if (typeof parameters.workspaceId === 'string') {
      sanitized.workspaceId = parameters.workspaceId;
    }
    if (typeof parameters.cwd === 'string') {
      sanitized.cwd = parameters.cwd;
    }
    if (typeof parameters.timeoutMs === 'number') {
      sanitized.timeoutMs = parameters.timeoutMs;
    }
    if (typeof parameters.runInBackground === 'boolean') {
      sanitized.runInBackground = parameters.runInBackground;
    }

    // If extra properties were provided, record only their key names
    const knownKeys = new Set([
      'executable',
      'args',
      'cwd',
      'timeoutMs',
      'env',
      'workspaceId',
      'runInBackground',
    ]);
    const extraKeys = Object.keys(parameters).filter((k) => !knownKeys.has(k));
    if (extraKeys.length > 0) {
      sanitized.extraPropertyKeys = extraKeys;
    }

    return sanitized;
  }

  // Mutation tools: authoritative pre-validation data minimization
  if ((RC03_MUTATION_TOOLS as readonly string[]).includes(toolName)) {
    return sanitizePreValidationMutationParameters(toolName, parameters);
  }

  // Generic sanitizer for other tools: scrub raw args/env objects
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(parameters)) {
    if (key === 'env' && typeof value === 'object' && value !== null) {
      sanitized.envKeys = Object.keys(value);
    } else if (key === 'args' && Array.isArray(value)) {
      sanitized.argCount = value.length;
    } else if (typeof value === 'string' && value.length > 256) {
      sanitized[key] = `[STRING_EXCEEDS_LENGTH_BOUND: ${value.length} chars]`;
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

export class ArcMcpServer implements IArcMcpServer {
  private server: Server;
  private transport?: StdioServerTransport;
  /** Remote TLS admission gateway. Present only in remote mode. */
  private remoteGateway?: RemoteGateway;
  /** Immutable transport mode for this process. */
  private readonly transportMode: 'stdio' | 'remote';
  /** Remote configuration, retained only in remote mode. */
  private readonly remoteConfig?: RemoteConfig;
  private defaultWorkspaceId?: string;
  public processRegistry?: ProcessRegistry;
  /** Approval state manager. Always present; a fresh one is created if not injected. */
  public readonly approvalStateManager: ApprovalStateManager;
  /**
   * Bounded lifecycle audit sink. Buffers safe lifecycle events emitted by the
   * state machine and flushes them into the one existing audit hash chain.
   */
  public readonly approvalAuditSink: ApprovalAuditSink;
  /** Immutable effective Layer-2 policy engine. Undefined only on fail-closed init. */
  public readonly effectivePolicyEngine?: DeclarativePolicyEngine;
  /** Safe failure category when an explicitly configured policy was invalid. */
  public readonly policyInitializationFailure?: PolicyInitializationFailure;
  /**
   * The ONE pending-enrollment authority for this process (RC-05 Task 4).
   *
   * Always present. When an admin IPC channel is composed in, this IS that
   * channel's manager — the constructor adopts it or refuses the composition —
   * so the object the remote gateway completes against is provably the same
   * object the operator channel creates challenges in.
   */
  public readonly enrollmentManager: EnrollmentManager;
  /**
   * The ONE process-local session authority (RC-05 Task 6).
   *
   * Volatile, process-local, and never configured: the frozen TTLs, quotas, and
   * header contract are not overridable through ArcServerConfig, the
   * environment, the CLI, or any network input. Task 8 consumes THIS object for
   * session issuance and request authentication, so there is no second manager
   * hidden in a transport adapter.
   */
  public readonly sessionManager: SessionManager;
  /** Remote execution bridge. Present only once a remote gateway is bound. */
  private remoteExecutionBridge?: RemoteExecutionBridge;
  /**
   * The ONE process-local Layer C limiter and per-session concurrency state
   * (RC-05 Task 7).
   *
   * Volatile and process-local: the frozen 300/min, burst 60, 1024-key ceiling,
   * and 4-outstanding-request bound are not overridable through ArcServerConfig,
   * the environment, the CLI, or any network input. It is reset on shutdown, so
   * a restart gets a clean rate and concurrency state and nothing is persisted.
   */
  private readonly authenticatedRequestLimiter: BoundedRequestLimiter;
  /**
   * The ONE authoritative durable audit runtime for this process (RC-06 Task 6).
   *
   * Present only between a successful `start()` audit startup and `stop()`. The
   * persistent chain it owns is the DURABLE EXECUTION AUTHORITY: every
   * privileged operation's STARTED and terminal records, every denial, every
   * rotation checkpoint and every anchor handoff flow through this one object.
   * There is no second persistent chain, no per-transport chain, and no way to
   * reach the store except through it.
   */
  private auditRuntime?: AuditRuntime;
  /** Trusted launch configuration for {@link auditRuntime}. */
  private readonly auditConfig?: AuditConfig;
  /** Test-only composite framework harness (RC-07 Task 1). */
  #testCompositeHarness?: TestCompositeHarness;
  /** Privileged internal deterministic execution capability (RC-07 Task 1). */
  #internalDeterministicExecutor?: IInternalDeterministicExecutor;
  /** Authoritative closed deterministic execution registry (RC-07 Task 1). */
  #deterministicRegistry: DeterministicExecutionRegistry;
  /** Aggregate execution timeout ceiling for Task-2 read-only tools. */
  #task2TimeoutMs: number;
  /** Aggregate execution timeout ceiling for Task-3 read-only tools. */
  #task3TimeoutMs: number;
  /** Per-step execution timeout ceiling for Task-4 verification steps. */
  #task4StepTimeoutMs: number;
  /** Aggregate execution timeout ceiling for Task-4 verification suite. */
  #task4AggregateTimeoutMs: number;

  constructor(
    public readonly workspaceRegistry: WorkspaceRegistry,
    public readonly securityKernel: SecurityKernel,
    public readonly auditLogger: AuditLogger,
    public readonly filesystemSubsystem: FilesystemSubsystem,
    public readonly gitSubsystem: GitSubsystem,
    config?: Partial<ArcServerConfig>,
    public readonly terminalSubsystem?: ITerminalSubsystem,
    processRegistry?: ProcessRegistry,
    /**
     * Optional approval state manager. Composition only: Task 3 does not route
     * MCP requests through it, and MCP mutations still execute nothing.
     */
    approvalStateManager?: ApprovalStateManager,
    /**
     * Optional authenticated local admin channel. Started only when trusted
     * launch configuration supplies both an endpoint and an operator key.
     */
    public readonly adminIpcServer?: AdminIpcServer,
    /**
     * The ONE pending-enrollment authority for this process (RC-05 Task 4).
     *
     * The authenticated local admin IPC channel creates and cancels pending
     * challenges through it, and the remote bootstrap endpoint completes them
     * through the SAME object. There is exactly one instance per process: no
     * copy, no synchronization, no second remote manager, and no persistence of
     * pending challenges, which stay volatile and die with the process.
     *
     * This is not merely a convention: when an admin channel is composed in, the
     * constructor ADOPTS or VERIFIES its manager, so an invalid composition
     * cannot reach a running state.
     */
    enrollmentManager?: EnrollmentManager,
    /**
     * Optional session authority injection for deterministic and integration
     * tests. NOT reachable from ArcServerConfig, the environment, the CLI, or
     * any network input: the factory always supplies exactly one instance, and a
     * server constructed without one creates it here.
     */
    sessionManager?: SessionManager,
  ) {
    this.#deterministicRegistry = createProductionDeterministicRegistry();
    this.#task2TimeoutMs = DEFAULT_TASK2_TIMEOUT_MS;
    this.#task3TimeoutMs = DEFAULT_TASK3_TIMEOUT_MS;
    this.#task4StepTimeoutMs = DEFAULT_TASK4_STEP_TIMEOUT_MS;
    this.#task4AggregateTimeoutMs = DEFAULT_TASK4_AGGREGATE_TIMEOUT_MS;
    if (terminalSubsystem && terminalSubsystem instanceof ControlledProcessRunner) {
      this.#internalDeterministicExecutor = createServerDeterministicExecutor(terminalSubsystem);
    }
    SERVER_INTERNAL_ACCESS.set(this, {
      setTestCompositeHarness: (harness) => {
        this.#testCompositeHarness = harness;
      },
      getTestCompositeHarness: () => this.#testCompositeHarness,
      setInternalDeterministicExecutor: (executor) => {
        this.#internalDeterministicExecutor = executor;
      },
      getInternalDeterministicExecutor: () => this.#internalDeterministicExecutor,
      setDeterministicRegistry: (registry) => {
        this.#deterministicRegistry = registry;
      },
      getDeterministicRegistry: () => this.#deterministicRegistry,
      setTask2TimeoutMs: (timeoutMs: number) => {
        if (
          typeof timeoutMs !== 'number' ||
          !Number.isFinite(timeoutMs) ||
          Number.isNaN(timeoutMs)
        ) {
          throw new TypeError('Task-2 timeout must be a finite number.');
        }
        if (timeoutMs <= 0) {
          throw new RangeError(`Task-2 timeout must be > 0 ms (got ${timeoutMs}).`);
        }
        if (timeoutMs > DEFAULT_TASK2_TIMEOUT_MS) {
          throw new RangeError(
            `Task-2 timeout cannot exceed frozen maximum of ${DEFAULT_TASK2_TIMEOUT_MS} ms (got ${timeoutMs}).`,
          );
        }
        this.#task2TimeoutMs = timeoutMs;
      },
      getTask2TimeoutMs: () => this.#task2TimeoutMs,
      setTask3TimeoutMs: (timeoutMs: number) => {
        if (
          typeof timeoutMs !== 'number' ||
          !Number.isFinite(timeoutMs) ||
          Number.isNaN(timeoutMs)
        ) {
          throw new TypeError('Task-3 timeout must be a finite number.');
        }
        if (timeoutMs <= 0) {
          throw new RangeError(`Task-3 timeout must be > 0 ms (got ${timeoutMs}).`);
        }
        if (timeoutMs > DEFAULT_TASK3_TIMEOUT_MS) {
          throw new RangeError(
            `Task-3 timeout cannot exceed frozen maximum of ${DEFAULT_TASK3_TIMEOUT_MS} ms (got ${timeoutMs}).`,
          );
        }
        this.#task3TimeoutMs = timeoutMs;
      },
      getTask3TimeoutMs: () => this.#task3TimeoutMs,
      setTask4StepTimeoutMs: (timeoutMs: number) => {
        if (
          typeof timeoutMs !== 'number' ||
          !Number.isFinite(timeoutMs) ||
          Number.isNaN(timeoutMs)
        ) {
          throw new TypeError('Task-4 step timeout must be a finite number.');
        }
        if (timeoutMs <= 0) {
          throw new RangeError(`Task-4 step timeout must be > 0 ms (got ${timeoutMs}).`);
        }
        if (timeoutMs > DEFAULT_TASK4_STEP_TIMEOUT_MS) {
          throw new RangeError(
            `Task-4 step timeout cannot exceed frozen maximum of ${DEFAULT_TASK4_STEP_TIMEOUT_MS} ms (got ${timeoutMs}).`,
          );
        }
        this.#task4StepTimeoutMs = timeoutMs;
      },
      getTask4StepTimeoutMs: () => this.#task4StepTimeoutMs,
      setTask4AggregateTimeoutMs: (timeoutMs: number) => {
        if (
          typeof timeoutMs !== 'number' ||
          !Number.isFinite(timeoutMs) ||
          Number.isNaN(timeoutMs)
        ) {
          throw new TypeError('Task-4 aggregate timeout must be a finite number.');
        }
        if (timeoutMs <= 0) {
          throw new RangeError(`Task-4 aggregate timeout must be > 0 ms (got ${timeoutMs}).`);
        }
        if (timeoutMs > DEFAULT_TASK4_AGGREGATE_TIMEOUT_MS) {
          throw new RangeError(
            `Task-4 aggregate timeout cannot exceed frozen maximum of ${DEFAULT_TASK4_AGGREGATE_TIMEOUT_MS} ms (got ${timeoutMs}).`,
          );
        }
        this.#task4AggregateTimeoutMs = timeoutMs;
      },
      getTask4AggregateTimeoutMs: () => this.#task4AggregateTimeoutMs,
    });
    // Transport mode is resolved once, at construction, and is immutable. A
    // remote configuration supplied alongside stdio is NOT activated.
    this.transportMode = config?.transport ?? 'stdio';
    this.remoteConfig = this.transportMode === 'remote' ? config?.remote : undefined;
    // Retained verbatim and never defaulted: an absent audit configuration is a
    // startup failure, not a reason to run un-audited.
    this.auditConfig = config?.audit;

    // The approval state manager is mandatory for Task 4 authorization.
    this.approvalStateManager = approvalStateManager ?? new ApprovalStateManager();

    // Lifecycle audit evidence: the manager emits synchronously, the sink
    // buffers, and the control plane flushes into the existing audit chain.
    // The sink is memoized per chain so a separately composed admin channel
    // over the same logger cannot register a second observer (which would
    // double-write every transition).
    this.approvalAuditSink = getApprovalAuditSink(this.auditLogger);
    this.approvalStateManager.registerLifecycleSink(this.approvalAuditSink);

    // RC-05 Task 4 composition invariant: ONE pending-enrollment authority.
    //
    // The local operator channel and the remote bootstrap endpoint must observe
    // the same challenge table, and this is enforced STRUCTURALLY rather than by
    // convention. When an admin channel is composed in, its manager is adopted
    // (or must be the exact instance supplied). Supplying two different
    // instances is a construction failure, so a server with an active admin IPC
    // channel can never silently run a SECOND pending table beside it, and a
    // remote listener can never be bound against the wrong one.
    const composedAdminManager = this.adminIpcServer?.getEnrollmentManager();
    if (composedAdminManager !== undefined) {
      if (enrollmentManager !== undefined && enrollmentManager !== composedAdminManager) {
        throw new Error(
          'Invalid composition: the admin IPC channel and the enrollment manager must be the same instance.',
        );
      }
      this.enrollmentManager = composedAdminManager;
    } else {
      this.enrollmentManager = enrollmentManager ?? new EnrollmentManager();
    }

    // RC-05 Task 6: exactly ONE process-local session authority. Volatile, with
    // frozen TTLs and caps that are not configurable, and shared by every remote
    // consumer through `getRemoteExecutionBridge()`.
    this.sessionManager = sessionManager ?? new SessionManager();

    // RC-05 Task 7: exactly ONE process-local Layer C limiter and per-session
    // concurrency state. Volatile, with frozen bounds that are not configurable,
    // shared by every remote consumer through the ONE execution bridge, and
    // reset on shutdown.
    this.authenticatedRequestLimiter = createAuthenticatedRequestLimiter();

    this.defaultWorkspaceId = config?.defaultWorkspaceId;
    this.processRegistry =
      processRegistry ||
      (terminalSubsystem && 'processRegistry' in terminalSubsystem
        ? (terminalSubsystem as ControlledProcessRunner).processRegistry
        : undefined);

    if (this.processRegistry) {
      const sink = new ProcessAuditSink(this.auditLogger, this.workspaceRegistry);
      this.processRegistry.registerLifecycleSink(sink);
    }

    if (config?.authorizedRoots) {
      for (const root of config.authorizedRoots) {
        this.workspaceRegistry.registerWorkspace(root.id, root.path);
        if (!this.defaultWorkspaceId) {
          this.defaultWorkspaceId = root.id;
        }
      }
    }

    // Layer 2: one immutable effective policy engine, built once at startup.
    //
    // Startup order matters: the trusted configured roots MUST already be
    // registered before workspace assertions are verified, otherwise a valid
    // external policy naming a configured workspace would fail
    // UNKNOWN_WORKSPACE_ID. Policy workspaces still only ASSERT expected
    // registry identity; they never authorize or register a root.
    //
    // An explicitly configured but INVALID external policy fails closed with no
    // fallback to the built-in compatibility policy (rc04 §12, §44).
    const policyConfig = config?.policy;
    if (policyConfig !== undefined && policyConfig !== null) {
      try {
        this.effectivePolicyEngine = DeclarativePolicyEngine.fromExternalText(
          this.workspaceRegistry,
          policyConfig.sourceText,
          policyConfig.format,
        );
      } catch (err: unknown) {
        this.effectivePolicyEngine = undefined;
        const code = (err as { code?: string })?.code;
        this.policyInitializationFailure = {
          reason: code === 'POLICY_LOAD_ERROR' ? 'POLICY_LOAD_ERROR' : 'POLICY_PARSE_ERROR',
        };
      }
    } else {
      this.effectivePolicyEngine = DeclarativePolicyEngine.builtIn(this.workspaceRegistry);
      this.policyInitializationFailure = undefined;
    }

    this.server = new Server(
      {
        name: 'cesspace-arc',
        version: '0.6.0-rc06',
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    this.setupHandlers();
  }

  public getRegisteredTools(): Tool[] {
    return ALL_TOOL_DEFINITIONS;
  }

  /**
   * Defense-in-depth gate for mutation execution.
   *
   * Throws unless the current invocation recorded a successful approval
   * consumption. This is deliberately a method rather than an inline check so
   * the invariant is stated in exactly one place.
   */
  private assertApprovalConsumed(consumed: boolean, toolName: string): void {
    if (!consumed) {
      throw ArcError.policyDenied(
        `Internal authorization failure: tool '${toolName}' reached execution without verified approval consumption.`,
      );
    }
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: ALL_TOOL_DEFINITIONS,
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      // The generic registered-tool gate. An unregistered name is a JSON-RPC
      // `-32601` here, at the protocol boundary, and never becomes a tool
      // result: it does not reach the shared execution pipeline, policy, the
      // approval manager, or any subsystem. Identical to the remote boundary
      // below, so both transports answer an unknown tool the same way.
      if (!isRegisteredToolName(toolName)) {
        throw unknownToolError();
      }
      const params = (request.params.arguments || {}) as Record<string, unknown>;
      return this.dispatchToolCall(toolName, params);
    });
  }

  /* ------------------------------------------------------------------------ *
   * RC-06 Task 6 — the durable audit runtime.
   *
   * One chain, one writer, one lock. Every persistent write in this file goes
   * through one of the three methods below, and each of them routes the record
   * through `AuditLogger.log()` FIRST so the central minimization and redaction
   * authority (rc04 §31/§32, rc05 §24, rc06 §19) is the only serialization path
   * — there is no weaker second path that bypasses it.
   * ------------------------------------------------------------------------ */

  /**
   * Establishes the durable audit runtime.
   *
   * Runs the frozen §22.1 startup sequence to completion BEFORE any transport is
   * bound, so there is no window in which a session exists and tool dispatch can
   * begin before the audit chain is verified. A failure here is a startup
   * failure: nothing is bound, nothing is served, and no historical evidence is
   * touched.
   */
  private async startAuditRuntime(): Promise<void> {
    const config = this.auditConfig;
    if (config === undefined) {
      throw new Error(
        'Audit configuration is required: refused to start privileged MCP service without a durable audit runtime.',
      );
    }
    try {
      this.auditRuntime = await this.openAuditRuntimeForProcess(config);
    } catch (cause) {
      throw new Error(
        `Audit runtime startup failed (${boundedAuditFailureCode(cause)}); privileged MCP service was not started.`,
        { cause },
      );
    }
    // The durable chain is verified and open, so the production write authority
    // can now commit to it. This runs BEFORE any transport is bound: there is no
    // window in which a gateway event, an approval transition or a process
    // lifecycle record can be emitted into a process whose evidence authority is
    // still the in-memory mirror alone.
    getAuditWriteAuthority(this.auditLogger).bindDurableRuntime(this.auditRuntime);
  }

  /**
   * Opens the durable audit runtime this process will serve over.
   *
   * Production is exactly `openAuditRuntime`: the frozen §22.1 sequence, one
   * writer lock, one verified store. It is a `protected` method rather than a
   * direct call so the Task-6 durability suite can compose that SAME runtime
   * with deterministic fault seams — the only way "the subsystem receives zero
   * calls when STARTED persistence fails" can be proved against the real
   * boundary rather than inferred from a response shape.
   *
   * @internal Following this application's existing internal-seam convention
   * (`AdmissionLimiter`, `RemoteGateway`, `EnrollmentBootstrapController`): it
   * is `protected`, it is never exported from the package root, and it cannot be
   * reached from `ArcServerConfig`, the environment, the CLI, an MCP parameter,
   * a remote header or a request body. An override still has to return a runtime
   * produced by the audit package's own capability-gated entry point — there is
   * no path that skips the frozen §22.1 verification.
   */
  protected async openAuditRuntimeForProcess(config: AuditConfig): Promise<AuditRuntime> {
    return openAuditRuntime(config);
  }

  /**
   * The ONE gate every privileged dispatch passes before it can reach a
   * subsystem.
   *
   * It refuses when the process-wide degraded latch is set, when Tier-3 anchor
   * backpressure is at its ceiling, and when the frozen archive or byte budget
   * is exhausted. It performs no subsystem call and creates no approval state.
   *
   * @internal
   */
  private assertPrivilegedDispatchAllowed(): void {
    const runtime = this.auditRuntime;
    if (runtime === undefined) {
      throw new Error('audit runtime unavailable');
    }
    runtime.assertPrivilegedOperationsAllowed();
  }

  /**
   * Appends one record to the DURABLE chain, propagating any failure.
   *
   * The record is first produced by the historical in-memory `AuditLogger`, so
   * the persistent chain receives exactly the minimized, redacted projection the
   * in-memory chain always received — including `minimizeTarget`'s digesting of
   * a raw workspace path. Only the persistence-owned fields are stripped, and
   * the lifecycle block is added.
   *
   * This is a delegation to the ONE production write authority every other
   * emitter uses — the gateway sink, the approval sink and the process sink —
   * so there is a single definition of "a production audit record" rather than
   * one per emitter. It remains here because the call sites below are the tool
   * lifecycle, and their contract (a rejection means the evidence is not
   * secured) is unchanged.
   *
   * @internal
   */
  private async appendDurableRecord(
    body: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>,
    lifecycle?: AuditLifecycleMetadata,
  ): Promise<void> {
    // No durable chain is composed for this object only when it was never
    // started; a started server always has a runtime bound to the authority by
    // `startAuditRuntime`. In that state the write is the historical
    // in-memory-only write, exactly as it was before Task 6 — this is NOT a
    // second authority, because the mirror never defines production truth.
    await getAuditWriteAuthority(this.auditLogger).write(body, lifecycle);
  }

  /**
   * Records a refusal that is decided BEFORE any subsystem boundary.
   *
   * Every policy, authorization, schema and security denial is a standalone
   * terminal `DENIED` branch carrying its own server-generated UUIDv4
   * `operationId` (rc06 §7.2, §22). A fresh identifier is minted per denial and
   * is never reused, so `STARTED → DENIED` cannot arise from this path.
   *
   * A failure to make the denial durable is NOT swallowed. The denial the caller
   * asked about is a policy fact; "the refusal is not on the record" is a
   * different fact, and answering with the first would tell the caller the
   * refusal was recorded when the durable chain holds no record of it — at the
   * exact moment the process became unfit to serve. So this method:
   *
   *   1. latches the process-wide degraded audit state, so no later privileged
   *      operation is dispatched against a chain that cannot record its outcome;
   *   2. raises {@link AuditPersistenceFailure} carrying the bounded
   *      audit-persistence refusal — never the ordinary policy/schema denial,
   *      and never a fabricated durable `DENIED` record.
   *
   * It runs before any subsystem boundary and before any approval record is
   * created, inspected or redeemed, so a persistence failure here executes zero
   * privileged subsystem work — {@link executeAuthenticatedToolCall} converts it
   * into the response, and nothing else in the pipeline has run.
   *
   * @internal
   */
  private async recordDurableDenial(
    body: Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'>,
  ): Promise<void> {
    const operationId = randomUUID();
    try {
      await this.appendDurableRecord(body, { operationId, phase: 'DENIED' });
    } catch (cause) {
      this.auditRuntime?.latchDegradedAuditFailure();
      throw new AuditPersistenceFailure(boundedAuditPersistenceFailure(cause));
    }
  }

  /**
   * The stdio/local entry point into the ONE shared execution pipeline.
   *
   * The `actorOverride` seam exists for stdio callers and backward-compatible
   * tests ONLY. It is deliberately NOT the remote boundary: the remote path
   * (Task 6) passes a COMPLETE, internally derived actor to
   * {@link executeAuthenticatedToolCall} and can never express a partial or
   * caller-selectable actor.
   */
  public async dispatchToolCall(
    toolName: string,
    parameters: Record<string, unknown>,
    actorOverride?: Partial<PolicyEvaluationContext['actor']>,
  ): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }> {
    const actor: CompleteActor = {
      clientId: actorOverride?.clientId ?? 'local-stdio-caller',
      clientType: actorOverride?.clientType ?? 'mcp-client',
      sessionId: actorOverride?.sessionId ?? 'stdio-session-01',
      deviceId: actorOverride?.deviceId ?? 'local-machine',
      authenticated: actorOverride?.authenticated ?? true,
    };
    return this.executeAuthenticatedToolCall(actor, toolName, parameters);
  }

  /**
   * The single, authoritative execution pipeline:
   * authenticated request -> caller context -> schema validation -> workspace
   *   binding -> policy admission -> filesystem/git safety checks -> tool
   *   execution -> structured audit event -> sanitized MCP response.
   *
   * Both transports converge HERE. stdio supplies its local actor, and the
   * RC-05 remote bridge supplies the exact actor derived from an authenticated
   * Task-5 session; neither forks the dispatch switch, duplicates the approval
   * gate, or reaches a subsystem directly.
   *
   * The actor parameter is COMPLETE by construction: there is no default, no
   * merge, and no partial override, so a caller cannot select or fill in any
   * authorization-relevant field.
   *
   * @internal Reachable from the remote bridge and from stdio; not a transport.
   */
  public async executeAuthenticatedToolCall(
    actor: CompleteActor,
    toolName: string,
    parameters: Record<string, unknown>,
  ): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }> {
    try {
      return await this.executeToolCallPipeline(actor, toolName, parameters);
    } catch (cause: unknown) {
      // The ONE place a failed durable denial becomes a response (rc06 §22, §26,
      // §44). Every DENIED branch in the pipeline records its refusal through
      // `recordDurableDenial`, which raises this sentinel rather than returning
      // the ordinary denial when the refusal could not be made durable. The
      // conversion lives here so the caller is answered with the bounded
      // audit-persistence failure instead of a policy answer it would have no way
      // to know is unrecorded.
      if (cause instanceof AuditPersistenceFailure) {
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(cause.refusal.toJSON(), null, 2) }],
        };
      }
      throw cause;
    }
  }

  /**
   * The execution pipeline itself, from admission to the terminal response.
   *
   * It is separate from {@link executeAuthenticatedToolCall} only so that one
   * failure — a denial that could not be recorded durably — has a single
   * conversion point that no branch inside can bypass, without a `try`/`catch`
   * around a thousand lines of dispatch logic that would also capture subsystem
   * failures.
   *
   * @internal
   */
  private async executeToolCallPipeline(
    actor: CompleteActor,
    toolName: string,
    parameters: Record<string, unknown>,
  ): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }> {
    const startTime = new Date().toISOString();
    const startMs = Date.now();

    // 1. Authenticated Caller Context. `auditActor` is exactly the four bound
    //    fields, in the same order the audit chain has always recorded them.
    const auditActor = {
      clientId: actor.clientId,
      clientType: actor.clientType,
      sessionId: actor.sessionId,
      deviceId: actor.deviceId,
    };

    /** Audits a denial and returns the sanitized MCP error response. */
    const denyWith = async (
      arcErr: ArcError,
      ruleId: string,
      decision: 'DENY' | 'REQUIRE_APPROVAL' | 'ALLOW',
      denialAuditParams: Record<string, unknown>,
      workspaceInfo?: { workspaceId: string; workspacePath: string },
      evalMs = 0,
    ): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }> => {
      await this.recordDurableDenial({
        timestamp: startTime,
        actor: auditActor,
        target: workspaceInfo ?? { workspaceId: 'unbound', workspacePath: '' },
        invocation: {
          toolName,
          parametersRedacted: denialAuditParams,
          payloadHash: computeSha256(canonicalJson(denialAuditParams)),
        },
        policy: { decision, ruleId, evaluationDurationMs: evalMs },
        execution: {
          status: 'DENIED',
          startTime,
          endTime: new Date().toISOString(),
          durationMs: Date.now() - startMs,
        },
        error: { code: arcErr.code, message: arcErr.message },
      });
      return {
        isError: true,
        content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
      };
    };

    // 1a. Global audit availability gate (rc06 §19, §21, §27, §28, §42).
    //
    // This is the FIRST thing a privileged invocation meets, before the reserved
    // control object is parsed and long before any approval record is created,
    // inspected or consumed. That ordering is load-bearing: an operation refused
    // here must leave the approval transaction completely untouched — no pending
    // request created, no token redeemed, no state transition — which is what
    // §19 requires of a latched process and what §42 requires of any operation
    // rejected by the global gate.
    //
    // It writes nothing. A latched process cannot write, and an operation that
    // was never admitted is not a lifecycle branch: there is no DENIED record to
    // append and no operationId to mint.
    //
    // `health` is the ONE non-dispatching surface (§21). Everything else —
    // including `system_status`, which stats a workspace path — is privileged and
    // is refused here.
    if (this.auditRuntime !== undefined && toolName !== 'health') {
      try {
        this.assertPrivilegedDispatchAllowed();
      } catch (gateErr: unknown) {
        const refusal = boundedAuditRefusal(gateErr);
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(refusal.toJSON(), null, 2) }],
        };
      }
    }

    // 1b. Reserved control-object admission (rc04 §4.1 step 1, §5, §6).
    // The control object is extracted and validated SEPARATELY, then removed, so
    // the business schemas below see exact business parameters and the subsystem
    // never receives it. A malformed control object creates no approval state and
    // performs no approval lookup.
    const rawControl = (parameters ?? {})[ARC_APPROVAL_KEY];
    const extracted = extractArcApproval(parameters);
    const businessParameters = extracted.businessParameters;

    // Bounded, non-sensitive audit facts about any supplied control object. A
    // malformed control object is untrusted input and is never serialized
    // wholesale, and the raw token never reaches an audit record.
    const approvalAuditMetadata = safeApprovalAuditMetadata(rawControl, extracted.control);

    if (extracted.malformed) {
      const arcErr = ArcError.invalidRequestSchema(
        `Invalid parameters for tool '${toolName}': reserved control object failed schema validation.`,
      );
      return denyWith(arcErr, 'schema-arc-approval-control', 'DENY', approvalAuditMetadata);
    }

    // 2. Pre-Admission Tool Name & Runtime Schema Validation Gate (P1-02)
    const isCompositeTool =
      (RC07_COMPOSITE_TOOLS as readonly string[]).includes(toolName) ||
      this.#testCompositeHarness?.toolName === toolName;
    const schema =
      (this.#testCompositeHarness?.toolName === toolName
        ? this.#testCompositeHarness.schema
        : undefined) ?? (TOOL_SCHEMAS as Record<string, z.ZodTypeAny | undefined>)[toolName];
    if (!schema) {
      const arcErr = ArcError.policyDenied(
        `Tool '${toolName}' is not permitted in RC-01 stage (read-only inspection core only).`,
      );
      const preAuditParams = sanitizePreValidationParameters(toolName, businessParameters);
      await this.recordDurableDenial({
        timestamp: startTime,
        actor: auditActor,
        target: { workspaceId: 'unbound', workspacePath: '' },
        invocation: {
          toolName,
          parametersRedacted: preAuditParams,
          payloadHash: computeSha256(canonicalJson(preAuditParams)),
        },
        policy: {
          decision: 'DENY',
          ruleId: 'default-deny-unregistered-tool',
          evaluationDurationMs: 0,
        },
        execution: {
          status: 'DENIED',
          startTime,
          endTime: new Date().toISOString(),
          durationMs: Date.now() - startMs,
        },
        error: {
          code: arcErr.code,
          message: arcErr.message,
        },
      });
      return {
        isError: true,
        content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
      };
    }

    const parseResult = schema.safeParse(businessParameters);
    if (!parseResult.success) {
      const isReadLengthTooLarge =
        toolName === 'read_file' &&
        parseResult.error.issues.some(
          (iss) => iss.path.includes('length') && iss.code === 'too_big',
        );

      const isMutation = (RC03_MUTATION_TOOLS as readonly string[]).includes(toolName);
      let issueMessages: string;
      if (isMutation) {
        issueMessages = parseResult.error.issues
          .map((iss) => {
            if (iss.code === 'unrecognized_keys') {
              return `unrecognized parameter(s) provided (count: ${iss.keys.length})`;
            }
            const pathKey = iss.path.length > 0 ? iss.path.join('.') : 'root';
            return `${pathKey}: ${iss.message}`;
          })
          .join('; ');
      } else {
        issueMessages = parseResult.error.issues
          .map((iss) => `${iss.path.join('.') || 'root'}: ${iss.message}`)
          .join('; ');
      }

      const arcErr = isReadLengthTooLarge
        ? ArcError.payloadTooLarge('Requested read length exceeds maximum allowed limit of 1 MiB.')
        : ArcError.invalidRequestSchema(
            `Invalid parameters for tool '${toolName}': ${issueMessages}`,
          );
      const preAuditParams = sanitizePreValidationParameters(toolName, businessParameters);
      await this.recordDurableDenial({
        timestamp: startTime,
        actor: auditActor,
        target: { workspaceId: 'unbound', workspacePath: '' },
        invocation: {
          toolName,
          parametersRedacted: preAuditParams,
          payloadHash: computeSha256(canonicalJson(preAuditParams)),
        },
        policy: {
          decision: 'DENY',
          ruleId: isReadLengthTooLarge ? 'schema-payload-too-large' : 'schema-validation-failure',
          evaluationDurationMs: 0,
        },
        execution: {
          status: 'DENIED',
          startTime,
          endTime: new Date().toISOString(),
          durationMs: Date.now() - startMs,
        },
        error: {
          code: arcErr.code,
          message: isMutation
            ? `Invalid parameters for tool '${toolName}': request failed schema validation.`
            : arcErr.message,
        },
      });
      return {
        isError: true,
        content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
      };
    }

    const validatedParams = parseResult.data as Record<string, unknown>;

    // Defense-in-depth: explicit whitespace-only workspaceId/workspaceRoot must fail closed
    if (validatedParams.workspaceId !== undefined) {
      if (
        typeof validatedParams.workspaceId !== 'string' ||
        validatedParams.workspaceId.trim().length === 0
      ) {
        const arcErr = ArcError.invalidRequestSchema(
          'Parameter workspaceId must be a non-empty string.',
        );
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
        };
      }
    }
    if (validatedParams.workspaceRoot !== undefined) {
      if (
        typeof validatedParams.workspaceRoot !== 'string' ||
        validatedParams.workspaceRoot.trim().length === 0
      ) {
        const arcErr = ArcError.invalidRequestSchema(
          'Parameter workspaceRoot must be a non-empty string.',
        );
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
        };
      }
    }

    // 3. Workspace Binding Gate (P1-01)
    const hasExplicitId =
      typeof validatedParams.workspaceId === 'string' &&
      validatedParams.workspaceId.trim().length > 0;
    const hasExplicitRoot =
      typeof validatedParams.workspaceRoot === 'string' &&
      validatedParams.workspaceRoot.trim().length > 0;

    let targetWorkspaceRecord: WorkspaceRecord | undefined;
    let workspaceConflict = false;
    let workspaceUnregistered = false;

    // Caller Identity Gate (P1): run_command & composite tools must fail closed before execution unless clientId and sessionId are non-empty
    if (toolName === 'run_command' || isCompositeTool) {
      if (
        !actor.clientId ||
        !actor.sessionId ||
        actor.clientId.trim().length === 0 ||
        actor.sessionId.trim().length === 0
      ) {
        const arcErr = isCompositeTool
          ? ArcError.unauthenticated(
              `Access denied: composite tool '${toolName}' requires verified caller identity (clientId and sessionId).`,
            )
          : ArcError.policyDenied(
              'Access denied: run_command requires verified caller identity (clientId and sessionId).',
            );
        const preAuditParams = sanitizePreValidationParameters(toolName, businessParameters);
        await this.recordDurableDenial({
          timestamp: startTime,
          actor: auditActor,
          target: { workspaceId: 'unbound', workspacePath: '' },
          invocation: {
            toolName,
            parametersRedacted: preAuditParams,
            payloadHash: computeSha256(canonicalJson(preAuditParams)),
          },
          policy: {
            decision: 'DENY',
            ruleId: 'deny-incomplete-caller-identity',
            evaluationDurationMs: 0,
          },
          execution: {
            status: 'DENIED',
            startTime,
            endTime: new Date().toISOString(),
            durationMs: Date.now() - startMs,
          },
          error: {
            code: arcErr.code,
            message: arcErr.message,
          },
        });
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
        };
      }
    }

    const isProcessLifecycleTool =
      toolName === 'process_status' ||
      toolName === 'process_output' ||
      toolName === 'terminate_process';

    if (isProcessLifecycleTool) {
      if (!this.processRegistry) {
        const arcErr = ArcError.policyDenied('Process ownership verifier is unavailable.');
        const preAuditParams = sanitizePreValidationParameters(toolName, businessParameters);
        await this.recordDurableDenial({
          timestamp: startTime,
          actor: auditActor,
          target: { workspaceId: 'unbound', workspacePath: '' },
          invocation: {
            toolName,
            parametersRedacted: preAuditParams,
            payloadHash: computeSha256(canonicalJson(preAuditParams)),
          },
          policy: {
            decision: 'DENY',
            ruleId: 'deny-missing-process-verifier',
            evaluationDurationMs: 0,
          },
          execution: {
            status: 'DENIED',
            startTime,
            endTime: new Date().toISOString(),
            durationMs: Date.now() - startMs,
          },
          error: {
            code: arcErr.code,
            message: arcErr.message,
          },
        });
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
        };
      }

      const processId = validatedParams.processId as string;
      const procRecord = this.processRegistry.getProcess(processId);
      if (!procRecord) {
        const arcErr = ArcError.processNotFound(`Process not found: '${processId}'.`);
        const preAuditParams = sanitizePreValidationParameters(toolName, businessParameters);
        await this.recordDurableDenial({
          timestamp: startTime,
          actor: auditActor,
          target: { workspaceId: 'unbound', workspacePath: '' },
          invocation: {
            toolName,
            parametersRedacted: preAuditParams,
            payloadHash: computeSha256(canonicalJson(preAuditParams)),
          },
          policy: {
            decision: 'DENY',
            ruleId: 'deny-process-not-found',
            evaluationDurationMs: 0,
          },
          execution: {
            status: 'DENIED',
            startTime,
            endTime: new Date().toISOString(),
            durationMs: Date.now() - startMs,
          },
          error: {
            code: arcErr.code,
            message: arcErr.message,
          },
        });
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
        };
      }

      const procWs = this.workspaceRegistry.getWorkspace(procRecord.workspaceId);
      if (!procWs) {
        const arcErr = ArcError.policyDenied(
          `Target workspace '${procRecord.workspaceId}' for process is not registered.`,
        );
        const preAuditParams = sanitizePreValidationParameters(toolName, businessParameters);
        await this.recordDurableDenial({
          timestamp: startTime,
          actor: auditActor,
          target: { workspaceId: procRecord.workspaceId, workspacePath: '' },
          invocation: {
            toolName,
            parametersRedacted: preAuditParams,
            payloadHash: computeSha256(canonicalJson(preAuditParams)),
          },
          policy: {
            decision: 'DENY',
            ruleId: 'deny-unregistered-workspace',
            evaluationDurationMs: 0,
          },
          execution: {
            status: 'DENIED',
            startTime,
            endTime: new Date().toISOString(),
            durationMs: Date.now() - startMs,
          },
          error: {
            code: arcErr.code,
            message: arcErr.message,
          },
        });
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
        };
      }

      if (validatedParams.workspaceId && validatedParams.workspaceId !== procRecord.workspaceId) {
        const arcErr = ArcError.policyDenied(
          'Access denied: Caller workspace does not match process workspace.',
        );
        const preAuditParams = sanitizePreValidationParameters(toolName, businessParameters);
        await this.recordDurableDenial({
          timestamp: startTime,
          actor: auditActor,
          target: { workspaceId: procRecord.workspaceId, workspacePath: procWs.rootPath },
          invocation: {
            toolName,
            parametersRedacted: preAuditParams,
            payloadHash: computeSha256(canonicalJson(preAuditParams)),
          },
          policy: {
            decision: 'DENY',
            ruleId: 'deny-process-ownership-mismatch',
            evaluationDurationMs: 0,
          },
          execution: {
            status: 'DENIED',
            startTime,
            endTime: new Date().toISOString(),
            durationMs: Date.now() - startMs,
          },
          error: {
            code: arcErr.code,
            message: arcErr.message,
          },
        });
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcErr.toJSON(), null, 2) }],
        };
      }

      targetWorkspaceRecord = procWs;
    } else if (toolName === 'health' || toolName === 'system_status') {
      targetWorkspaceRecord = this.defaultWorkspaceId
        ? this.workspaceRegistry.getWorkspace(this.defaultWorkspaceId)
        : undefined;
    } else if (toolName === 'arc_worktree_status') {
      const rawWsRoot =
        typeof validatedParams.workspaceRoot === 'string'
          ? (validatedParams.workspaceRoot as string)
          : undefined;

      // RC07-NEG-016: directory traversal (..) rejected before resolution
      if (rawWsRoot !== undefined && /(^|[/\\])\.\.([/\\]|$)/.test(rawWsRoot)) {
        const arcErr = ArcError.pathOutsideWorkspace(
          `Directory traversal (..) detected in path before resolution: '${rawWsRoot}'`,
        );
        return denyWith(arcErr, 'deny-directory-traversal', 'DENY', validatedParams, {
          workspaceId: 'traversal-denied',
          workspacePath: rawWsRoot,
        });
      }

      if (hasExplicitId) {
        const wsById = this.workspaceRegistry.getWorkspace(validatedParams.workspaceId as string);
        if (!wsById) {
          workspaceUnregistered = true;
        } else {
          targetWorkspaceRecord = wsById;
          if (rawWsRoot !== undefined) {
            try {
              await this.filesystemSubsystem.validateWorkspaceContainment(
                wsById.rootPath,
                rawWsRoot,
              );
            } catch (containErr: unknown) {
              const arcErr =
                containErr instanceof ArcError
                  ? containErr
                  : ArcError.pathOutsideWorkspace(String(containErr));
              return denyWith(arcErr, 'deny-path-outside-workspace', 'DENY', validatedParams, {
                workspaceId: wsById.id,
                workspacePath: wsById.rootPath,
              });
            }
          }
        }
      } else if (hasExplicitRoot) {
        const ws =
          this.workspaceRegistry.findWorkspaceForPath(validatedParams.workspaceRoot as string) ||
          this.workspaceRegistry.getWorkspace(validatedParams.workspaceRoot as string);
        if (!ws) {
          workspaceUnregistered = true;
        } else {
          targetWorkspaceRecord = ws;
        }
      } else {
        if (this.defaultWorkspaceId) {
          targetWorkspaceRecord = this.workspaceRegistry.getWorkspace(this.defaultWorkspaceId);
        } else {
          const allWorkspaces = this.workspaceRegistry.getWorkspaces();
          if (allWorkspaces.length === 1) {
            targetWorkspaceRecord = allWorkspaces[0];
          } else {
            workspaceUnregistered = true;
          }
        }
      }
    } else {
      if (hasExplicitId && hasExplicitRoot) {
        const wsById = this.workspaceRegistry.getWorkspace(validatedParams.workspaceId as string);
        const wsByPath =
          this.workspaceRegistry.findWorkspaceForPath(validatedParams.workspaceRoot as string) ||
          this.workspaceRegistry.getWorkspace(validatedParams.workspaceRoot as string);

        if (!wsById || !wsByPath) {
          workspaceUnregistered = true;
        } else if (wsById.id !== wsByPath.id) {
          workspaceConflict = true;
        } else {
          targetWorkspaceRecord = wsById;
        }
      } else if (hasExplicitId) {
        const ws = this.workspaceRegistry.getWorkspace(validatedParams.workspaceId as string);
        if (!ws) {
          workspaceUnregistered = true;
        } else {
          targetWorkspaceRecord = ws;
        }
      } else if (hasExplicitRoot) {
        const ws =
          this.workspaceRegistry.findWorkspaceForPath(validatedParams.workspaceRoot as string) ||
          this.workspaceRegistry.getWorkspace(validatedParams.workspaceRoot as string);
        if (!ws) {
          workspaceUnregistered = true;
        } else {
          targetWorkspaceRecord = ws;
        }
      } else {
        // Neither selector provided: fall back to defaultWorkspaceId or single registered workspace
        if (!targetWorkspaceRecord) {
          if (this.defaultWorkspaceId) {
            targetWorkspaceRecord = this.workspaceRegistry.getWorkspace(this.defaultWorkspaceId);
          } else {
            const allWorkspaces = this.workspaceRegistry.getWorkspaces();
            if (allWorkspaces.length === 1) {
              targetWorkspaceRecord = allWorkspaces[0];
            }
          }
        }
      }
    }

    const targetWorkspace: PolicyEvaluationContext['targetWorkspace'] = {
      workspaceId: workspaceConflict
        ? 'deny-conflicting-workspace-selectors'
        : workspaceUnregistered
          ? 'deny-unregistered-workspace'
          : targetWorkspaceRecord?.id || 'unbound',
      rootPath: targetWorkspaceRecord?.rootPath || '',
      isGitRepo: targetWorkspaceRecord?.isGitRepo || false,
    };

    // Composite tools require an authorized registered workspace (RC07-NEG-002, RC07-NEG-018)
    if (
      isCompositeTool &&
      (!targetWorkspaceRecord ||
        targetWorkspace.workspaceId === 'unbound' ||
        targetWorkspace.workspaceId.startsWith('deny-'))
    ) {
      let arcErr: ArcError;
      if (
        (toolName === 'arc_worktree_status' ||
          toolName === 'arc_ci_status' ||
          toolName === 'arc_stage_evidence') &&
        (workspaceUnregistered || targetWorkspace.workspaceId === 'deny-unregistered-workspace')
      ) {
        arcErr = ArcError.workspaceUnregistered(
          `Workspace '${String(validatedParams.workspaceId || validatedParams.workspaceRoot || '')}' is not registered in authorized workspaces.`,
        );
      } else if (
        (toolName === 'arc_repo_status' || toolName === 'arc_review_diff') &&
        (workspaceUnregistered || targetWorkspace.workspaceId === 'deny-unregistered-workspace')
      ) {
        arcErr = ArcError.gitRepositoryNotFound(
          `Path '${String(validatedParams.workspaceId || validatedParams.workspaceRoot || '')}' is not a valid Git repository.`,
        );
      } else {
        arcErr = ArcError.noWorkspaceConfigured(
          `Composite tool '${toolName}' requires an authorized registered workspace.`,
        );
      }
      const ruleId = targetWorkspace.workspaceId.startsWith('deny-')
        ? targetWorkspace.workspaceId
        : 'deny-unregistered-workspace';
      return denyWith(arcErr, ruleId, 'DENY', validatedParams, {
        workspaceId: targetWorkspace.workspaceId,
        workspacePath: targetWorkspace.rootPath,
      });
    }

    // Materialize authoritative deterministic plan for composite tools
    let compositePlan: CanonicalCompositePlan | undefined;
    let compositePlanHash: string | undefined;
    if (this.#testCompositeHarness?.toolName === toolName) {
      compositePlan = this.#testCompositeHarness.materializer({
        compositeTool: toolName,
        businessParameters: validatedParams,
        workspaceId: targetWorkspace.workspaceId,
        workspaceRoot: targetWorkspace.rootPath,
        registry: this.#deterministicRegistry,
      });
      // Validate all materialized steps against the closed registry
      for (const step of compositePlan.steps) {
        validateStepAgainstRegistry(step, this.#deterministicRegistry);
      }
      compositePlan = deepFreezePlan(compositePlan);
      compositePlanHash = computePlanHash(compositePlan);
    } else if (toolName === 'arc_verify') {
      compositePlan = materializeArcVerifyPlan({
        suite: validatedParams.suite as string | undefined,
        workspaceId: targetWorkspace.workspaceId,
        workspaceRoot: targetWorkspace.rootPath,
        registry: this.#deterministicRegistry,
        stepTimeoutMs: this.#task4StepTimeoutMs,
      });
      // Validate all materialized steps against the closed registry
      for (const step of compositePlan.steps) {
        validateStepAgainstRegistry(step, this.#deterministicRegistry);
      }
      compositePlan = deepFreezePlan(compositePlan);
      compositePlanHash = computePlanHash(compositePlan);
    } else if (toolName === 'arc_test') {
      let normalizedTestPath: string | undefined;
      if (validatedParams.testPath !== undefined) {
        try {
          normalizedTestPath = await this.filesystemSubsystem.validateTestPath(
            targetWorkspace.rootPath,
            validatedParams.testPath as string,
          );
        } catch (pathErr: unknown) {
          const arcErr =
            pathErr instanceof ArcError ? pathErr : ArcError.invalidRequestSchema(String(pathErr));
          return denyWith(arcErr, 'deny-invalid-test-path', 'DENY', validatedParams, {
            workspaceId: targetWorkspace.workspaceId,
            workspacePath: targetWorkspace.rootPath,
          });
        }
      }

      if (validatedParams.filter !== undefined) {
        try {
          validateTestFilter(validatedParams.filter as string);
        } catch (filterErr: unknown) {
          const arcErr =
            filterErr instanceof ArcError
              ? filterErr
              : ArcError.invalidRequestSchema(String(filterErr));
          return denyWith(arcErr, 'deny-invalid-test-filter', 'DENY', validatedParams, {
            workspaceId: targetWorkspace.workspaceId,
            workspacePath: targetWorkspace.rootPath,
          });
        }
      }

      compositePlan = materializeArcTestPlan({
        testPath: normalizedTestPath,
        filter: validatedParams.filter as string | undefined,
        testRunner: validatedParams.testRunner as 'node' | undefined,
        maxDurationMs: validatedParams.maxDurationMs as number | undefined,
        workspaceId: targetWorkspace.workspaceId,
        workspaceRoot: targetWorkspace.rootPath,
        registry: this.#deterministicRegistry,
      });

      for (const step of compositePlan.steps) {
        validateStepAgainstRegistry(step, this.#deterministicRegistry);
      }
      compositePlan = deepFreezePlan(compositePlan);
      compositePlanHash = computePlanHash(compositePlan);
    }

    const context: PolicyEvaluationContext = {
      actor,
      targetWorkspace,
      request: {
        toolName,
        parameters: validatedParams,
      },
      environment: {
        timestamp: startTime,
      },
    };

    // Safe audit parameters for data minimization (P1-01):
    // For run_command, replace raw arguments with safe metadata (argCount, safeFlags).
    // For RC-03 mutation tools, use the authoritative mutation audit sanitizer so that
    // raw content, patches, and hostile paths NEVER enter audit records.
    let auditParams: Record<string, unknown> = validatedParams;
    if (toolName === 'run_command') {
      const rawArgs = Array.isArray(validatedParams.args) ? (validatedParams.args as string[]) : [];
      const safeFlags = rawArgs.filter(
        (a) =>
          typeof a === 'string' &&
          (a === '--version' || a === '-v' || a === '--help' || a === '-h' || a === '-V'),
      );
      auditParams = {
        ...validatedParams,
        args: {
          argCount: rawArgs.length,
          safeFlags,
        },
      };
    } else if ((RC03_MUTATION_TOOLS as readonly string[]).includes(toolName)) {
      // Mutation tools: authoritative data minimization — raw content/patch NEVER in audit
      auditParams = sanitizeMutationAuditParameters(toolName, validatedParams);
    }

    if (Object.keys(approvalAuditMetadata).length > 0) {
      auditParams = { ...auditParams, ...approvalAuditMetadata };
    }

    // Authoritative payload hash uses sanitized params for mutation tools (not raw params)
    const auditPayloadHash = computeSha256(canonicalJson(auditParams));

    // 3. Authorization: Layer 1 (permanent kernel), then Layer 2 (declarative
    //    policy), then the mutation floor, and only then approval validation.
    //
    // Frozen redemption order (rc04 §4.1). Both DENY decisions are determined
    // BEFORE any approval record is inspected or any token is validated, so a
    // token can never override a current DENY.

    // An explicitly configured but invalid external policy fails closed: there
    // is no fallback to the built-in compatibility policy (rc04 §13, §44).
    //
    // The minimal diagnostic tools remain callable so an operator can diagnose
    // the failure (rc04 §12.2 / §12.3); every other operation is refused.
    const policyEngine = this.effectivePolicyEngine;
    const isDiagnosticTool = toolName === 'health' || toolName === 'system_status';
    if (policyEngine === undefined && !isDiagnosticTool) {
      const arcErr = ArcError.policyLoadError(
        'Policy engine is not active: the configured declarative policy could not be loaded.',
        { policyEngineActive: false },
      );
      return denyWith(arcErr, 'deny-policy-engine-unavailable', 'DENY', auditParams, {
        workspaceId: targetWorkspace.workspaceId,
        workspacePath: targetWorkspace.rootPath,
      });
    }

    const evalStart = Date.now();

    // apply_patch embeds its target paths inside the patch body. Parse with the
    // authoritative RC-03 parser BEFORE any approval creation or consumption, so
    // Layer 1 and Layer 2 can see every real target and a malformed patch can
    // never create or consume an approval.
    let patchTargetPaths: string[] | undefined;
    if (toolName === 'apply_patch') {
      try {
        patchTargetPaths = parsePatchTargetPaths(validatedParams.patch);
      } catch (parseErr: unknown) {
        const arcErr =
          parseErr instanceof ArcError
            ? parseErr
            : ArcError.patchParseError('Patch payload could not be parsed.');
        return denyWith(arcErr, 'patch-parse-failure', 'DENY', auditParams, {
          workspaceId: targetWorkspace.workspaceId,
          workspacePath: targetWorkspace.rootPath,
        });
      }
    }

    // --- Layer 1: permanent SecurityKernel --------------------------------
    // Evaluated for the business target and, for apply_patch, once per parsed
    // target through an INTERNAL derived context. That derived context is not
    // the business parameter object, is never hashed, and is never passed to any
    // subsystem; it exists only so the kernel can see patch-embedded paths.
    const layer1Decisions: Array<{
      effect: PolicyEffect;
      matchingRuleId: string;
      reason: string;
    }> = [];
    if (isCompositeTool) {
      const planFacts: CompositePlanSecurityFacts | undefined = compositePlan
        ? {
            toolName,
            workspaceRoot: targetWorkspace.rootPath,
            steps: compositePlan.steps.map((s) => ({
              toolRegistryId: s.toolRegistryId,
              executable: s.executable,
              cwd: s.cwd,
              sideEffectClass: s.sideEffectClass,
              projectCodeExecution: s.projectCodeExecution,
            })),
          }
        : undefined;
      layer1Decisions.push(await this.securityKernel.evaluateComposite(context, planFacts));
    } else {
      layer1Decisions.push(await this.securityKernel.evaluate(context));
      if (toolName === 'apply_patch' && patchTargetPaths !== undefined) {
        for (const targetPath of patchTargetPaths) {
          const derivedContext: PolicyEvaluationContext = {
            ...context,
            request: { toolName, parameters: { ...validatedParams, path: targetPath } },
          };
          layer1Decisions.push(await this.securityKernel.evaluate(derivedContext));
        }
      }
    }
    // Multi-target Layer-1 reduction uses the same most-restrictive precedence.
    const layer1 = reduceDecisions(layer1Decisions) as {
      effect: PolicyEffect;
      matchingRuleId: string;
      reason: string;
    };
    const evalDuration = Date.now() - evalStart;

    if (layer1.effect === 'DENY') {
      return denyWith(
        ArcError.policyDenied(layer1.reason),
        layer1.matchingRuleId,
        'DENY',
        auditParams,
        { workspaceId: targetWorkspace.workspaceId, workspacePath: targetWorkspace.rootPath },
        evalDuration,
      );
    }

    // --- Layer 2: current declarative policy ------------------------------
    // One deterministic target-extraction helper feeds every branch; multi-target
    // operations are reduced with the same precedence so the result is
    // independent of target order.
    // With no engine (fail-closed diagnostic path) the mode is irrelevant;
    // EXTERNAL keeps the strictest target semantics.
    const policyMode = policyEngine?.getSourceMode() ?? 'EXTERNAL';

    // ONE authoritative canonical-target derivation, shared by the policy
    // matcher and the operator review summary, so the human-reviewed target,
    // the policy target, and the filesystem target can never diverge. It does
    // not mutate `validatedParams`: the execution payload hash and subsystem
    // execution remain bound to the exact post-schema validated parameters.
    const canonicalTargets = deriveCanonicalPathTargets(
      toolName,
      validatedParams,
      targetWorkspace.rootPath,
      patchTargetPaths,
      policyMode,
    );

    const layer2Targets = extractPolicyTargets(
      toolName,
      validatedParams,
      targetWorkspace.rootPath,
      patchTargetPaths,
      policyMode,
    );

    if (isCompositeTool && compositePlan) {
      for (const step of compositePlan.steps) {
        if (step.sideEffectClass === 'EXECUTION') {
          layer2Targets.push({
            toolName,
            executableBasename: step.executable.toLowerCase(),
            path: step.cwd || undefined,
          });
        }
      }
    }

    // An empty target list means a supplied path had no safe canonical
    // workspace-relative form (traversal, NUL, backslash, or the workspace root
    // itself, which the frozen policy grammar cannot express). Dropping the path
    // would let a `paths` rule silently miss, so the request fails closed.
    if (canonicalTargets.blocked || layer2Targets.length === 0) {
      return denyWith(
        ArcError.policyDenied('Target path has no safe canonical workspace-relative form.'),
        'deny-unnormalizable-target-path',
        'DENY',
        auditParams,
        { workspaceId: targetWorkspace.workspaceId, workspacePath: targetWorkspace.rootPath },
      );
    }
    // On the fail-closed diagnostic path there is no Layer-2 engine at all; the
    // diagnostic tools carry no targets and no side effects, so the absent layer
    // contributes no restriction. Every other tool was already refused above.
    const layer2Decisions: Array<{
      effect: PolicyEffect;
      matchingRuleId: string;
      reason: string;
    }> =
      policyEngine === undefined
        ? [{ effect: 'ALLOW' as PolicyEffect, matchingRuleId: 'no-layer2-engine', reason: '' }]
        : layer2Targets.map((target: PolicyMatchTarget) => {
            return policyEngine.evaluate(target as never);
          });
    const layer2 = reduceDecisions(layer2Decisions) as {
      effect: PolicyEffect;
      matchingRuleId: string;
      reason: string;
    };

    if (layer2.effect === 'DENY') {
      return denyWith(
        ArcError.policyDenied(layer2.reason),
        layer2.matchingRuleId,
        'DENY',
        auditParams,
        { workspaceId: targetWorkspace.workspaceId, workspacePath: targetWorkspace.rootPath },
        evalDuration,
      );
    }

    // --- Composition and the mandatory mutation approval floor -------------
    let effectiveEffect: PolicyEffect = mostRestrictive(layer1.effect, layer2.effect);
    let effectiveRuleId =
      layer1.effect === effectiveEffect ? layer1.matchingRuleId : layer2.matchingRuleId;

    const isMutationTool = (RC03_MUTATION_TOOLS as readonly string[]).includes(toolName);
    if (effectiveEffect === 'ALLOW' && isMutationTool) {
      // Defense in depth: a mutation can never resolve to automatic ALLOW.
      effectiveEffect = 'REQUIRE_APPROVAL';
      effectiveRuleId = 'require-approval-file-mutation';
    }

    // Invocation-local, non-user-controlled authorization state. Mutation
    // execution requires this to be set true by a SUCCESSFUL consumption during
    // this invocation. It is never derived from parameters, actor input, a
    // policy ALLOW, or any request property.
    let approvalConsumedForExecution = false;
    let consumedApprovalRequestId: string | undefined;
    let consumedApprovalContext:
      | {
          requestId: string;
          toolName: string;
          actor: {
            clientId: string;
            clientType: string;
            sessionId?: string;
            deviceId?: string;
          };
          workspaceId: string;
          workspaceRootHash: string;
          policyHash: string;
        }
      | undefined;

    if (effectiveEffect === 'REQUIRE_APPROVAL') {
      const actorBinding = {
        clientId: actor.clientId,
        clientType: actor.clientType,
        sessionId: actor.sessionId,
        deviceId: actor.deviceId,
      };
      // The raw host path never enters the binding; only its digest.
      const workspaceRootHash = sha256Hex(targetWorkspace.rootPath);
      const workspaceBinding = {
        workspaceId: targetWorkspace.workspaceId,
        workspaceRootHash,
      };
      // The approval path is unreachable without a Layer-2 engine: with no
      // engine, Layer 2 contributes ALLOW and only the two side-effect-free
      // diagnostic tools are admitted.
      const currentPolicyHash = (policyEngine as DeclarativePolicyEngine).getPolicyHash();
      const executionPayloadHash = computeExecutionPayloadHash({
        toolName,
        businessParameters: validatedParams,
        actor: actorBinding,
        workspaceId: workspaceBinding.workspaceId,
        workspaceRootHash,
        policyHash: currentPolicyHash,
        planHash: compositePlanHash,
      });

      if (extracted.control === null) {
        // Scenario A: no control object -> create or reuse a pending approval.
        const { reviewMaterial, reviewSummary } = buildReviewPayload(
          toolName,
          validatedParams,
          canonicalTargets.paths,
          compositePlan && compositePlanHash
            ? {
                planId: compositePlan.planId,
                planHash: compositePlanHash,
                stepCount: compositePlan.steps.length,
                steps: compositePlan.steps.map((s) => ({
                  stepId: s.stepId,
                  toolRegistryId: s.toolRegistryId,
                  sideEffectClass: s.sideEffectClass,
                })),
              }
            : undefined,
        );
        const snapshot = this.approvalStateManager.createOrReusePending({
          toolName,
          executionPayloadHash,
          binding: {
            actor: actorBinding,
            workspace: workspaceBinding,
            policyHash: currentPolicyHash,
          },
          reviewMaterial,
          reviewSummary,
        });

        const arcError = ArcError.approvalRequired(
          `Action requires human approval. Request ID: ${snapshot.requestId}`,
          {
            approvalRequestId: snapshot.requestId,
            toolName,
            expiresInSeconds: snapshot.remainingSeconds,
          },
        );

        // Lifecycle evidence is committed BEFORE the request ID is returned.
        // A failure here fails the initiating action closed rather than
        // proceeding without required audit evidence.
        try {
          await this.approvalAuditSink.flush();
        } catch {
          return denyWith(
            ArcError.internalError('Required approval audit evidence could not be recorded.'),
            'approval-audit-failed',
            'REQUIRE_APPROVAL',
            auditParams,
            { workspaceId: targetWorkspace.workspaceId, workspacePath: targetWorkspace.rootPath },
          );
        }

        await this.recordDurableDenial({
          timestamp: startTime,
          actor: auditActor,
          target: {
            workspaceId: targetWorkspace.workspaceId,
            workspacePath: targetWorkspace.rootPath,
          },
          invocation: {
            toolName,
            parametersRedacted: auditParams,
            payloadHash: auditPayloadHash,
          },
          policy: {
            decision: 'REQUIRE_APPROVAL',
            ruleId: effectiveRuleId,
            evaluationDurationMs: evalDuration,
            approvalId: snapshot.requestId,
          },
          execution: {
            status: 'DENIED',
            startTime,
            endTime: new Date().toISOString(),
            durationMs: Date.now() - startMs,
          },
          approval: {
            requestId: snapshot.requestId,
            state: snapshot.state,
            source: 'MCP',
          },
          error: { code: 'APPROVAL_REQUIRED', message: arcError.message },
        });

        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcError.toJSON(), null, 2) }],
        };
      }

      // Scenario C: a structurally valid control object is present. Only now is
      // the approval record inspected, validated, and atomically consumed.
      // The manager remains authoritative for expiry, state, policy, payload,
      // actor, and workspace binding, and for timing-safe token comparison.
      try {
        const consumption = this.approvalStateManager.redeemAndConsume({
          requestId: extracted.control.requestId,
          token: extracted.control.token,
          executionPayloadHash,
          actor: actorBinding,
          workspace: workspaceBinding,
          policyHash: currentPolicyHash,
        });
        // Consumption happened BEFORE any subsystem call. The CONSUMED
        // lifecycle evidence must be committed before execution begins; if it
        // cannot be recorded the subsystem MUST NOT run, and the approval
        // remains CONSUMED (never rolled back to APPROVED).
        try {
          await this.approvalAuditSink.flush();
        } catch {
          return denyWith(
            ArcError.internalError('Required approval audit evidence could not be recorded.'),
            'approval-audit-failed',
            'REQUIRE_APPROVAL',
            auditParams,
            {
              workspaceId: targetWorkspace.workspaceId,
              workspacePath: targetWorkspace.rootPath,
            },
            evalDuration,
          );
        }
        approvalConsumedForExecution = true;
        consumedApprovalRequestId = consumption.requestId;
        consumedApprovalContext = {
          requestId: consumption.requestId,
          toolName,
          actor: actorBinding,
          workspaceId: workspaceBinding.workspaceId,
          workspaceRootHash: workspaceBinding.workspaceRootHash,
          policyHash: currentPolicyHash,
        };
      } catch (redemptionErr: unknown) {
        const code = (redemptionErr as { code?: string })?.code;
        const arcError =
          code === 'APPROVAL_EXPIRED'
            ? ArcError.approvalExpired()
            : ArcError.approvalRejected(
                'Approval could not be redeemed. The request, token, or bindings are not valid.',
              );
        // Internal diagnostic ONLY. It is written to the audit record, never to
        // the ArcError, its details, toJSON(), or the MCP response (anti-oracle).
        const internalReason = getApprovalFailureReason(redemptionErr);

        await this.recordDurableDenial({
          timestamp: startTime,
          actor: auditActor,
          target: {
            workspaceId: targetWorkspace.workspaceId,
            workspacePath: targetWorkspace.rootPath,
          },
          invocation: {
            toolName,
            parametersRedacted: auditParams,
            payloadHash: auditPayloadHash,
          },
          policy: {
            decision: 'REQUIRE_APPROVAL',
            ruleId: effectiveRuleId,
            evaluationDurationMs: evalDuration,
            approvalId: extracted.control.requestId,
          },
          execution: {
            status: 'DENIED',
            startTime,
            endTime: new Date().toISOString(),
            durationMs: Date.now() - startMs,
          },
          approval: {
            requestId: extracted.control.requestId,
            source: 'MCP',
            ...(internalReason === undefined ? {} : { reasonCode: internalReason }),
          },
          error: { code: arcError.code, message: arcError.message },
        });

        // Expiry/invalidation discovered during redemption is lifecycle
        // evidence too, and must be committed before the rejection is returned.
        //
        // Which failure this was matters: POLICY_BINDING_MISMATCH permanently
        // INVALIDATES the record, and APPROVAL_EXPIRED is a real EXPIRED
        // transition. Both were committed to the state machine; only their
        // evidence is at stake here.
        let lifecycleEvidenceCommitted = true;
        try {
          await this.approvalAuditSink.flush();
        } catch {
          lifecycleEvidenceCommitted = false;
        }

        const causedLifecycleTransition =
          internalReason === 'POLICY_BINDING_MISMATCH' || code === 'APPROVAL_EXPIRED';

        if (!lifecycleEvidenceCommitted && causedLifecycleTransition) {
          // The record is permanently EXPIRED/INVALIDATED and is NOT rolled
          // back, but a semantic outcome (APPROVAL_EXPIRED / APPROVAL_REJECTED)
          // must not be reported as though its required lifecycle evidence were
          // durable. The queued evidence is retained for a later retry.
          const auditError = ArcError.internalError(
            'Required approval audit evidence could not be recorded.',
          );
          return {
            isError: true,
            content: [{ type: 'text', text: JSON.stringify(auditError.toJSON(), null, 2) }],
          };
        }

        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(arcError.toJSON(), null, 2) }],
        };
      }
    }

    // Approval classification is recorded truthfully on the ordinary invocation
    // audit record below: an approved execution is reported as REQUIRE_APPROVAL,
    // never as an ordinary ALLOW.
    const effectiveDecisionLabel: 'ALLOW' | 'REQUIRE_APPROVAL' = approvalConsumedForExecution
      ? 'REQUIRE_APPROVAL'
      : 'ALLOW';
    const effectiveRuleIdForAudit = approvalConsumedForExecution
      ? effectiveRuleId
      : layer2.matchingRuleId;

    // 3b. Universal pre-dispatch durability (rc06 §7.2, §8, §11).
    //
    // This is the LAST gate before the subsystem boundary and it runs for BOTH
    // transports: the stdio path and the authenticated remote bridge both arrive
    // here through {@link executeAuthenticatedToolCall}, so there is no
    // transport-specific early path and no per-transport chain.
    //
    // `health` is the ONE non-dispatching surface (rc06 §21). It reaches no
    // subsystem, reads no workspace, spawns no process and inspects no Git
    // state, so it emits no lifecycle evidence and is not gated — which is what
    // leaves an operator a bounded informational surface while the process is
    // latched. Everything else, INCLUDING `system_status` (which stats a
    // workspace path), is privileged.
    const isNonDispatchingHealthSurface = toolName === 'health';

    // The durable chain exists exactly when a transport was composed over a
    // verified store, which `start()` guarantees: it runs the frozen §22.1
    // sequence to step 12 before binding anything, and it refuses to bind at all
    // when no audit configuration was supplied. A server that was never started
    // has no transport, no session and no reachable caller, and keeps the
    // historical in-memory chain its backward-compatibility suites were written
    // against — it is not a second authority for any started process.
    const durableChainActive = this.auditRuntime !== undefined;
    let lifecycleOperationId: string | undefined;

    /**
     * The ONE semantic request projection shared by STARTED and COMPLETED
     * (rc06 §32).
     *
     * `operationId` is the lifecycle binder, so both records must describe the
     * SAME operation. Building them from one closure — rather than two
     * independently written literals — is what makes that structural: there is
     * no second recomputation that could drift, and no raw request object is
     * ever placed into persistent storage.
     */
    const buildInvocationRecordBody = (
      execution: AuditRecord['execution'],
      error: AuditRecord['error'],
    ): Omit<AuditRecord, 'eventId' | 'sequenceNumber' | 'integrity'> => ({
      timestamp: startTime,
      actor: auditActor,
      target: {
        workspaceId: targetWorkspace.workspaceId,
        workspacePath: targetWorkspace.rootPath,
      },
      invocation: {
        toolName,
        parametersRedacted: auditParams,
        payloadHash: auditPayloadHash,
      },
      policy: {
        // Truthful classification: an approved execution is recorded as
        // REQUIRE_APPROVAL, never as an ordinary ALLOW.
        decision: effectiveDecisionLabel,
        ruleId: effectiveRuleIdForAudit,
        evaluationDurationMs: evalDuration,
        ...(consumedApprovalRequestId === undefined
          ? {}
          : { approvalId: consumedApprovalRequestId }),
      },
      ...(consumedApprovalRequestId === undefined
        ? {}
        : {
            approval: {
              requestId: consumedApprovalRequestId,
              state: 'CONSUMED' as const,
              source: 'MCP' as const,
            },
          }),
      execution,
      error,
    });

    if (durableChainActive && !isNonDispatchingHealthSurface) {
      // (a) Audit availability, re-checked immediately before the durable
      //     STARTED write. Section 1a already refused a latched or exhausted
      //     process before any approval state existed; this second check is not
      //     redundant, because policy evaluation and approval redemption are
      //     `await` boundaries and a concurrent invocation can latch the process
      //     between them. The chain is checked again at the last moment that a
      //     refusal can still prevent every subsystem call.
      try {
        this.assertPrivilegedDispatchAllowed();
      } catch (gateErr: unknown) {
        const refusal = boundedAuditRefusal(gateErr);
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(refusal.toJSON(), null, 2) }],
        };
      }

      // (b) STARTED, durably complete BEFORE the subsystem boundary. If this
      //     write fails, the operation is aborted and the subsystem receives
      //     ZERO calls: there is no read/mutation distinction here, because a
      //     read that cannot be evidenced is treated exactly as a mutation that
      //     cannot be evidenced.
      //
      //     Ordering note (rc06 §34): an approval is consumed BEFORE this point,
      //     exactly as it always has been. When STARTED persistence then fails,
      //     the approval stays CONSUMED and is never rolled back — the same
      //     frozen semantics the pre-existing `approval-audit-failed` path has
      //     always had, where a consumed-but-never-executed mutation is the
      //     documented outcome. Nothing new is invented here.
      lifecycleOperationId = randomUUID();
      const startedOperationId = lifecycleOperationId;
      try {
        await this.appendDurableRecord(
          buildInvocationRecordBody(
            {
              // The Task-1 status vocabulary is closed and deliberately not
              // widened (rc06 §7.1, §22.2). A STARTED record's authority is
              // `lifecycle.phase`; its `execution` block records only that the
              // invocation became eligible here, with zero elapsed terminal
              // time — it makes no claim about an outcome that has not happened.
              status: 'SUCCESS',
              startTime,
              endTime: startTime,
              durationMs: 0,
            },
            undefined,
          ),
          { operationId: startedOperationId, phase: 'STARTED' },
        );
      } catch (startedErr: unknown) {
        const refusal = boundedAuditRefusal(startedErr);
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(refusal.toJSON(), null, 2) }],
        };
      }
    }

    // 4. Tool Execution within Authorized Boundaries

    let result: unknown;
    let arcError: ArcError | undefined;
    let auditArcError: ArcError | undefined;
    let bytesRead = 0;

    try {
      if (isCompositeTool && compositePlan) {
        try {
          const admissionTicket = createServerCompositeAdmissionTicket({
            toolName,
            admittedPlanHash: compositePlanHash!,
            workspaceId: targetWorkspace.workspaceId,
            operationId: lifecycleOperationId || 'composite-operation',
          });

          const compositeResult = await enterCompositeInvocation(toolName, async () => {
            return await runWithCompositeAdmissionTicket(admissionTicket, async () => {
              return await executeCompositePlan({
                plan: compositePlan!,
                admittedPlanHash: compositePlanHash!,
                actor,
                targetWorkspace,
                internalExecutor: this.#internalDeterministicExecutor,
                registry: this.#deterministicRegistry,
                aggregateTimeoutMs: this.#task4AggregateTimeoutMs,
                testPostAdmissionMutationHook:
                  this.#testCompositeHarness?.testPostAdmissionMutationHook,
              });
            });
          });

          if (this.#testCompositeHarness?.toolName === toolName) {
            result = compositeResult;
            if (compositeResult.status === 'FAILED') {
              arcError = ArcError.internalError(`Composite tool '${toolName}' execution failed.`);
            }
          } else if (toolName === 'arc_verify') {
            const suite = (validatedParams.suite || 'all') as
              'all' | 'format' | 'lint' | 'typecheck' | 'test';
            const verifyResponse = projectArcVerifyResponse(compositeResult, suite);
            result = verifyResponse;

            if (compositeResult.aggregateTimedOut) {
              auditArcError = ArcError.compositeTimeout(
                'Composite verification exceeded aggregate timeout ceiling.',
              );
            } else if (verifyResponse.status === 'TIMED_OUT') {
              auditArcError = ArcError.executionTimeout(
                `Verification step '${verifyResponse.failedStep || 'unknown'}' timed out.`,
              );
            } else if (verifyResponse.status === 'FAILED') {
              auditArcError = ArcError.internalError(
                `Verification step '${verifyResponse.failedStep || 'unknown'}' failed.`,
              );
            }
          } else if (toolName === 'arc_test') {
            const stepResult = compositeResult.steps[0];
            if (
              stepResult?.status === 'FAILED' &&
              stepResult.errorMessage?.includes('Workspace process limit reached')
            ) {
              throw ArcError.concurrencyExceeded(stepResult.errorMessage);
            }

            const requestedTarget = (
              validatedParams.testPath
                ? (compositePlan.steps[0]?.argv.find(
                    (a) =>
                      !a.startsWith('-') && a !== '--test' && !a.startsWith('--test-reporter='),
                  ) ?? '.')
                : '.'
            ) as string;

            const testResponse = projectArcTestResponse(compositeResult, requestedTarget);
            result = testResponse;

            if (testResponse.status === 'TIMED_OUT') {
              auditArcError = ArcError.executionTimeout('Test execution timed out.');
            } else if (testResponse.status === 'FAILED') {
              auditArcError = ArcError.internalError('Test execution failed.');
            }
          }
        } catch (execErr: unknown) {
          if (
            toolName === 'arc_test' &&
            execErr instanceof ArcError &&
            execErr.code === 'RESOURCE_EXHAUSTED' &&
            execErr.message.includes('Workspace process limit reached')
          ) {
            arcError = ArcError.concurrencyExceeded(execErr.message);
          } else {
            arcError =
              execErr instanceof ArcError ? execErr : ArcError.internalError(String(execErr));
          }
        }
      } else {
        switch (toolName) {
          case 'health': {
            // Truthful runtime reporting: the policy engine is active only when a
            // usable effective Layer-2 engine was initialized. An explicitly
            // configured but invalid policy reports UNHEALTHY with no fallback.
            const policyEngineActive = this.effectivePolicyEngine !== undefined;
            const gatewayStatus = this.remoteGateway?.getStatus();
            // A bound listener whose certificate has expired cannot serve new
            // sessions, so it is neither active nor healthy.
            const gatewayDegradedForHealth = gatewayStatus?.degraded === true;
            // The bounded RC-06 audit block (rc06 §22.2, §31). STATE and COUNTS
            // only: no audit directory, no key path, no public key body, no
            // endpoint, no receipt body, no spool filename or hash, no host path.
            const auditHealth: AuditHealthMetadata | undefined = this.auditRuntime?.getHealth();
            const health: HealthResponse = {
              status: !policyEngineActive
                ? 'UNHEALTHY'
                : gatewayDegradedForHealth || this.auditRuntime?.isDegraded() === true
                  ? 'DEGRADED'
                  : 'HEALTHY',
              version: '0.6.0-rc06',
              stage: 'RC-06',
              policyEngineActive,
              // A chain is always active: the durable RC-06 chain on a started
              // server, the in-memory chain otherwise. The durable chain's own
              // STATE is reported by `audit.persistence` and by `status`, so this
              // frozen RC-01 field keeps its original meaning rather than being
              // overloaded into a second, weaker health signal.
              auditActive: true,
              authorizedWorkspacesCount: this.workspaceRegistry.getWorkspaces().length,
              transportMode: this.transportMode,
              remoteGatewayActive: gatewayStatus?.activeAndServing ?? false,
              // §16/§17: authentication is active only while a remote gateway is
              // actually admitting authenticated requests. A degraded gateway has
              // latched its certificate expiry and refuses every new TLS and
              // session admission, so it reports authentication inactive too.
              authenticationActive:
                this.transportMode === 'remote' && (gatewayStatus?.activeAndServing ?? false),
              // Counts only, from the two existing authorities: the gateway's
              // authoritative trust store and the ONE process-local session
              // manager. No device list, no session list, no identifier.
              enrolledDevicesCount: this.remoteGateway?.getEnrolledDeviceCount() ?? 0,
              activeSessionsCount: this.sessionManager.getActiveSessionCount(),
              // A bounded informational surface, and nothing more. `health` is the
              // ONE tool that reaches no subsystem (rc06 §21): reporting the
              // degraded condition must not become a read-only escape hatch, so
              // this block is emitted here and the latch is enforced everywhere
              // else.
              ...(auditHealth === undefined ? {} : { audit: auditHealth }),
              // Only safe, bounded fields cross this boundary: no certificate or
              // key bytes, no file paths, no pins, no peer addresses.
              ...(gatewayStatus === undefined
                ? {}
                : {
                    remoteGatewayDegraded: gatewayStatus.degraded,
                    ...(gatewayStatus.degradedReason === undefined
                      ? {}
                      : {
                          remoteGatewayDegradedReason: gatewayStatus.degradedReason,
                          degradedReason: gatewayStatus.degradedReason,
                        }),
                  }),
            };
            result = health;
            break;
          }

          case 'system_status': {
            let workspaceDiskFreeBytes = 0;
            if (targetWorkspace.rootPath) {
              try {
                const fsStat = statfsSync(targetWorkspace.rootPath);
                workspaceDiskFreeBytes = Number(fsStat.bavail) * Number(fsStat.bsize);
              } catch {
                // ignore
              }
            }
            const sysStatus: SystemStatusResponse = {
              os: platform(),
              arch: arch(),
              cpuCount: cpus().length,
              memoryTotalBytes: totalmem(),
              memoryFreeBytes: freemem(),
              workspaceDiskFreeBytes,
            };
            result = sysStatus;
            break;
          }

          case 'list_directory': {
            const listRes = await this.filesystemSubsystem.listDirectory(
              targetWorkspace.rootPath,
              validatedParams,
            );
            result = listRes;
            break;
          }

          case 'read_file': {
            if (!validatedParams.path) {
              throw ArcError.invalidRequestSchema('Path parameter is required for read_file.');
            }
            const readRes = await this.filesystemSubsystem.readFile(
              targetWorkspace.rootPath,
              validatedParams as { path: string; offset?: number; length?: number },
            );
            bytesRead = readRes.bytesRead;
            result = readRes;
            break;
          }

          case 'search_files': {
            if (!validatedParams.pattern) {
              throw ArcError.invalidRequestSchema(
                'Pattern parameter is required for search_files.',
              );
            }
            const searchRes = await this.filesystemSubsystem.searchFiles(
              targetWorkspace.rootPath,
              validatedParams as { pattern: string; subPath?: string; maxResults?: number },
            );
            result = searchRes;
            break;
          }

          case 'search_text': {
            if (!validatedParams.query) {
              throw ArcError.invalidRequestSchema('Query parameter is required for search_text.');
            }
            const textRes = await this.filesystemSubsystem.searchText(
              targetWorkspace.rootPath,
              validatedParams as {
                query: string;
                isRegex?: boolean;
                filePattern?: string;
                maxMatches?: number;
              },
            );
            result = textRes;
            break;
          }

          case 'git_status': {
            const statusRes = await this.gitSubsystem.getStatus(
              targetWorkspace.rootPath,
              validatedParams,
            );
            result = statusRes;
            break;
          }

          case 'git_diff': {
            const diffRes = await this.gitSubsystem.getDiff(
              targetWorkspace.rootPath,
              validatedParams,
            );
            result = diffRes;
            break;
          }

          case 'git_log': {
            const logRes = await this.gitSubsystem.getLog(
              targetWorkspace.rootPath,
              validatedParams,
            );
            result = logRes;
            break;
          }

          case 'arc_repo_status': {
            result = await enterCompositeInvocation(toolName, async () => {
              return await handleArcRepoStatus({
                targetWorkspace: {
                  workspaceId: targetWorkspace.workspaceId,
                  rootPath: targetWorkspace.rootPath,
                  isGitRepo: targetWorkspace.isGitRepo,
                },
                gitSubsystem: this.gitSubsystem,
                filesystemSubsystem: this.filesystemSubsystem,
                timeoutMs: this.#task2TimeoutMs,
              });
            });
            break;
          }

          case 'arc_worktree_status': {
            result = await enterCompositeInvocation(toolName, async () => {
              return await handleArcWorktreeStatus({
                targetWorkspace: {
                  workspaceId: targetWorkspace.workspaceId,
                  rootPath: targetWorkspace.rootPath,
                  isGitRepo: targetWorkspace.isGitRepo,
                },
                validatedParams,
                gitSubsystem: this.gitSubsystem,
                filesystemSubsystem: this.filesystemSubsystem,
                timeoutMs: this.#task2TimeoutMs,
              });
            });
            break;
          }

          case 'arc_review_diff': {
            result = await enterCompositeInvocation(toolName, async () => {
              return await handleArcReviewDiff({
                targetWorkspace: {
                  workspaceId: targetWorkspace.workspaceId,
                  rootPath: targetWorkspace.rootPath,
                  isGitRepo: targetWorkspace.isGitRepo,
                },
                validatedParams,
                gitSubsystem: this.gitSubsystem,
                filesystemSubsystem: this.filesystemSubsystem,
                timeoutMs: this.#task3TimeoutMs,
              });
            });
            break;
          }

          case 'arc_ci_status': {
            result = await enterCompositeInvocation(toolName, async () => {
              return await handleArcCiStatus({
                targetWorkspace: {
                  workspaceId: targetWorkspace.workspaceId,
                  rootPath: targetWorkspace.rootPath,
                  isGitRepo: targetWorkspace.isGitRepo,
                },
                validatedParams: validatedParams as ArcCiStatusRequest,
                gitSubsystem: this.gitSubsystem,
                filesystemSubsystem: this.filesystemSubsystem,
              });
            });
            break;
          }

          case 'arc_stage_evidence': {
            result = await enterCompositeInvocation(toolName, async () => {
              return await handleArcStageEvidence({
                targetWorkspace: {
                  workspaceId: targetWorkspace.workspaceId,
                  rootPath: targetWorkspace.rootPath,
                  isGitRepo: targetWorkspace.isGitRepo,
                },
                validatedParams: validatedParams as unknown as ArcStageEvidenceRequest,
                gitSubsystem: this.gitSubsystem,
                auditRuntime: this.auditRuntime,
                currentOperationId: lifecycleOperationId,
              });
            });
            break;
          }

          case 'run_command': {
            if (!this.terminalSubsystem) {
              throw ArcError.policyDenied(
                'Terminal subsystem is not available in this configuration.',
              );
            }
            if (!validatedParams.executable) {
              throw ArcError.invalidRequestSchema(
                'Executable parameter is required for run_command.',
              );
            }
            const cmdRes = await this.terminalSubsystem.executeCommand(
              validatedParams as unknown as RunCommandRequest,
              actor,
              targetWorkspace,
            );
            result = cmdRes;
            break;
          }

          case 'process_status': {
            if (!this.terminalSubsystem) {
              throw ArcError.policyDenied(
                'Terminal subsystem is not available in this configuration.',
              );
            }
            const psRes = this.terminalSubsystem.getProcessStatus(
              validatedParams.processId as string,
              actor,
              targetWorkspace,
            );
            result = psRes;
            break;
          }

          case 'process_output': {
            if (!this.terminalSubsystem) {
              throw ArcError.policyDenied(
                'Terminal subsystem is not available in this configuration.',
              );
            }
            const outputRes = this.terminalSubsystem.getProcessOutput(
              validatedParams.processId as string,
              {
                offset: validatedParams.offset as number | undefined,
                stdoutCursor: validatedParams.stdoutCursor as number | undefined,
                stderrCursor: validatedParams.stderrCursor as number | undefined,
                maxBytes: validatedParams.maxBytes as number | undefined,
                workspaceId: validatedParams.workspaceId as string | undefined,
              },
              validatedParams.maxBytes as number | undefined,
              actor,
              targetWorkspace,
            );
            result = outputRes;
            break;
          }

          case 'terminate_process': {
            if (!this.terminalSubsystem) {
              throw ArcError.policyDenied(
                'Terminal subsystem is not available in this configuration.',
              );
            }
            const termRes = await this.terminalSubsystem.terminateProcess(
              validatedParams.processId as string,
              validatedParams.signal as 'SIGTERM' | 'SIGKILL' | undefined,
              actor,
              targetWorkspace,
            );
            result = termRes;
            break;
          }

          // RC-03 mutation routes (RC-04 Task 4). Each of these is reachable ONLY
          // after a successful atomic APPROVED -> CONSUMED transition during THIS
          // invocation. The guard is invocation-local state, never derived from
          // parameters, actor input, a policy ALLOW, or any request property.
          //
          // Only validated business parameters are forwarded; the reserved control
          // object was removed before schema validation and is never passed here.
          case 'create_file': {
            this.assertApprovalConsumed(approvalConsumedForExecution, toolName);
            result = await this.filesystemSubsystem.createFile(targetWorkspace.rootPath, {
              path: validatedParams.path as string,
              content: validatedParams.content as string,
            } as never);
            break;
          }

          case 'write_file': {
            this.assertApprovalConsumed(approvalConsumedForExecution, toolName);
            result = await this.filesystemSubsystem.writeFile(targetWorkspace.rootPath, {
              path: validatedParams.path as string,
              content: validatedParams.content as string,
              expectedHash: validatedParams.expectedHash as string,
              overwrite: true,
            } as never);
            break;
          }

          case 'delete_file': {
            this.assertApprovalConsumed(approvalConsumedForExecution, toolName);
            result = await this.filesystemSubsystem.deleteFile(targetWorkspace.rootPath, {
              path: validatedParams.path as string,
              expectedHash: validatedParams.expectedHash as string,
            } as never);
            break;
          }

          case 'move_file': {
            this.assertApprovalConsumed(approvalConsumedForExecution, toolName);
            result = await this.filesystemSubsystem.moveFile(targetWorkspace.rootPath, {
              sourcePath: validatedParams.sourcePath as string,
              destinationPath: validatedParams.destinationPath as string,
              expectedSourceHash: validatedParams.expectedSourceHash as string,
            } as never);
            break;
          }

          case 'apply_patch': {
            this.assertApprovalConsumed(approvalConsumedForExecution, toolName);
            // dryRun: true still belongs to RC03_MUTATION_TOOLS and still requires
            // human approval; there is no dry-run bypass.
            result = await this.filesystemSubsystem.applyPatch(targetWorkspace.rootPath, {
              patch: validatedParams.patch as string,
              dryRun: validatedParams.dryRun === true,
              ...(validatedParams.fuzz !== undefined ? { fuzz: validatedParams.fuzz } : {}),
            } as never);
            break;
          }

          default:
            // Defense-in-depth backstop. A mutation tool must never reach an
            // unguarded execution path, whatever the policy outcome was.
            if ((RC03_MUTATION_TOOLS as readonly string[]).includes(toolName)) {
              throw ArcError.policyDenied(
                `Tool '${toolName}' requires verified human approval consumption before execution.`,
              );
            }
            throw ArcError.policyDenied(`Tool '${toolName}' execution route not configured.`);
        }
      }
    } catch (err: unknown) {
      if (err instanceof ArcError) {
        arcError = err;
      } else {
        arcError = ArcError.internalError('An internal error occurred during tool execution.');
      }
    }

    const endMs = Date.now();
    const endTime = new Date().toISOString();

    // 5. Structured Audit Event (Data Minimization First)
    //
    // The terminal record is built from the SAME projection the STARTED record
    // used, so STARTED and COMPLETED describe one semantic operation bound by
    // `operationId` (rc06 §32). It is then disposed of in exactly one of two
    // ways:
    //
    //  - a privileged operation appends it to the DURABLE chain as its terminal
    //    COMPLETED record; or
    //  - the non-dispatching `health` surface, which emits no lifecycle
    //    evidence, keeps it on the historical in-memory chain alone.
    //
    // Either way there is exactly one record per invocation per chain, and the
    // durable chain receives the same minimized, redacted projection the
    // in-memory chain has always received — there is no second, weaker
    // serialization path.
    const effectiveAuditError = auditArcError ?? arcError;
    const terminalExecution: AuditRecord['execution'] = {
      // Truthful terminal outcome (rc06 §34): an execution failure is still a
      // completed invocation, and a timeout is a timeout, not a generic error.
      status: deriveTerminalExecutionStatus(effectiveAuditError),
      startTime,
      endTime,
      durationMs: endMs - startMs,
      bytesRead: bytesRead > 0 ? bytesRead : undefined,
    };
    const terminalBody = buildInvocationRecordBody(
      terminalExecution,
      effectiveAuditError
        ? {
            code: effectiveAuditError.code,
            message: sanitizeClientErrorMessage(effectiveAuditError.message),
          }
        : undefined,
    );

    if (lifecycleOperationId === undefined) {
      await this.auditLogger.log(terminalBody);
    } else {
      // Post-dispatch durability (rc06 §14, §15). The subsystem has already
      // run, so a failure here means the outcome can no longer be evidenced:
      // the process-wide latch is set, every later privileged invocation through
      // EITHER transport is refused, and the caller is NOT told the operation
      // succeeded. The durable STARTED remains truthful evidence — it is
      // precisely what makes the uncertain outcome recoverable as
      // RECOVERY_INDETERMINATE after a restart — and no rollback, no synthetic
      // DENIED and no false SUCCESS terminal record is invented.
      try {
        await this.appendDurableRecord(terminalBody, {
          operationId: lifecycleOperationId,
          phase: 'COMPLETED',
        });
      } catch {
        this.auditRuntime?.latchDegradedAuditFailure();
        const refusal = boundedAuditRefusal(undefined);
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify(refusal.toJSON(), null, 2) }],
        };
      }
    }

    // Execution lifecycle evidence, emitted ONLY when this invocation actually
    // consumed an approval. Ordered after the ordinary invocation record, and
    // committed before the MCP response returns.
    if (consumedApprovalContext !== undefined) {
      this.approvalAuditSink.onApprovalLifecycleEvent({
        eventType: effectiveAuditError
          ? 'APPROVED_EXECUTION_FAILED'
          : 'APPROVED_EXECUTION_SUCCEEDED',
        requestId: consumedApprovalContext.requestId,
        state: 'CONSUMED',
        toolName: consumedApprovalContext.toolName,
        actor: consumedApprovalContext.actor,
        workspaceId: consumedApprovalContext.workspaceId,
        workspaceRootHash: consumedApprovalContext.workspaceRootHash,
        policyHash: consumedApprovalContext.policyHash,
        occurredAt: new Date().toISOString(),
      });
      try {
        await this.approvalAuditSink.flush();
      } catch {
        // Required lifecycle evidence could not be committed. The subsystem
        // call already happened, but a client MUST NOT receive a successful
        // result for an approved execution whose evidence is missing: fail the
        // invocation closed with a sanitized error instead of returning the
        // result. An already-failing execution keeps its more specific error;
        // the chain retains the queued evidence and keeps failing closed on
        // every later flush. The execution fact stays truthfully recorded above.
        arcError ??= ArcError.internalError(
          'Required approval audit evidence could not be recorded.',
        );
      }
    }

    // 6. Sanitized Response Formatting
    if (arcError) {
      const sanitizedError = new ArcError({
        code: arcError.code,
        category: arcError.category,
        message: sanitizeClientErrorMessage(arcError.message),
        retryable: arcError.retryable,
        remediationHint: arcError.remediationHint
          ? sanitizeClientErrorMessage(arcError.remediationHint)
          : undefined,
      });

      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify(sanitizedError.toJSON(), null, 2),
          },
        ],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  }

  public async start(): Promise<void> {
    // RC-06 Task 6 stage 1..11 — BEFORE step 12, which is everything below.
    //
    // The full-history verification, reconciliation and runtime-cursor stages
    // run to completion first, and no transport is bound until they have. There
    // is therefore no window in which a session exists, a listener is reachable,
    // or a tool call can be dispatched before the durable audit chain is
    // verified and reconciled — for either transport, because both bind below.
    //
    // A failure here propagates unchanged: nothing is bound, nothing is served,
    // and `start()` has released everything stage 1..11 acquired.
    await this.startAuditRuntime();

    // Exactly one transport mode runs per process (§4 L-4). In remote mode the
    // stdio transport is never connected, so there is no second listener and no
    // way for a remote failure to fall back to stdio.
    if (this.transportMode === 'remote') {
      const remoteConfig = this.remoteConfig;
      if (remoteConfig === undefined) {
        throw new Error('Remote transport requires remote gateway configuration.');
      }
      // The SAME pending-enrollment authority the admin IPC channel uses. A
      // challenge created locally through the authenticated operator channel is
      // therefore immediately completable remotely, with no copying and no
      // cross-process or cross-instance synchronization.
      const gateway = new RemoteGateway(remoteConfig, {
        enrollmentManager: this.enrollmentManager,
        // RC-05 Task 10: the ONE audit chain. The gateway, the enrollment
        // bootstrap, the MCP surface, and the local admin channel all write
        // their lifecycle evidence into THIS logger's existing append-only
        // chain — there is no second logger, no gateway-only chain, and no
        // external persistence (RC-06 owns that).
        auditLogger: this.auditLogger,
      });

      // ONE admission authority per process, over the ONE process-wide Layer C
      // limiter. The transport admits every authenticated MCP request with it —
      // POST, GET SSE, DELETE, `tools/list`, `ping`, and `tools/call` alike — and
      // the execution bridge executes against the SAME instance, so a `tools/call`
      // is neither authenticated nor rate-charged a second time.
      const admission = new RemoteRequestAdmission({
        sessionManager: this.sessionManager,
        authenticatedLimiter: this.authenticatedRequestLimiter,
      });

      // The remote execution bridge is composed over the gateway's CURRENT
      // authoritative trust store. The resolver is called per request and is
      // never cached, so device revocation takes effect on the next call.
      //
      // It is built BEFORE the listener binds, so the ONE remote execution path
      // exists before any request can reach it.
      this.remoteExecutionBridge = new RemoteExecutionBridge({
        sessionManager: this.sessionManager,
        resolveActiveDeviceIdentity: (spkiPin) => gateway.resolveActiveDeviceIdentity(spkiPin),
        sink: this,
        authenticatedLimiter: this.authenticatedRequestLimiter,
        admission,
      });

      // §3/§5/RC05-NEG-06: the stateful Streamable HTTP surface is constructed
      // and attached BEFORE the listener binds. Its constructor obtains the
      // session-ID generator from the ONE Task-5 session authority and throws if
      // that authority is unusable, so a missing or stateless-capable
      // configuration fails startup with NO listener bound — there is no
      // fallback path to a stateless transport, and no window in which `/mcp` is
      // reachable without its transport.
      try {
        const surface = new RemoteMcpSurface({
          sessionManager: this.sessionManager,
          admission,
          createSessionServer: () => this.createRemoteSessionServer(),
          publicHostname: remoteConfig.publicHostname,
          // The memoized-per-chain sink, so the surface writes into the SAME
          // chain and the SAME queue the gateway already emits through.
          auditSink: getGatewayAuditSink(this.auditLogger),
        });
        gateway.attachMcpSurface(surface);

        // RC-05 Task 9: the ONE local device/session administration authority,
        // composed over the gateway's CURRENT authoritative trust state and the
        // Task-8 transport registry that remote requests are actually served
        // from. It is attached before the listener binds, so there is no window
        // in which the local operator channel answers administration requests
        // from anything other than the running trust root.
        //
        // The authority is attached ONLY here, in the remote composition. A
        // process with no authoritative remote trust state therefore has no
        // administration authority at all, and every administration method
        // fails closed rather than loading a second device store.
        if (this.adminIpcServer) {
          this.adminIpcServer.attachDeviceAdministration(
            new GatewayDeviceAdministration(
              gateway.getDeviceTrustAuthority(),
              this.sessionManager,
              () => surface,
              getGatewayAuditSink(this.auditLogger),
            ),
          );
        }

        await gateway.start();
      } catch (err: unknown) {
        // All-or-nothing: nothing is left bound, and stdio is NOT started as a
        // fallback.
        await gateway.stop();
        throw err;
      }
      this.remoteGateway = gateway;

      // The admin channel is a LOCAL IPC channel, so starting it in remote mode
      // adds no network surface: it remains local-only and Ed25519-authenticated,
      // and it is the operator's device/enrollment administration path. It is
      // started only after the gateway is bound, and a failure here tears the
      // whole process back down rather than leaving a half-active composition.
      if (this.adminIpcServer) {
        try {
          await this.adminIpcServer.start();
        } catch (err: unknown) {
          await this.stop();
          if (err instanceof AdminIpcError) {
            throw new Error(`Admin IPC channel failed to start: ${err.reason}`, { cause: err });
          }
          throw new Error('Admin IPC channel failed to start.', { cause: err });
        }
      }
      return;
    }

    this.transport = new StdioServerTransport();
    await this.server.connect(this.transport);

    // The admin channel exists only when explicitly composed in. There is no
    // implicit endpoint and no default socket path.
    if (this.adminIpcServer) {
      try {
        await this.adminIpcServer.start();
      } catch (err: unknown) {
        // Fail closed and tear down stdio rather than running without the
        // admin channel the operator configured.
        await this.stop();
        if (err instanceof AdminIpcError) {
          throw new Error(`Admin IPC channel failed to start: ${err.reason}`, { cause: err });
        }
        throw new Error('Admin IPC channel failed to start.', { cause: err });
      }
    }
  }

  /** The single active transport mode for this process. */
  public getTransportMode(): 'stdio' | 'remote' {
    return this.transportMode;
  }

  /** Bounded, non-secret remote gateway status. Undefined in stdio mode. */
  public getRemoteGatewayStatus(): RemoteGatewayStatus | undefined {
    return this.remoteGateway?.getStatus();
  }

  /**
   * The application-level remote execution entry point (RC-05 Task 6).
   *
   * Undefined until a remote gateway is bound, and undefined in stdio mode,
   * which has no device trust store and no sessions. Task 8 will call this from
   * the Streamable HTTP transport; Task 6 exposes it as an application API only
   * — no network path reaches it, and the Task-4 `/mcp` route remains deny-only.
   */
  public getRemoteExecutionBridge(): RemoteExecutionBridge | undefined {
    return this.remoteExecutionBridge;
  }

  /**
   * Builds the MCP `Server` for ONE remote session (RC-05 Task 8).
   *
   * Deliberately assembled from the SAME parts as the stdio server — the same
   * SDK `Server` shape, the same `ALL_TOOL_DEFINITIONS` catalog, and the same
   * `CallToolRequestSchema` entry point — so remote cannot expose a tool the
   * local catalog does not already define, and there is no second tool
   * dispatcher anywhere.
   *
   * The one difference is the destination of a tool call: stdio calls
   * `dispatchToolCall`, while a remote call routes into the EXISTING
   * `RemoteExecutionBridge`, which is the only component that may construct a
   * trusted remote actor. The admission the transport already granted for this
   * HTTP request travels with it as `extra.authInfo.admission`, so the bridge
   * authenticates nothing a second time and charges no second rate token or
   * concurrency slot. Neither path calls a subsystem, the policy kernel, the
   * approval manager, or the filesystem directly — both converge on
   * `executeAuthenticatedToolCall`.
   */
  private createRemoteSessionServer(): Server {
    const server = new Server(
      {
        name: 'cesspace-arc',
        version: '0.6.0-rc06',
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: ALL_TOOL_DEFINITIONS,
      };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const bridge = this.remoteExecutionBridge;
      const requestContext = readRemoteRequestContext(extra.authInfo);
      if (bridge === undefined || requestContext === null) {
        // Fail closed. A remote MCP call whose gateway request context is
        // missing cannot be attributed to a trusted mTLS identity, so it is
        // refused with exactly the error an unauthenticated caller receives.
        // The SPKI pin is NOT taken from the session context as a fallback:
        // identity must come from the request that is being executed.
        return this.remoteToolErrorResult(ArcError.unauthenticated());
      }

      const toolName = request.params.name;

      // The generic registered-tool gate, applied AFTER the authentication
      // check above and BEFORE the bridge: an authenticated caller naming an
      // unregistered tool gets the transport-level `-32601`, exactly as it
      // would for an unregistered JSON-RPC method.
      //
      // It is intentionally ordered after the fail-closed context check so an
      // UNAUTHENTICATED caller still receives the SAME generic refusal for
      // every name, registered or not: the registration check must not become
      // an oracle that tells an unauthenticated prober which names exist.
      //
      // No administrative name list appears here. The rule is membership in the
      // one registered catalog, so no administrative capability can be reached
      // through the remote call path by any name, and no administrative name is
      // confirmed or denied by the shape of the answer.
      if (!isRegisteredToolName(toolName)) {
        throw unknownToolError();
      }

      const parameters = (request.params.arguments || {}) as Record<string, unknown>;

      try {
        return remoteToolResult(
          await bridge.executeRemoteToolCall({
            trustedSpkiPin: requestContext.spkiPin,
            presentedSessionId: requestContext.presentedSessionId,
            authorizationHeader: requestContext.authorizationHeader,
            hasExistingSessionContext: requestContext.presentedSessionId !== null,
            // The admission THIS HTTP request already paid for: the tool call
            // executes against it, so ONE Layer C rate token and ONE §26 C-3
            // slot cover the whole request rather than being charged twice.
            admission: requestContext.admission,
            toolName,
            parameters,
          }),
        );
      } catch (err: unknown) {
        // The bridge throws only bounded ArcErrors, and only BEFORE dispatch.
        // Anything the shared pipeline itself rejects is already returned from
        // `executeAuthenticatedToolCall` as a tool result, so it never arrives
        // here and its semantics are unchanged.
        return this.remoteToolErrorResult(
          err instanceof ArcError ? err : ArcError.internalError('Tool execution failed.'),
        );
      }
    });

    return server;
  }

  /**
   * Converts a pre-dispatch ArcError into a tool result.
   *
   * Uses the same error shape and the same message sanitizer as the shared
   * stdio pipeline, so a remote caller observes identical error semantics.
   */
  private remoteToolErrorResult(arcError: ArcError): {
    isError: true;
    content: Array<{ type: 'text'; text: string }>;
  } {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              code: arcError.code,
              category: arcError.category,
              message: sanitizeClientErrorMessage(arcError.message),
              retryable: arcError.retryable,
            },
            null,
            2,
          ),
        },
      ],
    };
  }

  public async flushAudit(): Promise<void> {
    await this.approvalAuditSink.flush();
    if (this.processRegistry) {
      await this.processRegistry.flushLifecycleEvents();
    }
  }

  public async stop(): Promise<void> {
    if (this.remoteGateway !== undefined) {
      await this.remoteGateway.stop();
      this.remoteGateway = undefined;
    }
    // Sessions are volatile and die with the gateway that authenticated them.
    this.remoteExecutionBridge = undefined;
    this.sessionManager.clear();
    // Layer C rate and concurrency state is equally volatile: a restarted
    // gateway gets a clean budget, and nothing about it is ever persisted.
    this.authenticatedRequestLimiter.reset();
    if (this.adminIpcServer) {
      await this.adminIpcServer.stop();
    }
    // The last records are committed before the surface that produced them is
    // released. A failure to secure them is NOT swallowed — it is rethrown after
    // teardown below, because a caller that is told shutdown succeeded has been
    // told the evidence is durable. What it must not do is stop the teardown:
    // the flush is the one step here that can fail on a store that is already
    // degraded, and abandoning the rest of this method on that failure would
    // strand the transport, the writer lock and every descriptor the runtime
    // holds, leaving a process that holds its store lock forever and a listener
    // that never closes. Teardown therefore always runs to completion, and the
    // failure is reported from the end.
    let flushFailure: unknown;
    try {
      await this.flushAudit();
    } catch (cause: unknown) {
      flushFailure = cause;
    }
    if (this.transport) {
      await this.transport.close();
    }
    // The durable audit runtime is released LAST, once no transport can produce
    // another record: its writer lock and every descriptor it owns (active
    // segment, checkpoint artifact, anchor receipt ledger, anchor spool) must
    // outlive the surface that writes through them, and releasing it earlier
    // would leave a window in which a served request has no durable chain to
    // write to. One deterministic order, no descriptor or lock leak, and no
    // historical evidence deleted.
    await this.closeAuditRuntime();
    if (flushFailure !== undefined) {
      throw flushFailure;
    }
  }

  /**
   * Releases the durable audit runtime and its single-writer lock.
   *
   * Idempotent, so a failed `start()` followed by a `stop()` cannot double
   * release. A runtime that was never established is a no-op.
   *
   * @internal
   */
  private async closeAuditRuntime(): Promise<void> {
    const runtime = this.auditRuntime;
    this.auditRuntime = undefined;
    await runtime?.close();
  }
}

/* -------------------------------------------------------------------------- *
 * RC-06 Task 6 — bounded audit failure projection (rc06 §26, §44).
 * -------------------------------------------------------------------------- */

/**
 * Reduces an arbitrary startup or runtime audit failure to a bounded code.
 *
 * The audit layer's own coded errors carry a machine-readable code and no host
 * path; anything else — a raw `fs` error, a `node:crypto` error, a PEM parse
 * failure, an `AggregateError` — is reported as `AUDIT_FAILURE` rather than
 * passed through. No directory, key path, endpoint, stack trace, inode or device
 * number can reach a caller or a log line through this function.
 */
export function boundedAuditFailureCode(cause: unknown): string {
  const code = (cause as { code?: unknown })?.code;
  return typeof code === 'string' && /^[A-Z][A-Z0-9_]{2,63}$/.test(code) ? code : 'AUDIT_FAILURE';
}

/**
 * The bounded client-facing refusal for a privileged dispatch the audit layer
 * will not admit (rc06 §11, §18, §26, §27).
 *
 * The message names no audit directory, key path, endpoint, receipt, spool file,
 * sequence number or subsystem detail. It is the SAME refusal for a read and for
 * a mutation: there is no read-only escape hatch.
 */
export function boundedAuditRefusal(cause: unknown): ArcError {
  const code = boundedAuditFailureCode(cause);
  if (code === 'ANCHOR_SPOOL_FULL' || code === 'AUDIT_STORAGE_EXHAUSTED') {
    return ArcError.resourceExhausted(
      'Audit evidence capacity is exhausted. Privileged operations are halted until an operator remediates the audit store.',
    );
  }
  return ArcError.internalError(
    'Privileged operations are halted: durable audit evidence could not be secured.',
  );
}

/**
 * The bounded client-facing failure for a refusal the audit layer could not
 * record durably (rc06 §22, §26, §44).
 *
 * The operation it answers WAS denied by policy, authorization or schema — and
 * that denial is evidence. A process that returns the ordinary denial has told
 * the caller "you were refused, and the refusal is on the record" when the
 * durable chain holds no such record, and it has done so at the exact moment the
 * process-wide degraded latch was set. The two facts are not interchangeable, so
 * they do not share a response.
 *
 * It carries the frozen bounded vocabulary and the same shape as
 * {@link boundedAuditRefusal}: no `fs` error, no directory, no key path, no
 * sequence number, no store detail, and no raw cause.
 */
export function boundedAuditPersistenceFailure(cause: unknown): ArcError {
  const code = boundedAuditFailureCode(cause);
  if (code === 'ANCHOR_SPOOL_FULL' || code === 'AUDIT_STORAGE_EXHAUSTED') {
    return ArcError.resourceExhausted(
      'Audit evidence capacity is exhausted, so the refusal could not be recorded. Privileged operations are halted until an operator remediates the audit store.',
    );
  }
  return ArcError.internalError(
    'The refusal could not be recorded durably: durable audit evidence could not be secured. Privileged operations are halted until restart.',
  );
}

/**
 * The truthful terminal status for a COMPLETED record (rc06 §34).
 *
 * A subsystem exception is `ERROR`, a timeout is `TIMEOUT`, and a clean return
 * is `SUCCESS`. No subsystem in the frozen composition produces a cancellation
 * outcome, so `CANCELLED` stays representable in the Task-1 vocabulary and
 * unreachable here rather than being invented.
 */
export function deriveTerminalExecutionStatus(
  arcError: ArcError | undefined,
): 'SUCCESS' | 'ERROR' | 'TIMEOUT' {
  if (arcError === undefined) return 'SUCCESS';
  return arcError.code === 'EXECUTION_TIMEOUT' || arcError.code === 'COMPOSITE_TIMEOUT'
    ? 'TIMEOUT'
    : 'ERROR';
}

/**
 * Sanitizes client-facing error messages by stripping host paths, usernames, and raw internal traces.
 */
export function sanitizeClientErrorMessage(msg: string): string {
  if (!msg) return msg;
  let sanitized = msg;
  // Redact absolute host paths
  sanitized = sanitized.replace(
    /(?:\/(?:home|tmp|root|Users|var|private|opt|etc|usr|bin|lib)[^\s'",;:]*)/gi,
    '[REDACTED_PATH]',
  );
  sanitized = sanitized.replace(/[a-zA-Z]:\\[^\s'",;:]*/g, '[REDACTED_PATH]');

  // Redact active username
  const user = process.env.USER || process.env.USERNAME;
  if (user && user.length > 1) {
    const userRegex = new RegExp(`\\b${user}\\b`, 'g');
    sanitized = sanitized.replace(userRegex, '[USER]');
  }
  return sanitized;
}

/**
 * Factory helper to construct a fully configured ArcMcpServer.
 */
export function createArcMcpServer(config?: Partial<ArcServerConfig>): ArcMcpServer {
  const workspaceRegistry = new WorkspaceRegistry();
  const processRegistry = new ProcessRegistry();
  const securityKernel = new SecurityKernel(workspaceRegistry, processRegistry);
  const auditLogger = new AuditLogger();
  const filesystemSubsystem = new FilesystemSubsystem();
  const gitSubsystem = new GitSubsystem();
  const terminalSubsystem = new ControlledProcessRunner(processRegistry);
  const internalExecutor = createServerDeterministicExecutor(terminalSubsystem);

  const approvalStateManager = new ApprovalStateManager();

  // RC-05 Task 4: exactly ONE pending-enrollment authority per process. It is
  // passed to the local admin IPC channel (which creates and cancels pending
  // challenges) and to the remote gateway (which completes them over mTLS), so
  // both halves of an enrollment observe the same in-memory challenge table.
  const enrollmentManager = new EnrollmentManager();

  // RC-05 Task 6: exactly ONE session authority for the process. It is handed to
  // the server, which composes the remote execution bridge over it, so session
  // issuance and request authentication can never diverge.
  const sessionManager = new SessionManager();

  // The admin channel is opt-in through trusted launch configuration only.
  // Supplying exactly one half of the pair fails closed rather than starting
  // partially configured admin access.
  let adminIpcServer: AdminIpcServer | undefined;
  const admin = config?.admin;
  if (admin !== undefined && admin !== null) {
    const endpoint = admin.endpoint;
    const operatorPublicKeyB64 = admin.operatorPublicKeyB64;
    const hasEndpoint = typeof endpoint === 'string' && endpoint.length > 0;
    const hasKey = typeof operatorPublicKeyB64 === 'string' && operatorPublicKeyB64.length > 0;
    if (hasEndpoint !== hasKey) {
      throw new Error(
        'Admin channel requires both a local IPC endpoint and an operator public key; exactly one was supplied.',
      );
    }
    if (hasEndpoint && hasKey) {
      adminIpcServer = new AdminIpcServer({
        endpoint: endpoint as string,
        operatorPublicKeyB64: operatorPublicKeyB64 as string,
        approvalStateManager,
        auditLogger,
        // The SAME instance the remote bootstrap endpoint completes against.
        enrollmentManager,
      });
    }
  }

  const server = new ArcMcpServer(
    workspaceRegistry,
    securityKernel,
    auditLogger,
    filesystemSubsystem,
    gitSubsystem,
    config,
    terminalSubsystem,
    processRegistry,
    approvalStateManager,
    adminIpcServer,
    enrollmentManager,
    sessionManager,
  );
  const access = SERVER_INTERNAL_ACCESS.get(server)!;
  access.setInternalDeterministicExecutor(internalExecutor);
  access.setDeterministicRegistry(createProductionDeterministicRegistry());
  return server;
}

// Auto-start in stdio transport mode if executed directly as script
// Enforces P1-05: Remove implicit process.cwd() authorization; require explicit trusted workspace configuration
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const configuredWorkspace = process.env.CESSPACE_WORKSPACE;
  const authorizedRoots = configuredWorkspace
    ? [
        {
          id: 'workspace',
          path: configuredWorkspace,
        },
      ]
    : [];

  // Admin channel configuration is PUBLIC-ONLY on the server side.
  // CESSPACE_ARC_ADMIN_SOCKET is the local IPC endpoint and
  // CESSPACE_ARC_ADMIN_PUBLIC_KEY_B64 is the operator public key (not a secret).
  // No private key, secret, or bearer token is accepted in server environment.
  const adminSocket = process.env.CESSPACE_ARC_ADMIN_SOCKET;
  const adminPublicKey = process.env.CESSPACE_ARC_ADMIN_PUBLIC_KEY_B64;
  const hasAdminSocket = typeof adminSocket === 'string' && adminSocket.length > 0;
  const hasAdminKey = typeof adminPublicKey === 'string' && adminPublicKey.length > 0;

  if (hasAdminSocket !== hasAdminKey) {
    process.stderr.write(
      'Admin channel requires both CESSPACE_ARC_ADMIN_SOCKET and CESSPACE_ARC_ADMIN_PUBLIC_KEY_B64; exactly one was supplied.\n',
    );
    process.exit(1);
  }

  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots,
    defaultWorkspaceId: configuredWorkspace ? 'workspace' : undefined,
    admin: hasAdminSocket
      ? { endpoint: adminSocket, operatorPublicKeyB64: adminPublicKey }
      : undefined,
  });

  server.start().catch((err) => {
    process.stderr.write(`Failed to start CesSpace ARC MCP Server: ${err.message}\n`);
    process.exit(1);
  });
}
