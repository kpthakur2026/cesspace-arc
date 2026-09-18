#!/usr/bin/env node
import { platform, arch, cpus, totalmem, freemem } from 'node:os';
import { statfsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

import {
  ArcError,
  PolicyOutcome,
  type HealthResponse,
  type SystemStatusResponse,
  type PolicyEvaluationContext,
  type RunCommandRequest,
} from '@cesspace-arc/protocol';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
  type WorkspaceRecord,
  RC03_MUTATION_TOOLS,
} from '@cesspace-arc/policy';
import { AdminIpcError, AdminIpcServer } from './admin-ipc.js';
import { AuditLogger, computeSha256, canonicalJson } from '@cesspace-arc/audit';
import { FilesystemSubsystem } from '@cesspace-arc/filesystem';
import { GitSubsystem } from '@cesspace-arc/git';
import {
  ProcessRegistry,
  type IProcessLifecycleSink,
  type ProcessLifecycleEvent,
} from '@cesspace-arc/processes';
import { ControlledProcessRunner, type ITerminalSubsystem } from '@cesspace-arc/terminal';
import { z } from 'zod';

export interface ArcServerConfig {
  transport: 'stdio';
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
} as const;

/**
 * Definition of the 4 RC-02 MCP Tools (controlled terminal & process execution).
 */
export const RC02_TOOL_DEFINITIONS: Tool[] = [
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
];

/**
 * Definition of the 5 RC-03 MCP Tools (file mutation primitives).
 * All invocations require explicit human approval and remain non-executable in RC-03.
 */
export const RC03_TOOL_DEFINITIONS: Tool[] = [
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
];

/**
 * Definition of the 9 RC-01 MCP Tools.
 */
export const RC01_TOOL_DEFINITIONS: Tool[] = [
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
];

/**
 * Authoritative complete list of all 18 registered tools (RC-01 + RC-02 + RC-03).
 * Used directly by the ListTools handler.
 */
export const ALL_TOOL_DEFINITIONS: Tool[] = [
  ...RC01_TOOL_DEFINITIONS,
  ...RC02_TOOL_DEFINITIONS,
  ...RC03_TOOL_DEFINITIONS,
];

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

export class ProcessAuditSink implements IProcessLifecycleSink {
  constructor(
    private auditLogger: AuditLogger,
    private workspaceRegistry: WorkspaceRegistry,
  ) {}

  public async onProcessEvent(event: ProcessLifecycleEvent): Promise<void> {
    const ws = this.workspaceRegistry.getWorkspace(event.workspaceId);
    const workspacePath = ws ? ws.rootPath : '';

    const isFailure = event.eventType === 'PROCESS_SPAWN_FAILED';
    const isTimeout = event.eventType === 'PROCESS_TIMEOUT';

    await this.auditLogger.log({
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
  private defaultWorkspaceId?: string;
  public processRegistry?: ProcessRegistry;

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
    public readonly approvalStateManager?: ApprovalStateManager,
    /**
     * Optional authenticated local admin channel. Started only when trusted
     * launch configuration supplies both an endpoint and an operator key.
     */
    public readonly adminIpcServer?: AdminIpcServer,
  ) {
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

    this.server = new Server(
      {
        name: 'cesspace-arc',
        version: '0.3.0-rc03',
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

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: ALL_TOOL_DEFINITIONS,
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      const params = (request.params.arguments || {}) as Record<string, unknown>;
      return this.dispatchToolCall(toolName, params);
    });
  }

  /**
   * The single, authoritative execution pipeline:
   * MCP request -> schema validation -> caller context -> workspace binding
   *   -> policy admission -> filesystem/git safety checks -> tool execution
   *   -> structured audit event -> sanitized MCP response.
   */
  public async dispatchToolCall(
    toolName: string,
    parameters: Record<string, unknown>,
    actorOverride?: Partial<PolicyEvaluationContext['actor']>,
  ): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }> {
    const startTime = new Date().toISOString();
    const startMs = Date.now();

    // 1. Authenticated / Local Caller Context
    const auditActor = {
      clientId: actorOverride?.clientId ?? 'local-stdio-caller',
      clientType: actorOverride?.clientType ?? 'mcp-client',
      sessionId: actorOverride?.sessionId ?? 'stdio-session-01',
      deviceId: actorOverride?.deviceId ?? 'local-machine',
    };

    const actor: PolicyEvaluationContext['actor'] = {
      ...auditActor,
      authenticated: actorOverride?.authenticated ?? true,
    };

    // 2. Pre-Admission Tool Name & Runtime Schema Validation Gate (P1-02)
    const schema = (TOOL_SCHEMAS as Record<string, z.ZodTypeAny | undefined>)[toolName];
    if (!schema) {
      const arcErr = ArcError.policyDenied(
        `Tool '${toolName}' is not permitted in RC-01 stage (read-only inspection core only).`,
      );
      const preAuditParams = sanitizePreValidationParameters(toolName, parameters);
      await this.auditLogger.log({
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

    const parseResult = schema.safeParse(parameters);
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
      const preAuditParams = sanitizePreValidationParameters(toolName, parameters);
      await this.auditLogger.log({
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

    // Caller Identity Gate (P1): run_command must fail closed before execution unless clientId and sessionId are non-empty
    if (toolName === 'run_command') {
      if (
        !actor.clientId ||
        !actor.sessionId ||
        actor.clientId.trim().length === 0 ||
        actor.sessionId.trim().length === 0
      ) {
        const arcErr = ArcError.policyDenied(
          'Access denied: run_command requires verified caller identity (clientId and sessionId).',
        );
        const preAuditParams = sanitizePreValidationParameters(toolName, parameters);
        await this.auditLogger.log({
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
        const preAuditParams = sanitizePreValidationParameters(toolName, parameters);
        await this.auditLogger.log({
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
        const preAuditParams = sanitizePreValidationParameters(toolName, parameters);
        await this.auditLogger.log({
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
        const preAuditParams = sanitizePreValidationParameters(toolName, parameters);
        await this.auditLogger.log({
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
        const preAuditParams = sanitizePreValidationParameters(toolName, parameters);
        await this.auditLogger.log({
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

    // Authoritative payload hash uses sanitized params for mutation tools (not raw params)
    const auditPayloadHash = computeSha256(canonicalJson(auditParams));

    // 3. Minimal Security Kernel Policy Admission (Default-Deny)
    const evalStart = Date.now();
    const decision = await this.securityKernel.evaluate(context);
    const evalDuration = Date.now() - evalStart;

    if (decision.outcome === PolicyOutcome.REQUIRE_APPROVAL) {
      // RC-03 gate: mutation tools require human approval — not available until RC-04.
      // Emit structured APPROVAL_REQUIRED audit record and return isError response.
      // Filesystem mutation methods MUST NOT be called.
      const endMs = Date.now();
      const endTime = new Date().toISOString();

      await this.auditLogger.log({
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
          ruleId: decision.matchingRuleId,
          evaluationDurationMs: evalDuration,
        },
        execution: {
          status: 'DENIED',
          startTime,
          endTime,
          durationMs: endMs - startMs,
        },
        error: {
          code: 'APPROVAL_REQUIRED',
          message: decision.reason,
        },
      });

      const arcError = ArcError.approvalRequired(decision.reason);
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify(arcError.toJSON(), null, 2),
          },
        ],
      };
    }

    if (decision.outcome !== PolicyOutcome.ALLOW) {
      // DENY or any other non-ALLOW, non-REQUIRE_APPROVAL outcome
      const endMs = Date.now();
      const endTime = new Date().toISOString();

      await this.auditLogger.log({
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
          decision: decision.effect,
          ruleId: decision.matchingRuleId,
          evaluationDurationMs: evalDuration,
        },
        execution: {
          status: 'DENIED',
          startTime,
          endTime,
          durationMs: endMs - startMs,
        },
        error: {
          code: 'POLICY_DENIED',
          message: decision.reason,
        },
      });

      const arcError = ArcError.policyDenied(decision.reason);
      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify(arcError.toJSON(), null, 2),
          },
        ],
      };
    }

    // 4. Tool Execution within Authorized Boundaries

    let result: unknown;
    let executionStatus: 'SUCCESS' | 'ERROR' = 'SUCCESS';
    let arcError: ArcError | undefined;
    let bytesRead = 0;

    try {
      switch (toolName) {
        case 'health': {
          const health: HealthResponse = {
            status: 'HEALTHY',
            version: '0.3.0-rc03',
            stage: 'RC-03',
            policyEngineActive: true,
            auditActive: true,
            authorizedWorkspacesCount: this.workspaceRegistry.getWorkspaces().length,
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
            throw ArcError.invalidRequestSchema('Pattern parameter is required for search_files.');
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
          const logRes = await this.gitSubsystem.getLog(targetWorkspace.rootPath, validatedParams);
          result = logRes;
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

        default:
          // Defense-in-depth: RC-03 mutation tools MUST NEVER reach this execution path.
          // Even if policy evaluation unexpectedly returns ALLOW for a mutation tool
          // (e.g. via a future refactor or configuration error), this backstop ensures
          // that filesystem mutation methods are never called in RC-03.
          if ((RC03_MUTATION_TOOLS as readonly string[]).includes(toolName)) {
            throw ArcError.policyDenied(
              `RC-03 backstop: tool '${toolName}' requires human approval and cannot be executed. ` +
                `Approval workflow is not available until RC-04.`,
            );
          }
          throw ArcError.policyDenied(`Tool '${toolName}' execution route not configured.`);
      }
    } catch (err: unknown) {
      executionStatus = 'ERROR';
      if (err instanceof ArcError) {
        arcError = err;
      } else {
        arcError = ArcError.internalError('An internal error occurred during tool execution.');
      }
    }

    const endMs = Date.now();
    const endTime = new Date().toISOString();

    // 5. Structured Audit Event (Data Minimization First)
    await this.auditLogger.log({
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
        decision: 'ALLOW',
        ruleId: decision.matchingRuleId,
        evaluationDurationMs: evalDuration,
      },
      execution: {
        status: executionStatus,
        startTime,
        endTime,
        durationMs: endMs - startMs,
        bytesRead: bytesRead > 0 ? bytesRead : undefined,
      },
      error: arcError
        ? {
            code: arcError.code,
            message: sanitizeClientErrorMessage(arcError.message),
          }
        : undefined,
    });

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

  public async flushAudit(): Promise<void> {
    if (this.processRegistry) {
      await this.processRegistry.flushLifecycleEvents();
    }
  }

  public async stop(): Promise<void> {
    if (this.adminIpcServer) {
      await this.adminIpcServer.stop();
    }
    await this.flushAudit();
    if (this.transport) {
      await this.transport.close();
    }
  }
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

  const approvalStateManager = new ApprovalStateManager();

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
      });
    }
  }

  return new ArcMcpServer(
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
  );
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
