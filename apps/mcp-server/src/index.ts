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
  type HealthResponse,
  type SystemStatusResponse,
  type PolicyEvaluationContext,
  type RunCommandRequest,
} from '@cesspace-arc/protocol';
import { SecurityKernel, WorkspaceRegistry, type WorkspaceRecord } from '@cesspace-arc/policy';
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

/**
 * Strict Zod validation schemas for all permitted tools (RC-01 read-only + RC-02 controlled execution).
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
    })
    .strict(),
  process_output: z
    .object({
      processId: ProcessIdSchema,
      offset: z.number().int().min(0).optional(),
      maxBytes: z.number().int().min(1).max(131072).optional(),
    })
    .strict(),
  terminate_process: z
    .object({
      processId: ProcessIdSchema,
      signal: z.enum(['SIGTERM', 'SIGKILL']).optional(),
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
          description: 'Byte offset into the combined output buffer.',
          minimum: 0,
        },
        maxBytes: {
          type: 'integer',
          description: 'Maximum bytes to return (max 131072).',
          minimum: 1,
          maximum: 131072,
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
      },
      required: ['processId'],
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

export interface IArcMcpServer {
  start(): Promise<void>;
  stop(): Promise<void>;
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
        clientType: 'ces-agent',
        deviceId: 'device-0',
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
        version: '0.2.0-rc02',
      },
      {
        capabilities: {
          tools: {},
        },
      },
    );

    this.setupHandlers();
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [...RC01_TOOL_DEFINITIONS, ...RC02_TOOL_DEFINITIONS],
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
      await this.auditLogger.log({
        timestamp: startTime,
        actor: auditActor,
        target: { workspaceId: 'unbound', workspacePath: '' },
        invocation: {
          toolName,
          parametersRedacted: parameters,
          payloadHash: computeSha256(canonicalJson(parameters)),
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

      const issueMessages = parseResult.error.issues
        .map((iss) => `${iss.path.join('.') || 'root'}: ${iss.message}`)
        .join('; ');
      const arcErr = isReadLengthTooLarge
        ? ArcError.payloadTooLarge('Requested read length exceeds maximum allowed limit of 1 MiB.')
        : ArcError.invalidRequestSchema(
            `Invalid parameters for tool '${toolName}': ${issueMessages}`,
          );
      await this.auditLogger.log({
        timestamp: startTime,
        actor: auditActor,
        target: { workspaceId: 'unbound', workspacePath: '' },
        invocation: {
          toolName,
          parametersRedacted: parameters,
          payloadHash: computeSha256(canonicalJson(parameters)),
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
          message: arcErr.message,
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

    if (
      toolName === 'health' ||
      toolName === 'system_status' ||
      toolName === 'process_status' ||
      toolName === 'process_output' ||
      toolName === 'terminate_process'
    ) {
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
        // Process tools: resolve workspace from the process itself if available (P1-05)
        if (
          (toolName === 'process_status' ||
            toolName === 'process_output' ||
            toolName === 'terminate_process') &&
          validatedParams.processId &&
          this.processRegistry
        ) {
          const proc = this.processRegistry.getProcess(validatedParams.processId as string);
          if (proc) {
            targetWorkspaceRecord = this.workspaceRegistry.getWorkspace(proc.workspaceId);
          }
        }

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
    // For run_command, replace raw arguments with safe metadata (argCount, safeFlags)
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
    }

    // 3. Minimal Security Kernel Policy Admission (Default-Deny)
    const evalStart = Date.now();
    const decision = await this.securityKernel.evaluate(context);
    const evalDuration = Date.now() - evalStart;

    if (decision.outcome !== 2 /* PolicyOutcome.ALLOW */) {
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
          payloadHash: computeSha256(canonicalJson(validatedParams)),
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
            version: '0.2.0-rc02',
            stage: 'RC-02',
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
            validatedParams.offset as number | undefined,
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
        payloadHash: computeSha256(canonicalJson(validatedParams)),
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
  }

  public async stop(): Promise<void> {
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

  return new ArcMcpServer(
    workspaceRegistry,
    securityKernel,
    auditLogger,
    filesystemSubsystem,
    gitSubsystem,
    config,
    terminalSubsystem,
    processRegistry,
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

  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots,
    defaultWorkspaceId: configuredWorkspace ? 'workspace' : undefined,
  });

  server.start().catch((err) => {
    process.stderr.write(`Failed to start CesSpace ARC MCP Server: ${err.message}\n`);
    process.exit(1);
  });
}
