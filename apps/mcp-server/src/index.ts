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
} from '@cesspace-arc/protocol';
import { SecurityKernel, WorkspaceRegistry } from '@cesspace-arc/policy';
import { AuditLogger, computeSha256, canonicalJson } from '@cesspace-arc/audit';
import { FilesystemSubsystem } from '@cesspace-arc/filesystem';
import { GitSubsystem } from '@cesspace-arc/git';

export interface ArcServerConfig {
  transport: 'stdio';
  authorizedRoots: Array<{ id: string; path: string }>;
  defaultWorkspaceId?: string;
}

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

export class ArcMcpServer implements IArcMcpServer {
  private server: Server;
  private transport?: StdioServerTransport;
  private defaultWorkspaceId?: string;

  constructor(
    public readonly workspaceRegistry: WorkspaceRegistry,
    public readonly securityKernel: SecurityKernel,
    public readonly auditLogger: AuditLogger,
    public readonly filesystemSubsystem: FilesystemSubsystem,
    public readonly gitSubsystem: GitSubsystem,
    config?: Partial<ArcServerConfig>,
  ) {
    this.defaultWorkspaceId = config?.defaultWorkspaceId;

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
        version: '0.1.0-rc01',
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
        tools: RC01_TOOL_DEFINITIONS,
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
      clientId: actorOverride?.clientId || 'local-stdio-caller',
      clientType: actorOverride?.clientType || 'mcp-client',
      sessionId: actorOverride?.sessionId || 'stdio-session-01',
      deviceId: actorOverride?.deviceId || 'local-machine',
    };

    const actor: PolicyEvaluationContext['actor'] = {
      ...auditActor,
      authenticated: actorOverride?.authenticated ?? true,
    };

    // 2. Workspace Binding
    const requestedWorkspaceId =
      (parameters.workspaceId as string | undefined) ||
      (parameters.workspaceRoot as string | undefined) ||
      this.defaultWorkspaceId;

    let targetWorkspaceRecord = requestedWorkspaceId
      ? this.workspaceRegistry.getWorkspace(requestedWorkspaceId) ||
        this.workspaceRegistry.findWorkspaceForPath(requestedWorkspaceId)
      : undefined;

    if (!targetWorkspaceRecord) {
      const allWorkspaces = this.workspaceRegistry.getWorkspaces();
      if (allWorkspaces.length > 0) {
        targetWorkspaceRecord = allWorkspaces[0];
      }
    }

    const targetWorkspace: PolicyEvaluationContext['targetWorkspace'] = {
      workspaceId: targetWorkspaceRecord?.id || 'unbound',
      rootPath: targetWorkspaceRecord?.rootPath || '',
      isGitRepo: targetWorkspaceRecord?.isGitRepo || false,
    };

    const context: PolicyEvaluationContext = {
      actor,
      targetWorkspace,
      request: {
        toolName,
        parameters,
      },
      environment: {
        timestamp: startTime,
      },
    };

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
          parametersRedacted: parameters,
          payloadHash: computeSha256(canonicalJson(parameters)),
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
            version: '0.1.0-rc01',
            stage: 'RC-01',
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
            parameters,
          );
          result = listRes;
          break;
        }

        case 'read_file': {
          if (!parameters.path) {
            throw ArcError.invalidRequestSchema('Path parameter is required for read_file.');
          }
          const readRes = await this.filesystemSubsystem.readFile(
            targetWorkspace.rootPath,
            parameters as { path: string; offset?: number; length?: number },
          );
          bytesRead = readRes.bytesRead;
          result = readRes;
          break;
        }

        case 'search_files': {
          if (!parameters.pattern) {
            throw ArcError.invalidRequestSchema('Pattern parameter is required for search_files.');
          }
          const searchRes = await this.filesystemSubsystem.searchFiles(
            targetWorkspace.rootPath,
            parameters as { pattern: string; subPath?: string; maxResults?: number },
          );
          result = searchRes;
          break;
        }

        case 'search_text': {
          if (!parameters.query) {
            throw ArcError.invalidRequestSchema('Query parameter is required for search_text.');
          }
          const textRes = await this.filesystemSubsystem.searchText(
            targetWorkspace.rootPath,
            parameters as {
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
          const statusRes = await this.gitSubsystem.getStatus(targetWorkspace.rootPath, parameters);
          result = statusRes;
          break;
        }

        case 'git_diff': {
          const diffRes = await this.gitSubsystem.getDiff(targetWorkspace.rootPath, parameters);
          result = diffRes;
          break;
        }

        case 'git_log': {
          const logRes = await this.gitSubsystem.getLog(targetWorkspace.rootPath, parameters);
          result = logRes;
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
        arcError = ArcError.internalError((err as Error).message);
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
        parametersRedacted: parameters,
        payloadHash: computeSha256(canonicalJson(parameters)),
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
            message: arcError.message,
          }
        : undefined,
    });

    // 6. Sanitized Response Formatting
    if (arcError) {
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
 * Factory helper to construct a fully configured ArcMcpServer.
 */
export function createArcMcpServer(config?: Partial<ArcServerConfig>): ArcMcpServer {
  const workspaceRegistry = new WorkspaceRegistry();
  const securityKernel = new SecurityKernel(workspaceRegistry);
  const auditLogger = new AuditLogger();
  const filesystemSubsystem = new FilesystemSubsystem();
  const gitSubsystem = new GitSubsystem();

  return new ArcMcpServer(
    workspaceRegistry,
    securityKernel,
    auditLogger,
    filesystemSubsystem,
    gitSubsystem,
    config,
  );
}

// Auto-start in stdio transport mode if executed directly as script
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: [
      {
        id: 'workspace',
        path: process.env.CESSPACE_WORKSPACE || process.cwd(),
      },
    ],
  });

  server.start().catch((err) => {
    process.stderr.write(`Failed to start CesSpace ARC MCP Server: ${err.message}\n`);
    process.exit(1);
  });
}
