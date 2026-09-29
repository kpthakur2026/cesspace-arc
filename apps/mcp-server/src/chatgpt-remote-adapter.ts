/**
 * CesSpace ARC — ChatGPT Remote MCP Transport Adapter
 *
 * Implements a remote MCP transport adapter suitable for private tunnel or
 * reverse-proxy deployment (e.g. OpenAI ChatGPT custom actions / developer mode).
 *
 * Invariants:
 * 1. The adapter itself DOES NOT call filesystem, git, terminal, process, or
 *    approval subsystems directly.
 * 2. All tool execution flows exclusively through the shared authenticated ARC
 *    tool execution path (`sink.executeAuthenticatedToolCall`).
 * 3. Does not invent a second tool catalog; returns ARC's authoritative 25 tools.
 * 4. Opt-in only; no listener starts unless explicitly configured.
 * 5. Fails closed on any missing authentication, oversized payload, unknown tool,
 *    or policy denial.
 */

import http from 'node:http';
import net from 'node:net';
import { randomUUID } from 'node:crypto';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { ArcError } from '@cesspace-arc/protocol';
import type { AuditLogger } from '@cesspace-arc/audit';
import { exceedsMaxJsonNestingDepth } from './json-nesting.js';
import {
  findActorFieldInjection,
  type CompleteActor,
  type RemoteToolCallResult,
} from './remote-execution.js';
import {
  BoundedRequestLimiter,
  LAYER_C_BURST,
  LAYER_C_REQUESTS_PER_MINUTE,
  MAX_LAYER_C_KEYS,
  MAX_OUTSTANDING_REQUESTS_PER_SESSION,
} from './remote-resource-limits.js';
import {
  resolveChatGptRemoteConfig,
  verifyBearerToken,
  type ChatGptRemoteConfig,
  type ResolvedChatGptRemoteConfig,
} from './chatgpt-profile.js';

export const MAX_HEADER_BYTES = 16 * 1024; // 16 KiB

/**
 * Sink interface required by ChatGptRemoteAdapter.
 * Matches ArcMcpServer's shared authenticated tool dispatch pipeline.
 */
export interface ChatGptExecutionSink {
  executeAuthenticatedToolCall(
    actor: CompleteActor,
    toolName: string,
    parameters: Record<string, unknown>,
    options?: { signal?: AbortSignal },
  ): Promise<RemoteToolCallResult>;
  getRegisteredTools?: () => Tool[];
  isRegisteredTool?: (name: string) => boolean;
}

export interface ChatGptRemoteAdapterDeps {
  config: ChatGptRemoteConfig;
  sink: ChatGptExecutionSink;
  auditLogger?: AuditLogger;
}

export interface ChatGptAdapterStatus {
  active: boolean;
  bindHost: string;
  port: number;
  path: string;
  tunnelHostname?: string;
  activeSessions: number;
}

interface ActiveSessionRecord {
  sessionId: string;
  createdAt: number;
  lastActive: number;
}

export class ChatGptRemoteAdapter {
  private readonly rawConfig: ChatGptRemoteConfig;
  private readonly sink: ChatGptExecutionSink;
  private readonly auditLogger?: AuditLogger;
  private resolvedConfig?: ResolvedChatGptRemoteConfig;
  private server?: http.Server;
  private actualPort = 0;
  private readonly sessions = new Map<string, ActiveSessionRecord>();
  private readonly openSockets = new Set<net.Socket>();
  private readonly limiter: BoundedRequestLimiter;

  constructor(deps: ChatGptRemoteAdapterDeps) {
    this.rawConfig = deps.config;
    this.sink = deps.sink;
    this.auditLogger = deps.auditLogger;
    this.limiter = new BoundedRequestLimiter({
      requestsPerMinute: LAYER_C_REQUESTS_PER_MINUTE,
      burst: LAYER_C_BURST,
      maxKeys: MAX_LAYER_C_KEYS,
      maxOutstandingPerKey: MAX_OUTSTANDING_REQUESTS_PER_SESSION,
    });
  }

  /**
   * Starts the HTTP listener if enabled.
   */
  public async start(): Promise<void> {
    this.resolvedConfig = resolveChatGptRemoteConfig(this.rawConfig);
    if (!this.resolvedConfig.enabled) {
      return;
    }

    const { bindHost, port } = this.resolvedConfig;

    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        this.handleRequest(req, res).catch((_err: unknown) => {
          if (!res.headersSent) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id: null,
                error: {
                  code: -32603,
                  message: 'Internal server error in remote adapter.',
                },
              }),
            );
          }
        });
      });

      server.on('connection', (socket) => {
        this.openSockets.add(socket);
        socket.once('close', () => {
          this.openSockets.delete(socket);
        });
      });

      server.on('error', (err) => {
        reject(err);
      });

      server.listen(port, bindHost, () => {
        const address = server.address();
        if (address && typeof address === 'object') {
          this.actualPort = address.port;
        } else {
          this.actualPort = port;
        }
        this.server = server;
        resolve();
      });
    });
  }

  /**
   * Stops the HTTP listener and terminates active connections.
   */
  public async stop(): Promise<void> {
    if (!this.server) {
      return;
    }

    const server = this.server;
    this.server = undefined;

    for (const socket of this.openSockets) {
      socket.destroy();
    }
    this.openSockets.clear();
    this.sessions.clear();

    return new Promise((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  }

  /**
   * Returns runtime status of the adapter.
   */
  public getStatus(): ChatGptAdapterStatus {
    return {
      active: this.server !== undefined && this.server.listening,
      bindHost: this.resolvedConfig?.bindHost ?? this.rawConfig.bindHost ?? '127.0.0.1',
      port: this.actualPort,
      path: this.resolvedConfig?.path ?? this.rawConfig.path ?? '/mcp',
      tunnelHostname: this.resolvedConfig?.tunnelHostname,
      activeSessions: this.sessions.size,
    };
  }

  /**
   * Primary ingress handler for incoming HTTP requests from the tunnel.
   */
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const config = this.resolvedConfig;
    if (!config || !config.enabled) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'ChatGPT remote profile is not active' }));
      return;
    }

    // 1. Host header validation (DNS rebinding and tunnel spoofing protection)
    if (config.tunnelHostname !== undefined) {
      const rawHost = req.headers.host;
      if (!rawHost) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forbidden', message: 'Missing Host header' }));
        return;
      }
      const hostOnly = rawHost.split(':')[0].toLowerCase();
      if (hostOnly !== config.tunnelHostname.toLowerCase()) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forbidden', message: 'Host header mismatch' }));
        return;
      }
    }

    // 2. Path routing
    const parsedUrl = new URL(req.url ?? '/', 'http://localhost');
    const pathname = parsedUrl.pathname;

    // Handle health probe
    if (pathname === '/health') {
      const authHeader = req.headers.authorization;
      if (!verifyBearerToken(authHeader, config.expectedToken)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized', message: 'Authentication required' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          service: 'cesspace-arc',
          profile: 'chatgpt-remote',
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // Verify MCP path
    if (pathname !== config.path) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not Found' }));
      return;
    }

    // 3. Supported methods: POST (MCP JSON-RPC), GET (SSE / status), DELETE (session close), OPTIONS
    const method = (req.method ?? 'GET').toUpperCase();
    if (method === 'OPTIONS') {
      res.writeHead(204, {
        Allow: 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Mcp-Session-Id',
      });
      res.end();
      return;
    }

    if (!['GET', 'POST', 'DELETE'].includes(method)) {
      res.writeHead(405, {
        Allow: 'GET, POST, DELETE, OPTIONS',
        'Content-Type': 'application/json',
      });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
      return;
    }

    // 4. Mandatory Authentication: verify bearer token
    const authHeader = req.headers.authorization;
    if (!verifyBearerToken(authHeader, config.expectedToken)) {
      if (method === 'POST') {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32000,
              message: 'UNAUTHENTICATED',
              data: { code: 'UNAUTHENTICATED' },
            },
          }),
        );
      } else {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized', message: 'Authentication required' }));
      }
      return;
    }

    // 5. Session identification & rate limiting
    let sessionId = req.headers['mcp-session-id'];
    if (Array.isArray(sessionId)) {
      sessionId = sessionId[0];
    }
    if (sessionId !== undefined && sessionId.length > 0) {
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(sessionId)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32000, message: 'INVALID_SESSION_TOKEN' },
          }),
        );
        return;
      }
    } else {
      sessionId = randomUUID();
    }

    const sessionKey = `chatgpt:${sessionId}`;
    const consumeResult = this.limiter.consume(sessionKey);
    if (!consumeResult.consumed) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32000,
            message: 'RATE_LIMIT_EXCEEDED',
            data: { code: 'RATE_LIMIT_EXCEEDED' },
          },
        }),
      );
      return;
    }

    const holdResult = this.limiter.tryHold(consumeResult.bucket);
    if (!holdResult.held) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32000,
            message: 'RATE_LIMIT_EXCEEDED',
            data: { code: 'RATE_LIMIT_EXCEEDED' },
          },
        }),
      );
      return;
    }

    this.sessions.set(sessionId, {
      sessionId,
      createdAt: Date.now(),
      lastActive: Date.now(),
    });

    try {
      if (method === 'GET') {
        await this.handleGet(req, res, sessionId);
      } else if (method === 'DELETE') {
        this.handleDelete(req, res, sessionId);
      } else {
        await this.handlePost(req, res, sessionId, config.maxRequestBodyBytes);
      }
    } finally {
      holdResult.release();
    }
  }

  /**
   * Handles GET requests: opens an SSE stream or returns connection status.
   */
  private async handleGet(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    sessionId: string,
  ): Promise<void> {
    const acceptHeader = req.headers.accept ?? '';
    if (acceptHeader.includes('text/event-stream')) {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'Mcp-Session-Id': sessionId,
      });
      res.write(`event: endpoint\ndata: ${this.resolvedConfig?.path ?? '/mcp'}\n\n`);

      const keepAliveInterval = setInterval(() => {
        if (!res.writableEnded) {
          res.write(': keepalive\n\n');
        }
      }, 15000);

      req.on('close', () => {
        clearInterval(keepAliveInterval);
      });
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Mcp-Session-Id': sessionId,
    });
    res.end(
      JSON.stringify({
        status: 'ok',
        transport: 'chatgpt-remote',
        sessionId,
      }),
    );
  }

  /**
   * Handles DELETE requests: terminates the current session.
   */
  private handleDelete(
    _req: http.IncomingMessage,
    res: http.ServerResponse,
    sessionId: string,
  ): void {
    this.sessions.delete(sessionId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        jsonrpc: '2.0',
        result: { sessionClosed: true },
      }),
    );
  }

  /**
   * Handles POST requests: reads JSON-RPC payload and dispatches tools.
   */
  private async handlePost(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    sessionId: string,
    maxBodyBytes: number,
  ): Promise<void> {
    // Read request body with strict size ceiling
    const rawBody = await this.readRequestBody(req, maxBodyBytes);
    if (rawBody === null) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Payload Too Large' }));
      return;
    }

    // Parse JSON
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' },
        }),
      );
      return;
    }

    // Nesting depth defense
    if (exceedsMaxJsonNestingDepth(parsed)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32600, message: 'Invalid Request: JSON nesting exceeds limit' },
        }),
      );
      return;
    }

    // Batching refusal (fail-closed per MCP specification)
    if (Array.isArray(parsed)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32600, message: 'JSON-RPC batching is not supported.' },
        }),
      );
      return;
    }

    if (typeof parsed !== 'object' || parsed === null) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32600, message: 'Invalid Request' },
        }),
      );
      return;
    }

    const jsonRpcMsg = parsed as {
      jsonrpc?: unknown;
      id?: unknown;
      method?: unknown;
      params?: unknown;
    };

    const requestId =
      typeof jsonRpcMsg.id === 'string' || typeof jsonRpcMsg.id === 'number' ? jsonRpcMsg.id : null;

    const method = typeof jsonRpcMsg.method === 'string' ? jsonRpcMsg.method : '';

    // Dispatch JSON-RPC methods
    switch (method) {
      case 'initialize': {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
        });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: { tools: {} },
              serverInfo: { name: 'cesspace-arc', version: '1.0.0' },
            },
          }),
        );
        return;
      }

      case 'notifications/initialized': {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: requestId, result: {} }));
        return;
      }

      case 'ping': {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: requestId, result: {} }));
        return;
      }

      case 'tools/list': {
        const tools = this.sink.getRegisteredTools ? this.sink.getRegisteredTools() : [];
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
        });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            result: { tools },
          }),
        );
        return;
      }

      case 'tools/call': {
        await this.handleToolCall(jsonRpcMsg.params, requestId, sessionId, res);
        return;
      }

      default: {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            error: {
              code: -32601,
              message: `Method not found: ${method}`,
            },
          }),
        );
        return;
      }
    }
  }

  /**
   * Handles tools/call: validates arguments, derives CompleteActor, and executes via shared sink.
   */
  private async handleToolCall(
    params: unknown,
    requestId: string | number | null,
    sessionId: string,
    res: http.ServerResponse,
  ): Promise<void> {
    if (typeof params !== 'object' || params === null || Array.isArray(params)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: requestId,
          error: { code: -32602, message: 'Invalid params for tools/call' },
        }),
      );
      return;
    }

    const { name, arguments: toolArgs } = params as {
      name?: unknown;
      arguments?: unknown;
    };

    if (typeof name !== 'string' || name.length === 0) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: requestId,
          error: { code: -32602, message: "Missing or invalid 'name' in tools/call" },
        }),
      );
      return;
    }

    const registeredTools = this.sink.getRegisteredTools ? this.sink.getRegisteredTools() : [];
    const isKnown = this.sink.isRegisteredTool
      ? this.sink.isRegisteredTool(name)
      : registeredTools.some((t) => t.name === name);

    if (!isKnown) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: requestId,
          error: { code: -32601, message: `Tool not found: ${name}` },
        }),
      );
      return;
    }

    const parameters =
      typeof toolArgs === 'object' && toolArgs !== null && !Array.isArray(toolArgs)
        ? (toolArgs as Record<string, unknown>)
        : {};

    // Parameter actor-field injection guard (prevents spoofing internal actor state)
    const injection = findActorFieldInjection(parameters);
    if (injection !== null) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: requestId,
          error: {
            code: -32602,
            message: `Invalid parameters for tool '${name}': reserved actor or transport identity field is not permitted.`,
          },
        }),
      );
      return;
    }

    // Construct the authoritative server-derived CompleteActor
    const actor: CompleteActor = {
      clientId: 'chatgpt-client',
      clientType: 'chatgpt-remote',
      deviceId: 'chatgpt-tunnel-gateway',
      sessionId,
      authenticated: true,
    };

    try {
      const callResult = await this.sink.executeAuthenticatedToolCall(actor, name, parameters);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Mcp-Session-Id': sessionId,
      });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: requestId,
          result: {
            content: callResult.content,
            isError: callResult.isError ?? false,
          },
        }),
      );
    } catch (err: unknown) {
      if (err instanceof ArcError) {
        // Known protocol error from pipeline (e.g. unknown tool or unauthenticated)
        if ((err.code as string) === 'UNREGISTERED_TOOL' || err.message.includes('Unknown tool')) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: requestId,
              error: { code: -32601, message: err.message },
            }),
          );
          return;
        }

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
        });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            result: {
              isError: true,
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({
                    error: err.code,
                    category: err.category,
                    message: err.message,
                  }),
                },
              ],
            },
          }),
        );
        return;
      }

      // Check generic unknown tool error shape
      const errMsg = err instanceof Error ? err.message : String(err);
      if (errMsg.includes('Unknown tool') || errMsg.includes('not a tool')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            error: { code: -32601, message: errMsg },
          }),
        );
        return;
      }

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Mcp-Session-Id': sessionId,
      });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: requestId,
          result: {
            isError: true,
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  error: 'INTERNAL_ERROR',
                  category: 'SYSTEM',
                  message: 'Tool execution failed.',
                }),
              },
            ],
          },
        }),
      );
    }
  }

  /**
   * Reads request body into a string, enforcing byte limit.
   * Returns null if the body exceeds maxBytes.
   */
  private readRequestBody(req: http.IncomingMessage, maxBytes: number): Promise<string | null> {
    return new Promise((resolve, reject) => {
      let totalBytes = 0;
      const chunks: Buffer[] = [];

      req.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > maxBytes) {
          req.pause();
          resolve(null);
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        if (totalBytes <= maxBytes) {
          resolve(Buffer.concat(chunks).toString('utf8'));
        }
      });

      req.on('error', (err) => {
        reject(err);
      });
    });
  }
}
