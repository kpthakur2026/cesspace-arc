/**
 * CesSpace ARC — ChatGPT Remote MCP Transport Adapter
 *
 * Implements a remote MCP transport adapter suitable for private tunnel or
 * reverse-proxy deployment (e.g. OpenAI ChatGPT custom actions / developer mode).
 *
 * Invariants:
 * 1. The adapter itself DOES NOT call filesystem, git, terminal, process, or
 *    approval subsystems directly.
 * 2. The adapter NEVER synthesizes a CompleteActor and NEVER sets authenticated: true.
 * 3. All tool execution and actor creation flows strictly through the server-owned
 *    ChatGptAuthBridge.
 * 4. Opt-in only; no listener starts unless explicitly configured.
 * 5. Fails closed on any missing authentication, oversized payload, unknown tool,
 *    or policy denial.
 */

import http from 'node:http';
import net from 'node:net';
import { ArcError } from '@cesspace-arc/protocol';
import type { AuditLogger } from '@cesspace-arc/audit';
import { exceedsMaxJsonNestingDepth } from './json-nesting.js';
import {
  BoundedRequestLimiter,
  LAYER_C_BURST,
  LAYER_C_REQUESTS_PER_MINUTE,
  MAX_LAYER_C_KEYS,
  MAX_OUTSTANDING_REQUESTS_PER_SESSION,
} from './remote-resource-limits.js';
import {
  resolveChatGptRemoteConfig,
  type ChatGptRemoteConfig,
  type ResolvedChatGptRemoteConfig,
} from './chatgpt-profile.js';
import type { ChatGptAuthBridge } from './chatgpt-auth-bridge.js';

export const MAX_HEADER_BYTES = 16 * 1024; // 16 KiB

export interface ChatGptRemoteAdapterDeps {
  config: ChatGptRemoteConfig;
  bridge: ChatGptAuthBridge;
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

export class ChatGptRemoteAdapter {
  private readonly rawConfig: ChatGptRemoteConfig;
  private readonly bridge: ChatGptAuthBridge;
  private readonly auditLogger?: AuditLogger;
  private resolvedConfig?: ResolvedChatGptRemoteConfig;
  private server?: http.Server;
  private actualPort = 0;
  private readonly openSockets = new Set<net.Socket>();
  private readonly limiter: BoundedRequestLimiter;

  constructor(deps: ChatGptRemoteAdapterDeps) {
    this.rawConfig = deps.config;
    this.bridge = deps.bridge;
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
   * Stops the HTTP listener and terminates existing connections.
   */
  public async stop(): Promise<void> {
    for (const socket of this.openSockets) {
      socket.destroy();
    }
    this.openSockets.clear();

    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server?.close(() => {
          resolve();
        });
      });
      this.server = undefined;
    }
    this.actualPort = 0;
  }

  /**
   * Returns adapter operational status.
   */
  public getStatus(): ChatGptAdapterStatus {
    const config = this.resolvedConfig;
    return {
      active: this.server !== undefined && this.actualPort > 0,
      bindHost: config?.bindHost ?? this.rawConfig.bindHost ?? '127.0.0.1',
      port: this.actualPort,
      path: config?.path ?? this.rawConfig.path ?? '/mcp',
      tunnelHostname: config?.tunnelHostname ?? this.rawConfig.tunnelHostname,
      activeSessions: this.bridge.getActiveSessionCount(),
    };
  }

  /**
   * Dispatches incoming HTTP requests according to MCP specification.
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
      if (!this.bridge.verifyTransportAuth(authHeader)) {
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

    if (method !== 'POST' && method !== 'GET' && method !== 'DELETE') {
      res.writeHead(405, {
        'Content-Type': 'application/json',
        Allow: 'GET, POST, DELETE, OPTIONS',
      });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
      return;
    }

    // 4. Transport credential check
    const authHeader = req.headers.authorization;
    if (!this.bridge.verifyTransportAuth(authHeader)) {
      if (method === 'POST') {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32001,
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

    // 5. Rate limiting & concurrency bounding
    const rawSessionId = req.headers['mcp-session-id'];
    const presentedSessionId = Array.isArray(rawSessionId) ? rawSessionId[0] : rawSessionId;

    if (presentedSessionId !== undefined && presentedSessionId.length > 0) {
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(presentedSessionId)) {
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
    }

    const sessionKey = `chatgpt:${presentedSessionId ?? 'pre-session'}`;
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
            message: 'CONCURRENCY_LIMIT_EXCEEDED',
            data: { code: 'CONCURRENCY_LIMIT_EXCEEDED' },
          },
        }),
      );
      return;
    }

    try {
      if (method === 'GET') {
        await this.handleGet(req, res, presentedSessionId, authHeader);
      } else if (method === 'DELETE') {
        this.handleDelete(req, res, presentedSessionId, authHeader);
      } else {
        await this.handlePost(req, res, presentedSessionId, authHeader, config.maxRequestBodyBytes);
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
    presentedSessionId: string | undefined,
    authHeader: string | undefined,
  ): Promise<void> {
    const acceptHeader = req.headers.accept ?? '';
    if (acceptHeader.includes('text/event-stream')) {
      try {
        const activeSession = this.bridge.validateSession(presentedSessionId, authHeader);
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
          'Mcp-Session-Id': activeSession.sessionId,
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
      } catch (err: unknown) {
        if (err instanceof ArcError && err.code === 'INVALID_SESSION_TOKEN') {
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
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized', message: 'Authentication required' }));
        return;
      }
    }

    res.writeHead(200, {
      'Content-Type': 'application/json',
      ...(presentedSessionId ? { 'Mcp-Session-Id': presentedSessionId } : {}),
    });
    res.end(
      JSON.stringify({
        status: 'ok',
        transport: 'chatgpt-remote',
        activeSessions: this.bridge.getActiveSessionCount(),
      }),
    );
  }

  /**
   * Handles DELETE requests: terminates the current session.
   */
  private handleDelete(
    _req: http.IncomingMessage,
    res: http.ServerResponse,
    presentedSessionId: string | undefined,
    authHeader: string | undefined,
  ): void {
    try {
      this.bridge.validateSession(presentedSessionId, authHeader);
      this.bridge.revokeSession(presentedSessionId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          result: { sessionClosed: true },
        }),
      );
    } catch (err: unknown) {
      if (err instanceof ArcError && err.code === 'INVALID_SESSION_TOKEN') {
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
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized', message: 'Authentication required' }));
    }
  }

  /**
   * Handles POST requests: receives MCP JSON-RPC payloads.
   */
  private async handlePost(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    presentedSessionId: string | undefined,
    authHeader: string | undefined,
    maxRequestBodyBytes: number,
  ): Promise<void> {
    const rawContentType = req.headers['content-type'] ?? '';
    const contentType = rawContentType.split(';')[0].trim().toLowerCase();
    if (contentType !== 'application/json') {
      res.writeHead(415, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32700,
            message: "Unsupported Media Type: expected 'application/json'",
          },
        }),
      );
      return;
    }

    const rawContentLength = req.headers['content-length'];
    if (rawContentLength !== undefined) {
      const parsedLength = parseInt(rawContentLength, 10);
      if (!Number.isFinite(parsedLength) || parsedLength > maxRequestBodyBytes) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32000,
              message: `Payload Too Large: request exceeds maximum of ${maxRequestBodyBytes} bytes`,
            },
          }),
        );
        return;
      }
    }

    let bodyBuffer = Buffer.alloc(0);
    let bytesReceived = 0;

    for await (const chunk of req) {
      const chunkBuf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytesReceived += chunkBuf.length;
      if (bytesReceived > maxRequestBodyBytes) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32000,
              message: `Payload Too Large: request exceeds maximum of ${maxRequestBodyBytes} bytes`,
            },
          }),
        );
        return;
      }
      bodyBuffer = Buffer.concat([bodyBuffer, chunkBuf]);
    }

    const rawBody = bodyBuffer.toString('utf8');

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error: malformed JSON' },
        }),
      );
      return;
    }

    if (exceedsMaxJsonNestingDepth(parsed)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32600,
            message: 'Invalid Request: JSON payload nesting exceeds depth limit',
          },
        }),
      );
      return;
    }

    if (Array.isArray(parsed)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32600,
            message: 'Invalid Request: JSON-RPC batching is not supported',
          },
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
          error: { code: -32600, message: 'Invalid Request: expected JSON object' },
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
        try {
          const initResult = this.bridge.createSession(authHeader);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Mcp-Session-Id': initResult.sessionId,
          });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: requestId,
              result: initResult,
            }),
          );
        } catch (err: unknown) {
          this.handleAuthOrBridgeError(err, requestId, res);
        }
        return;
      }

      case 'notifications/initialized': {
        try {
          this.bridge.validateSession(presentedSessionId, authHeader);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: requestId, result: {} }));
        } catch (err: unknown) {
          this.handleAuthOrBridgeError(err, requestId, res);
        }
        return;
      }

      case 'ping': {
        try {
          this.bridge.validateSession(presentedSessionId, authHeader);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id: requestId, result: {} }));
        } catch (err: unknown) {
          this.handleAuthOrBridgeError(err, requestId, res);
        }
        return;
      }

      case 'tools/list': {
        try {
          const activeSession = this.bridge.validateSession(presentedSessionId, authHeader);
          const tools = this.bridge.getRegisteredTools();
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Mcp-Session-Id': activeSession.sessionId,
          });
          res.end(
            JSON.stringify({
              jsonrpc: '2.0',
              id: requestId,
              result: { tools },
            }),
          );
        } catch (err: unknown) {
          this.handleAuthOrBridgeError(err, requestId, res);
        }
        return;
      }

      case 'tools/call': {
        await this.handleToolCall(
          jsonRpcMsg.params,
          requestId,
          presentedSessionId,
          authHeader,
          res,
        );
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
   * Handles tools/call: delegates session validation, parameter guard, CompleteActor
   * derivation, and execution entirely to the server-owned ChatGptAuthBridge.
   */
  private async handleToolCall(
    params: unknown,
    requestId: string | number | null,
    presentedSessionId: string | undefined,
    authHeader: string | undefined,
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

    if (!this.bridge.isRegisteredTool(name)) {
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

    try {
      const callResult = await this.bridge.executeToolCall({
        presentedSessionId,
        authorizationHeader: authHeader,
        toolName: name,
        parameters,
      });

      res.writeHead(200, {
        'Content-Type': 'application/json',
        ...(presentedSessionId ? { 'Mcp-Session-Id': presentedSessionId } : {}),
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
      this.handleAuthOrBridgeError(err, requestId, res);
    }
  }

  /**
   * Translates ArcErrors and authentication failures into proper wire responses.
   */
  private handleAuthOrBridgeError(
    err: unknown,
    requestId: string | number | null,
    res: http.ServerResponse,
  ): void {
    if (err instanceof ArcError) {
      if (err.code === 'UNAUTHENTICATED') {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            error: {
              code: -32001,
              message: 'UNAUTHENTICATED',
              data: { code: 'UNAUTHENTICATED' },
            },
          }),
        );
        return;
      }

      if (err.code === 'INVALID_SESSION_TOKEN') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            error: {
              code: -32000,
              message: 'INVALID_SESSION_TOKEN',
              data: { code: 'INVALID_SESSION_TOKEN' },
            },
          }),
        );
        return;
      }

      if (err.code === 'INVALID_REQUEST_SCHEMA') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: requestId,
            error: { code: -32602, message: err.message },
          }),
        );
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id: requestId,
          result: {
            isError: true,
            content: [
              {
                type: 'text',
                text: JSON.stringify(err.toJSON(), null, 2),
              },
            ],
          },
        }),
      );
      return;
    }

    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        jsonrpc: '2.0',
        id: requestId,
        error: { code: -32603, message: 'Internal error' },
      }),
    );
  }
}
