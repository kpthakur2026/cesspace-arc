/**
 * CesSpace ARC — ChatGPT Server-Owned Authentication Bridge
 *
 * Sits strictly outside the HTTP adapter and owns all ChatGPT authentication
 * decisions, session minting, credential binding, and CompleteActor derivation.
 *
 * Invariants:
 * 1. The HTTP adapter NEVER synthesizes a CompleteActor and NEVER sets authenticated: true.
 * 2. Only this bridge can validate credentials, mint sessions, and produce a CompleteActor.
 * 3. Client-controlled Mcp-Session-Id values are untrusted; all session IDs are server-generated.
 * 4. Sessions are bound to the verified transport credential and expire after inactivity.
 * 5. Unknown, deleted, or revoked sessions cannot execute tool calls.
 * 6. Parameter injection targeting actor/session fields is rejected before dispatch.
 */

import crypto from 'node:crypto';
import { ArcError } from '@cesspace-arc/protocol';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { CompleteActor } from './remote-execution.js';
import { findActorFieldInjection } from './remote-execution.js';
import { verifyBearerToken } from './chatgpt-profile.js';

import type { AuditLogger } from '@cesspace-arc/audit';

export interface ChatGptSessionRecord {
  sessionId: string;
  credentialHash: string;
  createdAt: number;
  lastActiveAt: number;
  revoked: boolean;
  actor: {
    clientId: string;
    clientType: string;
    deviceId: string;
  };
}

export interface ChatGptExecutionSink {
  executeAuthenticatedToolCall(
    actor: CompleteActor,
    toolName: string,
    parameters: Record<string, unknown>,
    options?: { signal?: AbortSignal },
  ): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }>;
  getRegisteredTools?: () => Tool[];
  isRegisteredTool?: (name: string) => boolean;
}

export interface ChatGptAuthBridgeDeps {
  expectedToken: string;
  sink: ChatGptExecutionSink;
  sessionTtlMs?: number;
  maxActiveSessions?: number;
  auditLogger?: AuditLogger;
}

export const DEFAULT_CHATGPT_SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour
export const DEFAULT_MAX_ACTIVE_CHATGPT_SESSIONS = 100;

export class ChatGptAuthBridge {
  private readonly expectedToken: string;
  private readonly credentialHash: string;
  private readonly sink: ChatGptExecutionSink;
  private readonly sessionTtlMs: number;
  private readonly maxActiveSessions: number;
  private readonly sessions = new Map<string, ChatGptSessionRecord>();

  constructor(deps: ChatGptAuthBridgeDeps) {
    if (typeof deps.expectedToken !== 'string' || deps.expectedToken.length === 0) {
      throw new Error('ChatGptAuthBridge requires a non-empty expectedToken.');
    }
    this.expectedToken = deps.expectedToken;
    this.credentialHash = crypto.createHash('sha256').update(this.expectedToken).digest('hex');
    this.sink = deps.sink;
    this.sessionTtlMs = deps.sessionTtlMs ?? DEFAULT_CHATGPT_SESSION_TTL_MS;
    this.maxActiveSessions = deps.maxActiveSessions ?? DEFAULT_MAX_ACTIVE_CHATGPT_SESSIONS;
  }

  /**
   * Verifies the transport-level Bearer authorization header against the expected token.
   */
  public verifyTransportAuth(authorizationHeader: string | undefined | null): boolean {
    return verifyBearerToken(authorizationHeader, this.expectedToken);
  }

  /**
   * Creates a new server-generated session bound to the verified transport credential.
   *
   * Only the server may mint session identifiers. Client-supplied IDs are never adopted.
   */
  public createSession(authorizationHeader: string | undefined | null): {
    sessionId: string;
    protocolVersion: string;
    capabilities: { tools: Record<string, unknown> };
    serverInfo: { name: string; version: string };
  } {
    if (!this.verifyTransportAuth(authorizationHeader)) {
      throw ArcError.unauthenticated('Authentication required.');
    }

    this.sweepExpiredSessions();

    if (this.sessions.size >= this.maxActiveSessions) {
      throw ArcError.unauthenticated('Session capacity reached.');
    }

    // Server-minted session ID
    const sessionId = `chatgpt-sess-${crypto.randomBytes(16).toString('hex')}`;
    const now = Date.now();

    const record: ChatGptSessionRecord = {
      sessionId,
      credentialHash: this.credentialHash,
      createdAt: now,
      lastActiveAt: now,
      revoked: false,
      actor: {
        clientId: 'chatgpt-client',
        clientType: 'chatgpt-remote',
        deviceId: 'chatgpt-tunnel-gateway',
      },
    };

    this.sessions.set(sessionId, record);

    return {
      sessionId,
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'cesspace-arc', version: '1.0.0' },
    };
  }

  /**
   * Validates an incoming presented session ID and its transport credential.
   * Fails closed if the session is absent, unknown, revoked, expired, or bound to a mismatched credential.
   */
  public validateSession(
    presentedSessionId: string | undefined | null,
    authorizationHeader: string | undefined | null,
  ): ChatGptSessionRecord {
    // 1. Session ID presence and format
    if (typeof presentedSessionId !== 'string' || presentedSessionId.length === 0) {
      throw ArcError.invalidSessionToken('Missing required Mcp-Session-Id header.');
    }

    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(presentedSessionId)) {
      throw ArcError.invalidSessionToken('Malformed Mcp-Session-Id header.');
    }

    // 2. Transport credential verification
    if (!this.verifyTransportAuth(authorizationHeader)) {
      throw ArcError.unauthenticated('Authentication required.');
    }

    // 3. Session lookup in server authority
    const session = this.sessions.get(presentedSessionId);
    if (!session) {
      throw ArcError.invalidSessionToken('Unknown or unminted session identifier.');
    }

    // 4. Revocation check
    if (session.revoked) {
      throw ArcError.invalidSessionToken('Session has been revoked or closed.');
    }

    // 5. Expiry check
    const now = Date.now();
    if (now - session.lastActiveAt > this.sessionTtlMs) {
      session.revoked = true;
      this.sessions.delete(presentedSessionId);
      throw ArcError.invalidSessionToken('Session has expired.');
    }

    // 6. Credential binding check (detects token rotation/tampering)
    if (session.credentialHash !== this.credentialHash) {
      session.revoked = true;
      this.sessions.delete(presentedSessionId);
      throw ArcError.unauthenticated('Session credential binding mismatch.');
    }

    session.lastActiveAt = now;
    return session;
  }

  /**
   * Closes / revokes an existing session. Subsequent calls using this session will fail.
   */
  public revokeSession(sessionId: string | undefined | null): boolean {
    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      return false;
    }
    const session = this.sessions.get(sessionId);
    if (session) {
      session.revoked = true;
      this.sessions.delete(sessionId);
      return true;
    }
    return false;
  }

  /**
   * Revokes all active sessions (e.g., during server shutdown or key rotation).
   */
  public revokeAllSessions(): void {
    for (const session of this.sessions.values()) {
      session.revoked = true;
    }
    this.sessions.clear();
  }

  /**
   * Checks whether a session ID is currently active and valid.
   */
  public isSessionActive(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.revoked) {
      return false;
    }
    if (Date.now() - session.lastActiveAt > this.sessionTtlMs) {
      session.revoked = true;
      this.sessions.delete(sessionId);
      return false;
    }
    return true;
  }

  /**
   * Returns current active session count.
   */
  public getActiveSessionCount(): number {
    this.sweepExpiredSessions();
    return this.sessions.size;
  }

  /**
   * Authenticates and executes a tool call through the ARC tool pipeline.
   *
   * Only this method may construct the authoritative CompleteActor and only
   * after validateSession has succeeded.
   */
  public async executeToolCall(input: {
    presentedSessionId: string | undefined | null;
    authorizationHeader: string | undefined | null;
    toolName: string;
    parameters: Record<string, unknown>;
    signal?: AbortSignal;
  }): Promise<{ isError?: boolean; content: Array<{ type: 'text'; text: string }> }> {
    // 1. Validate session and transport credentials
    const session = this.validateSession(input.presentedSessionId, input.authorizationHeader);

    // 2. Reject client-supplied parameter injection targeting actor/session fields
    const injection = findActorFieldInjection(input.parameters);
    if (injection !== null) {
      throw ArcError.invalidRequestSchema(
        `Invalid parameters for tool '${input.toolName}': reserved actor or transport identity field is not permitted in remote request parameters.`,
      );
    }

    // 3. Construct the server-authoritative CompleteActor from the validated session
    const actor: CompleteActor = {
      clientId: session.actor.clientId,
      clientType: session.actor.clientType,
      deviceId: session.actor.deviceId,
      sessionId: session.sessionId,
      authenticated: true,
    };

    // 4. Dispatch through the existing ARC authenticated execution sink
    return await this.sink.executeAuthenticatedToolCall(
      actor,
      input.toolName,
      input.parameters,
      input.signal ? { signal: input.signal } : undefined,
    );
  }

  /**
   * Returns registered tool catalog from the shared sink.
   */
  public getRegisteredTools(): Tool[] {
    return this.sink.getRegisteredTools ? this.sink.getRegisteredTools() : [];
  }

  /**
   * Checks if a tool name is registered in the shared sink catalog.
   */
  public isRegisteredTool(name: string): boolean {
    if (this.sink.isRegisteredTool) {
      return this.sink.isRegisteredTool(name);
    }
    const tools = this.getRegisteredTools();
    return tools.some((t) => t.name === name);
  }

  private sweepExpiredSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions.entries()) {
      if (session.revoked || now - session.lastActiveAt > this.sessionTtlMs) {
        session.revoked = true;
        this.sessions.delete(id);
      }
    }
  }
}
