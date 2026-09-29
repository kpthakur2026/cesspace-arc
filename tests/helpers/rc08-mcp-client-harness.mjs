/**
 * CesSpace ARC — RC-08 Task 1 MCP Client Conformance Harness Helper.
 *
 * Provides cross-client test adapters:
 * 1. RawJsonRpcStdioClient: A clean-room, independent JSON-RPC 2.0 client
 *    with ZERO imports from `@cesspace-arc` or `@modelcontextprotocol/sdk`.
 * 2. createMtlsFetch: Custom fetch implementation over TLS 1.3 / mTLS
 *    for `@modelcontextprotocol/sdk` StreamableHTTPClientTransport.
 * 3. Test fixtures for spawning ARC stdio server processes and remote gateways.
 */

import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import https from 'node:https';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { createArcMcpServer } from '../../apps/mcp-server/dist/index.js';
import { createAuditConfig } from './rc06-audit-runtime.mjs';
import { deriveSpkiPin, DeviceTrustStore } from '../../packages/auth/dist/index.js';

/**
 * Finds an available TCP port on loopback.
 * @returns {Promise<number>}
 */
export async function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen({ host: '127.0.0.1', port: 0 }, () => {
      const { port } = probe.address();
      probe.close((err) => (err ? reject(err) : resolve(port)));
    });
  });
}

/**
 * Spawns an isolated CesSpace ARC MCP server child process over stdio.
 *
 * @param {object} opts
 * @param {string} opts.tempDir
 * @param {string} [opts.workspaceDir]
 * @param {string} [opts.label]
 * @returns {{ proc: import('node:child_process').ChildProcess, workspaceDir: string, auditConfig: object, cleanup: () => Promise<void> }}
 */
export function spawnArcStdioServerProcess({ tempDir, workspaceDir, label = 'stdio' }) {
  const ws = workspaceDir ?? `${tempDir}/workspace-${label}`;
  fs.mkdirSync(ws, { recursive: true });

  const auditConfig = createAuditConfig(tempDir, `stdio-${label}`);

  const runnerCode = `
    import { createArcMcpServer } from './apps/mcp-server/dist/index.js';
    const server = createArcMcpServer({
      transport: 'stdio',
      authorizedRoots: [{ id: 'workspace', path: ${JSON.stringify(ws)} }],
      defaultWorkspaceId: 'workspace',
      audit: ${JSON.stringify(auditConfig)}
    });
    await server.start();
  `;

  const proc = spawn('node', ['--input-type=module', '-e', runnerCode], {
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: process.cwd(),
  });

  let exited = false;
  proc.once('exit', () => {
    exited = true;
  });
  proc.once('close', () => {
    exited = true;
  });

  const cleanup = async () => {
    if (exited || proc.exitCode !== null || proc.signalCode !== null) {
      return;
    }

    const waitForExit = (timeoutMs) => {
      return new Promise((resolve) => {
        if (exited || proc.exitCode !== null || proc.signalCode !== null) {
          resolve(true);
          return;
        }
        const onExit = () => {
          clearTimeout(timer);
          resolve(true);
        };
        const timer = setTimeout(() => {
          proc.off('exit', onExit);
          proc.off('close', onExit);
          resolve(false);
        }, timeoutMs);
        proc.once('exit', onExit);
        proc.once('close', onExit);
      });
    };

    try {
      proc.kill('SIGTERM');
    } catch {
      // process might have exited in the interim
    }

    const termExited = await waitForExit(2000);
    if (termExited) return;

    try {
      proc.kill('SIGKILL');
    } catch {
      // process might have exited in the interim
    }

    const killExited = await waitForExit(3000);
    if (!killExited) {
      throw new Error(
        `Failed to confirm child process exit (pid: ${proc.pid}) within bounded deadline`,
      );
    }
  };

  return { proc, workspaceDir: ws, auditConfig, cleanup };
}

/**
 * Clean-room, independent raw JSON-RPC 2.0 stdio client with ZERO framework imports.
 */
export class RawJsonRpcStdioClient {
  /**
   * @param {import('node:child_process').ChildProcess} proc
   */
  constructor(proc) {
    this.proc = proc;
    this.nextRequestId = 1;
    this.pendingRequests = new Map();
    this.incomingQueue = [];
    this.readWaiters = [];
    this.buffer = '';
    this.closed = false;

    this.proc.stdout.on('data', (chunk) => {
      this.buffer += chunk.toString('utf8');
      this._drainBuffer();
    });

    this.proc.on('close', () => {
      this.closed = true;
      for (const waiter of this.readWaiters) {
        waiter.reject(new Error('Process closed while waiting for message'));
      }
      this.readWaiters = [];
      for (const { reject } of this.pendingRequests.values()) {
        reject(new Error('Process closed while waiting for response'));
      }
      this.pendingRequests.clear();
    });
  }

  _drainBuffer() {
    let newlineIndex = this.buffer.indexOf('\n');
    while (newlineIndex !== -1) {
      const line = this.buffer.slice(0, newlineIndex).trim();
      this.buffer = this.buffer.slice(newlineIndex + 1);
      if (line.length > 0) {
        try {
          const parsed = JSON.parse(line);
          this._handleMessage(parsed, line);
        } catch {
          // If unparseable, queue as raw object
          this._handleMessage({ __raw: line }, line);
        }
      }
      newlineIndex = this.buffer.indexOf('\n');
    }
  }

  _handleMessage(msg, _rawLine) {
    if (msg && msg.id !== undefined && this.pendingRequests.has(msg.id)) {
      const { resolve } = this.pendingRequests.get(msg.id);
      this.pendingRequests.delete(msg.id);
      resolve(msg);
      return;
    }

    if (this.readWaiters.length > 0) {
      const waiter = this.readWaiters.shift();
      waiter.resolve(msg);
      return;
    }

    this.incomingQueue.push(msg);
  }

  /**
   * Sends raw string line over stdin.
   * @param {string} line
   */
  sendRaw(line) {
    if (this.closed) throw new Error('Client is closed');
    this.proc.stdin.write(line.endsWith('\n') ? line : line + '\n');
  }

  /**
   * Sends a JSON-RPC 2.0 request and awaits the response.
   * @param {string} method
   * @param {object} [params]
   * @param {string|number} [id]
   * @param {number} [timeoutMs]
   * @returns {Promise<any>}
   */
  async request(method, params, id = undefined, timeoutMs = 5000) {
    if (this.closed) throw new Error('Client is closed');
    const reqId = id !== undefined ? id : this.nextRequestId++;
    const req = {
      jsonrpc: '2.0',
      id: reqId,
      method,
      ...(params !== undefined ? { params } : {}),
    };

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(reqId);
        reject(
          new Error(`Request timed out after ${timeoutMs}ms (method: ${method}, id: ${reqId})`),
        );
      }, timeoutMs);

      this.pendingRequests.set(reqId, {
        resolve: (val) => {
          clearTimeout(timer);
          resolve(val);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });

      this.sendRaw(JSON.stringify(req));
    });
  }

  /**
   * Sends a JSON-RPC 2.0 notification (no response expected).
   * @param {string} method
   * @param {object} [params]
   */
  notify(method, params) {
    if (this.closed) throw new Error('Client is closed');
    const notif = {
      jsonrpc: '2.0',
      method,
      ...(params !== undefined ? { params } : {}),
    };
    this.sendRaw(JSON.stringify(notif));
  }

  /**
   * Reads next message from queue or waits for next stdout message.
   * @param {number} [timeoutMs]
   * @returns {Promise<any>}
   */
  async readNext(timeoutMs = 5000) {
    if (this.incomingQueue.length > 0) {
      return this.incomingQueue.shift();
    }

    if (this.closed) {
      throw new Error('Client is closed and queue is empty');
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.readWaiters.findIndex((w) => w.timer === timer);
        if (idx !== -1) this.readWaiters.splice(idx, 1);
        reject(new Error(`readNext timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      this.readWaiters.push({
        resolve: (val) => {
          clearTimeout(timer);
          resolve(val);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
        timer,
      });
    });
  }

  /** Closes stdin */
  close() {
    this.closed = true;
    try {
      this.proc.stdin.end();
    } catch {
      // ignore
    }
  }
}

/**
 * Creates custom mTLS fetch adapter for SDK StreamableHTTPClientTransport.
 * Auto-injects mcp-session-id and arc-session-token on subsequent requests.
 */
export function createMtlsFetch({ caPath, certPath, keyPath, rejectUnauthorized = true }) {
  const agent = new https.Agent({
    ca: fs.readFileSync(caPath),
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
    rejectUnauthorized,
    minVersion: 'TLSv1.3',
  });

  let capturedSessionId = null;
  let capturedSessionToken = null;

  const customFetch = async (url, init = {}) => {
    const urlObj = new URL(url);
    return new Promise((resolve, reject) => {
      const headers = new Headers(init.headers || {});
      if (capturedSessionId && !headers.has('mcp-session-id')) {
        headers.set('mcp-session-id', capturedSessionId);
      }
      if (capturedSessionToken && !headers.has('authorization')) {
        headers.set('authorization', 'Bearer ' + capturedSessionToken);
      }
      const reqHeaders = {};
      for (const [k, v] of headers.entries()) {
        reqHeaders[k] = v;
      }
      const req = https.request(
        {
          protocol: urlObj.protocol,
          hostname: urlObj.hostname,
          port: urlObj.port,
          path: urlObj.pathname + urlObj.search,
          method: init.method || 'GET',
          headers: reqHeaders,
          agent,
        },
        (res) => {
          const sessId = res.headers['mcp-session-id'];
          if (sessId && typeof sessId === 'string') capturedSessionId = sessId;
          const sessTok = res.headers['arc-session-token'];
          if (sessTok && typeof sessTok === 'string') capturedSessionToken = sessTok;

          const stream = Readable.toWeb(res);
          const responseHeaders = new Headers();
          for (const [k, v] of Object.entries(res.headers)) {
            if (Array.isArray(v)) {
              for (const item of v) responseHeaders.append(k, item);
            } else if (v !== undefined) {
              responseHeaders.set(k, v);
            }
          }
          resolve(
            new Response(stream, {
              status: res.statusCode,
              statusText: res.statusMessage,
              headers: responseHeaders,
            }),
          );
        },
      );
      req.on('error', reject);
      if (init.body) {
        if (typeof init.body === 'string' || Buffer.isBuffer(init.body)) {
          req.write(init.body);
        }
      }
      req.end();
    });
  };

  customFetch.getSessionId = () => capturedSessionId;
  customFetch.getSessionToken = () => capturedSessionToken;
  customFetch.resetSession = () => {
    capturedSessionId = null;
    capturedSessionToken = null;
  };

  return customFetch;
}

/**
 * Starts a real remote-mode ArcMcpServer over real mTLS for testing.
 */
export async function startTestRemoteServer({
  tempDir,
  pki,
  tag = 'remote',
  enrolledClientCertPaths = [],
  extraRemote = {},
  config = {},
} = {}) {
  const port = await freePort();
  const ws = path.join(tempDir, `ws-${tag}`);
  fs.mkdirSync(ws, { recursive: true });

  const storePath = path.join(tempDir, `devices-${tag}.json`);
  const store = DeviceTrustStore.createEmpty();
  for (let i = 0; i < enrolledClientCertPaths.length; i++) {
    const certPath = enrolledClientCertPaths[i];
    store.enrollDevice({
      deviceId: `device-${tag}-${i + 1}`,
      clientId: `client-${tag}-${i + 1}`,
      clientType: 'integration-test',
      pin: deriveSpkiPin(fs.readFileSync(certPath, 'utf8')),
    });
  }
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);

  const audit = createAuditConfig(tempDir, `audit-${tag}`);

  const server = createArcMcpServer({
    transport: 'remote',
    authorizedRoots: [{ id: 'workspace', path: ws }],
    defaultWorkspaceId: 'workspace',
    audit,
    ...config,
    remote: {
      bindHost: '127.0.0.1',
      port,
      publicHostname: 'localhost',
      serverCertificatePath: pki.serverCertPath,
      privateKey: { kind: 'file', path: pki.serverKeyPath },
      clientCaPaths: [pki.trustedCaCertPath],
      trustStorePath: storePath,
      ...extraRemote,
    },
  });

  await server.start();
  return {
    server,
    port,
    workspaceDir: ws,
    storePath,
    audit,
    cleanup: async () => {
      await server.stop();
    },
  };
}

/**
 * Creates a raw HTTPS request with the underlying ClientRequest exposed
 * so that tests can destroy the socket mid-stream to simulate client disconnect.
 */
export function makeRawHttpsRequest({
  port,
  caPath,
  certPath,
  keyPath,
  method = 'POST',
  reqPath = '/mcp',
  headers = {},
  body = undefined,
}) {
  let req;
  const promise = new Promise((resolve, reject) => {
    req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: reqPath,
        servername: 'localhost',
        ca: [fs.readFileSync(caPath)],
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
        rejectUnauthorized: true,
        headers: {
          Host: 'localhost:' + port,
          Accept: 'application/json, text/event-stream',
          'Content-Type': 'application/json',
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
  return { req, promise };
}

/**
 * Parses an MCP response body, handling both application/json and text/event-stream (SSE).
 * @param {Response} response
 * @returns {Promise<any>}
 */
export async function parseMcpResponse(response) {
  const text = await response.text();
  const dataLine = text.split('\n').find((l) => l.startsWith('data:'));
  if (dataLine) {
    return JSON.parse(dataLine.slice(5).trim());
  }
  return JSON.parse(text.trim());
}
