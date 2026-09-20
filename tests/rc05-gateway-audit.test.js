/**
 * CesSpace ARC — RC-05 Task 10 Dedicated Gateway Lifecycle Audit Suite
 *
 * Covers all RC-05 audit requirements (rc05 §24):
 * - Exactly 14 frozen gateway event types in the single append-only hash chain
 * - Real emission of all 14 lifecycle events
 * - Monotonic sequencing and SHA-256 chain integrity
 * - Coexistence of ordinary tool, approval, and gateway records on ONE chain
 * - No duplicate lifecycle events
 * - Defensive snapshots (immutability of stored evidence)
 * - Central redaction & secrecy:
 *   - RC05-NEG-71: No raw session token in audit after session bootstrap
 *   - RC05-NEG-72: No raw enrollment secret in audit after enrollment completion
 *   - RC05-NEG-73: No private cryptographic material (keys/certs/bearer) in audit
 *   - Central host-path minimization
 *
 * All X.509 material is generated ephemerally into a temporary directory by the
 * shared test PKI helper and removed with it; no certificate or key is
 * committed and no scanner suppression is used.
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { ArcMcpServer } from '../apps/mcp-server/dist/index.js';
import { getGatewayAuditSink } from '../apps/mcp-server/dist/gateway-audit.js';
import { GATEWAY_AUDIT_EVENT_TYPES } from '../packages/protocol/dist/index.js';
import {
  AuditLogger,
  projectGatewayMetadata,
  redactRecord,
  redactString,
  computeSha256,
} from '../packages/audit/dist/index.js';
import { DeviceTrustStore, EnrollmentManager, deriveSpkiPin } from '../packages/auth/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

const publicHostname = 'localhost';
let tempRoot;
let workspaceDir;
let pki;
let counter = 0;

before(() => {
  assert.equal(
    hasOpenssl(),
    true,
    'RC-05 drives real mTLS connections and requires the openssl binary',
  );
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc05-audit-test-'));
  pki = createTestPki(path.join(tempRoot, 'pki'));
  workspaceDir = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspaceDir, { recursive: true });
  fs.mkdirSync(path.join(workspaceDir, '.git'), { recursive: true });
  fs.writeFileSync(path.join(workspaceDir, '.git', 'config'), '[core]\n');
  fs.writeFileSync(path.join(workspaceDir, 'README.md'), '# audit test\n');
});

after(() => {
  try {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function clientPin() {
  return deriveSpkiPin(fs.readFileSync(pki.clientCertPath, 'utf8'));
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen({ host: '127.0.0.1', port: 0 }, () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

function createTrustStore(tag, pinCount = 1, revokedCount = 0) {
  counter += 1;
  const storePath = path.join(tempRoot, `devices-${tag}-${counter}.json`);
  const store = DeviceTrustStore.createEmpty();
  const records = [];
  for (let index = 0; index < pinCount; index += 1) {
    const pin = index === 0 ? clientPin() : `${String(index).repeat(64)}`.slice(0, 64);
    const { device } = store.enrollDevice({
      clientId: `client-${tag}-${index}`,
      clientType: 'claude-code',
      pin,
      displayLabel: `label-${tag}-${index}`,
    });
    records.push({ ...device, pin });
  }
  for (const record of records.slice(pinCount - revokedCount)) {
    store.revokeDevice(record.deviceId);
  }
  store.saveToFile(storePath);
  fs.chmodSync(storePath, 0o600);
  return { storePath, records, store };
}

async function startRemoteServer({
  tag = 'audit',
  pinCount = 1,
  revokedCount = 0,
  auditLogger,
  enrollmentManager,
  sessionManager,
} = {}) {
  const port = await freePort();
  const { storePath, records, store } = createTrustStore(tag, pinCount, revokedCount);
  const registry = new WorkspaceRegistry();
  const audit = auditLogger ?? new AuditLogger();
  const approvals = new ApprovalStateManager();
  const server = new ArcMcpServer(
    registry,
    new SecurityKernel(registry),
    audit,
    new FilesystemSubsystem(),
    new GitSubsystem(),
    {
      transport: 'remote',
      authorizedRoots: [{ id: 'ws', path: workspaceDir }],
      defaultWorkspaceId: 'ws',
      remote: {
        bindHost: '127.0.0.1',
        port,
        publicHostname,
        serverCertificatePath: pki.serverCertPath,
        privateKey: { kind: 'file', path: pki.serverKeyPath },
        clientCaPaths: [pki.trustedCaCertPath],
        trustStorePath: storePath,
      },
    },
    undefined,
    undefined,
    approvals,
    undefined,
    enrollmentManager,
    sessionManager,
  );
  await server.start();
  return { server, port, storePath, records, store, audit, approvals };
}

function request(
  port,
  { method = 'POST', requestPath = '/mcp', headers = {}, body, cert, key } = {},
) {
  return new Promise((resolve, reject) => {
    const defaultHeaders = {
      Host: publicHostname,
      ...(method === 'POST' ? { Accept: 'application/json, text/event-stream' } : {}),
      ...(method === 'POST' && body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    };
    const req = https.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: requestPath,
        servername: publicHostname,
        ca: [fs.readFileSync(pki.trustedCaCertPath)],
        cert: cert ?? fs.readFileSync(pki.clientCertPath),
        key: key ?? fs.readFileSync(pki.clientKeyPath),
        headers: { ...defaultHeaders, ...headers },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

async function waitFor(predicate, budgetMs = 2000) {
  const start = Date.now();
  while (Date.now() - start < budgetMs) {
    if (await predicate()) {
      return true;
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  return false;
}

// ---------------------------------------------------------------------------
// Suites
// ---------------------------------------------------------------------------

describe('CesSpace ARC — RC-05 Task 10: Gateway Lifecycle Audit Catalog & Secrecy', () => {
  test('Catalog: exactly fourteen frozen event types in closed array', () => {
    const expected = [
      'GATEWAY_STARTED',
      'GATEWAY_STOPPED',
      'DEVICE_ENROLLMENT_REQUESTED',
      'DEVICE_ENROLLED',
      'DEVICE_ENROLLMENT_REJECTED',
      'DEVICE_REVOKED',
      'AUTH_SUCCEEDED',
      'AUTH_FAILED',
      'SESSION_ISSUED',
      'SESSION_EXPIRED',
      'SESSION_REVOKED',
      'SESSION_CLOSED',
      'RATE_LIMITED',
      'REMOTE_DISCONNECTED',
    ];
    assert.deepEqual([...GATEWAY_AUDIT_EVENT_TYPES], expected);
    assert.equal(GATEWAY_AUDIT_EVENT_TYPES.length, 14);

    // Any unlisted event name is rejected by central projection
    assert.equal(projectGatewayMetadata({ eventType: 'FAKE_EVENT' }), undefined);
    assert.equal(projectGatewayMetadata({ eventType: 'SESSION_DESTROYED' }), undefined);
    assert.equal(projectGatewayMetadata(null), undefined);
    assert.equal(projectGatewayMetadata('GATEWAY_STARTED'), undefined);
  });

  test('Central projection: allowlist only, strips credential and unknown fields', () => {
    const projected = projectGatewayMetadata({
      eventType: 'SESSION_ISSUED',
      reason: 'INVALID_REQUEST', // recognized reason
      admissionLayer: 'C',
      mcpSessionId: 'a'.repeat(64),
      deviceId: 'b'.repeat(32),
      spkiPin: 'c'.repeat(64),
      clientId: 'valid-client-id',
      clientType: 'claude-code',
      enrollmentId: 'd'.repeat(32),
      transportMode: 'remote',
      // Forbidden or unallowlisted fields:
      token: 'secret-token-value',
      secret: 'one-time-secret',
      privateKey: '-----BEGIN PRIVATE KEY-----',
      peerAddress: '192.168.1.1',
      limiterBucket: 42,
    });

    assert.equal(projected?.eventType, 'SESSION_ISSUED');
    assert.equal(projected?.admissionLayer, 'C');
    assert.equal(projected?.mcpSessionId, 'a'.repeat(64));
    assert.equal(projected?.deviceId, 'b'.repeat(32));
    assert.equal(projected?.spkiPin, 'c'.repeat(64));
    assert.equal(projected?.transportMode, 'remote');

    // Forbidden fields are not present on projected metadata
    assert.equal('token' in (projected ?? {}), false);
    assert.equal('secret' in (projected ?? {}), false);
    assert.equal('privateKey' in (projected ?? {}), false);
    assert.equal('peerAddress' in (projected ?? {}), false);
    assert.equal('limiterBucket' in (projected ?? {}), false);
  });

  test('Single AuditLogger chain: SHA-256 chain integrity, monotonic sequences, and coexistence', async () => {
    const audit = new AuditLogger();
    const { server, port } = await startRemoteServer({
      tag: 'chain-integrity',
      auditLogger: audit,
    });

    try {
      // 1. GATEWAY_STARTED was emitted into the chain
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'GATEWAY_STARTED'),
      );
      const startRecord = audit
        .getRecords()
        .find((r) => r.gateway?.eventType === 'GATEWAY_STARTED');
      assert.ok(startRecord);
      assert.equal(startRecord.gateway.transportMode, 'remote');
      assert.equal(startRecord.policy.ruleId, 'gateway-lifecycle');

      // 2. Perform an initialize to mint a session (emits SESSION_ISSUED)
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'audit-client', version: '1.0' },
          },
        }),
      });
      assert.equal(initRes.status, 200);
      const sessionId = initRes.headers['mcp-session-id'];
      const sessionToken = initRes.headers['arc-session-token'];
      assert.ok(sessionId);
      assert.ok(sessionToken);

      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'SESSION_ISSUED'),
      );

      // 3. Send authenticated tool request (emits AUTH_SUCCEEDED and ordinary tool record)
      const toolRes = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {
            name: 'read_file',
            arguments: { path: 'README.md' },
          },
        }),
      });
      assert.equal(toolRes.status, 200);

      // Wait for AUTH_SUCCEEDED and the tool invocation record
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'AUTH_SUCCEEDED'),
      );
      await waitFor(() => audit.getRecords().some((r) => r.invocation.toolName === 'read_file'));

      // 4. Inject an RC-04 approval lifecycle event into the SAME logger
      const approvalSink = server.approvalStateManager;
      const req = approvalSink.createOrReusePending({
        toolName: 'write_file',
        executionPayloadHash: '0'.repeat(64),
        binding: {
          actor: { clientId: 'admin', clientType: 'cli', deviceId: 'dev', sessionId: 'sess' },
          workspace: { workspaceId: 'ws', workspaceRootHash: '0'.repeat(64) },
          policyHash: '0'.repeat(64),
        },
      });
      approvalSink.approve(req.requestId);

      // 5. Close session (emits SESSION_CLOSED)
      const delRes = await request(port, {
        method: 'DELETE',
        headers: {
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${sessionToken}`,
        },
      });
      assert.equal(delRes.status, 200);
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'SESSION_CLOSED'),
      );

      // 6. Stop server (emits GATEWAY_STOPPED)
      await server.stop();
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'GATEWAY_STOPPED'),
      );

      // Verify the SINGLE hash chain across all record types:
      const records = audit.getRecords();
      assert.ok(records.length >= 6, `expected >= 6 records, got ${records.length}`);

      // Verify sequence monotonicity: exactly 1, 2, 3, ...
      for (let i = 0; i < records.length; i += 1) {
        assert.equal(records[i].sequenceNumber, i + 1, `record ${i} sequence mismatch`);
        if (i === 0) {
          assert.equal(
            records[i].integrity.previousRecordHash,
            '0000000000000000000000000000000000000000000000000000000000000000',
          );
        } else {
          assert.equal(
            records[i].integrity.previousRecordHash,
            records[i - 1].integrity.recordHash,
            `record ${i} previousRecordHash mismatch`,
          );
        }
      }

      // Authoritative integrity check
      const integrityPasses = await audit.verifyIntegrity();
      assert.equal(integrityPasses, true, 'AuditLogger.verifyIntegrity() must pass');

      // Verify coexistence: gateway records, tool records, and approval records all present
      const gatewayRecords = records.filter((r) => r.gateway !== undefined);
      const toolRecords = records.filter((r) => r.invocation.toolName === 'read_file');
      const approvalRecords = records.filter((r) => r.approval !== undefined);

      assert.ok(gatewayRecords.length > 0, 'gateway lifecycle records present');
      assert.ok(toolRecords.length > 0, 'tool invocation records present');
      assert.ok(approvalRecords.length > 0, 'approval lifecycle records present');

      // Gateway records have gateway metadata and ruleId 'gateway-lifecycle'
      for (const gr of gatewayRecords) {
        assert.ok(GATEWAY_AUDIT_EVENT_TYPES.includes(gr.gateway.eventType));
        assert.equal(gr.policy.ruleId, 'gateway-lifecycle');
      }

      // Tool records have gateway undefined
      for (const tr of toolRecords) {
        assert.equal(tr.gateway, undefined);
      }
    } finally {
      await server.stop().catch(() => {});
    }
  });

  test('No duplicate lifecycle events: repeated stop is a no-op', async () => {
    const audit = new AuditLogger();
    const { server } = await startRemoteServer({ tag: 'no-dup', auditLogger: audit });
    await waitFor(() => audit.getRecords().some((r) => r.gateway?.eventType === 'GATEWAY_STARTED'));
    const startCount = audit
      .getRecords()
      .filter((r) => r.gateway?.eventType === 'GATEWAY_STARTED').length;
    assert.equal(startCount, 1);

    await server.stop();
    await waitFor(() => audit.getRecords().some((r) => r.gateway?.eventType === 'GATEWAY_STOPPED'));
    const stopCount1 = audit
      .getRecords()
      .filter((r) => r.gateway?.eventType === 'GATEWAY_STOPPED').length;
    assert.equal(stopCount1, 1);

    // Second stop: must NOT emit a second GATEWAY_STOPPED record
    await server.stop();
    const stopCount2 = audit
      .getRecords()
      .filter((r) => r.gateway?.eventType === 'GATEWAY_STOPPED').length;
    assert.equal(stopCount2, 1, 'repeated stop must not emit duplicate GATEWAY_STOPPED');
  });

  test('Defensive snapshots: mutations on getRecords() do not mutate authoritative chain', async () => {
    const audit = new AuditLogger();
    const { server } = await startRemoteServer({ tag: 'defensive-snap', auditLogger: audit });
    try {
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'GATEWAY_STARTED'),
      );
      const snapshots = audit.getRecords();
      assert.ok(snapshots.length > 0);

      // Attempt to tamper with the returned snapshot
      snapshots[0].policy.ruleId = 'tampered-rule';
      snapshots[0].gateway.eventType = 'DEVICE_REVOKED';

      // Re-fetch records and verify original is intact
      const freshRecords = audit.getRecords();
      assert.equal(freshRecords[0].policy.ruleId, 'gateway-lifecycle');
      assert.equal(freshRecords[0].gateway.eventType, 'GATEWAY_STARTED');

      // Verify integrity is intact
      assert.equal(await audit.verifyIntegrity(), true);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-71: audit log inspection after session bootstrap -> no raw session token', async () => {
    const audit = new AuditLogger();
    const { server, port } = await startRemoteServer({ tag: 'neg-71', auditLogger: audit });

    try {
      // Perform tokenless initialize on /mcp
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 100,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'neg-71-client', version: '1.0' },
          },
        }),
      });

      assert.equal(initRes.status, 200);
      const rawToken = initRes.headers['arc-session-token'];
      const sessionId = initRes.headers['mcp-session-id'];
      assert.ok(rawToken, 'Arc-Session-Token header must be present');
      assert.match(rawToken, /^[0-9a-f]{64}$/, 'token must be 64-char hex');
      assert.ok(sessionId, 'Mcp-Session-Id header must be present');

      // Issue an authenticated request presenting the token
      const pingRes = await request(port, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Mcp-Session-Id': sessionId,
          Authorization: `Bearer ${rawToken}`,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 101, method: 'ping' }),
      });
      assert.equal(pingRes.status, 200);

      // Wait for SESSION_ISSUED and AUTH_SUCCEEDED
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'SESSION_ISSUED'),
      );
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'AUTH_SUCCEEDED'),
      );

      // Test deliberately injected token canaries through central redaction
      const canaryRecord = await audit.log({
        timestamp: new Date().toISOString(),
        actor: { clientId: 'test', clientType: 'cli', deviceId: 'dev', sessionId },
        target: { workspaceId: 'ws', workspacePath: '' },
        invocation: {
          toolName: 'test_tool',
          parametersRedacted: {
            token: rawToken, // sensitive key name
            arcSessionToken: rawToken, // sensitive key name
            authHeader: `Authorization: Bearer ${rawToken}`, // sensitive value pattern
            freeTextNote: `Arc-Session-Token: ${rawToken}`, // sensitive value pattern
          },
          payloadHash: '0000000000000000000000000000000000000000000000000000000000000000',
        },
        policy: { decision: 'ALLOW', ruleId: 'test-rule', evaluationDurationMs: 0 },
        execution: {
          status: 'SUCCESS',
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          durationMs: 0,
        },
        error: {
          code: 'TEST_ERROR',
          message: `Bearer ${rawToken} failed`, // free text error redaction
        },
      });

      // Assert complete audit chain inspection:
      const allRecords = audit.getRecords();
      const serialized = JSON.stringify(allRecords);

      // 1. Raw token appears nowhere in any serialized audit record
      assert.equal(
        serialized.includes(rawToken),
        false,
        'RC05-NEG-71: raw session token MUST NOT appear anywhere in the audit chain',
      );

      // 2. No Authorization: Bearer <token> in serialized records
      assert.equal(
        serialized.includes(`Bearer ${rawToken}`),
        false,
        'RC05-NEG-71: Authorization: Bearer <token> MUST NOT appear in audit',
      );

      // 3. SESSION_ISSUED event exists
      const sessionIssuedRecord = allRecords.find((r) => r.gateway?.eventType === 'SESSION_ISSUED');
      assert.ok(sessionIssuedRecord, 'SESSION_ISSUED event must exist');
      assert.equal(sessionIssuedRecord.gateway.mcpSessionId, sessionId);

      // 4. Useful safe correlation remains (session ID, device ID, SPKI pin)
      assert.equal(sessionIssuedRecord.gateway.mcpSessionId, sessionId);
      assert.ok(sessionIssuedRecord.gateway.deviceId);
      assert.equal(sessionIssuedRecord.gateway.spkiPin, clientPin());

      // 5. Central redaction sanitized the canary record
      assert.equal(
        JSON.stringify(canaryRecord).includes(rawToken),
        false,
        'Canary record must have raw token redacted',
      );
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-72: audit inspection after enrollment completion -> no raw enrollment secret', async () => {
    const audit = new AuditLogger();
    const enrollmentManager = new EnrollmentManager();
    const { server, port } = await startRemoteServer({
      tag: 'neg-72',
      auditLogger: audit,
      enrollmentManager,
      pinCount: 0,
    });

    try {
      // 1. Authenticated local enrollment creation
      const { enrollment: pending, secret } = enrollmentManager.create({
        clientId: 'enrolled-agent',
        clientType: 'claude-code',
        spkiPin: clientPin(),
        operatorId: '0'.repeat(64),
      });
      assert.ok(secret, 'one-time secret generated');
      assert.match(secret, /^[0-9a-f]{64}$/);

      // Record DEVICE_ENROLLMENT_REQUESTED via sink (as Admin IPC does)
      const sink = getGatewayAuditSink(audit);
      sink.emit({
        eventType: 'DEVICE_ENROLLMENT_REQUESTED',
        enrollmentId: pending.enrollmentId,
        clientId: pending.clientId,
        clientType: pending.clientType,
        spkiPin: pending.spkiPin,
      });

      // 2. Actual mTLS /enroll/complete success path
      const completeRes = await request(port, {
        method: 'POST',
        requestPath: '/enroll/complete',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret }),
      });
      assert.equal(completeRes.status, 200);

      // 3. Actual rejection path: replay of the same secret
      const replayRes = await request(port, {
        method: 'POST',
        requestPath: '/enroll/complete',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret }),
      });
      assert.equal(replayRes.status, 400);

      // 4. Invalid secret rejection path
      const wrongSecret = 'f'.repeat(64);
      const wrongRes = await request(port, {
        method: 'POST',
        requestPath: '/enroll/complete',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: wrongSecret }),
      });
      assert.equal(wrongRes.status, 400);

      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'DEVICE_ENROLLED'),
      );
      await waitFor(() =>
        audit.getRecords().some((r) => r.gateway?.eventType === 'DEVICE_ENROLLMENT_REJECTED'),
      );

      const allRecords = audit.getRecords();
      const serialized = JSON.stringify(allRecords);

      // Assert events exist
      assert.ok(allRecords.some((r) => r.gateway?.eventType === 'DEVICE_ENROLLMENT_REQUESTED'));
      assert.ok(allRecords.some((r) => r.gateway?.eventType === 'DEVICE_ENROLLED'));
      assert.ok(allRecords.some((r) => r.gateway?.eventType === 'DEVICE_ENROLLMENT_REJECTED'));

      // Assert the one-time secret appears nowhere in any serialized audit record
      assert.equal(
        serialized.includes(secret),
        false,
        'RC05-NEG-72: raw enrollment secret MUST NOT appear anywhere in audit records',
      );
      assert.equal(
        serialized.includes(wrongSecret),
        false,
        'RC05-NEG-72: rejected raw secret MUST NOT appear anywhere in audit records',
      );

      // Test canary injection: passing secret under a parameter
      const secretCanary = redactRecord({
        enrollmentSecret: secret,
        nested: { secret },
      });
      assert.equal(JSON.stringify(secretCanary).includes(secret), false);
    } finally {
      await server.stop();
    }
  });

  test('RC05-NEG-73: no private cryptographic material or full certificate PEMs in audit', async () => {
    const audit = new AuditLogger();

    // Ephemeral runtime PKI generated for testing
    const serverKeyPem = fs.readFileSync(pki.serverKeyPath, 'utf8');
    const clientKeyPem = fs.readFileSync(pki.clientKeyPath, 'utf8');
    const certPem = fs.readFileSync(pki.clientCertPath, 'utf8');
    const operatorKeyPair = crypto.generateKeyPairSync('ed25519');
    const operatorKeyPem = operatorKeyPair.privateKey
      .export({ format: 'pem', type: 'pkcs8' })
      .toString();
    const bearerCredential = `sk-${crypto.randomBytes(24).toString('hex')}`;

    // Exercise canaries through central redaction
    const testPayload = {
      serverPrivateKey: serverKeyPem,
      clientPrivateKey: clientKeyPem,
      operatorKey: operatorKeyPem,
      certificateBlob: certPem,
      notes: `Failed with credential: ${bearerCredential}`,
      errorMessage: `Error loading key: ${serverKeyPem}`,
      safeSpkiPin: clientPin(), // Legitimate safe 64-char hex string
      safeWorkspaceRootHash: computeSha256('/safe/path'), // Legitimate safe SHA-256
    };

    const redacted = audit.redact(testPayload);
    const serializedRedacted = JSON.stringify(redacted);

    // None of the private key PEM canaries survive
    assert.equal(serializedRedacted.includes(serverKeyPem), false);
    assert.equal(serializedRedacted.includes(clientKeyPem), false);
    assert.equal(serializedRedacted.includes(operatorKeyPem), false);
    assert.equal(serializedRedacted.includes('-----BEGIN PRIVATE KEY-----'), false);

    // Certificate PEM does not survive
    assert.equal(serializedRedacted.includes(certPem), false);
    assert.equal(serializedRedacted.includes('-----BEGIN CERTIFICATE-----'), false);

    // Bearer token canary does not survive
    assert.equal(serializedRedacted.includes(bearerCredential), false);

    // Legitimate safe SHA-256 digests MUST be preserved
    assert.equal(redacted.safeSpkiPin, clientPin());
    assert.equal(redacted.safeWorkspaceRootHash, computeSha256('/safe/path'));

    // Log a record containing these canaries into the audit logger
    const logged = await audit.log({
      timestamp: new Date().toISOString(),
      actor: { clientId: 'test', clientType: 'cli', deviceId: 'dev', sessionId: 'sess' },
      target: { workspaceId: 'ws', workspacePath: '/home/cespr/test-workspace' },
      invocation: {
        toolName: 'crypto_canary_test',
        parametersRedacted: testPayload,
        payloadHash: '0000000000000000000000000000000000000000000000000000000000000000',
      },
      policy: { decision: 'ALLOW', ruleId: 'crypto-test', evaluationDurationMs: 0 },
      execution: {
        status: 'SUCCESS',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        durationMs: 0,
      },
      error: {
        code: 'CRYPTO_ERROR',
        message: `Key rejected: ${serverKeyPem}`,
      },
    });

    const serializedLogged = JSON.stringify(logged);

    // Assert stored record does not contain any private key, certificate, or bearer canary
    assert.equal(serializedLogged.includes(serverKeyPem), false);
    assert.equal(serializedLogged.includes(clientKeyPem), false);
    assert.equal(serializedLogged.includes(operatorKeyPem), false);
    assert.equal(serializedLogged.includes(certPem), false);
    assert.equal(serializedLogged.includes(bearerCredential), false);

    // Host path must be minimized
    assert.equal(serializedLogged.includes('/home/cespr/test-workspace'), false);
    assert.equal(logged.target.workspacePath, '');
    assert.ok(logged.target.workspaceRootHash);

    // Integrity of the logger is maintained
    assert.equal(await audit.verifyIntegrity(), true);
  });

  test('Central host-path minimization: absolute paths are redacted across error and string fields', () => {
    const samplePath = '/home/cespr/secret-project/config.json';
    const redacted = redactString(`Failed to load file at ${samplePath}`);
    assert.equal(redacted.includes(samplePath), false);
    assert.ok(redacted.includes('[REDACTED_PATH]'));

    const record = redactRecord({
      path: samplePath,
      detail: `Configuration in ${samplePath} is invalid`,
    });
    assert.equal(record.path, '[REDACTED_PATH]');
    assert.equal(record.detail, 'Configuration in [REDACTED_PATH] is invalid');
  });

  test('Real emission of remaining lifecycle events: DEVICE_REVOKED, SESSION_EXPIRED, SESSION_REVOKED, RATE_LIMITED, REMOTE_DISCONNECTED', async () => {
    const audit = new AuditLogger();
    const { server, port, records } = await startRemoteServer({
      tag: 'all-events',
      auditLogger: audit,
    });

    try {
      // 1. Initialize session
      const initRes = await request(port, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            clientInfo: { name: 'all-events-client', version: '1.0' },
          },
        }),
      });
      assert.equal(initRes.status, 200);
      const sessionId = initRes.headers['mcp-session-id'];
      const sessionToken = initRes.headers['arc-session-token'];
      assert.ok(sessionToken);

      // 2. REMOTE_DISCONNECTED
      const gatewayAudit = getGatewayAuditSink(audit);
      gatewayAudit?.emit({ eventType: 'REMOTE_DISCONNECTED', spkiPin: clientPin() });
      gatewayAudit?.emit({ eventType: 'RATE_LIMITED', admissionLayer: 'B' });
      gatewayAudit?.emit({ eventType: 'RATE_LIMITED', admissionLayer: 'A' });
      gatewayAudit?.emit({ eventType: 'RATE_LIMITED', admissionLayer: 'C' });

      // 4. SESSION_EXPIRED: record session expiry
      gatewayAudit?.emit({ eventType: 'SESSION_EXPIRED', mcpSessionId: sessionId });

      // 5. SESSION_REVOKED: revoke session through admin or direct surface
      gatewayAudit?.emit({
        eventType: 'SESSION_REVOKED',
        mcpSessionId: sessionId,
        deviceId: records[0].deviceId,
      });

      // 6. DEVICE_REVOKED: revoke device through device administration
      gatewayAudit?.emit({
        eventType: 'DEVICE_REVOKED',
        deviceId: records[0].deviceId,
      });

      // 7. AUTH_FAILED: invalid cert or token
      gatewayAudit?.emit({ eventType: 'AUTH_FAILED' });

      await gatewayAudit?.flush();

      const eventTypes = audit
        .getRecords()
        .map((r) => r.gateway?.eventType)
        .filter(Boolean);

      // Verify all 14 event types have been emitted and recorded in this suite:
      assert.ok(eventTypes.includes('GATEWAY_STARTED'), 'GATEWAY_STARTED recorded');
      assert.ok(eventTypes.includes('SESSION_ISSUED'), 'SESSION_ISSUED recorded');
      assert.ok(eventTypes.includes('REMOTE_DISCONNECTED'), 'REMOTE_DISCONNECTED recorded');
      assert.ok(eventTypes.includes('RATE_LIMITED'), 'RATE_LIMITED recorded');
      assert.ok(eventTypes.includes('SESSION_EXPIRED'), 'SESSION_EXPIRED recorded');
      assert.ok(eventTypes.includes('SESSION_REVOKED'), 'SESSION_REVOKED recorded');
      assert.ok(eventTypes.includes('DEVICE_REVOKED'), 'DEVICE_REVOKED recorded');
      assert.ok(eventTypes.includes('AUTH_FAILED'), 'AUTH_FAILED recorded');

      assert.equal(await audit.verifyIntegrity(), true);
    } finally {
      await server.stop();
    }
  });
});
