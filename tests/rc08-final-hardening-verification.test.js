/** RC-08 Task 8 — Cross-Cutting Hardening, Final Verification & Promotion. */
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';

import {
  ALL_TOOL_DEFINITIONS,
  ArcMcpServer,
  createArcMcpServer,
  sanitizeClientErrorMessage,
} from '../apps/mcp-server/dist/index.js';
import {
  createProductionDeterministicRegistry,
  VERIFY_FORMAT_REGISTRY_ID,
  VERIFY_LINT_REGISTRY_ID,
  VERIFY_TEST_REGISTRY_ID,
  VERIFY_TYPECHECK_REGISTRY_ID,
  ARC_TEST_NODE_REGISTRY_ID,
} from '../apps/mcp-server/dist/composite-framework.js';
import {
  ACTIVE_SEGMENT_FILENAME,
  AuditLogger,
  redactRecord,
} from '../packages/audit/dist/index.js';
import { createTestAuditRuntime } from '../packages/audit/dist/internal/runtime-testing.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { GitSubsystem } from '../packages/git/dist/index.js';
import {
  ApprovalStateManager,
  SecurityKernel,
  WorkspaceRegistry,
} from '../packages/policy/dist/index.js';
import { ProcessRegistry, scrubOutput } from '../packages/processes/dist/index.js';
import { ControlledProcessRunner } from '../packages/terminal/dist/index.js';
import { createAuditConfig } from './helpers/rc06-audit-runtime.mjs';
import { createTestPki, hasOpenssl } from './helpers/rc05-test-pki.mjs';
import {
  RawJsonRpcStdioClient,
  makeRawHttpsRequest,
  spawnArcStdioServerProcess,
  startTestRemoteServer,
} from './helpers/rc08-mcp-client-harness.mjs';
import { assertRc08ControlCoverage } from './helpers/rc08-control-coverage.mjs';

const require = createRequire(import.meta.url);
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc08-task8-'));
const resources = [];
const ACTOR = {
  clientId: 'rc08-task8-client',
  clientType: 'agent',
  sessionId: 'rc08-task8-session',
  deviceId: 'rc08-task8-device',
  authenticated: true,
};
const EXPECTED_TOOLS = Object.freeze([
  'health',
  'system_status',
  'list_directory',
  'read_file',
  'search_files',
  'search_text',
  'git_status',
  'git_diff',
  'git_log',
  'run_command',
  'process_status',
  'process_output',
  'terminate_process',
  'create_file',
  'write_file',
  'delete_file',
  'move_file',
  'apply_patch',
  'arc_repo_status',
  'arc_worktree_status',
  'arc_review_diff',
  'arc_verify',
  'arc_test',
  'arc_ci_status',
  'arc_stage_evidence',
]);
const EXPECTED_REGISTRY = Object.freeze([
  VERIFY_FORMAT_REGISTRY_ID,
  VERIFY_LINT_REGISTRY_ID,
  VERIFY_TYPECHECK_REGISTRY_ID,
  VERIFY_TEST_REGISTRY_ID,
  ARC_TEST_NODE_REGISTRY_ID,
]);
let pki;

before(() => {
  assert.equal(hasOpenssl(), true);
  pki = createTestPki(path.join(tempRoot, 'pki'));
});

after(async () => {
  for (const resource of resources.reverse()) {
    try {
      await resource.stop?.();
      await resource.cleanup?.();
    } catch {
      // Best-effort cleanup of test-owned resources.
    }
  }
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

function responseBody(response) {
  return JSON.parse(response.content[0].text);
}

function remotePayload(text) {
  const value = text.trim();
  if (value.startsWith('{')) return JSON.parse(value);
  const line = value.split('\n').find((entry) => entry.startsWith('data:'));
  assert.ok(line, 'SSE response must contain a data frame');
  return JSON.parse(line.slice(5).trim());
}

function workspace(label) {
  const root = path.join(tempRoot, label);
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, 'README.md'), '# RC-08 Task 8\n');
  return root;
}

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function initializeGit(root) {
  git(root, ['init', '-b', 'main']);
  git(root, ['config', 'user.email', 'task8@example.invalid']);
  git(root, ['config', 'user.name', 'Task 8']);
}

function localServer(label, options = {}) {
  const root = options.root ?? workspace(label);
  const audit = options.audit === true ? createAuditConfig(tempRoot, `${label}-audit`) : undefined;
  const processStateDir = path.join(tempRoot, `${label}-process-state`);
  const server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: [{ id: 'ws', path: root }],
    defaultWorkspaceId: 'ws',
    processStateDir,
    ...(audit ? { audit } : {}),
  });
  return { server, root, audit, processStateDir };
}

async function approveAndRedeem(server, toolName, args) {
  const challenge = await server.executeAuthenticatedToolCall(ACTOR, toolName, args);
  const challengeBody = responseBody(challenge);
  assert.equal(challengeBody.code, 'APPROVAL_REQUIRED');
  const requestId = challengeBody.details.approvalRequestId;
  const grant = server.approvalStateManager.approve(requestId);
  const response = await server.executeAuthenticatedToolCall(ACTOR, toolName, {
    ...args,
    _arcApproval: { requestId, token: grant.token },
  });
  return { challengeBody, requestId, grant, response };
}

function snapshotDirectory(root) {
  const snapshot = new Map();
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile())
        snapshot.set(path.relative(root, absolute), fs.readFileSync(absolute));
    }
  };
  visit(root);
  return snapshot;
}

async function remoteCall(harness, headers, rpc) {
  const { promise } = makeRawHttpsRequest({
    port: harness.port,
    caPath: pki.trustedCaCertPath,
    certPath: pki.clientCertPath,
    keyPath: pki.clientKeyPath,
    headers,
    body: JSON.stringify(rpc),
  });
  return promise;
}

async function initializeRemote(harness, id) {
  const response = await remoteCall(
    harness,
    {},
    {
      jsonrpc: '2.0',
      id,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'rc08-task8', version: '1' },
      },
    },
  );
  assert.equal(remotePayload(response.body).error, undefined);
  return {
    'Mcp-Session-Id': response.headers['mcp-session-id'],
    Authorization: `Bearer ${response.headers['arc-session-token']}`,
  };
}

function deriveCompositeFiles() {
  const serverSource = fs.readFileSync('apps/mcp-server/src/index.ts', 'utf8');
  const derived = new Set(['apps/mcp-server/src/composite-framework.ts']);
  const importPattern = /from ['"]\.\/internal\/([^'"]+)\.js['"]/g;
  const implementationNames = new Set([
    'repo-worktree-status',
    'review-diff',
    'verify',
    'test',
    'ci-status',
    'stage-evidence',
  ]);
  let match;
  while ((match = importPattern.exec(serverSource)) !== null) {
    if (implementationNames.has(match[1])) {
      derived.add(`apps/mcp-server/src/internal/${match[1]}.ts`);
    }
  }
  assert.equal(
    derived.size,
    7,
    'all six production composite handlers plus framework are required',
  );
  return [...derived].sort();
}

test('RC08-NEG-081: frozen production discovery is exactly the same 25 tools locally, over stdio, and remotely', async () => {
  const expected = [...EXPECTED_TOOLS].sort();
  const production = ALL_TOOL_DEFINITIONS.map((tool) => tool.name);
  assert.equal(production.length, 25);
  assert.equal(new Set(production).size, 25);
  assert.deepEqual([...production].sort(), expected);

  const stdio = spawnArcStdioServerProcess({ tempDir: tempRoot, label: 'neg081' });
  const client = new RawJsonRpcStdioClient(stdio.proc);
  const remote = await startTestRemoteServer({
    tempDir: tempRoot,
    pki,
    tag: 'neg081',
    enrolledClientCertPaths: [pki.clientCertPath],
  });
  try {
    await client.request('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'task8-stdio', version: '1' },
    });
    client.notify('notifications/initialized', {});
    const stdioNames = (await client.request('tools/list', {})).result.tools.map(
      (tool) => tool.name,
    );
    assert.deepEqual(stdioNames.sort(), expected);

    const headers = await initializeRemote(remote, 811);
    const remoteNames = remotePayload(
      (
        await remoteCall(remote, headers, {
          jsonrpc: '2.0',
          id: 812,
          method: 'tools/list',
          params: {},
        })
      ).body,
    ).result.tools.map((tool) => tool.name);
    assert.deepEqual(remoteNames.sort(), expected);
  } finally {
    client.close();
    await stdio.cleanup();
    await remote.cleanup();
  }
});

test('RC08-NEG-082: every production composite module is free of direct child_process imports', () => {
  const pattern =
    /(?:from\s+['"](?:node:)?child_process['"]|require\(['"](?:node:)?child_process['"]\))/;
  for (const file of deriveCompositeFiles()) {
    assert.equal(
      pattern.test(fs.readFileSync(file, 'utf8')),
      false,
      `${file} bypasses supervision`,
    );
  }
});

test('RC08-NEG-083: every production composite module is free of direct fs imports', () => {
  const pattern =
    /(?:from\s+['"](?:node:)?fs(?:\/promises)?['"]|require\(['"](?:node:)?fs(?:\/promises)?['"]\))/;
  for (const file of deriveCompositeFiles()) {
    assert.equal(pattern.test(fs.readFileSync(file, 'utf8')), false, `${file} bypasses filesystem`);
  }
});

test('RC08-NEG-084: production deterministic execution registry is exactly the frozen five identities', () => {
  const ids = createProductionDeterministicRegistry().listEntryIds();
  assert.equal(ids.length, 5);
  assert.equal(new Set(ids).size, 5);
  assert.deepEqual([...ids].sort(), [...EXPECTED_REGISTRY].sort());
});

test('RC08-NEG-085: public run_command denies package runners, shells, and arbitrary command strings', async () => {
  const { server } = localServer('neg085');
  const forbidden = [
    { executable: 'npm', args: ['run', 'test'] },
    { executable: 'pnpm', args: ['run', 'test'] },
    { executable: 'yarn', args: ['test'] },
    { executable: 'sh', args: ['-c', 'echo forbidden'] },
    { executable: 'bash', args: ['-c', 'echo forbidden'] },
    { executable: 'cmd', args: ['/c', 'echo forbidden'] },
    { executable: 'powershell', args: ['-Command', 'Write-Output forbidden'] },
    { executable: 'node', args: ['--version;echo forbidden'] },
  ];
  for (const request of forbidden) {
    const response = await server.executeAuthenticatedToolCall(ACTOR, 'run_command', request);
    assert.equal(response.isError, true);
    assert.match(
      responseBody(response).code,
      /^(POLICY_DENIED|INVALID_REQUEST_SCHEMA|FORBIDDEN_COMMAND)$/,
    );
  }
  assert.equal(server.processRegistry.listProcesses().length, 0);
  const safe = await server.executeAuthenticatedToolCall(ACTOR, 'run_command', {
    executable: 'node',
    args: ['--version'],
  });
  assert.equal(safe.isError, undefined);
  assert.match(responseBody(safe).stdout, /^v\d+/);
});

test('RC08-NEG-086: arc_ci_status succeeds from local state with every Node outbound API trapped', async () => {
  const root = workspace('neg086');
  initializeGit(root);
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(
    path.join(root, '.github', 'workflows', 'ci.yml'),
    'name: CI\non: [push]\njobs: {}\n',
  );
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'fixture']);
  const { server } = localServer('neg086-server', { root });
  let attempts = 0;
  const originals = {
    fetch: globalThis.fetch,
    httpRequest: http.request,
    httpsRequest: https.request,
    netConnect: net.connect,
    tlsConnect: tls.connect,
  };
  const trap = () => {
    attempts += 1;
    throw new Error('outbound network forbidden by RC08-NEG-086');
  };
  globalThis.fetch = trap;
  http.request = trap;
  https.request = trap;
  net.connect = trap;
  tls.connect = trap;
  let response;
  try {
    response = await server.executeAuthenticatedToolCall(ACTOR, 'arc_ci_status', {});
  } finally {
    globalThis.fetch = originals.fetch;
    http.request = originals.httpRequest;
    https.request = originals.httpsRequest;
    net.connect = originals.netConnect;
    tls.connect = originals.tlsConnect;
  }
  assert.equal(attempts, 0);
  assert.equal(response.isError, undefined);
  const result = responseBody(response);
  assert.equal(result.localSimulationMode, true);
  assert.equal(result.remoteQueryDeferred, true);
  assert.equal(result.workflowsFound.length, 1);
});

class MutationSpy extends FilesystemSubsystem {
  constructor() {
    super();
    this.mutations = 0;
    this.reads = 0;
  }
  async createFile(root, request) {
    this.mutations += 1;
    return super.createFile(root, request);
  }
  async readFile(root, request) {
    this.reads += 1;
    return super.readFile(root, request);
  }
}

class FaultInjectedServer extends ArcMcpServer {
  constructor(parts, runtimeOptions) {
    super(
      parts.registry,
      parts.kernel,
      parts.auditLogger,
      parts.filesystem,
      parts.gitSubsystem,
      parts.config,
      parts.terminal,
      parts.processRegistry,
      parts.approvals,
    );
    this.runtimeOptions = runtimeOptions;
  }
  async openAuditRuntimeForProcess(config) {
    return createTestAuditRuntime(config, this.runtimeOptions);
  }
}

test('RC08-NEG-087: durable audit degradation blocks approved and subsequent privileged execution', async () => {
  const root = workspace('neg087');
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('ws', root);
  const processRegistry = new ProcessRegistry();
  const approvals = new ApprovalStateManager();
  const filesystem = new MutationSpy();
  const config = {
    transport: 'stdio',
    authorizedRoots: [{ id: 'ws', path: root }],
    defaultWorkspaceId: 'ws',
    audit: createAuditConfig(tempRoot, 'neg087-audit'),
  };
  const parts = {
    registry,
    processRegistry,
    approvals,
    filesystem,
    config,
    kernel: new SecurityKernel(registry, processRegistry),
    auditLogger: new AuditLogger(),
    gitSubsystem: new GitSubsystem(),
    terminal: new ControlledProcessRunner(processRegistry),
  };
  const server = new FaultInjectedServer(parts, { hooks: { failAppendPhase: 'STARTED' } });
  await server.start();
  resources.push(server);

  const challenge = await server.executeAuthenticatedToolCall(ACTOR, 'create_file', {
    workspaceId: 'ws',
    path: 'blocked.txt',
    content: 'must-not-exist',
  });
  const challengeBody = responseBody(challenge);
  assert.equal(challengeBody.code, 'APPROVAL_REQUIRED');
  const grant = server.approvalStateManager.approve(challengeBody.details.approvalRequestId);
  const redemption = await server.executeAuthenticatedToolCall(ACTOR, 'create_file', {
    workspaceId: 'ws',
    path: 'blocked.txt',
    content: 'must-not-exist',
    _arcApproval: { requestId: challengeBody.details.approvalRequestId, token: grant.token },
  });
  assert.equal(responseBody(redemption).code, 'INTERNAL_ERROR');
  assert.equal(filesystem.mutations, 0);
  assert.equal(fs.existsSync(path.join(root, 'blocked.txt')), false);

  const later = await server.executeAuthenticatedToolCall(ACTOR, 'read_file', {
    workspaceId: 'ws',
    path: 'README.md',
  });
  assert.equal(responseBody(later).code, 'INTERNAL_ERROR');
  assert.equal(filesystem.reads, 0);
  assert.equal(processRegistry.listProcesses().length, 0);
  const ledger = fs.readFileSync(
    path.join(config.audit.directory, ACTIVE_SEGMENT_FILENAME),
    'utf8',
  );
  assert.equal(ledger.includes('"phase":"FAILED"'), false);
});

test('RC08-NEG-088: central redaction removes secret shapes from errors, audit, and process output', async () => {
  const githubToken = 'ghp_' + 'A'.repeat(36);
  const apiToken = 'sk-' + 'B'.repeat(24);
  const bearer = 'Bearer ' + 'C'.repeat(40);
  const sessionToken = 'session_token=' + 'D'.repeat(48);
  const approvalToken = 'approval-token-' + 'E'.repeat(48);
  const privateKey = [
    '-----BEGIN PRIVATE KEY-----',
    'PRIVATE-DATA',
    '-----END PRIVATE KEY-----',
  ].join('\n');
  const certificate = [
    '-----BEGIN CERTIFICATE-----',
    'CERT-DATA',
    '-----END CERTIFICATE-----',
  ].join('\n');
  const hostPath = path.join(tempRoot, 'confidential', 'token.txt');
  const digest = 'f'.repeat(64);
  const rawSecrets = [
    githubToken,
    apiToken,
    bearer,
    sessionToken,
    approvalToken,
    privateKey,
    certificate,
    hostPath,
    'ENV-CONFIDENTIAL-088',
  ];
  const projected = redactRecord({
    parameters: { githubToken, apiToken, authorization: bearer, sessionToken, hostPath },
    error: `${privateKey}\n${certificate}\n${hostPath}`,
    processOutput: `${githubToken}\n${apiToken}\n${bearer}\n${privateKey}\n${certificate}`,
    gatewayMetadata: { sessionToken, certificate },
    approvalMetadata: { approvalToken },
    env: { SECRET_VALUE: 'ENV-CONFIDENTIAL-088' },
    digest,
  });
  const projectedText = JSON.stringify(projected);
  for (const secret of rawSecrets) assert.equal(projectedText.includes(secret), false);
  assert.equal(projectedText.includes(digest), true, 'safe SHA-256 evidence remains visible');

  const publicError = sanitizeClientErrorMessage(
    `${githubToken} ${apiToken} ${bearer} ${privateKey} ${certificate} ${hostPath}`,
  );
  const processOutput = scrubOutput(
    `${githubToken} ${apiToken} ${bearer} ${privateKey} ${certificate}`,
  );
  for (const secret of [githubToken, apiToken, bearer, privateKey, certificate, hostPath]) {
    assert.equal(publicError.includes(secret), false);
  }
  for (const secret of [githubToken, apiToken, bearer, privateKey, certificate]) {
    assert.equal(processOutput.includes(secret), false);
  }

  const parts = localServer('neg088', { audit: true });
  await parts.server.start();
  await parts.server.executeAuthenticatedToolCall(ACTOR, 'read_file', {
    path: 'README.md',
    apiKey: apiToken,
    authorization: bearer,
    privateKey,
    certificate,
    env: { SECRET_VALUE: 'ENV-CONFIDENTIAL-088' },
    hostPath,
  });
  await parts.server.stop();
  const ledger = fs.readFileSync(path.join(parts.audit.directory, ACTIVE_SEGMENT_FILENAME), 'utf8');
  for (const secret of rawSecrets) assert.equal(ledger.includes(secret), false);
});

test('RC08-NEG-089: clean Git, passing tests, and a tracked verifier cannot fabricate stage approval', async () => {
  const root = workspace('neg089');
  initializeGit(root);
  fs.mkdirSync(path.join(root, 'scripts'));
  fs.writeFileSync(path.join(root, 'scripts', 'verify-rc08.sh'), '#!/usr/bin/env bash\nexit 0\n');
  fs.writeFileSync(
    path.join(root, 'passing.test.js'),
    "import test from 'node:test';test('passes',()=>{});\n",
  );
  git(root, ['add', '.']);
  git(root, ['commit', '-m', 'clean fixture']);
  const parts = localServer('neg089-server', { root, audit: true });
  await parts.server.start();
  resources.push(parts.server);

  const passing = await approveAndRedeem(parts.server, 'arc_test', { testPath: 'passing.test.js' });
  assert.equal(responseBody(passing.response).status, 'PASSED');
  const evidence = await parts.server.executeAuthenticatedToolCall(ACTOR, 'arc_stage_evidence', {
    targetStage: 'RC-08',
  });
  assert.equal(evidence.isError, undefined);
  const evidenceBody = responseBody(evidence);
  assert.equal(evidenceBody.repository.isClean, true);
  assert.equal(evidenceBody.verification.scriptPresent, true);
  assert.equal(evidenceBody.verification.verifiedLocally, false);
  assert.equal(evidenceBody.acceptanceMet, false);
  assert.match(evidenceBody.disclaimer, /does not constitute.*approval/i);

  const wrongStage = await parts.server.executeAuthenticatedToolCall(ACTOR, 'arc_stage_evidence', {
    targetStage: 'RC-99',
  });
  assert.equal(responseBody(wrongStage).code, 'STAGE_NOT_FOUND');
  const noAudit = localServer('neg089-no-audit', { root }).server;
  const absent = await noAudit.executeAuthenticatedToolCall(ACTOR, 'arc_stage_evidence', {
    targetStage: 'RC-08',
  });
  assert.equal(responseBody(absent).code, 'EVIDENCE_NOT_MET');
});

test('RC08-NEG-090: promotion provenance and every authoritative current version surface are consistent', () => {
  const parentPackage = JSON.parse(
    execFileSync('git', ['show', 'a94515e2d4b83b89944ac9f6618ac183e9e17481:package.json'], {
      encoding: 'utf8',
    }),
  );
  const parentServer = execFileSync(
    'git',
    ['show', 'a94515e2d4b83b89944ac9f6618ac183e9e17481:apps/mcp-server/src/index.ts'],
    { encoding: 'utf8' },
  );
  assert.equal(parentPackage.version, '0.7.0-rc07');
  assert.match(parentServer, /stage: 'RC-07'/);

  for (const manifest of [
    'package.json',
    'apps/mcp-server/package.json',
    'apps/cli/package.json',
  ]) {
    assert.equal(JSON.parse(fs.readFileSync(manifest, 'utf8')).version, '1.0.0');
  }
  const serverSource = fs.readFileSync('apps/mcp-server/src/index.ts', 'utf8');
  assert.equal((serverSource.match(/1\.0\.0/g) ?? []).length, 5);
  assert.match(serverSource, /stage: 'ARC-1\.0'/);
  assert.match(fs.readFileSync('apps/cli/src/index.ts', 'utf8'), /CLI_VERSION = '1\.0\.0'/);
  const verifier = fs.readFileSync('scripts/verify-rc08.sh', 'utf8');
  assert.match(verifier, /EXPECTED_VERSION="0\.8\.0-rc08"/);
  assert.match(verifier, /EXPECTED_STAGE="RC-08"/);
  assert.match(fs.readFileSync('README.md', 'utf8'), /\| \*\*RC-08\*\*.*\| Implemented \|/);
});

test('RC08-FLOW-18: approved production arc_verify runs the complete frozen check-only suite once', async () => {
  const root = workspace('flow018');
  fs.writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({ name: 'rc08-flow18', type: 'module' }, null, 2) + '\n',
  );
  fs.writeFileSync(path.join(root, 'index.ts'), 'export const answer: number = 42;\n');
  fs.writeFileSync(path.join(root, 'eslint.config.js'), 'export default [];\n');
  fs.writeFileSync(
    path.join(root, 'tsconfig.json'),
    JSON.stringify({ compilerOptions: { noEmit: true }, files: ['index.ts'] }, null, 2) + '\n',
  );
  fs.mkdirSync(path.join(root, 'test'));
  fs.writeFileSync(
    path.join(root, 'test', 'passing.test.js'),
    "import test from 'node:test';import assert from 'node:assert/strict';test('ok',()=>assert.equal(2+2,4));\n",
  );
  const prettierPackage = require.resolve('prettier/package.json');
  const prettierBin = path.resolve(path.dirname(prettierPackage), 'bin/prettier.cjs');
  execFileSync(process.execPath, [prettierBin, '--write', '.'], { cwd: root });
  const before = snapshotDirectory(root);
  const parts = localServer('flow018-server', { root, audit: true });
  await parts.server.start();
  resources.push(parts.server);
  const flow = await approveAndRedeem(parts.server, 'arc_verify', { suite: 'all' });
  assert.equal(flow.response.isError, undefined);
  const result = responseBody(flow.response);
  assert.equal(result.status, 'PASSED');
  assert.deepEqual(
    result.steps.map((step) => [step.stepName, step.status, step.exitCode]),
    [
      ['format', 'PASSED', 0],
      ['lint', 'PASSED', 0],
      ['typecheck', 'PASSED', 0],
      ['test', 'PASSED', 0],
    ],
  );
  assert.deepEqual(createProductionDeterministicRegistry().listEntryIds(), EXPECTED_REGISTRY);
  assert.equal(parts.server.processRegistry.listProcesses().length, 4);
  const after = snapshotDirectory(root);
  assert.deepEqual([...after.keys()].sort(), [...before.keys()].sort());
  for (const [file, content] of before)
    assert.deepEqual(after.get(file), content, `${file} mutated`);
  assert.equal(parts.server.approvalStateManager.getRequest(flow.requestId).state, 'CONSUMED');
  await parts.server.stop();
  const ledger = fs.readFileSync(path.join(parts.audit.directory, ACTIVE_SEGMENT_FILENAME), 'utf8');
  assert.equal(ledger.includes(flow.grant.token), false);
  const phases = ledger
    .trim()
    .split('\n')
    .map(JSON.parse)
    .filter((record) => record.invocation.toolName === 'arc_verify')
    .map((record) => record.lifecycle?.phase);
  assert.deepEqual(
    phases.filter((phase) => phase === 'STARTED' || phase === 'COMPLETED'),
    ['STARTED', 'COMPLETED'],
  );
  assert.equal(phases.includes('FAILED'), false);
});

test('RC08-FLOW-19: approved production arc_test runs only its targeted passing test with bounded output', async () => {
  const root = workspace('flow019');
  const secret = 'ghp_' + 'Z'.repeat(36);
  fs.writeFileSync(
    path.join(root, 'target.test.js'),
    `import test from 'node:test';import assert from 'node:assert/strict';test('target',()=>{console.log('${secret}');assert.equal(1,1);});\n`,
  );
  fs.writeFileSync(
    path.join(root, 'must-not-run.test.js'),
    "import test from 'node:test';test('must-not-run',()=>{throw new Error('WRONG_FILE_EXECUTED')});\n",
  );
  const parts = localServer('flow019-server', { root, audit: true });
  await parts.server.start();
  resources.push(parts.server);
  const flow = await approveAndRedeem(parts.server, 'arc_test', {
    testPath: 'target.test.js',
    maxDurationMs: 10_000,
  });
  assert.equal(flow.response.isError, undefined);
  const result = responseBody(flow.response);
  assert.equal(result.status, 'PASSED');
  assert.equal(result.target, 'target.test.js');
  assert.equal(result.passedCount, 1);
  assert.equal(result.failedCount, 0);
  assert.match(result.processId, /^arc-proc-/);
  assert.equal(result.outputExcerpt.includes(secret), false);
  assert.equal(result.outputExcerpt.includes('WRONG_FILE_EXECUTED'), false);
  assert.equal(Buffer.byteLength(JSON.stringify(result), 'utf8') <= 256 * 1024, true);
  assert.equal(parts.server.approvalStateManager.getRequest(flow.requestId).state, 'CONSUMED');
  assert.equal(parts.server.processRegistry.countRunning(), 0);
  assert.deepEqual(
    fs.existsSync(parts.processStateDir) ? fs.readdirSync(parts.processStateDir) : [],
    [],
  );
  await parts.server.stop();
  const ledger = fs.readFileSync(path.join(parts.audit.directory, ACTIVE_SEGMENT_FILENAME), 'utf8');
  assert.equal(ledger.includes(flow.grant.token), false);
  assert.deepEqual(
    ledger
      .trim()
      .split('\n')
      .map(JSON.parse)
      .filter((record) => record.invocation.toolName === 'arc_test')
      .map((record) => record.lifecycle?.phase)
      .filter((phase) => phase === 'STARTED' || phase === 'COMPLETED'),
    ['STARTED', 'COMPLETED'],
  );
});

test('RC08-FLOW-20: authoritative verifier owns all final gates and implementation coverage', () => {
  const scriptPath = 'scripts/verify-rc08.sh';
  const branchGatePath = path.resolve('scripts/verify-rc08-branch.sh');
  fs.accessSync(scriptPath, fs.constants.X_OK);
  fs.accessSync(branchGatePath, fs.constants.X_OK);
  const source = fs.readFileSync(scriptPath, 'utf8');
  assert.match(source, /^#!\/usr\/bin\/env bash/m);
  assert.match(source, /set -euo pipefail/);
  assert.equal(source.includes('||' + ' true'), false);
  const gates = [...source.matchAll(/(?:^|\n)# Gate (\d+):/g)].map((match) => Number(match[1]));
  assert.deepEqual(
    gates,
    Array.from({ length: 20 }, (_, index) => index + 1),
  );
  for (const required of [
    'pnpm run check:format',
    'pnpm run lint',
    'pnpm run typecheck',
    'pnpm run build',
    'pnpm run test',
    'bash scripts/check-docs.sh',
    'bash scripts/check-secrets.sh',
    'pnpm audit',
    'git diff --check',
    'tests/helpers/rc08-control-coverage.mjs',
  ]) {
    assert.equal(source.includes(required), true, `missing verification gate: ${required}`);
  }
  const coverage = assertRc08ControlCoverage();
  assert.equal(coverage.negativeFound, 90);
  assert.equal(coverage.flowsFound, 20);

  const verifyBranch = (branch) => {
    const root = workspace(`flow20-branch-${branch.replaceAll('/', '-')}`);
    initializeGit(root);
    git(root, ['add', 'README.md']);
    git(root, ['commit', '-m', 'fixture']);
    if (branch !== 'main') git(root, ['branch', '-m', branch]);
    return () => execFileSync('bash', [branchGatePath], { cwd: root, encoding: 'utf8' });
  };

  assert.doesNotThrow(verifyBranch('feat/rc-08-integrations-security-review'));
  assert.doesNotThrow(verifyBranch('main'));
  assert.throws(
    verifyBranch('rc08-invalid-branch'),
    /RC-08 verification must run on .* or main; got rc08-invalid-branch/,
  );
});
