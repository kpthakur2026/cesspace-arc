import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import fc from 'fast-check';

import {
  ALL_TOOL_DEFINITIONS,
  TOOL_SCHEMAS,
  createArcMcpServer,
} from '../apps/mcp-server/dist/index.js';
import { extractArcApproval } from '../apps/mcp-server/dist/approval-gate.js';
import {
  readBoundedRequestBody,
  RequestBodyError,
} from '../apps/mcp-server/dist/remote-request-bounds.js';
import { FilesystemSubsystem } from '../packages/filesystem/dist/index.js';
import { validateGitArgument } from '../packages/git/dist/index.js';
import {
  RawJsonRpcStdioClient,
  spawnArcStdioServerProcess,
} from './helpers/rc08-mcp-client-harness.mjs';
import {
  DEFAULT_FUZZ_SEED,
  EXTENDED_FUZZ_RUNS,
  FUZZ_PATH,
  FUZZ_RUNS,
  FUZZ_SEED,
  MAX_GENERATED_ARRAY_LENGTH,
  MAX_GENERATED_DEPTH,
  MAX_GENERATED_PAYLOAD_BYTES,
  MAX_GENERATED_STRING_BYTES,
  NORMAL_FUZZ_RUNS,
  assertFuzzProperty,
  fastCheckParameters,
  reportFuzzConfiguration,
  reproductionCommand,
} from './helpers/rc08-fuzz-harness.mjs';

const HASH = 'a'.repeat(64);

// Test-only and deliberately explicit: additions to the production catalog must
// make this file fail until their schema fuzz classification is reviewed.
const TOOL_MANIFEST = [
  { name: 'health', args: {}, required: [], types: {}, paths: [], git: [], composite: [] },
  { name: 'system_status', args: {}, required: [], types: {}, paths: [], git: [], composite: [] },
  {
    name: 'list_directory',
    args: {},
    required: [],
    types: { path: 'string', recursive: 'boolean', maxDepth: 'number' },
    paths: ['path'],
    git: [],
    composite: [],
  },
  {
    name: 'read_file',
    args: { path: 'README.md' },
    required: ['path'],
    types: { path: 'string', offset: 'number', length: 'number' },
    paths: ['path'],
    git: [],
    composite: [],
  },
  {
    name: 'search_files',
    args: { pattern: '*.js' },
    required: ['pattern'],
    types: { pattern: 'string', subPath: 'string', maxResults: 'number' },
    paths: ['subPath'],
    git: [],
    composite: [],
  },
  {
    name: 'search_text',
    args: { query: 'safe' },
    required: ['query'],
    types: { query: 'string', isRegex: 'boolean', filePattern: 'string', maxMatches: 'number' },
    paths: [],
    git: [],
    composite: [],
  },
  {
    name: 'git_status',
    args: {},
    required: [],
    types: { workspaceRoot: 'string' },
    paths: ['workspaceRoot'],
    git: [],
    composite: [],
  },
  {
    name: 'git_diff',
    args: {},
    required: [],
    types: { target: 'string', path: 'string', cached: 'boolean' },
    paths: ['path'],
    git: ['target'],
    composite: [],
  },
  {
    name: 'git_log',
    args: {},
    required: [],
    types: { maxCount: 'number', revision: 'string', path: 'string' },
    paths: ['path'],
    git: ['revision'],
    composite: [],
  },
  {
    name: 'run_command',
    args: { executable: 'node' },
    required: ['executable'],
    types: {
      executable: 'string',
      args: 'array',
      cwd: 'string',
      timeoutMs: 'number',
      env: 'object',
      runInBackground: 'boolean',
    },
    paths: ['cwd'],
    git: [],
    composite: [],
  },
  {
    name: 'process_status',
    args: { processId: 'arc-proc-safe' },
    required: ['processId'],
    types: { processId: 'string' },
    paths: [],
    git: [],
    composite: [],
  },
  {
    name: 'process_output',
    args: { processId: 'arc-proc-safe' },
    required: ['processId'],
    types: {
      processId: 'string',
      offset: 'number',
      stdoutCursor: 'number',
      stderrCursor: 'number',
      maxBytes: 'number',
    },
    paths: [],
    git: [],
    composite: [],
  },
  {
    name: 'terminate_process',
    args: { processId: 'arc-proc-safe' },
    required: ['processId'],
    types: { processId: 'string', signal: 'string' },
    paths: [],
    git: [],
    composite: [],
  },
  {
    name: 'create_file',
    args: { path: 'new.txt', content: 'safe' },
    required: ['path', 'content'],
    types: { path: 'string', content: 'string' },
    paths: ['path'],
    git: [],
    composite: [],
  },
  {
    name: 'write_file',
    args: { path: 'file.txt', content: 'safe', expectedHash: HASH, overwrite: true },
    required: ['path', 'content', 'expectedHash', 'overwrite'],
    types: { path: 'string', content: 'string', expectedHash: 'string', overwrite: 'boolean' },
    paths: ['path'],
    git: [],
    composite: [],
  },
  {
    name: 'delete_file',
    args: { path: 'file.txt', expectedHash: HASH },
    required: ['path', 'expectedHash'],
    types: { path: 'string', expectedHash: 'string' },
    paths: ['path'],
    git: [],
    composite: [],
  },
  {
    name: 'move_file',
    args: { sourcePath: 'from.txt', destinationPath: 'to.txt', expectedSourceHash: HASH },
    required: ['sourcePath', 'destinationPath', 'expectedSourceHash'],
    types: { sourcePath: 'string', destinationPath: 'string', expectedSourceHash: 'string' },
    paths: ['sourcePath', 'destinationPath'],
    git: [],
    composite: [],
  },
  {
    name: 'apply_patch',
    args: { patch: 'safe' },
    required: ['patch'],
    types: { patch: 'string', dryRun: 'boolean', fuzz: 'number' },
    paths: [],
    git: [],
    composite: [],
  },
  {
    name: 'arc_repo_status',
    args: {},
    required: [],
    types: { workspaceId: 'string', workspaceRoot: 'string' },
    paths: ['workspaceRoot'],
    git: [],
    composite: [],
  },
  {
    name: 'arc_worktree_status',
    args: {},
    required: [],
    types: { workspaceId: 'string', workspaceRoot: 'string' },
    paths: ['workspaceRoot'],
    git: [],
    composite: [],
  },
  {
    name: 'arc_review_diff',
    args: {},
    required: [],
    types: { mode: 'string', targetRevision: 'string', path: 'string', maxBytes: 'number' },
    paths: ['path'],
    git: ['targetRevision'],
    composite: ['path'],
  },
  {
    name: 'arc_verify',
    args: {},
    required: [],
    types: { suite: 'string' },
    paths: [],
    git: [],
    composite: [],
  },
  {
    name: 'arc_test',
    args: {},
    required: [],
    types: { testPath: 'string', filter: 'string', testRunner: 'string', maxDurationMs: 'number' },
    paths: ['testPath'],
    git: [],
    composite: ['testPath', 'filter'],
  },
  {
    name: 'arc_ci_status',
    args: {},
    required: [],
    types: { workflowName: 'string' },
    paths: [],
    git: [],
    composite: [],
  },
  {
    name: 'arc_stage_evidence',
    args: { targetStage: 'RC-07' },
    required: ['targetStage'],
    types: { targetStage: 'string' },
    paths: [],
    git: [],
    composite: [],
  },
];

let tempRoot;
let workspace;
let server;

function parsedToolError(result) {
  assert.equal(result.isError, true);
  return JSON.parse(result.content[0].text);
}

function wrongValue(type) {
  return { string: [], number: {}, boolean: [], array: {}, object: false }[type];
}

function makeNested(depth) {
  let value = 'health';
  for (let index = 0; index < depth; index += 1) value = { nested: value };
  return value;
}

async function initializedStdio(label) {
  const spawned = spawnArcStdioServerProcess({ tempDir: tempRoot, workspaceDir: workspace, label });
  const client = new RawJsonRpcStdioClient(spawned.proc);
  const response = await client.request('initialize', {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'rc08-fuzzer', version: '1.0.0' },
  });
  assert.ok(response.result);
  client.notify('notifications/initialized', {});
  return { ...spawned, client };
}

function rawResponse(client, raw) {
  client.sendRaw(raw);
  return client.readNext(5_000);
}

before(() => {
  reportFuzzConfiguration();
  tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc08-fuzz-'));
  workspace = path.join(tempRoot, 'workspace');
  fs.mkdirSync(workspace);
  fs.writeFileSync(path.join(workspace, 'README.md'), 'fixture\n');
  server = createArcMcpServer({
    transport: 'stdio',
    authorizedRoots: [{ id: 'ws', path: workspace }],
    defaultWorkspaceId: 'ws',
  });
});

after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

test('RC08-NEG-011: deeply nested JSON is rejected at the real stdio protocol boundary and recovery succeeds', async () => {
  const { client, cleanup } = await initializedStdio('neg-011');
  try {
    const response = await rawResponse(
      client,
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1101,
        method: 'tools/call',
        params: { name: makeNested(11), arguments: {} },
      }),
    );
    assert.ok(response.error);
    assert.ok([-32600, -32602, -32603].includes(response.error.code));
    const healthy = await client.request('tools/call', { name: 'health', arguments: {} }, 1102);
    assert.ok(healthy.result);
  } finally {
    client.close();
    await cleanup();
  }
});

test('RC08-NEG-012: 10,001-item arrays and unsafe IEEE-754 integers are rejected before execution', async () => {
  const largeArray = Array.from({ length: 10_001 }, () => 'x');
  assert.equal(
    TOOL_SCHEMAS.run_command.safeParse({ executable: 'node', args: largeArray }).success,
    false,
  );
  assert.equal(
    TOOL_SCHEMAS.process_output.safeParse({
      processId: 'arc-proc-safe',
      offset: Number.MAX_SAFE_INTEGER + 1,
    }).success,
    false,
  );
  assert.equal(
    parsedToolError(
      await server.dispatchToolCall('run_command', { executable: 'node', args: largeArray }),
    ).code,
    'INVALID_REQUEST_SCHEMA',
  );
  assert.equal(
    parsedToolError(
      await server.dispatchToolCall('process_output', {
        processId: 'arc-proc-safe',
        offset: Number.MAX_SAFE_INTEGER + 1,
      }),
    ).code,
    'INVALID_REQUEST_SCHEMA',
  );
  assert.ok((await server.dispatchToolCall('health', {})).content);
});

test('RC08-NEG-013: invalid UTF-8 bytes and malformed Unicode escape syntax fail at parser boundaries', async () => {
  const stream = new PassThrough();
  stream.headers = {};
  const bodyPromise = readBoundedRequestBody(stream, { maxBytes: 1024 });
  stream.end(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]));
  await assert.rejects(
    bodyPromise,
    (error) => error instanceof RequestBodyError && error.kind === 'INVALID_UTF8',
  );

  const { client, cleanup } = await initializedStdio('neg-013');
  try {
    client.sendRaw('{"jsonrpc":"2.0","id":1301,"method":"ping\\x"}');
    client.sendRaw(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1302,
        method: 'tools/call',
        params: { name: 'health', arguments: {} },
      }),
    );
    const recovered = await client.readNext(5_000);
    assert.equal(recovered.id, 1302);
    assert.ok(recovered.result);
  } finally {
    client.close();
    await cleanup();
  }
});

test('RC08-NEG-014: NUL and C0 controls are rejected across every relevant string schema', () => {
  let covered = 0;
  for (const entry of TOOL_MANIFEST) {
    for (const [field, type] of Object.entries(entry.types)) {
      if (type !== 'string') continue;
      for (const control of ['\0', '\u0001', '\u001f', '\u007f']) {
        const candidate = { ...entry.args, [field]: `safe${control}value` };
        assert.equal(
          TOOL_SCHEMAS[entry.name].safeParse(candidate).success,
          false,
          `${entry.name}.${field}`,
        );
      }
      covered += 1;
    }
  }
  assert.ok(covered > 0);
});

test('RC08-NEG-015: duplicate and prototype-pollution-shaped JSON keys are deterministic and harmless', async () => {
  const beforePrototype = Object.prototype._rc08Polluted;
  const { client, cleanup } = await initializedStdio('neg-015');
  try {
    const template = (id) =>
      `{"jsonrpc":"2.0","id":${id},"method":"tools/call","method":"unknown/duplicate","params":{"name":"health","arguments":{"__proto__":{"_rc08Polluted":true},"constructor":{"prototype":{"_rc08Polluted":true}},"prototype":{"_rc08Polluted":true}},"arguments":{}}}`;
    const first = await rawResponse(client, template(1501));
    const second = await rawResponse(client, template(1502));
    assert.equal(first.error?.code, -32601);
    assert.equal(second.error?.code, first.error?.code);
    assert.equal(second.error?.message, first.error?.message);
    assert.equal(Object.prototype._rc08Polluted, beforePrototype);
  } finally {
    client.close();
    await cleanup();
  }
});

test('RC08-NEG-016: unknown properties are rejected for the exact 25-tool production catalog', async () => {
  const covered = new Set();
  for (const entry of TOOL_MANIFEST) {
    const args = { ...entry.args, _rc08UnknownProperty: true };
    assert.equal(TOOL_SCHEMAS[entry.name].safeParse(args).success, false, entry.name);
    assert.equal(
      parsedToolError(await server.dispatchToolCall(entry.name, args)).code,
      'INVALID_REQUEST_SCHEMA',
    );
    covered.add(entry.name);
  }
  assert.equal(covered.size, 25);
  assert.deepEqual([...covered].sort(), ALL_TOOL_DEFINITIONS.map((tool) => tool.name).sort());
});

test('RC08-NEG-017: each required business property is rejected when missing and all 25 tools are classified', () => {
  const classified = new Set();
  for (const entry of TOOL_MANIFEST) {
    for (const field of entry.required) {
      const candidate = { ...entry.args };
      delete candidate[field];
      assert.equal(
        TOOL_SCHEMAS[entry.name].safeParse(candidate).success,
        false,
        `${entry.name}.${field}`,
      );
    }
    if (entry.required.length === 0)
      assert.equal(TOOL_SCHEMAS[entry.name].safeParse(entry.args).success, true);
    classified.add(entry.name);
  }
  assert.equal(classified.size, 25);
});

test('RC08-NEG-018: primitive and container type confusion is rejected across all 25 tools', () => {
  const covered = new Set();
  for (const entry of TOOL_MANIFEST) {
    const fields = Object.entries(entry.types);
    if (fields.length === 0) {
      assert.equal(TOOL_SCHEMAS[entry.name].safeParse([]).success, false);
    } else {
      const [field, type] = fields[0];
      assert.equal(
        TOOL_SCHEMAS[entry.name].safeParse({ ...entry.args, [field]: wrongValue(type) }).success,
        false,
        entry.name,
      );
    }
    covered.add(entry.name);
  }
  assert.equal(covered.size, 25);
});

test('RC08-NEG-019: traversal variants fail with PATH_OUTSIDE_WORKSPACE and do not touch outside files', async () => {
  const outside = path.join(tempRoot, 'outside.txt');
  fs.writeFileSync(outside, 'untouched');
  const filesystem = new FilesystemSubsystem();
  for (const payload of [
    '../outside.txt',
    '../../outside.txt',
    '....//outside.txt',
    '..\\outside.txt',
    '%2e%2e/outside.txt',
  ]) {
    await assert.rejects(
      filesystem.resolveSecurePath(workspace, payload),
      (error) => error?.code === 'PATH_OUTSIDE_WORKSPACE',
    );
  }
  assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched');
});

test('RC08-NEG-020: Git option and shell-shaped arguments fail as INVALID_GIT_ARGUMENT before invocation', () => {
  for (const payload of [
    '--upload-pack',
    '-o',
    '--exec',
    '-danger',
    '$(touch nope)',
    '`touch nope`',
    'HEAD;touch nope',
  ]) {
    assert.throws(
      () => validateGitArgument('revision', payload),
      (error) => error?.code === 'INVALID_GIT_ARGUMENT',
    );
  }
});

test('RC08-NEG-021: composite filter and path metacharacters fail schema admission before plan execution', () => {
  for (const payload of [';', '|', '&', '$()', '`id`', 'x\ny', 'x\ry', '>out']) {
    assert.equal(TOOL_SCHEMAS.arc_test.safeParse({ testPath: payload }).success, false);
    assert.equal(TOOL_SCHEMAS.arc_test.safeParse({ filter: payload }).success, false);
    assert.equal(TOOL_SCHEMAS.arc_review_diff.safeParse({ path: payload }).success, false);
  }
});

test('RC08-NEG-022: fragmented requests parse once while truncated frames fail and the stdio server recovers', async () => {
  const { client, proc, cleanup } = await initializedStdio('neg-022');
  try {
    const valid = `${JSON.stringify({ jsonrpc: '2.0', id: 2201, method: 'tools/call', params: { name: 'health', arguments: {} } })}\n`;
    for (const fragment of [valid.slice(0, 7), valid.slice(7, 31), valid.slice(31)]) {
      await new Promise((resolve, reject) =>
        proc.stdin.write(fragment, (error) => (error ? reject(error) : resolve())),
      );
    }
    assert.ok((await client.readNext(5_000)).result);
    client.sendRaw('{"jsonrpc":"2.0","id":2202,"method":');
    client.sendRaw(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 2203,
        method: 'tools/call',
        params: { name: 'health', arguments: {} },
      }),
    );
    const recovered = await client.readNext(5_000);
    assert.equal(recovered.id, 2203);
    assert.ok(recovered.result);
  } finally {
    client.close();
    await cleanup();
  }
});

test('RC08-NEG-023: a 1 MiB + 1 byte string is rejected without filesystem mutation or giant error output', async () => {
  const content = 'x'.repeat(1024 * 1024 + 1);
  const target = path.join(workspace, 'oversized.txt');
  assert.equal(
    TOOL_SCHEMAS.create_file.safeParse({ path: 'oversized.txt', content }).success,
    false,
  );
  const result = await server.dispatchToolCall('create_file', { path: 'oversized.txt', content });
  assert.equal(parsedToolError(result).code, 'INVALID_REQUEST_SCHEMA');
  assert.ok(Buffer.byteLength(result.content[0].text, 'utf8') < 4096);
  assert.equal(fs.existsSync(target), false);
});

test('RC08-NEG-024: malformed reserved approval controls never pass admission', async () => {
  const cases = [
    { requestId: 'a'.repeat(32), token: 'g'.repeat(64) },
    { requestId: 'a'.repeat(32), token: 'a'.repeat(63) },
    { requestId: 'a'.repeat(32), token: 'é'.repeat(32) },
    { requestId: 'not-an-id', token: 'a'.repeat(64) },
    { requestId: 'a'.repeat(32) },
    { requestId: 'a'.repeat(32), token: 'a'.repeat(64), unexpected: true },
  ];
  for (const control of cases) {
    const extracted = extractArcApproval({ _arcApproval: control });
    const error = parsedToolError(
      await server.dispatchToolCall('health', { _arcApproval: control }),
    );
    if (extracted.malformed) assert.equal(error.code, 'INVALID_REQUEST_SCHEMA');
    else
      assert.ok(
        ['INVALID_REQUEST_SCHEMA', 'APPROVAL_REJECTED', 'POLICY_DENIED'].includes(error.code),
      );
  }
});

test('RC08-NEG-025: a fast-check seed plus path reproduces the same controlled counterexample trajectory', () => {
  const property = fc.property(fc.integer({ min: 0, max: 100 }), (value) => value < 7);
  const first = fc.check(property, { seed: 424_242, numRuns: 100, endOnFailure: true });
  assert.equal(first.failed, true);
  const second = fc.check(property, {
    seed: first.seed,
    path: first.counterexamplePath,
    numRuns: 100,
    endOnFailure: true,
  });
  assert.equal(second.failed, true);
  assert.deepEqual(second.counterexample, first.counterexample);
  assert.equal(second.counterexamplePath, first.counterexamplePath);
  assert.match(reproductionCommand(first.seed, first.counterexamplePath), /FUZZ_SEED=424242/);
});

test('RC08-FLOW-05: deterministic corpus executes 100 normal cases against JSON parsing and every production schema', () => {
  assert.equal(DEFAULT_FUZZ_SEED, 1_592_639_710);
  assert.ok(FUZZ_RUNS === NORMAL_FUZZ_RUNS || FUZZ_RUNS === EXTENDED_FUZZ_RUNS);
  assert.equal(MAX_GENERATED_DEPTH, 10);
  assert.equal(MAX_GENERATED_ARRAY_LENGTH, 10_000);
  assert.equal(MAX_GENERATED_STRING_BYTES, 1024 * 1024);
  assert.equal(MAX_GENERATED_PAYLOAD_BYTES, 2 * 1024 * 1024);
  const catalog = ALL_TOOL_DEFINITIONS.map((tool) => tool.name).sort();
  assert.equal(TOOL_MANIFEST.length, 25);
  assert.deepEqual(TOOL_MANIFEST.map((entry) => entry.name).sort(), catalog);
  assertFuzzProperty(
    fc,
    'RC08-FLOW-05-json',
    fc.property(fc.jsonValue({ maxDepth: 10 }), (value) => {
      const encoded = JSON.stringify(value);
      assert.equal(JSON.stringify(JSON.parse(encoded)), encoded);
      return true;
    }),
  );
  for (const entry of TOOL_MANIFEST)
    assert.equal(TOOL_SCHEMAS[entry.name].safeParse(entry.args).success, true, entry.name);
});

test('RC08-FLOW-06: fast-check verifies strict, typed, bounded schema invariants for all 25 tools', () => {
  const indexArbitrary = fc.integer({ min: 0, max: TOOL_MANIFEST.length - 1 });
  assertFuzzProperty(
    fc,
    'RC08-FLOW-06-unknown',
    fc.property(indexArbitrary, fc.string({ maxLength: 32 }), (index, suffix) => {
      const entry = TOOL_MANIFEST[index];
      return !TOOL_SCHEMAS[entry.name].safeParse({ ...entry.args, [`_rc08_${suffix}`]: true })
        .success;
    }),
  );
  assertFuzzProperty(
    fc,
    'RC08-FLOW-06-valid',
    fc.property(indexArbitrary, (index) => {
      const entry = TOOL_MANIFEST[index];
      return TOOL_SCHEMAS[entry.name].safeParse(entry.args).success;
    }),
  );
  assertFuzzProperty(
    fc,
    'RC08-FLOW-06-types',
    fc.property(indexArbitrary, (index) => {
      const entry = TOOL_MANIFEST[index];
      const fields = Object.entries(entry.types);
      return fields.length === 0
        ? !TOOL_SCHEMAS[entry.name].safeParse('scalar').success
        : !TOOL_SCHEMAS[entry.name].safeParse({
            ...entry.args,
            [fields[0][0]]: wrongValue(fields[0][1]),
          }).success;
    }),
  );
  const sequenceA = fc.sample(fc.string({ maxLength: 24 }), {
    seed: FUZZ_SEED,
    numRuns: FUZZ_RUNS,
  });
  const sequenceB = fc.sample(fc.string({ maxLength: 24 }), {
    seed: FUZZ_SEED,
    numRuns: FUZZ_RUNS,
  });
  assert.deepEqual(sequenceA, sequenceB);
  assert.equal(TOOL_MANIFEST.length, 25);
  assert.equal(fastCheckParameters().seed, FUZZ_SEED);
  assert.equal(fastCheckParameters().numRuns, FUZZ_RUNS);
  assert.equal(fastCheckParameters().path, FUZZ_PATH);
});
