#!/usr/bin/env node
/**
 * CesSpace ARC — RC-04 Declarative Policy Engine Benchmark
 *
 * Measures in-memory performance of the Layer 2 declarative policy engine:
 * - maximum-size (256-rule) policy parse/validation
 * - canonical normalization + policyHash derivation
 * - representative policy evaluation throughput
 *
 * Reports timings only. This harness deliberately asserts NO timing threshold:
 * CI must not become flaky on shared runners. Correctness is enforced by
 * tests/rc04-policy-engine.test.js, not by this file.
 *
 * No network access. No filesystem traversal during evaluation.
 */

import { performance } from 'node:perf_hooks';

import {
  DeclarativePolicyEngine,
  WorkspaceRegistry,
  MAX_POLICY_BYTES,
  MAX_POLICY_RULES,
  MAX_MATCHER_ITEMS,
} from '../packages/policy/dist/index.js';

const MAX_RULES = MAX_POLICY_RULES;

function percentile(sortedValues, p) {
  if (sortedValues.length === 0) return 0;
  const index = (p / 100) * (sortedValues.length - 1);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sortedValues[lower];
  return sortedValues[lower] + (sortedValues[upper] - sortedValues[lower]) * (index - lower);
}

function round(value) {
  return Number.isFinite(value) ? Math.round(value * 1000) / 1000 : 0;
}

const REGISTERED_TOOLS = [
  'health',
  'list_directory',
  'read_file',
  'search_files',
  'search_text',
  'git_status',
  'git_diff',
  'git_log',
  'system_status',
  'run_command',
  'process_status',
  'process_output',
  'terminate_process',
  'create_file',
  'write_file',
  'apply_patch',
  'delete_file',
  'move_file',
];

/**
 * Builds a declarative policy document.
 *
 * Every generated fixture is asserted against MAX_POLICY_BYTES so the benchmark
 * can never silently measure an invalid document.
 */
function buildPolicyYaml({
  ruleCount,
  toolsPerRule,
  patternsPerRule,
  commandsPerRule,
  gitPerRule,
}) {
  const lines = ["version: '1.0'", 'metadata:', "  name: 'rc04-benchmark'", 'rules:'];

  for (let i = 0; i < ruleCount; i++) {
    const effect = i % 3 === 0 ? 'DENY' : i % 3 === 1 ? 'REQUIRE_APPROVAL' : 'ALLOW';
    lines.push(`  - id: 'bench-rule-${String(i).padStart(3, '0')}'`);
    lines.push(`    effect: '${effect}'`);

    const tools = [];
    for (let t = 0; t < toolsPerRule; t++) {
      tools.push(`'${REGISTERED_TOOLS[t % REGISTERED_TOOLS.length]}'`);
    }
    lines.push(`    tools: [${tools.join(', ')}]`);

    const patterns = [];
    for (let p = 0; p < patternsPerRule; p++) {
      patterns.push(`'src/module-${p}/**'`);
    }
    lines.push('    paths:');
    lines.push(`      patterns: [${patterns.join(', ')}]`);

    const binaries = [];
    for (let c = 0; c < commandsPerRule; c++) {
      binaries.push(c % 2 === 0 ? `'bin-${c}'` : `'tool-${c}'`);
    }
    lines.push('    commands:');
    lines.push(
      effect === 'DENY'
        ? `      blockedBinaries: [${binaries.join(', ')}]`
        : `      allowedBinaries: [${binaries.join(', ')}]`,
    );

    const branches = [];
    for (let g = 0; g < gitPerRule; g++) {
      branches.push(`'release/${g}/**'`);
    }
    const actions = [];
    for (let a = 0; a < gitPerRule; a++) {
      actions.push(`'action-${a}'`);
    }
    lines.push('    git:');
    lines.push(`      protectedBranches: [${branches.join(', ')}]`);
    lines.push(`      actions: [${actions.join(', ')}]`);
  }

  return `${lines.join('\n')}\n`;
}

/** Maximum rule count (256 rules) within the 256 KiB document budget. */
function buildMaxRulesPolicyYaml() {
  return buildPolicyYaml({
    ruleCount: MAX_RULES,
    toolsPerRule: 12,
    patternsPerRule: 12,
    commandsPerRule: 8,
    gitPerRule: 8,
  });
}

/** Maximum matcher array width (128 items per array) within the document budget. */
function buildMaxMatchersPolicyYaml() {
  return buildPolicyYaml({
    ruleCount: 24,
    toolsPerRule: MAX_MATCHER_ITEMS,
    patternsPerRule: MAX_MATCHER_ITEMS,
    commandsPerRule: MAX_MATCHER_ITEMS,
    gitPerRule: MAX_MATCHER_ITEMS,
  });
}

function assertWithinDocumentBudget(text, label) {
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes > MAX_POLICY_BYTES) {
    throw new Error(`${label} is ${bytes} bytes, exceeding the ${MAX_POLICY_BYTES} byte limit`);
  }
  return bytes;
}

function measure(label, iterations, fn) {
  // Warmup for JIT stabilization.
  for (let i = 0; i < Math.min(5, iterations); i++) {
    fn(i);
  }
  const samples = [];
  for (let i = 0; i < iterations; i++) {
    const started = performance.now();
    fn(i);
    samples.push(performance.now() - started);
  }
  samples.sort((a, b) => a - b);
  const mean = samples.reduce((sum, value) => sum + value, 0) / samples.length;
  const opsPerSec = mean > 0 ? 1000 / mean : 0;
  return {
    label,
    iterations,
    p50: round(percentile(samples, 50)),
    p95: round(percentile(samples, 95)),
    p99: round(percentile(samples, 99)),
    min: round(samples[0]),
    mean: round(mean),
    opsPerSec: Math.round(opsPerSec),
  };
}

function main() {
  const registry = new WorkspaceRegistry();
  registry.registerWorkspace('primary', process.cwd());

  const maxRulesText = buildMaxRulesPolicyYaml();
  const maxRulesBytes = assertWithinDocumentBudget(maxRulesText, 'max-rules policy');
  const maxMatchersText = buildMaxMatchersPolicyYaml();
  const maxMatchersBytes = assertWithinDocumentBudget(maxMatchersText, 'max-matchers policy');

  process.stdout.write('CesSpace ARC — RC-04 Declarative Policy Engine Benchmark\n');
  process.stdout.write('='.repeat(72) + '\n');
  process.stdout.write(`Max-rules policy    : ${MAX_RULES} rules, ${maxRulesBytes} bytes UTF-8\n`);
  process.stdout.write(
    `Max-matchers policy : 24 rules, ${maxMatchersBytes} bytes UTF-8 (128 items/array)\n\n`,
  );

  const results = [];

  // 1. Parse + schema validation + workspace binding (maximum rule count).
  results.push(
    measure('parse+validate (256 rules)', 25, () => {
      DeclarativePolicyEngine.fromExternalText(registry, maxRulesText, 'yaml');
    }),
  );

  // 2. Full pipeline including normalization and policyHash derivation.
  results.push(
    measure('parse+normalize+hash (256 rules)', 25, () => {
      const engine = DeclarativePolicyEngine.fromExternalText(registry, maxRulesText, 'yaml');
      engine.getPolicyHash();
    }),
  );

  // 3. Parse + validate with every matcher array at its 128-item maximum.
  results.push(
    measure('parse+validate (128-item arrays)', 25, () => {
      DeclarativePolicyEngine.fromExternalText(registry, maxMatchersText, 'yaml');
    }),
  );

  // 4. Representative evaluation against a maximal rule set.
  const maximalEngine = DeclarativePolicyEngine.fromExternalText(registry, maxRulesText, 'yaml');
  const targets = [
    { toolName: 'read_file', path: 'src/module-0/index.ts' },
    { toolName: 'write_file', path: 'src/module-12/deep/file.ts' },
    { toolName: 'run_command', executableBasename: 'npm' },
    { toolName: 'git_status', gitBranch: 'release/1.0', gitAction: 'push' },
    { toolName: 'search_text', path: 'docs/README.md' },
  ];
  results.push(
    measure('evaluate (256 rules, mixed targets)', 2000, (i) => {
      maximalEngine.evaluate(targets[i % targets.length]);
    }),
  );

  // 4. Built-in compatibility policy evaluation.
  const builtInEngine = DeclarativePolicyEngine.builtIn(registry);
  results.push(
    measure('evaluate (built-in policy)', 5000, (i) => {
      builtInEngine.evaluate(targets[i % targets.length]);
    }),
  );

  // 5. Normalization + hash only (no parse).
  results.push(
    measure('getNormalizedPolicy (defensive copy)', 200, () => {
      maximalEngine.getNormalizedPolicy();
    }),
  );

  process.stdout.write(
    '| Operation | Iterations | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | ops/sec |\n',
  );
  process.stdout.write('| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n');
  for (const r of results) {
    process.stdout.write(
      `| ${r.label} | ${r.iterations} | ${r.p50} | ${r.p95} | ${r.p99} | ${r.mean} | ${r.opsPerSec} |\n`,
    );
  }

  process.stdout.write('\nReference hashes\n');
  process.stdout.write('-'.repeat(72) + '\n');
  process.stdout.write(`maximal policy policyHash : ${maximalEngine.getPolicyHash()}\n`);
  process.stdout.write(`built-in policy policyHash : ${builtInEngine.getPolicyHash()}\n`);

  process.stdout.write('\nNotes\n');
  process.stdout.write('-'.repeat(72) + '\n');
  process.stdout.write('No timing threshold is asserted. Timings are informational only.\n');
  process.stdout.write(
    'Evaluation is purely in-memory: no filesystem, network, or process access.\n',
  );
  process.stdout.write('Policy semantics are enforced by tests/rc04-policy-engine.test.js.\n');
}

try {
  main();
} catch (err) {
  process.stderr.write(`Benchmark error: ${err.stack || err.message}\n`);
  process.exit(1);
}
