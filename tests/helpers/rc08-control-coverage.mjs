import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const RC08_TEST_FILES = Object.freeze([
  'tests/rc08-cross-client-conformance.test.js',
  'tests/rc08-protocol-schema-fuzzing.test.js',
  'tests/rc08-remote-gateway-adversarial.test.js',
  'tests/rc08-filesystem-git-adversarial.test.js',
  'tests/rc08-process-approval-audit-adversarial.test.js',
  'tests/rc08-concurrency-resource-robustness.test.js',
  'tests/rc08-cross-workspace-client-isolation.test.js',
  'tests/rc08-final-hardening-verification.test.js',
]);

function collectTestOwners(rootDir) {
  const owners = new Map();
  const malformed = [];
  const disabled = [];
  const authoritativePattern = /(?:test|it)\s*\(\s*['"`](RC08-(?:NEG|FLOW)-\d+):[^'"`]*['"`]/g;
  const namedIdPattern = /(?:test|it)\s*\(\s*['"`](RC08-(?:NEG|FLOW)-[^:'"`\s]+):[^'"`]*['"`]/g;

  for (const relativeFile of RC08_TEST_FILES) {
    const absoluteFile = path.join(rootDir, relativeFile);
    assert.equal(fs.existsSync(absoluteFile), true, `Missing RC-08 owner suite: ${relativeFile}`);
    const source = fs.readFileSync(absoluteFile, 'utf8');
    if (/(?:test|it|describe)\.(?:skip|todo)\s*\(/.test(source)) disabled.push(relativeFile);

    const authoritative = new Set();
    let match;
    while ((match = authoritativePattern.exec(source)) !== null) {
      authoritative.add(match[1]);
      const locations = owners.get(match[1]) ?? [];
      locations.push(relativeFile);
      owners.set(match[1], locations);
    }

    while ((match = namedIdPattern.exec(source)) !== null) {
      if (!/^RC08-(?:NEG-\d{3}|FLOW-\d{2})$/.test(match[1])) malformed.push(match[1]);
    }
  }

  return { owners, malformed, disabled };
}

export function auditRc08ControlCoverage(rootDir = process.cwd()) {
  const { owners, malformed, disabled } = collectTestOwners(rootDir);
  const expectedNegative = Array.from(
    { length: 90 },
    (_, index) => `RC08-NEG-${String(index + 1).padStart(3, '0')}`,
  );
  const expectedFlows = Array.from(
    { length: 20 },
    (_, index) => `RC08-FLOW-${String(index + 1).padStart(2, '0')}`,
  );
  const expected = new Set([...expectedNegative, ...expectedFlows]);
  const found = [...owners.keys()].sort();
  const missing = [...expected].filter((id) => !owners.has(id));
  const duplicates = found.filter((id) => owners.get(id).length !== 1);
  const outOfRange = found.filter((id) => !expected.has(id));

  return {
    negativeFound: expectedNegative.filter((id) => owners.has(id)).length,
    flowsFound: expectedFlows.filter((id) => owners.has(id)).length,
    missing,
    duplicates,
    outOfRange,
    malformed: [...new Set(malformed)].sort(),
    disabled,
    owners,
  };
}

export function assertRc08ControlCoverage(rootDir = process.cwd()) {
  const report = auditRc08ControlCoverage(rootDir);
  assert.equal(
    report.negativeFound,
    90,
    `Expected 90 negative controls; got ${report.negativeFound}`,
  );
  assert.equal(report.flowsFound, 20, `Expected 20 positive flows; got ${report.flowsFound}`);
  assert.deepEqual(report.missing, [], `Missing RC-08 IDs: ${report.missing.join(', ')}`);
  assert.deepEqual(report.duplicates, [], `Duplicate RC-08 IDs: ${report.duplicates.join(', ')}`);
  assert.deepEqual(
    report.outOfRange,
    [],
    `Out-of-range RC-08 IDs: ${report.outOfRange.join(', ')}`,
  );
  assert.deepEqual(report.malformed, [], `Malformed RC-08 IDs: ${report.malformed.join(', ')}`);
  assert.deepEqual(report.disabled, [], `Disabled RC-08 suites: ${report.disabled.join(', ')}`);
  return report;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  const report = assertRc08ControlCoverage();
  console.log(
    `RC-08 implementation coverage verified: ${report.negativeFound}/90 negative controls, ` +
      `${report.flowsFound}/20 positive flows, zero duplicates/missing/out-of-range/skipped/todo.`,
  );
}
