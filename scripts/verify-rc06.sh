#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — RC-06 Comprehensive Verification Script
# Validates all acceptance criteria, invariants, and quality gates for RC-06:
# Persistent append-only logging, crash consistency & restart recovery,
# universal pre-dispatch durability, size and time-based rotation, retention
# and gzip compression, Tier-2 Ed25519 signed checkpoints, Tier-3 external
# witness anchoring and spooling, CLI verifier and deterministic export, and
# central secrecy hardening with authoritative payloadHash derivation.
#
# This script is READ-ONLY with respect to git history: it never fetches,
# pushes, switches, rebases, or mutates branches.
# ==============================================================================
set -euo pipefail

FEATURE_BRANCH="feat/rc-06-audit-evidence"
FINAL_REPORT="docs/architecture/rc06-final-integration-report.md"
SCOPE_DOC="docs/architecture/rc06-scope-acceptance.md"
EXPECTED_VERSION="0.6.0-rc06"
EXPECTED_STAGE="RC-06"

echo "========================================================================"
echo "          CesSpace ARC — RC-06 Verification Suite                       "
echo "========================================================================"
echo ""

# Gate 1: Git Branch Check
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "--> Gate 1: Git Branch Check"
echo "    Current branch: $CURRENT_BRANCH"
if [[ "$CURRENT_BRANCH" != "$FEATURE_BRANCH" ]]; then
  echo "    [FAIL] Not on required feature branch '$FEATURE_BRANCH'!"
  exit 1
fi
echo "    [PASS] Correct feature branch: $FEATURE_BRANCH"
echo ""

# Gate 2: Frozen Lockfile Install
echo "--> Gate 2: Frozen Lockfile Install (pnpm install --frozen-lockfile)"
pnpm install --frozen-lockfile
echo "    [PASS] Dependencies installed from the frozen lockfile."
echo ""

# Gate 3: Formatting Check
echo "--> Gate 3: Code Formatting Check (Prettier)"
pnpm run check:format
echo "    [PASS] Formatting verified."
echo ""

# Gate 4: Static Analysis & Lint Check
echo "--> Gate 4: Static Analysis & Lint Check (ESLint)"
pnpm run lint
echo "    [PASS] Linting clean."
echo ""

# Gate 5: TypeScript Clean Build Check
echo "--> Gate 5: TypeScript Clean Build Check (tsc --build --clean)"
pnpm exec tsc --build --clean
echo "    [PASS] Clean build succeeded."
echo ""

# Gate 6: TypeScript Typecheck
echo "--> Gate 6: TypeScript Monorepo Typecheck (pnpm run typecheck)"
pnpm run typecheck
echo "    [PASS] Typecheck clean across all monorepo packages."
echo ""

# Gate 7: Monorepo Package Build
echo "--> Gate 7: Monorepo Package Build (pnpm -r run build)"
pnpm -r run build
echo "    [PASS] Monorepo build clean."
echo ""

# Gate 8: Dedicated RC-06 Negative Controls Suite
echo "--> Gate 8: Dedicated RC-06 Negative Controls Suite"
node --test tests/rc06-negative-controls.test.js
echo "    [PASS] Dedicated RC-06 negative controls suite passed."
echo ""

# Gate 9: Dedicated RC-06 Positive Flows Suite
echo "--> Gate 9: Dedicated RC-06 Positive Flows Acceptance Suite"
node --test tests/rc06-positive-flows.test.js
echo "    [PASS] Dedicated RC-06 positive flows suite passed."
echo ""

# Gate 10: All 8 RC-06 Owner Suites
echo "--> Gate 10: All 8 RC-06 Owner Suites"
node --test \
  tests/rc06-storage.test.js \
  tests/rc06-recovery.test.js \
  tests/rc06-runtime-durability.test.js \
  tests/rc06-rotation.test.js \
  tests/rc06-checkpoint.test.js \
  tests/rc06-anchor.test.js \
  tests/rc06-cli-verifier.test.js \
  tests/rc06-negative-controls.test.js
echo "    [PASS] All 8 RC-06 owner suites passed."
echo ""

# Gate 11: Full Test Suite
echo "--> Gate 11: Full Monorepo Test Suite (pnpm run test)"
if [[ "$OSTYPE" == "linux"* ]]; then
  REAL_NODE=$(realpath "$(command -v node)")
  if [[ "$REAL_NODE" == "$HOME"* ]]; then
    TEST_HOME=$(mktemp -d /tmp/arc-test-home.XXXXXX)
    trap 'rm -rf "$TEST_HOME"' EXIT
    HOME="$TEST_HOME" pnpm run test
  else
    pnpm run test
  fi
else
  pnpm run test
fi
echo "    [PASS] All monorepo test suites passed."
echo ""

# Gate 12: Git Diff Cleanliness Check
echo "--> Gate 12: Git Diff Cleanliness Check (git diff --check)"
git diff --check
echo "    [PASS] Zero whitespace errors or conflict markers."
echo ""

# Gate 13: Documentation Completeness & Links
echo "--> Gate 13: Documentation Completeness & Link Verification"
bash scripts/check-docs.sh
echo "    [PASS] Documentation integrity verified."
echo ""

# Gate 14: Secret & Credential Scanning
echo "--> Gate 14: Secret & Credential Scanning (Gitleaks + Policy)"
bash scripts/check-secrets.sh
echo "    [PASS] Zero secrets or sensitive files detected."
echo ""

# Gate 15: Dependency Security Audit
echo "--> Gate 15: Dependency Security Audit (pnpm audit)"
pnpm audit
echo "    [PASS] Dependency audit completed."
echo ""

# Gate 16: Negative-Control Contiguity & Completeness (RC06-NEG-01..108)
echo "--> Gate 16: RC-06 Frozen Negative-Control Completeness (RC06-NEG-01..108)"
node -e '
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const SUITES = [
  "tests/rc06-storage.test.js",
  "tests/rc06-recovery.test.js",
  "tests/rc06-rotation.test.js",
  "tests/rc06-checkpoint.test.js",
  "tests/rc06-anchor.test.js",
  "tests/rc06-runtime-durability.test.js",
  "tests/rc06-cli-verifier.test.js",
  "tests/rc06-negative-controls.test.js",
];

const pattern = /(?:test|it)\s*\(\s*[\x27\x22\x60](RC06-NEG-(?:0[1-9]|[1-9][0-9]|10[0-8])):\s/g;
const found = new Map();

for (const rel of SUITES) {
  const content = fs.readFileSync(rel, "utf8");
  let match;
  while ((match = pattern.exec(content)) !== null) {
    const id = match[1];
    if (!found.has(id)) found.set(id, []);
    found.get(id).push(rel);
  }
}

assert.strictEqual(found.size, 108, `Expected exactly 108 unique controls; found ${found.size}`);
for (let i = 1; i <= 108; i++) {
  const id = `RC06-NEG-${String(i).padStart(i < 100 ? 2 : 3, "0")}`;
  const locs = found.get(id);
  assert.ok(locs && locs.length >= 1, `Missing negative control: ${id}`);
  assert.strictEqual(locs.length, 1, `Duplicate negative control: ${id} in ${JSON.stringify(locs)}`);
}
console.log("    [PASS] All 108 contiguous unique RC06-NEG controls verified.");
'
echo ""

# Gate 17: Positive Acceptance Flows Completeness (RC06-FLOW-01..23)
echo "--> Gate 17: RC-06 Frozen Positive-Flows Completeness (RC06-FLOW-01..23)"
node -e '
const fs = require("fs");
const assert = require("assert");

const content = fs.readFileSync("tests/rc06-positive-flows.test.js", "utf8");
const pattern = /(?:test|it)\s*\(\s*[\x27\x22\x60](RC06-FLOW-(?:0[1-9]|1[0-9]|2[0-3])):\s/g;
const found = new Map();

let match;
while ((match = pattern.exec(content)) !== null) {
  const id = match[1];
  if (!found.has(id)) found.set(id, 0);
  found.set(id, found.get(id) + 1);
}

assert.strictEqual(found.size, 23, `Expected exactly 23 unique flows; found ${found.size}`);
for (let i = 1; i <= 23; i++) {
  const id = `RC06-FLOW-${String(i).padStart(2, "0")}`;
  const count = found.get(id);
  assert.ok(count && count >= 1, `Missing positive flow: ${id}`);
  assert.strictEqual(count, 1, `Duplicate positive flow: ${id} (${count} occurrences)`);
}
console.log("    [PASS] All 23 contiguous unique RC06-FLOW flows verified.");
'
echo ""

# Gate 18: No Disabled or Deferred Tests
echo "--> Gate 18: No Disabled or Deferred RC-06 Tests"
RC06_TEST_FILES=(
  "tests/rc06-storage.test.js"
  "tests/rc06-recovery.test.js"
  "tests/rc06-runtime-durability.test.js"
  "tests/rc06-rotation.test.js"
  "tests/rc06-checkpoint.test.js"
  "tests/rc06-anchor.test.js"
  "tests/rc06-cli-verifier.test.js"
  "tests/rc06-negative-controls.test.js"
  "tests/rc06-positive-flows.test.js"
)

for TEST_FILE in "${RC06_TEST_FILES[@]}"; do
  if [[ ! -f "$TEST_FILE" ]]; then
    echo "    [FAIL] Required test file '$TEST_FILE' does not exist"
    exit 1
  fi
  if grep -q "test\.skip" "$TEST_FILE"; then
    echo "    [FAIL] '$TEST_FILE' contains a disabled test (test.skip)"
    exit 1
  fi
  if grep -q "test\.todo" "$TEST_FILE"; then
    echo "    [FAIL] '$TEST_FILE' contains a deferred test (test.todo)"
    exit 1
  fi
  if grep -q "describe\.skip" "$TEST_FILE"; then
    echo "    [FAIL] '$TEST_FILE' contains a skipped suite (describe.skip)"
    exit 1
  fi
  if grep -q "it\.skip" "$TEST_FILE"; then
    echo "    [FAIL] '$TEST_FILE' contains a disabled case (it.skip)"
    exit 1
  fi
done
echo "    [PASS] Zero disabled or deferred RC-06 tests."
echo ""

# Gate 19: Security-Scanner Suppression Check
echo "--> Gate 19: Security-Scanner Suppression Check"
SUPPRESSION_PATTERN="gitleaks:"'allow'
PRAGMA_PATTERN="pragma: "'allowlist secret'
SUPPRESSION_STATUS=0

set +e
git grep -n -- "$SUPPRESSION_PATTERN" . > /dev/null 2>&1
STATUS_1=$?
git grep -n -- "$PRAGMA_PATTERN" . > /dev/null 2>&1
STATUS_2=$?
set -e

if [[ $STATUS_1 -eq 0 ]] || [[ $STATUS_2 -eq 0 ]]; then
  echo "    [FAIL] Inline scanner suppression markers found in repository!"
  exit 1
fi
echo "    [PASS] Zero inline security scanner suppressions."
echo ""

# Gate 20: Verification Script Integrity Self-Check
echo "--> Gate 20: Verification Script Self-Check (no error-masking fallback)"
FALSE_FALLBACK_PATTERN='||'' true'
set +e
grep -nF -- "$FALSE_FALLBACK_PATTERN" "scripts/verify-rc06.sh" > /dev/null 2>&1
SELF_STATUS=$?
set -e

if [[ $SELF_STATUS -eq 0 ]]; then
  echo "    [FAIL] Error-masking fallback found in scripts/verify-rc06.sh!"
  exit 1
fi
echo "    [PASS] Verification script integrity confirmed (no error-masking fallback)."
echo ""

# Gate 21: Package Version Consistency
echo "--> Gate 21: Package Version Consistency ($EXPECTED_VERSION)"
check_version() {
  local FILE="$1"
  if ! grep -q "\"version\": \"$EXPECTED_VERSION\"" "$FILE"; then
    echo "    [FAIL] $FILE does not declare version $EXPECTED_VERSION"
    exit 1
  fi
  echo "    [PASS] $FILE == $EXPECTED_VERSION"
}

check_version "package.json"
check_version "apps/mcp-server/package.json"
check_version "apps/cli/package.json"

CLI_SRC="apps/cli/src/index.ts"
if ! grep -q "CLI_VERSION = '$EXPECTED_VERSION'" "$CLI_SRC"; then
  echo "    [FAIL] $CLI_SRC does not declare CLI_VERSION $EXPECTED_VERSION"
  exit 1
fi
echo "    [PASS] $CLI_SRC declares CLI_VERSION $EXPECTED_VERSION"
echo ""

# Gate 22: Health Stage Consistency
echo "--> Gate 22: Health Stage Consistency ($EXPECTED_STAGE)"
MCP_SRC="apps/mcp-server/src/index.ts"
if ! grep -q "stage: '$EXPECTED_STAGE'" "$MCP_SRC"; then
  echo "    [FAIL] Health response in $MCP_SRC does not report stage '$EXPECTED_STAGE'"
  exit 1
fi
echo "    [PASS] $MCP_SRC reports stage $EXPECTED_STAGE"
echo ""

# Gate 23: Final Integration Report Check
echo "--> Gate 23: Final Integration Report Check ($FINAL_REPORT)"
if [[ ! -s "$FINAL_REPORT" ]]; then
  echo "    [FAIL] $FINAL_REPORT is missing or empty!"
  exit 1
fi
if ! grep -q "# RC-06 Final Integration & Acceptance Report" "$FINAL_REPORT"; then
  echo "    [FAIL] $FINAL_REPORT does not contain correct report header"
  exit 1
fi
echo "    [PASS] $FINAL_REPORT verified and non-empty."
echo ""

# Gate 24: Scope Document Check
echo "--> Gate 24: Scope Document Check ($SCOPE_DOC)"
if [[ ! -s "$SCOPE_DOC" ]]; then
  echo "    [FAIL] $SCOPE_DOC is missing or empty!"
  exit 1
fi
echo "    [PASS] $SCOPE_DOC verified and present."
echo ""

echo "========================================================================"
echo "          RC-06 VERIFICATION SUCCESSFUL: ALL 24 GATES PASSED            "
echo "========================================================================"
