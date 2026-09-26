#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — RC-07 Comprehensive Verification Script
# Validates all acceptance criteria, invariants, and quality gates for RC-07:
# Engineering-Aware Tools Architecture: arc_repo_status, arc_worktree_status,
# arc_review_diff, arc_verify, arc_test, arc_ci_status, arc_stage_evidence.
#
# This script is READ-ONLY with respect to git history: it never fetches,
# pushes, switches, rebases, or mutates branches.
# ==============================================================================
set -euo pipefail

FEATURE_BRANCH="feat/rc-07-engineering-aware-tools"
FINAL_REPORT="docs/architecture/rc07-final-integration-report.md"
SCOPE_DOC="docs/architecture/rc07-scope-acceptance.md"
EXPECTED_VERSION="0.7.0-rc07"
EXPECTED_STAGE="RC-07"

echo "========================================================================"
echo "          CesSpace ARC — RC-07 Verification Suite                       "
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

# Gate 8: Dedicated RC-07 Hardening Suite
echo "--> Gate 8: Dedicated RC-07 Hardening Suite"
node --test tests/rc07-hardening.test.js
echo "    [PASS] Dedicated RC-07 hardening suite passed."
echo ""

# Gate 9: All 8 RC-07 Owner Suites
echo "--> Gate 9: All 8 RC-07 Owner Suites"
node --test \
  tests/rc07-composite-framework.test.js \
  tests/rc07-repo-worktree-status.test.js \
  tests/rc07-review-diff.test.js \
  tests/rc07-verify.test.js \
  tests/rc07-test.test.js \
  tests/rc07-ci-status.test.js \
  tests/rc07-stage-evidence.test.js \
  tests/rc07-hardening.test.js
echo "    [PASS] All 8 RC-07 owner suites passed."
echo ""

# Gate 10: Full Test Suite
echo "--> Gate 10: Full Monorepo Test Suite (pnpm run test)"
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

# Gate 11: Git Diff Cleanliness Check
echo "--> Gate 11: Git Diff Cleanliness Check (git diff --check)"
git diff --check
echo "    [PASS] Zero whitespace errors or conflict markers."
echo ""

# Gate 12: Documentation Completeness & Links
echo "--> Gate 12: Documentation Completeness & Link Verification"
bash scripts/check-docs.sh
echo "    [PASS] Documentation integrity verified."
echo ""

# Gate 13: Secret & Credential Scanning
echo "--> Gate 13: Secret & Credential Scanning (Gitleaks + Policy)"
if [[ -x /tmp/gitleaks ]] && ! command -v gitleaks >/dev/null 2>&1; then
  PATH="/tmp:$PATH" bash scripts/check-secrets.sh
else
  bash scripts/check-secrets.sh
fi
echo "    [PASS] Zero secrets or sensitive files detected."
echo ""

# Gate 14: Dependency Security Audit
echo "--> Gate 14: Dependency Security Audit (pnpm audit)"
pnpm audit
echo "    [PASS] Dependency audit completed."
echo ""

# Gate 15: Negative-Control Contiguity & Completeness (RC07-NEG-001..075)
echo "--> Gate 15: RC-07 Frozen Negative-Control Completeness (RC07-NEG-001..075)"
node -e '
const fs = require("fs");
const assert = require("assert");

const SUITES = [
  "tests/rc07-composite-framework.test.js",
  "tests/rc07-repo-worktree-status.test.js",
  "tests/rc07-review-diff.test.js",
  "tests/rc07-verify.test.js",
  "tests/rc07-test.test.js",
  "tests/rc07-ci-status.test.js",
  "tests/rc07-stage-evidence.test.js",
  "tests/rc07-hardening.test.js",
];

const pattern = /(?:test|it)\s*\(\s*[\x27\x22\x60](RC07-NEG-(?:0[0-9]{2}|[0-9]{3})):\s/g;
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

assert.strictEqual(found.size, 75, `Expected exactly 75 unique controls; found ${found.size}`);
for (let i = 1; i <= 75; i++) {
  const id = `RC07-NEG-${String(i).padStart(3, "0")}`;
  const locs = found.get(id);
  assert.ok(locs && locs.length >= 1, `Missing negative control: ${id}`);
  assert.strictEqual(locs.length, 1, `Duplicate negative control: ${id} in ${JSON.stringify(locs)}`);
}
console.log("    [PASS] All 75 contiguous unique RC07-NEG controls verified.");
'
echo ""

# Gate 16: Positive Acceptance Flows Completeness (RC07-FLOW-01..20)
echo "--> Gate 16: RC-07 Frozen Positive-Flows Completeness (RC07-FLOW-01..20)"
node -e '
const fs = require("fs");
const assert = require("assert");

const SUITES = [
  "tests/rc07-composite-framework.test.js",
  "tests/rc07-repo-worktree-status.test.js",
  "tests/rc07-review-diff.test.js",
  "tests/rc07-verify.test.js",
  "tests/rc07-test.test.js",
  "tests/rc07-ci-status.test.js",
  "tests/rc07-stage-evidence.test.js",
  "tests/rc07-hardening.test.js",
];

const pattern = /(?:test|it)\s*\(\s*[\x27\x22\x60](RC07-FLOW-(?:0[1-9]|1[0-9]|20)):\s/g;
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

assert.strictEqual(found.size, 20, `Expected exactly 20 unique flows; found ${found.size}`);
for (let i = 1; i <= 20; i++) {
  const id = `RC07-FLOW-${String(i).padStart(2, "0")}`;
  const locs = found.get(id);
  assert.ok(locs && locs.length >= 1, `Missing positive flow: ${id}`);
  assert.strictEqual(locs.length, 1, `Duplicate positive flow: ${id} in ${JSON.stringify(locs)}`);
}
console.log("    [PASS] All 20 contiguous unique RC07-FLOW flows verified.");
'
echo ""

# Gate 17: No Disabled or Deferred Tests
echo "--> Gate 17: No Disabled or Deferred RC-07 Tests"
RC07_TEST_FILES=(
  "tests/rc07-composite-framework.test.js"
  "tests/rc07-repo-worktree-status.test.js"
  "tests/rc07-review-diff.test.js"
  "tests/rc07-verify.test.js"
  "tests/rc07-test.test.js"
  "tests/rc07-ci-status.test.js"
  "tests/rc07-stage-evidence.test.js"
  "tests/rc07-hardening.test.js"
)

for TEST_FILE in "${RC07_TEST_FILES[@]}"; do
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
echo "    [PASS] Zero disabled or deferred RC-07 tests."
echo ""

# Gate 18: Security-Scanner Suppression Check
echo "--> Gate 18: Security-Scanner Suppression Check"
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

# Gate 19: Verification Script Integrity Self-Check
echo "--> Gate 19: Verification Script Self-Check (no error-masking fallback)"
FALSE_FALLBACK_PATTERN='||'' true'
set +e
grep -nF -- "$FALSE_FALLBACK_PATTERN" "scripts/verify-rc07.sh" > /dev/null 2>&1
SELF_STATUS=$?
set -e

if [[ $SELF_STATUS -eq 0 ]]; then
  echo "    [FAIL] Error-masking fallback found in scripts/verify-rc07.sh!"
  exit 1
fi
echo "    [PASS] Verification script integrity confirmed (no error-masking fallback)."
echo ""

# Gate 20: Package Version & Script Consistency
echo "--> Gate 20: Package Version & Script Consistency ($EXPECTED_VERSION)"
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

if ! grep -q '"verify:rc07": "bash scripts/verify-rc07.sh"' "package.json"; then
  echo "    [FAIL] package.json does not map verify:rc07 to bash scripts/verify-rc07.sh"
  exit 1
fi
echo "    [PASS] package.json verify:rc07 maps to bash scripts/verify-rc07.sh"

CLI_SRC="apps/cli/src/index.ts"
if ! grep -q "CLI_VERSION = '$EXPECTED_VERSION'" "$CLI_SRC"; then
  echo "    [FAIL] $CLI_SRC does not declare CLI_VERSION $EXPECTED_VERSION"
  exit 1
fi
echo "    [PASS] $CLI_SRC declares CLI_VERSION $EXPECTED_VERSION"

MCP_SRC="apps/mcp-server/src/index.ts"
if ! grep -q "version: '$EXPECTED_VERSION'" "$MCP_SRC"; then
  echo "    [FAIL] $MCP_SRC does not advertise version $EXPECTED_VERSION"
  exit 1
fi
echo "    [PASS] $MCP_SRC advertises version $EXPECTED_VERSION"
echo ""

# Gate 21: Health Version & Stage Consistency
echo "--> Gate 21: Health Version & Stage Consistency ($EXPECTED_VERSION / $EXPECTED_STAGE)"
if ! grep -q "version: '$EXPECTED_VERSION'" "$MCP_SRC"; then
  echo "    [FAIL] Health response in $MCP_SRC does not report version '$EXPECTED_VERSION'"
  exit 1
fi
if ! grep -q "stage: '$EXPECTED_STAGE'" "$MCP_SRC"; then
  echo "    [FAIL] Health response in $MCP_SRC does not report stage '$EXPECTED_STAGE'"
  exit 1
fi
echo "    [PASS] $MCP_SRC reports health.version $EXPECTED_VERSION and health.stage $EXPECTED_STAGE"
echo ""

# Gate 22: Required Task-8 Files Check
echo "--> Gate 22: Required Task-8 Files Check"
TASK8_REQUIRED_FILES=(
  "tests/rc07-hardening.test.js"
  "scripts/verify-rc07.sh"
  "docs/architecture/rc07-final-integration-report.md"
  "docs/architecture/rc07-scope-acceptance.md"
)
for REQ_FILE in "${TASK8_REQUIRED_FILES[@]}"; do
  if [[ ! -s "$REQ_FILE" ]]; then
    echo "    [FAIL] Required Task-8 file '$REQ_FILE' does not exist or is empty"
    exit 1
  fi
  echo "    [PASS] Required Task-8 file '$REQ_FILE' verified."
done
echo ""

# Gate 23: Final Integration Report Check
echo "--> Gate 23: Final Integration Report Check ($FINAL_REPORT)"
if [[ ! -s "$FINAL_REPORT" ]]; then
  echo "    [FAIL] $FINAL_REPORT is missing or empty!"
  exit 1
fi
if ! grep -q "# RC-07 Final Integration & Acceptance Report" "$FINAL_REPORT"; then
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
if ! grep -q "# RC-07 Scope & Acceptance" "$SCOPE_DOC"; then
  echo "    [FAIL] $SCOPE_DOC does not contain correct scope header"
  exit 1
fi
echo "    [PASS] $SCOPE_DOC verified and present."
echo ""

# Gate 25: Tool Catalog & Deterministic Registry Invariants
echo "--> Gate 25: Tool Catalog & Deterministic Registry Invariants"
node -e '
const assert = require("assert");
const { createProductionDeterministicRegistry } = require("./apps/mcp-server/dist/composite-framework.js");
const { ALL_TOOL_DEFINITIONS } = require("./apps/mcp-server/dist/index.js");

// Verify exactly 25 tools advertised in production catalog
assert.strictEqual(
  ALL_TOOL_DEFINITIONS.length,
  25,
  `Expected exactly 25 tools in production catalog; found ${ALL_TOOL_DEFINITIONS.length}`
);

const advertisedNames = new Set(ALL_TOOL_DEFINITIONS.map((t) => t.name));
const expectedRc07Tools = [
  "arc_repo_status",
  "arc_worktree_status",
  "arc_review_diff",
  "arc_verify",
  "arc_test",
  "arc_ci_status",
  "arc_stage_evidence",
];
for (const toolName of expectedRc07Tools) {
  assert.ok(advertisedNames.has(toolName), `Tool ${toolName} must be advertised in production catalog`);
}

// Verify deterministic registry contains exactly the 5 approved entries
const expectedIdentities = [
  "verify-format-v1",
  "verify-lint-v1",
  "verify-typecheck-v1",
  "verify-test-v1",
  "arc-test-node-v1",
];

const registry = createProductionDeterministicRegistry();
const registeredIdentities = registry.listEntryIds();
assert.strictEqual(
  registeredIdentities.length,
  5,
  `Expected exactly 5 deterministic registry entries; found ${registeredIdentities.length}`
);

for (const id of expectedIdentities) {
  assert.ok(
    registeredIdentities.includes(id),
    `Missing required deterministic execution identity: ${id}`
  );
}
console.log("    [PASS] Tool catalog (25 tools) and deterministic execution registry (5 identities) verified.");
'
echo ""

echo "========================================================================"
echo "          RC-07 VERIFICATION SUCCESSFUL: ALL 25 GATES PASSED            "
echo "========================================================================"
