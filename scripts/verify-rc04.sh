#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — RC-04 Comprehensive Verification Script
# Validates all acceptance criteria, invariants, and quality gates for RC-04:
# declarative policy engine, approval state machine, authenticated local admin
# channel, MCP approval redemption, and the approval audit lifecycle.
#
# This script is READ-ONLY with respect to the repository: it never fetches,
# pushes, switches, or mutates branches.
# ==============================================================================
set -euo pipefail

FEATURE_BRANCH="feat/rc-04-policy-approvals"
ACCEPTANCE_SUITE="tests/rc04-negative-controls.test.js"
FINAL_REPORT="docs/architecture/rc04-final-integration-report.md"

echo "========================================================================"
echo "          CesSpace ARC — RC-04 Verification Suite                       "
echo "========================================================================"
echo ""

# 1. Branch verification
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "--> Gate 1: Git Branch Check"
echo "    Current branch: $CURRENT_BRANCH"
if [[ "$CURRENT_BRANCH" != "$FEATURE_BRANCH" ]]; then
  echo "    [FAIL] Not on required feature branch '$FEATURE_BRANCH'!"
  exit 1
fi
echo "    [PASS] Correct feature branch: $FEATURE_BRANCH"
echo ""

# 2. Toolchain / install gate
echo "--> Gate 2: Frozen Lockfile Install (pnpm install --frozen-lockfile)"
pnpm install --frozen-lockfile
echo "    [PASS] Dependencies installed from the frozen lockfile."
echo ""

# 3. Format check
echo "--> Gate 3: Code Formatting Check (Prettier)"
pnpm run check:format
echo "    [PASS] Formatting verified."
echo ""

# 4. Lint check
echo "--> Gate 4: Static Analysis & Lint Check (ESLint)"
pnpm run lint
echo "    [PASS] Linting clean."
echo ""

# 5. Typecheck and build
echo "--> Gate 5: TypeScript Monorepo Build Check"
pnpm exec tsc --build --clean
pnpm run typecheck
pnpm -r run build
echo "    [PASS] TypeScript compilation and build clean across all packages and apps."
echo ""

# 6. Dedicated RC-04 acceptance suite (standalone gate)
echo "--> Gate 6: Dedicated RC-04 Acceptance Suite (38 frozen negative controls)"
node --test "$ACCEPTANCE_SUITE"
echo "    [PASS] All 38 frozen RC-04 negative controls passed."
echo ""

# 7. Full test suite
echo "--> Gate 7: Full Monorepo Test Suite"
pnpm run test
echo "    [PASS] All suites passed."
echo ""

# 8. Policy engine benchmark
echo "--> Gate 8: RC-04 Policy Engine Benchmark"
pnpm run bench:rc04-policy
echo "    [PASS] Benchmark completed (informational; no timing threshold asserted)."
echo ""

# 9. Git diff cleanliness
echo "--> Gate 9: Git Diff Cleanliness Check (git diff --check)"
git diff --check
echo "    [PASS] Zero whitespace errors or conflict markers."
echo ""

# 10. Documentation completeness and links
echo "--> Gate 10: Documentation Completeness & Link Verification"
bash scripts/check-docs.sh
echo "    [PASS] Documentation integrity verified."
echo ""

# 11. Secret scanning and repository policy
echo "--> Gate 11: Secret & Credential Scanning (Gitleaks + Policy)"
bash scripts/check-secrets.sh
echo "    [PASS] Zero secrets or sensitive files detected."
echo ""

# 12. Dependency security audit
echo "--> Gate 12: Dependency Security Audit (pnpm audit)"
pnpm audit
echo "    [PASS] Dependency audit completed."
echo ""

# 13. Frozen negative-control ID completeness
echo "--> Gate 13: RC-04 Frozen Negative-Control Completeness (RC04-NEG-01..38)"

if [[ ! -f "$ACCEPTANCE_SUITE" ]]; then
  echo "    [FAIL] Acceptance suite '$ACCEPTANCE_SUITE' does not exist"
  exit 1
fi

for N in $(seq -w 1 38); do
  ID="RC04-NEG-${N}"
  if ! grep -q "$ID" "$ACCEPTANCE_SUITE"; then
    echo "    [FAIL] Frozen control '$ID' is missing from $ACCEPTANCE_SUITE"
    exit 1
  fi
  echo "    [PASS] $ID present"
done
echo "    [PASS] All 38 frozen RC-04 negative controls are represented."
echo ""

# 14. No disabled or deferred tests
echo "--> Gate 14: No Disabled or Deferred Tests"

RC04_TESTS=(
  "tests/rc04-approval-state.test.js"
  "tests/rc04-policy-engine.test.js"
  "tests/rc04-admin-ipc.test.js"
  "tests/rc04-cli.test.js"
  "tests/rc04-mcp-approval.test.js"
  "tests/rc04-security-audit.test.js"
  "tests/rc04-negative-controls.test.js"
)

for TEST_FILE in "${RC04_TESTS[@]}"; do
  if [[ ! -f "$TEST_FILE" ]]; then
    echo "    [FAIL] Required RC-04 test file '$TEST_FILE' does not exist"
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
echo "    [PASS] No disabled or deferred RC-04 tests."
echo ""

# 15. Security-scanner suppression check
echo "--> Gate 15: Security-Scanner Suppression Check (inline scanner markers)"

# The forbidden marker is assembled at runtime so this script's own source does
# not itself contain the literal it searches for.
SUPPRESSION_PATTERN="gitleaks:"'allow'
SUPPRESSION_MATCHES=$(git grep -n -- "$SUPPRESSION_PATTERN" . || true)
if [[ -n "$SUPPRESSION_MATCHES" ]]; then
  echo "    [FAIL] Inline scanner suppression markers found:"
  echo "$SUPPRESSION_MATCHES"
  exit 1
fi
echo "    [PASS] Zero inline scanner suppressions."
echo ""

# 16. Required RC-04 artifacts
echo "--> Gate 16: Required RC-04 Artifacts"
REQUIRED_FILES=(
  "docs/architecture/rc04-scope-acceptance.md"
  "$FINAL_REPORT"
  "tests/rc04-approval-state.test.js"
  "tests/rc04-policy-engine.test.js"
  "tests/rc04-admin-ipc.test.js"
  "tests/rc04-cli.test.js"
  "tests/rc04-mcp-approval.test.js"
  "tests/rc04-security-audit.test.js"
  "tests/rc04-negative-controls.test.js"
  "scripts/verify-rc04.sh"
  "examples/policies/policy.example.yaml"
)
for REQUIRED in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$REQUIRED" ]]; then
    echo "    [FAIL] Required RC-04 artifact missing: $REQUIRED"
    exit 1
  fi
  echo "    [PASS] $REQUIRED"
done
echo ""

# 17. Version and health consistency
echo "--> Gate 17: Version & Health Consistency (0.4.0-rc04 / RC-04)"
EXPECTED_VERSION="0.4.0-rc04"

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
echo "    [PASS] CLI_VERSION == $EXPECTED_VERSION"

MCP_SRC="apps/mcp-server/src/index.ts"
if ! grep -q "version: '$EXPECTED_VERSION'" "$MCP_SRC"; then
  echo "    [FAIL] Health response in $MCP_SRC does not report version $EXPECTED_VERSION"
  exit 1
fi
echo "    [PASS] health.version == $EXPECTED_VERSION"

if ! grep -q "stage: 'RC-04'" "$MCP_SRC"; then
  echo "    [FAIL] Health response in $MCP_SRC does not report stage 'RC-04'"
  exit 1
fi
echo "    [PASS] health.stage == RC-04"
echo ""

echo "========================================================================"
echo "          RC-04 VERIFICATION SUCCESSFUL: ALL GATES PASSED                "
echo "========================================================================"
