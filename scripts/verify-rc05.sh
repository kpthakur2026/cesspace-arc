#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — RC-05 Comprehensive Verification Script
# Validates all acceptance criteria, invariants, and quality gates for RC-05:
# Streamable HTTP gateway, in-process TLS 1.3 / mTLS, device identity and SPKI
# pinning, volatile session lifecycle, multi-layer resource limits, local device
# and session administration, gateway audit lifecycle, and acceptance suite.
#
# This script is READ-ONLY with respect to the repository: it never fetches,
# pushes, switches, or mutates branches.
# ==============================================================================
set -euo pipefail

FEATURE_BRANCH="feat/rc-05-secure-remote-gateway"
ACCEPTANCE_SUITE="tests/rc05-negative-controls.test.js"
POSITIVE_FLOWS_SUITE="tests/rc05-positive-flows.test.js"
GATEWAY_AUDIT_SUITE="tests/rc05-gateway-audit.test.js"
FINAL_REPORT="docs/architecture/rc05-final-integration-report.md"
SCOPE_DOC="docs/architecture/rc05-scope-acceptance.md"
EXPECTED_VERSION="0.5.0-rc05"
EXPECTED_STAGE="RC-05"

echo "========================================================================"
echo "          CesSpace ARC — RC-05 Verification Suite                       "
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

# 6. Dedicated RC-05 negative controls acceptance suite (standalone gate)
echo "--> Gate 6: Dedicated RC-05 Acceptance Suite (79 frozen negative controls)"
node --test "$ACCEPTANCE_SUITE"
echo "    [PASS] All 79 frozen RC-05 negative controls passed."
echo ""

# 7. Dedicated RC-05 positive acceptance flows suite
echo "--> Gate 7: Dedicated RC-05 Positive Flows Acceptance Suite (11 frozen flows)"
node --test "$POSITIVE_FLOWS_SUITE"
echo "    [PASS] All 11 frozen RC-05 positive acceptance flows passed."
echo ""

# 8. Dedicated RC-05 gateway audit & secrecy suite
echo "--> Gate 8: Dedicated RC-05 Gateway Audit & Secrecy Suite (14 events & redaction)"
node --test "$GATEWAY_AUDIT_SUITE"
echo "    [PASS] Gateway audit lifecycle and secret redaction verified."
echo ""

# 9. Full test suite
echo "--> Gate 9: Full Monorepo Test Suite"
pnpm run test
echo "    [PASS] All monorepo test suites passed."
echo ""

# 10. Git diff cleanliness
echo "--> Gate 10: Git Diff Cleanliness Check (git diff --check)"
git diff --check
echo "    [PASS] Zero whitespace errors or conflict markers."
echo ""

# 11. Documentation completeness and links
echo "--> Gate 11: Documentation Completeness & Link Verification"
bash scripts/check-docs.sh
echo "    [PASS] Documentation integrity verified."
echo ""

# 12. Secret scanning and repository policy
echo "--> Gate 12: Secret & Credential Scanning (Gitleaks + Policy)"
bash scripts/check-secrets.sh
echo "    [PASS] Zero secrets or sensitive files detected."
echo ""

# 13. Dependency security audit
echo "--> Gate 13: Dependency Security Audit (pnpm audit)"
pnpm audit
echo "    [PASS] Dependency audit completed."
echo ""

# 14. Frozen negative-control ID completeness
echo "--> Gate 14: RC-05 Frozen Negative-Control Completeness (RC05-NEG-01..79)"

if [[ ! -f "$ACCEPTANCE_SUITE" ]]; then
  echo "    [FAIL] Acceptance suite '$ACCEPTANCE_SUITE' does not exist"
  exit 1
fi

for N in $(seq -w 1 79); do
  ID="RC05-NEG-${N}"
  if ! grep -q "$ID" "$ACCEPTANCE_SUITE"; then
    echo "    [FAIL] Frozen control '$ID' is missing from $ACCEPTANCE_SUITE"
    exit 1
  fi
  echo "    [PASS] $ID present"
done
echo "    [PASS] All 79 frozen RC-05 negative controls are represented."
echo ""

# 15. No disabled or deferred tests
echo "--> Gate 15: No Disabled or Deferred RC-05 Tests"

RC05_TESTS=(
  "tests/rc05-device-trust-store.test.js"
  "tests/rc05-enrollment-lifecycle.test.js"
  "tests/rc05-enrollment-admin-ipc.test.js"
  "tests/rc05-enrollment-cli.test.js"
  "tests/rc05-tls-admission.test.js"
  "tests/rc05-enrollment-bootstrap.test.js"
  "tests/rc05-session-lifecycle.test.js"
  "tests/rc05-remote-actor-pipeline.test.js"
  "tests/rc05-resource-bounds.test.js"
  "tests/rc05-streamable-gateway.test.js"
  "tests/rc05-gateway-admission.test.js"
  "tests/rc05-device-session-admin-ipc.test.js"
  "tests/rc05-device-session-cli.test.js"
  "tests/rc05-remote-admin-isolation.test.js"
  "tests/rc05-gateway-audit.test.js"
  "tests/rc05-negative-controls.test.js"
  "tests/rc05-positive-flows.test.js"
)

for TEST_FILE in "${RC05_TESTS[@]}"; do
  if [[ ! -f "$TEST_FILE" ]]; then
    echo "    [FAIL] Required RC-05 test file '$TEST_FILE' does not exist"
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
echo "    [PASS] No disabled or deferred RC-05 tests."
echo ""

# 16. Security-scanner suppression check
echo "--> Gate 16: Security-Scanner Suppression Check (inline scanner markers)"

# The forbidden marker is assembled at runtime so this script's own source does
# not itself contain the literal it searches for.
SUPPRESSION_PATTERN="gitleaks:"'allow'
SUPPRESSION_OUTPUT=""
SUPPRESSION_STATUS=0

set +e
SUPPRESSION_OUTPUT=$(git grep -n -- "$SUPPRESSION_PATTERN" . 2>&1)
SUPPRESSION_STATUS=$?
set -e

if [[ $SUPPRESSION_STATUS -eq 0 ]]; then
  echo "    [FAIL] Inline scanner suppression markers found:"
  echo "$SUPPRESSION_OUTPUT"
  exit 1
elif [[ $SUPPRESSION_STATUS -eq 1 ]]; then
  echo "    [PASS] Zero inline scanner suppressions."
elif [[ $SUPPRESSION_STATUS -eq 128 ]]; then
  echo "    [FAIL] git grep could not run inside a repository:"
  echo "$SUPPRESSION_OUTPUT"
  exit 1
else
  echo "    [FAIL] git grep failed with unexpected status $SUPPRESSION_STATUS:"
  echo "$SUPPRESSION_OUTPUT"
  exit 1
fi
echo ""

# 17. Verification-script self-check
echo "--> Gate 17: Verification Script Self-Check (no error-masking fallback)"

# Assembled from pieces so this check does not find its own pattern text.
FALSE_FALLBACK_PATTERN='||'' true'
SELF_OUTPUT=""
SELF_STATUS=0

set +e
SELF_OUTPUT=$(grep -nF -- "$FALSE_FALLBACK_PATTERN" "scripts/verify-rc05.sh" 2>&1)
SELF_STATUS=$?
set -e

if [[ $SELF_STATUS -eq 0 ]]; then
  echo "    [FAIL] An error-masking fallback is present in scripts/verify-rc05.sh:"
  echo "$SELF_OUTPUT"
  exit 1
elif [[ $SELF_STATUS -eq 1 ]]; then
  echo "    [PASS] No error-masking fallback in the verification script."
else
  echo "    [FAIL] Self-check could not read scripts/verify-rc05.sh:"
  echo "$SELF_OUTPUT"
  exit 1
fi
echo ""

# 18. Required RC-05 artifacts
echo "--> Gate 18: Required RC-05 Artifacts"
REQUIRED_FILES=(
  "$SCOPE_DOC"
  "$FINAL_REPORT"
  "scripts/verify-rc05.sh"
  "apps/mcp-server/src/gateway-audit.ts"
  "tests/rc05-device-trust-store.test.js"
  "tests/rc05-enrollment-lifecycle.test.js"
  "tests/rc05-enrollment-admin-ipc.test.js"
  "tests/rc05-enrollment-cli.test.js"
  "tests/rc05-tls-admission.test.js"
  "tests/rc05-enrollment-bootstrap.test.js"
  "tests/rc05-session-lifecycle.test.js"
  "tests/rc05-remote-actor-pipeline.test.js"
  "tests/rc05-resource-bounds.test.js"
  "tests/rc05-streamable-gateway.test.js"
  "tests/rc05-gateway-admission.test.js"
  "tests/rc05-device-session-admin-ipc.test.js"
  "tests/rc05-device-session-cli.test.js"
  "tests/rc05-remote-admin-isolation.test.js"
  "tests/rc05-gateway-audit.test.js"
  "tests/rc05-negative-controls.test.js"
  "tests/rc05-positive-flows.test.js"
)
for REQUIRED in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$REQUIRED" ]]; then
    echo "    [FAIL] Required RC-05 artifact missing: $REQUIRED"
    exit 1
  fi
  echo "    [PASS] $REQUIRED"
done
echo ""

# 19. Version and health consistency
echo "--> Gate 19: Version & Health Consistency ($EXPECTED_VERSION / $EXPECTED_STAGE)"

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

if ! grep -q "stage: '$EXPECTED_STAGE'" "$MCP_SRC"; then
  echo "    [FAIL] Health response in $MCP_SRC does not report stage '$EXPECTED_STAGE'"
  exit 1
fi
echo "    [PASS] health.stage == $EXPECTED_STAGE"
echo ""

# 20. Final integration report verification
echo "--> Gate 20: Final Integration Report Check ($FINAL_REPORT)"
if ! grep -q "# RC-05 Final Integration & Acceptance Report" "$FINAL_REPORT"; then
  echo "    [FAIL] $FINAL_REPORT does not contain correct report header"
  exit 1
fi
echo "    [PASS] $FINAL_REPORT verified"
echo ""

echo "========================================================================"
echo "          RC-05 VERIFICATION SUCCESSFUL: ALL GATES PASSED                "
echo "========================================================================"
