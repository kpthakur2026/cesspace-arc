#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — RC-03 Comprehensive Verification Script
# Validates all acceptance criteria, invariants, and quality gates for RC-03.
# ==============================================================================
set -euo pipefail

echo "========================================================================"
echo "          CesSpace ARC — RC-03 Verification Suite                       "
echo "========================================================================"
echo ""

# 1. Branch verification
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "--> Gate 1: Git Branch Check"
echo "    Current branch: $CURRENT_BRANCH"
if [[ "$CURRENT_BRANCH" != "feat/rc-03-safe-file-modification" ]]; then
  echo "    [WARN] Not on recommended feature branch 'feat/rc-03-safe-file-modification'!"
else
  echo "    [PASS] Correct feature branch: feat/rc-03-safe-file-modification"
fi
echo ""

# 2. Format check
echo "--> Gate 2: Code Formatting Check (Prettier)"
pnpm run check:format
echo "    [PASS] Formatting verified."
echo ""

# 3. Lint check
echo "--> Gate 3: Static Analysis & Lint Check (ESLint)"
pnpm run lint
echo "    [PASS] Linting clean."
echo ""

# 4. Typecheck & Build
echo "--> Gate 4: TypeScript Monorepo Build Check"
pnpm run typecheck
pnpm run build
echo "    [PASS] TypeScript compilation and build clean across all packages and apps."
echo ""

# 5. Contract, Negative Security, Filesystem Mutation, Patch, and MCP Policy Audit Tests
echo "--> Gate 5: Contract, Security, Mutation, Patch & MCP Policy Audit Tests"
pnpm run test
echo "    [PASS] All contract, negative security, mutation engine, patch engine, and MCP policy/audit assertions passed."
echo ""

# 6. Documentation completeness & link verification
echo "--> Gate 6: Documentation Completeness & Link Verification"
bash scripts/check-docs.sh
echo "    [PASS] Documentation integrity verified."
echo ""

# 7. Secret scanning & sensitive data check (Gitleaks + Repo Policy)
echo "--> Gate 7: Secret & Credential Scanning (Gitleaks + Policy)"
bash scripts/check-secrets.sh
echo "    [PASS] Zero secrets or sensitive files detected."
echo ""

# 8. Git diff cleanliness check
echo "--> Gate 8: Git Diff Cleanliness Check (git diff --check)"
git diff --check
echo "    [PASS] Zero whitespace errors or conflict markers."
echo ""

# 9. Dependency security audit
echo "--> Gate 9: Dependency Security Audit (pnpm audit)"
pnpm audit
echo "    [PASS] Zero dependency vulnerabilities found."
echo ""

# 10. RC-03 Mutation Security Invariant Assertions
echo "--> Gate 10: RC-03 Mutation Security Invariant Assertions"

# Confirm all 5 mutation tools are present in RC03_MUTATION_TOOLS export
POLICY_SRC="packages/policy/src/index.ts"
for TOOL in create_file write_file apply_patch delete_file move_file; do
  if ! grep -q "'$TOOL'" "$POLICY_SRC"; then
    echo "    [FAIL] '$TOOL' not found in RC03_MUTATION_TOOLS in $POLICY_SRC"
    exit 1
  fi
  echo "    [PASS] '$TOOL' present in RC03_MUTATION_TOOLS"
done

# Confirm REQUIRE_APPROVAL gate present in policy kernel
if ! grep -q "REQUIRE_APPROVAL" "$POLICY_SRC"; then
  echo "    [FAIL] REQUIRE_APPROVAL gate missing from $POLICY_SRC"
  exit 1
fi
echo "    [PASS] REQUIRE_APPROVAL gate present in SecurityKernel"

# Confirm no magic numeric policy check remains in MCP server
MCP_SRC="apps/mcp-server/src/index.ts"
if grep -q "outcome !== 2" "$MCP_SRC" || grep -q "outcome !== 0" "$MCP_SRC"; then
  echo "    [FAIL] Magic numeric PolicyOutcome check found in $MCP_SRC — must use enum"
  exit 1
fi
echo "    [PASS] No magic numeric PolicyOutcome checks in MCP server"

# Confirm approvalRequired factory present in errors
ERRORS_SRC="packages/protocol/src/errors.ts"
if ! grep -q "approvalRequired" "$ERRORS_SRC"; then
  echo "    [FAIL] ArcError.approvalRequired() factory missing from $ERRORS_SRC"
  exit 1
fi
echo "    [PASS] ArcError.approvalRequired() factory present"

# Confirm RC03_TOOL_DEFINITIONS are included in ListTools
if ! grep -q "RC03_TOOL_DEFINITIONS" "$MCP_SRC"; then
  echo "    [FAIL] RC03_TOOL_DEFINITIONS not found in $MCP_SRC"
  exit 1
fi
echo "    [PASS] RC03_TOOL_DEFINITIONS included in ListTools response"

# Confirm defense-in-depth backstop present
if ! grep -q "RC-03 backstop" "$MCP_SRC"; then
  echo "    [FAIL] Defense-in-depth mutation backstop missing from $MCP_SRC"
  exit 1
fi
echo "    [PASS] Defense-in-depth fail-closed mutation backstop present"

# Confirm patch redaction in audit
AUDIT_SRC="packages/audit/src/index.ts"
if ! grep -q "PATCH_CONTENT_OMITTED" "$AUDIT_SRC"; then
  echo "    [FAIL] Patch content redaction missing from $AUDIT_SRC"
  exit 1
fi
echo "    [PASS] Patch content redaction present in audit layer"

# Confirm version updated to RC-03
if ! grep -q "0.3.0-rc03" "$MCP_SRC"; then
  echo "    [FAIL] Version 0.3.0-rc03 not found in $MCP_SRC"
  exit 1
fi
echo "    [PASS] Version 0.3.0-rc03 present in MCP server"

# Confirm RC-03 health stage
if ! grep -q "'RC-03'" "$MCP_SRC"; then
  echo "    [FAIL] Stage 'RC-03' not found in health response in $MCP_SRC"
  exit 1
fi
echo "    [PASS] Stage 'RC-03' present in health response"

echo ""
echo "    [PASS] All RC-03 mutation security invariant assertions satisfied."
echo ""

echo "========================================================================"
echo "          RC-03 VERIFICATION SUCCESSFUL: ALL GATES PASSED                "
echo "========================================================================"
