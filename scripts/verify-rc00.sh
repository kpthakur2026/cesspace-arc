#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — RC-00 Comprehensive Verification Script
# Validates all acceptance criteria, invariants, and quality gates for RC-00.
# ==============================================================================
set -euo pipefail

echo "========================================================================"
echo "          CesSpace ARC — RC-00 Verification Suite                       "
echo "========================================================================"
echo ""

# 1. Branch verification
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "--> Gate 1: Git Branch Check"
echo "    Current branch: $CURRENT_BRANCH"
if [[ "$CURRENT_BRANCH" != "feat/rc-00-architecture" ]]; then
  echo "    [WARN] Not on recommended initial branch 'feat/rc-00-architecture'!"
else
  echo "    [PASS] Correct feature branch: feat/rc-00-architecture"
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

# 4. Typecheck
echo "--> Gate 4: TypeScript Monorepo Build Check"
pnpm run typecheck
echo "    [PASS] TypeScript compilation clean across all packages and apps."
echo ""

# 5. Contract & Invariant Unit Tests (Deterministic Path)
echo "--> Gate 5: Contract & Invariant Tests"
node --test tests/protocol-contracts.test.js
echo "    [PASS] All contract and invariant assertions passed."
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

echo "========================================================================"
echo "          RC-00 VERIFICATION SUCCESSFUL: ALL GATES PASSED                "
echo "========================================================================"
