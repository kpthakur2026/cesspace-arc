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

# 2. Documentation completeness & link verification
echo "--> Gate 2: Documentation Completeness & Link Verification"
bash scripts/check-docs.sh
echo "    [PASS] Documentation integrity verified."
echo ""

# 3. Secret scanning & sensitive data check
echo "--> Gate 3: Secret & Credential Scanning"
bash scripts/check-secrets.sh
echo "    [PASS] Zero secrets or sensitive files detected."
echo ""

# 4. Architecture & Contract Unit Tests
echo "--> Gate 4: Contract & Invariant Tests"
node --test tests/**/*.test.js
echo "    [PASS] All contract and invariant assertions passed."
echo ""

# 5. Git diff check
echo "--> Gate 5: Git Diff Cleanliness Check (git diff --check)"
git diff --check
echo "    [PASS] Zero whitespace errors or conflict markers."
echo ""

echo "========================================================================"
echo "          RC-00 VERIFICATION SUCCESSFUL: ALL GATES PASSED                "
echo "========================================================================"
