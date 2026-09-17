#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — Secret & Sensitive Material Scanner
# Runs Gitleaks secret detection and repository policy validation.
# ==============================================================================
set -euo pipefail

echo "==> [1/3] Running Gitleaks secret scanner..."
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks detect --source . --no-git --verbose
  echo "    [PASS] Gitleaks scan clean."
else
  echo "ERROR: gitleaks binary not found in PATH."
  echo "Install gitleaks from https://github.com/gitleaks/gitleaks before running checks."
  exit 1
fi

echo "==> [2/3] Checking for forbidden file names..."
FORBIDDEN_FILES=$(git ls-files | grep -E "(^|/)(\.env|\.env\..+|.*\.pem|.*\.key|.*\.p12|.*\.pfx)$" | grep -v "\.env\.example" || true)
if [[ -n "$FORBIDDEN_FILES" ]]; then
  echo "ERROR: Forbidden credential files found in repository:"
  echo "$FORBIDDEN_FILES"
  exit 1
else
  echo "    [PASS] Zero forbidden credential files found."
fi

echo "==> [3/3] Scanning for private IP addresses in source code..."
FILES=$(git ls-files | grep -v -E "(scripts/check-secrets\.sh|\.example|pnpm-lock\.yaml)")
NON_DOC_FILES=$(echo "$FILES" | grep -v -E "(\.md$|\.yaml$|\.yml$)")
if [[ -n "$NON_DOC_FILES" ]]; then
  PRIVATE_IPS=$(grep -rnE "\b(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b" $NON_DOC_FILES 2>/dev/null || true)
  if [[ -n "$PRIVATE_IPS" ]]; then
    echo "ERROR: Potential private IP addresses found in repository:"
    echo "$PRIVATE_IPS"
    exit 1
  fi
fi
echo "    [PASS] Zero private IP addresses found."

echo "==> Secret scan PASSED: All secret and credential checks passed."
exit 0
