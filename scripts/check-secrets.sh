#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — Secret & Sensitive Material Scanner
# Scans git-tracked files for potential credentials, private keys, and CES data.
# ==============================================================================
set -euo pipefail

echo "==> [1/3] Running secret pattern scanning..."

FOUND_ISSUES=0

# Pattern list to flag (real key headers and tokens)
SECRET_PATTERNS=(
  "-----BEGIN [A-Z ]+ PRIVATE KEY-----"
  "-----BEGIN PGP PRIVATE KEY BLOCK-----"
  "AKIA[0-9A-Z]{16}"
  "ghp_[A-Za-z0-9_]{36}"
  "sk-[A-Za-z0-9]{32,}"
  "AIza[0-9A-Za-z\\-_]{35}"
)

# Search all tracked git files excluding .git, scripts/check-secrets.sh, and example templates
FILES=$(git ls-files | grep -v -E "(scripts/check-secrets\.sh|\.example|package-lock\.json)")

for PATTERN in "${SECRET_PATTERNS[@]}"; do
  MATCHES=$(grep -rnE "$PATTERN" $FILES 2>/dev/null || true)
  if [[ -n "$MATCHES" ]]; then
    echo "ERROR: Potential secret detected matching pattern '$PATTERN':"
    echo "$MATCHES"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
  fi
done

echo "==> [2/3] Checking for forbidden file names..."
FORBIDDEN_FILES=$(git ls-files | grep -E "(^|/)(\.env|\.env\..+|.*\.pem|.*\.key|.*\.p12|.*\.pfx)$" | grep -v "\.env\.example" || true)
if [[ -n "$FORBIDDEN_FILES" ]]; then
  echo "ERROR: Forbidden credential files found in repository:"
  echo "$FORBIDDEN_FILES"
  FOUND_ISSUES=$((FOUND_ISSUES + 1))
fi

echo "==> [3/3] Scanning for private IP addresses..."
# Exclude documentation files that mention RFC documentation IP ranges or examples
NON_DOC_FILES=$(echo "$FILES" | grep -v -E "(\.md$|\.yaml$|\.yml$)")
if [[ -n "$NON_DOC_FILES" ]]; then
  PRIVATE_IPS=$(grep -rnE "\b(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b" $NON_DOC_FILES 2>/dev/null || true)
  if [[ -n "$PRIVATE_IPS" ]]; then
    echo "ERROR: Potential private IP addresses found in repository:"
    echo "$PRIVATE_IPS"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
  fi
fi

if [[ $FOUND_ISSUES -eq 0 ]]; then
  echo "==> Secret scan PASSED: Zero secrets or forbidden patterns detected."
  exit 0
else
  echo "==> Secret scan FAILED: $FOUND_ISSUES violation(s) found."
  exit 1
fi
