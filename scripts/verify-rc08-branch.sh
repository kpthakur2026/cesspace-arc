#!/usr/bin/env bash
# Fail-closed branch admission for the authoritative RC-08 verifier.
set -euo pipefail

FEATURE_BRANCH="feat/rc-08-integrations-security-review"
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

case "$CURRENT_BRANCH" in
  "$FEATURE_BRANCH" | main)
    ;;
  *)
    echo "RC-08 verification must run on $FEATURE_BRANCH or main; got $CURRENT_BRANCH" >&2
    exit 1
    ;;
esac
