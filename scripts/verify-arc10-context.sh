#!/usr/bin/env bash
set -euo pipefail

EXPECTED_PARENT="f094b1bbad325e102792b3c568e21a3bd83e2bcf"
FEATURE_BRANCH="feat/arc-1.0-scope"

CURRENT_BRANCH="${1:?current branch is required}"
CURRENT_HEAD="${2:?current head is required}"
CURRENT_PARENT="${3:?current parent is required}"

case "$CURRENT_BRANCH" in
  "$FEATURE_BRANCH")
    [[ "$CURRENT_PARENT" == "$EXPECTED_PARENT" ]]
    ;;
  HEAD)
    if [[ "$CURRENT_PARENT" != "$EXPECTED_PARENT" ]]; then
      git merge-base --is-ancestor "$EXPECTED_PARENT" "$CURRENT_HEAD"
    fi
    ;;
  main)
    git merge-base --is-ancestor "$EXPECTED_PARENT" "$CURRENT_HEAD"
    ;;
  *)
    echo "ARC 1.0 verification rejects branch $CURRENT_BRANCH" >&2
    exit 1
    ;;
esac
