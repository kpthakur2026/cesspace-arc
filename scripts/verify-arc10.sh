#!/usr/bin/env bash
# CesSpace ARC 1.0 — authoritative Core-only stable verification.
set -euo pipefail

BASELINE="82cada15db3e655585fce796a35e970e7a972afe"
TEMP_ROOT=$(mktemp -d)
trap 'rm -rf "$TEMP_ROOT"' EXIT
GATE_COUNT=0

run_gate() {
  local name="$1"
  shift
  GATE_COUNT=$((GATE_COUNT + 1))
  echo "--> Gate $GATE_COUNT: $name"
  if [[ "${ARC10_VERIFY_FAIL_GATE:-}" == "$GATE_COUNT" || "${ARC10_VERIFY_FAIL_GATE:-}" == "$name" ]]; then
    echo "Injected mandatory gate failure: $name" >&2
    exit 97
  fi
  "$@"
}

verify_context() {
  local branch head parent
  branch=$(git rev-parse --abbrev-ref HEAD)
  head=$(git rev-parse HEAD)
  parent=$(git rev-parse HEAD^)
  bash scripts/verify-arc10-context.sh "$branch" "$head" "$parent"
}

verify_inherited_rc() {
  mapfile -t suites < <(find tests -maxdepth 1 -type f -name 'rc*.test.js' -printf '%p\n' | sort)
  [[ "${#suites[@]}" -gt 0 ]]
  node --test "${suites[@]}"
}

verify_gitleaks() {
  local binary="${GITLEAKS_BIN:-}"
  if [[ -z "$binary" ]]; then
    binary=$(command -v gitleaks)
  fi
  [[ -x "$binary" ]]
  local head
  head=$(git rev-parse HEAD)
  "$binary" git --no-banner --redact --log-opts="$head^..$head" .
  "$binary" git --no-banner --redact --log-opts="$BASELINE..$head" .
  "$binary" git --no-banner --redact --log-opts='--all' .
}

verify_artifact_report() {
  node --input-type=module -e '
    import assert from "node:assert/strict";
    import fs from "node:fs";
    const report = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    assert.equal(report.status, "PASS");
    assert.equal(report.version, "1.0.0");
    assert.equal(report.stage, "ARC-1.0");
    assert.equal(report.candidateGates, 12);
    assert.equal(report.uninstalled, true);
    assert.equal(report.preservedOperatorData, true);
    assert.equal(report.published, false);
    assert.equal(report.source.commit, process.argv[2]);
    assert.equal(report.source.tree, process.argv[3]);
  ' "$TEMP_ROOT/artifact.json" "$(git rev-parse HEAD)" "$(git rev-parse HEAD^{tree})"
}

run_gate "exact branch, head, and parent provenance" verify_context
run_gate "Task-7 parent pre-promotion identity" node scripts/arc10-final-check.mjs identity
run_gate "Core stable release profile" node scripts/arc10-final-check.mjs profile
run_gate "stable identity surface consistency" node scripts/arc10-final-check.mjs identity
run_gate "acceptance ownership completeness" node scripts/arc10-final-check.mjs ownership
run_gate "hosted profile absence" node scripts/arc10-final-check.mjs hosted-absence
run_gate "project final security review" node scripts/arc10-final-check.mjs security-review
run_gate "production build" pnpm run build
run_gate "exact tool and deterministic catalogs" node scripts/arc10-final-check.mjs catalogs
run_gate "Task-1 distribution acceptance" pnpm run test:arc10:task1
run_gate "Task-2 migration acceptance" pnpm run test:arc10:task2
run_gate "Task-7 supply-chain acceptance" pnpm run test:arc10:task7
run_gate "Task-8 final acceptance" pnpm run test:arc10:task8
run_gate "inherited RC-01 through RC-08 regressions" verify_inherited_rc
run_gate "full repository tests" pnpm run test
run_gate "formatting" pnpm run check:format
run_gate "static analysis" pnpm run lint
run_gate "typecheck" pnpm run typecheck
run_gate "documentation integrity" pnpm run check:docs
run_gate "repository secret safety" pnpm run check:secrets
run_gate "dependency vulnerability audit" pnpm audit
run_gate "Git diff integrity" git diff --check
run_gate "reproducible stable distribution and install" bash -c 'node scripts/arc10-stable-artifact-check.mjs > "$1"' _ "$TEMP_ROOT/artifact.json"
run_gate "offline signature and exact source provenance" verify_artifact_report
run_gate "SBOM, license, and provenance completeness" verify_artifact_report
run_gate "Core-only platform matrix" node scripts/arc10-final-check.mjs profile
run_gate "fresh stable install, health, read, and uninstall" verify_artifact_report
run_gate "RC-08 migration, recovery, and rollback evidence" pnpm run test:arc10:task2
run_gate "exact, ARC-1.0-range, and full-history Gitleaks" verify_gitleaks
run_gate "final verification report" node scripts/arc10-final-check.mjs report

[[ "$GATE_COUNT" -eq 30 ]]
echo "ARC 1.0 Core verification PASSED: 30/30 gates"
