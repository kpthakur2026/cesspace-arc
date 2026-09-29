#!/usr/bin/env bash
# CesSpace ARC — authoritative RC-08 final verification suite.
set -euo pipefail

FEATURE_BRANCH="feat/rc-08-integrations-security-review"
EXPECTED_VERSION="0.8.0-rc08"
EXPECTED_STAGE="RC-08"
RC08_SUITES=(
  tests/rc08-cross-client-conformance.test.js
  tests/rc08-protocol-schema-fuzzing.test.js
  tests/rc08-remote-gateway-adversarial.test.js
  tests/rc08-filesystem-git-adversarial.test.js
  tests/rc08-process-approval-audit-adversarial.test.js
  tests/rc08-concurrency-resource-robustness.test.js
  tests/rc08-cross-workspace-client-isolation.test.js
  tests/rc08-final-hardening-verification.test.js
)

echo "CesSpace ARC — RC-08 final verification"

# Gate 1: Required feature branch
echo "--> Gate 1: required feature branch"
[[ "$(git rev-parse --abbrev-ref HEAD)" == "$FEATURE_BRANCH" ]]

# Gate 2: Version, stage, and verification wiring
echo "--> Gate 2: promotion consistency"
node --input-type=module -e '
  import assert from "node:assert/strict";
  import fs from "node:fs";
  for (const file of ["package.json", "apps/mcp-server/package.json", "apps/cli/package.json"])
    assert.equal(JSON.parse(fs.readFileSync(file, "utf8")).version, "0.8.0-rc08");
  const server = fs.readFileSync("apps/mcp-server/src/index.ts", "utf8");
  assert.match(server, /version: "?\x270\.8\.0-rc08\x27"?/);
  assert.match(server, /stage: "?\x27RC-08\x27"?/);
  assert.match(fs.readFileSync("apps/cli/src/index.ts", "utf8"), /CLI_VERSION = \x270\.8\.0-rc08\x27/);
'
grep -q '"verify:rc08": "bash scripts/verify-rc08.sh"' package.json

# Gate 3: Formatting
echo "--> Gate 3: formatting"
pnpm run check:format

# Gate 4: Lint
echo "--> Gate 4: lint"
pnpm run lint

# Gate 5: Typecheck
echo "--> Gate 5: typecheck"
pnpm run typecheck

# Gate 6: Build
echo "--> Gate 6: build"
pnpm run build

# Gate 7: Task-8 owner suite
echo "--> Gate 7: Task-8 owner suite"
node --test tests/rc08-final-hardening-verification.test.js

# Gate 8: All RC-08 owner suites
echo "--> Gate 8: all RC-08 owner suites"
node --test "${RC08_SUITES[@]}"

# Gate 9: Full repository tests
echo "--> Gate 9: full repository tests"
pnpm run test

# Gate 10: Documentation integrity
echo "--> Gate 10: documentation integrity"
bash scripts/check-docs.sh

# Gate 11: Secret safety
echo "--> Gate 11: secret safety"
if command -v gitleaks >/dev/null 2>&1; then
  bash scripts/check-secrets.sh
elif [[ -x /tmp/rc08-gitleaks/gitleaks ]]; then
  PATH="/tmp/rc08-gitleaks:$PATH" bash scripts/check-secrets.sh
elif [[ -x /tmp/gitleaks ]]; then
  PATH="/tmp:$PATH" bash scripts/check-secrets.sh
else
  bash scripts/check-secrets.sh
fi

# Gate 12: Dependency security audit
echo "--> Gate 12: dependency audit"
pnpm audit

# Gate 13: Git diff cleanliness
echo "--> Gate 13: git diff cleanliness"
git diff --check

# Gate 14: Exact executable RC-08 control ownership
echo "--> Gate 14: 90 negative controls and 20 positive flows"
node tests/helpers/rc08-control-coverage.mjs

# Gate 15: No skipped or deferred RC-08 controls
echo "--> Gate 15: no skipped or deferred RC-08 controls"
for test_file in "${RC08_SUITES[@]}"; do
  if grep -Eq '(test|it|describe)\.(skip|todo)[[:space:]]*\(' "$test_file"; then
    echo "Disabled RC-08 test found in $test_file" >&2
    exit 1
  fi
done

# Gate 16: Frozen deterministic fuzz configuration
echo "--> Gate 16: deterministic fuzz configuration"
node --input-type=module -e '
  import assert from "node:assert/strict";
  import {
    DEFAULT_FUZZ_SEED, NORMAL_FUZZ_RUNS, EXTENDED_FUZZ_RUNS,
    MAX_GENERATED_PAYLOAD_BYTES, MAX_GENERATED_DEPTH,
    MAX_GENERATED_ARRAY_LENGTH, MAX_GENERATED_STRING_BYTES
  } from "./tests/helpers/rc08-fuzz-harness.mjs";
  assert.equal(DEFAULT_FUZZ_SEED, 1592639710);
  assert.equal(NORMAL_FUZZ_RUNS, 100);
  assert.equal(EXTENDED_FUZZ_RUNS, 5000);
  assert.equal(MAX_GENERATED_PAYLOAD_BYTES, 2 * 1024 * 1024);
  assert.equal(MAX_GENERATED_DEPTH, 10);
  assert.equal(MAX_GENERATED_ARRAY_LENGTH, 10000);
  assert.equal(MAX_GENERATED_STRING_BYTES, 1024 * 1024);
'

# Gate 17: Composite import boundary
echo "--> Gate 17: composite import boundary"
node --input-type=module -e '
  import assert from "node:assert/strict";
  import fs from "node:fs";
  const files = [
    "apps/mcp-server/src/composite-framework.ts",
    "apps/mcp-server/src/internal/repo-worktree-status.ts",
    "apps/mcp-server/src/internal/review-diff.ts",
    "apps/mcp-server/src/internal/verify.ts",
    "apps/mcp-server/src/internal/test.ts",
    "apps/mcp-server/src/internal/ci-status.ts",
    "apps/mcp-server/src/internal/stage-evidence.ts"
  ];
  const child = /(?:from\s+["\x27](?:node:)?child_process["\x27]|require\(["\x27](?:node:)?child_process["\x27]\))/;
  const directFs = /(?:from\s+["\x27](?:node:)?fs(?:\/promises)?["\x27]|require\(["\x27](?:node:)?fs(?:\/promises)?["\x27]\))/;
  for (const file of files) {
    const source = fs.readFileSync(file, "utf8");
    assert.equal(child.test(source), false, file);
    assert.equal(directFs.test(source), false, file);
  }
'

# Gate 18: Frozen tool and deterministic execution catalogs
echo "--> Gate 18: catalog invariants"
node --input-type=module -e '
  import assert from "node:assert/strict";
  import { ALL_TOOL_DEFINITIONS } from "./apps/mcp-server/dist/index.js";
  import { createProductionDeterministicRegistry } from "./apps/mcp-server/dist/composite-framework.js";
  assert.equal(ALL_TOOL_DEFINITIONS.length, 25);
  assert.equal(new Set(ALL_TOOL_DEFINITIONS.map((tool) => tool.name)).size, 25);
  assert.deepEqual(createProductionDeterministicRegistry().listEntryIds(), [
    "verify-format-v1", "verify-lint-v1", "verify-typecheck-v1", "verify-test-v1", "arc-test-node-v1"
  ]);
'

# Gate 19: Verification script integrity
echo "--> Gate 19: verifier integrity"
FALSE_FALLBACK_PATTERN='||'' true'
if grep -nF -- "$FALSE_FALLBACK_PATTERN" scripts/verify-rc08.sh >/dev/null 2>&1; then
  echo "Error-masking fallback found in scripts/verify-rc08.sh" >&2
  exit 1
fi
[[ -x scripts/verify-rc08.sh ]]

# Gate 20: Required final artifacts and promotion identity
echo "--> Gate 20: final artifacts"
for required_file in \
  docs/architecture/rc08-scope-acceptance.md \
  tests/rc08-final-hardening-verification.test.js \
  tests/helpers/rc08-control-coverage.mjs \
  scripts/verify-rc08.sh; do
  [[ -s "$required_file" ]]
done
grep -q "EXPECTED_VERSION=\"$EXPECTED_VERSION\"" scripts/verify-rc08.sh
grep -q "EXPECTED_STAGE=\"$EXPECTED_STAGE\"" scripts/verify-rc08.sh

echo "RC-08 VERIFICATION SUCCESSFUL: ALL 20 GATES PASSED"
