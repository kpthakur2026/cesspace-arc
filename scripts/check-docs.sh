#!/usr/bin/env bash
# ==============================================================================
# CesSpace ARC — Documentation & Link Verification Script
# Verifies all required RC-00 architecture and policy documents exist.
# ==============================================================================
set -euo pipefail

echo "==> [1/2] Verifying presence of required RC-00 documentation..."

REQUIRED_DOCS=(
  "README.md"
  "docs/governance/engineering-governance.md"
  "SECURITY.md"
  "CONTRIBUTING.md"
  "CODE_OF_CONDUCT.md"
  "LICENSE"
  "docs/architecture/overview.md"
  "docs/architecture/trust-boundaries.md"
  "docs/architecture/security-invariants.md"
  "docs/architecture/tool-taxonomy.md"
  "docs/architecture/permission-model.md"
  "docs/architecture/filesystem-boundary.md"
  "docs/architecture/audit-model.md"
  "docs/architecture/error-model.md"
  "docs/architecture/package-ownership.md"
  "docs/architecture/rc01-scope-acceptance.md"
  "docs/architecture/rc02-scope-acceptance.md"
  "docs/architecture/rc03-scope-acceptance.md"
  "docs/architecture/rc04-scope-acceptance.md"
  "docs/architecture/rc04-final-integration-report.md"
  "docs/architecture/rc05-scope-acceptance.md"
  "docs/architecture/rc05-final-integration-report.md"
  "docs/architecture/rc06-scope-acceptance.md"
  "docs/architecture/rc06-final-integration-report.md"
  "docs/architecture/rc07-scope-acceptance.md"
  "docs/architecture/rc07-final-integration-report.md"
  "docs/threat-model/threat-model.md"
  "docs/adr/README.md"
  "docs/adr/0001-mcp-as-standard-protocol.md"
  "docs/adr/0002-default-deny-policy-engine.md"
  "docs/adr/0003-canonical-filesystem-jailing.md"
  "docs/adr/0004-structured-audit-and-redaction.md"
  "docs/adr/0005-fail-closed-error-handling.md"
  "docs/adr/0006-monorepo-modular-architecture.md"
  "examples/policies/policy.example.yaml"
  "examples/config/config.example.yaml"
  ".env.example"
)

MISSING_DOCS=0

for DOC in "${REQUIRED_DOCS[@]}"; do
  if [[ ! -f "$DOC" ]]; then
    echo "ERROR: Missing required documentation file: $DOC"
    MISSING_DOCS=$((MISSING_DOCS + 1))
  else
    echo "  [OK] $DOC"
  fi
done

if [[ $MISSING_DOCS -gt 0 ]]; then
  echo "==> Documentation verification FAILED: $MISSING_DOCS file(s) missing."
  exit 1
fi

echo "==> [2/2] Verifying internal markdown links..."
# Basic check to ensure referenced markdown files exist relative to docs root
node -e '
const fs = require("fs");
const path = require("path");

const files = [
  "README.md",
  "docs/governance/engineering-governance.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "docs/adr/README.md"
];

let failed = false;
for (const file of files) {
  const content = fs.readFileSync(file, "utf8");
  const linkRegex = /\[.*?\]\((?!http|#|mailto:)(.*?)\)/g;
  let match;
  while ((match = linkRegex.exec(content)) !== null) {
    const rawLink = match[1].split("#")[0];
    if (!rawLink) continue;
    const resolvedPath = path.resolve(path.dirname(file), rawLink);
    if (!fs.existsSync(resolvedPath)) {
      console.error(`ERROR in ${file}: target link does not exist -> ${rawLink}`);
      failed = true;
    }
  }
}
if (failed) {
  process.exit(1);
} else {
  console.log("  [OK] All internal markdown links verified successfully.");
}
'

echo "==> All documentation checks PASSED."
exit 0
