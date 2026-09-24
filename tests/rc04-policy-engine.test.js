import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

import {
  DeclarativePolicyEngine,
  WorkspaceRegistry,
  RC01_ALLOWED_TOOLS,
  RC02_ALLOWED_TOOLS,
  RC03_MUTATION_TOOLS,
  RC03_REGISTERED_TOOLS,
  MAX_POLICY_BYTES,
  MAX_POLICY_DEPTH,
  MAX_POLICY_RULES,
  MAX_MATCHER_ITEMS,
  MAX_PATTERN_LENGTH,
  MAX_RULE_DESCRIPTION_LENGTH,
  DEFAULT_DENY_NO_RULE_MATCHED,
  DEFAULT_DENY_UNREGISTERED_TOOL,
  canonicalJson,
  computePolicyHash,
  compareStrings,
  validatePathPattern,
  normalizeTargetPath,
  matchPathGlob,
} from '../packages/policy/dist/index.js';
import { ArcError } from '../packages/protocol/dist/index.js';

describe('CesSpace ARC — RC-04 Task 2: Declarative Policy Engine', () => {
  let tempDir;
  let workspaceRoot;
  let registry;
  let workspaceRootHash;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arc-rc04-policy-test-'));
    workspaceRoot = path.join(tempDir, 'workspace');
    fs.mkdirSync(workspaceRoot, { recursive: true });

    registry = new WorkspaceRegistry();
    const record = registry.registerWorkspace('primary', workspaceRoot);
    workspaceRootHash = crypto.createHash('sha256').update(record.rootPath, 'utf8').digest('hex');

    // Second workspace so that ordering and multi-assertion behaviour is
    // actually exercised rather than trivially satisfied.
    const secondaryRoot = path.join(tempDir, 'secondary');
    fs.mkdirSync(secondaryRoot, { recursive: true });
    registry.registerWorkspace('secondary', secondaryRoot);
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  function expectParseError(fn, expectedReason) {
    let thrown;
    try {
      fn();
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown !== undefined, 'expected a POLICY_PARSE_ERROR to be thrown');
    assert.ok(thrown instanceof ArcError, `expected ArcError, received ${thrown}`);
    assert.equal(thrown.code, 'POLICY_PARSE_ERROR');
    if (expectedReason !== undefined) {
      assert.equal(thrown.details.reason, expectedReason);
    }
    return thrown;
  }

  function expectLoadError(fn, expectedReason) {
    let thrown;
    try {
      fn();
    } catch (err) {
      thrown = err;
    }
    assert.ok(thrown !== undefined, 'expected a POLICY_LOAD_ERROR to be thrown');
    assert.ok(thrown instanceof ArcError, `expected ArcError, received ${thrown}`);
    assert.equal(thrown.code, 'POLICY_LOAD_ERROR');
    if (expectedReason !== undefined) {
      assert.equal(thrown.details.reason, expectedReason);
    }
    return thrown;
  }

  /** Builds YAML policy text from a list of rule objects. */
  function yamlPolicy(rules, extra = {}) {
    const lines = ["version: '1.0'"];
    for (const [key, value] of Object.entries(extra)) {
      lines.push(`${key}: ${JSON.stringify(value)}`);
    }
    if (rules.length === 0) {
      lines.push('rules: []');
    } else {
      lines.push('rules:');
      for (const rule of rules) {
        lines.push(`  - id: ${JSON.stringify(rule.id)}`);
        lines.push(`    effect: ${JSON.stringify(rule.effect)}`);
        for (const [key, value] of Object.entries(rule)) {
          if (key === 'id' || key === 'effect') continue;
          lines.push(`    ${key}: ${JSON.stringify(value)}`);
        }
      }
    }
    return `${lines.join('\n')}\n`;
  }

  function jsonPolicy(rules) {
    return JSON.stringify({ version: '1.0', rules });
  }

  function engineFromYaml(text) {
    return DeclarativePolicyEngine.fromExternalText(registry, text, 'yaml');
  }

  function engineFromJson(text) {
    return DeclarativePolicyEngine.fromExternalText(registry, text, 'json');
  }

  function evaluate(engine, toolName, extra = {}) {
    return engine.evaluate({ toolName, ...extra });
  }

  // =========================================================================
  // 1. Valid parsing and YAML/JSON equivalence
  // =========================================================================

  describe('Parsing: valid documents', () => {
    test('RC04-P-01: valid YAML policy parses and evaluates', () => {
      const engine = engineFromYaml(`
version: '1.0'
metadata:
  name: 'example'
  description: 'strict project security policy'
  lastModified: '2026-09-18T12:00:00Z'
rules:
  - id: 'deny-config-write'
    effect: 'DENY'
    description: 'prevent modifying configuration files'
    tools:
      - 'write_file'
      - 'apply_patch'
    paths:
      patterns:
        - 'config/**'
        - '*.config.js'
`);
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
      assert.equal(engine.getPolicyHash().length, 64);
      assert.match(engine.getPolicyHash(), /^[0-9a-f]{64}$/);

      const decision = evaluate(engine, 'write_file', { path: 'config/server.yml' });
      assert.equal(decision.effect, 'DENY');
      assert.equal(decision.matchingRuleId, 'deny-config-write');
    });

    test('RC04-P-02: valid JSON policy parses and evaluates', () => {
      const engine = engineFromJson(
        jsonPolicy([{ id: 'deny-read', effect: 'DENY', tools: ['read_file'] }]),
      );
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
      assert.equal(evaluate(engine, 'read_file').effect, 'DENY');
    });

    test('RC04-P-03: YAML and JSON policies with identical semantics produce identical policyHash', () => {
      const rules = [
        {
          id: 'r-alpha',
          effect: 'DENY',
          tools: ['write_file', 'apply_patch'],
          paths: { patterns: ['src/**'] },
        },
        { id: 'r-beta', effect: 'ALLOW', tools: ['read_file'] },
      ];
      const yamlEngine = engineFromYaml(yamlPolicy(rules));
      const jsonEngine = engineFromJson(jsonPolicy(rules));
      assert.equal(yamlEngine.getPolicyHash(), jsonEngine.getPolicyHash());
    });

    test('RC04-P-04: empty rules array is a valid external policy', () => {
      const engine = engineFromYaml("version: '1.0'\nrules: []\n");
      assert.equal(evaluate(engine, 'read_file').effect, 'DENY');
      assert.equal(evaluate(engine, 'read_file').matchingRuleId, DEFAULT_DENY_NO_RULE_MATCHED);
    });
  });

  // =========================================================================
  // 2. JSON strictness and duplicate keys
  // =========================================================================

  describe('JSON strictness', () => {
    test('RC04-P-05: JSON comments are rejected', () => {
      expectParseError(() => engineFromJson('{\n// comment\n"version": "1.0", "rules": []\n}'));
      expectParseError(() => engineFromJson('{"version": "1.0", /* c */ "rules": []}'));
    });

    test('RC04-P-06: JSON trailing commas are rejected', () => {
      expectParseError(() => engineFromJson('{"version": "1.0", "rules": [],}'));
      expectParseError(() => engineFromJson('{"version": "1.0", "rules": [,]}'));
    });

    test('RC04-P-07: JSON unquoted keys are rejected', () => {
      expectParseError(() => engineFromJson('{version: "1.0", rules: []}'));
    });

    test('RC04-P-08: YAML syntax supplied to the JSON parser is rejected', () => {
      expectParseError(() => engineFromJson("version: '1.0'\nrules: []\n"));
    });

    test('RC04-P-09: duplicate JSON object keys are rejected despite JSON.parse accepting them', () => {
      // JSON.parse silently keeps the last value; the independent AST pass must catch it.
      assert.deepEqual(JSON.parse('{"a": 1, "a": 2}'), { a: 2 });
      expectParseError(
        () => engineFromJson('{"version": "1.0", "rules": [], "rules": []}'),
        'DUPLICATE_MAPPING_KEY',
      );
      expectParseError(
        () =>
          engineFromJson(
            '{"version": "1.0", "rules": [{"id": "a", "effect": "ALLOW", "effect": "DENY"}]}',
          ),
        'DUPLICATE_MAPPING_KEY',
      );
    });

    test('RC04-P-10: duplicate YAML mapping keys are rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\nrules: []\n"),
        'DUPLICATE_MAPPING_KEY',
      );
    });

    test('RC04-P-11: bare YAML syntax is rejected in JSON mode even when otherwise invalid', () => {
      expectParseError(() => engineFromJson('null'));
    });
  });

  // =========================================================================
  // 3. YAML hardening
  // =========================================================================

  describe('YAML parser hardening', () => {
    test('RC04-P-12: YAML anchors are rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nbase: &anchor value\nrules: []\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-P-13: YAML aliases are rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nbase: &a value\nalias: *a\nrules: []\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-P-14: YAML alias with no local anchor is rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: *undefined_alias\n"),
        'FORBIDDEN_YAML_ALIAS',
      );
    });

    test('RC04-P-15: YAML merge keys are rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nbase: &b\n  x: 1\nrules:\n  <<: *b\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\n<<: {}\n"),
        'FORBIDDEN_YAML_MERGE_KEY',
      );
    });

    test('RC04-P-16: custom and non-core YAML tags are rejected', () => {
      // Each tag carries a payload valid for that tag, so the rejection comes
      // from the tag allowlist rather than from a failed tag resolution.
      const tagged = [
        '!run value',
        '!include ./other.yml',
        '!env HOME',
        '!!timestamp 2026-09-18T12:00:00Z',
        '!!binary "aGk="',
        '!!set {a: null}',
        '!!merge {a: 1}',
      ];
      for (const tag of tagged) {
        expectParseError(
          () => engineFromYaml(`version: '1.0'\nrules: []\nx: ${tag}\n`),
          'FORBIDDEN_YAML_TAG',
        );
      }
    });

    test('RC04-P-16b: a malformed payload of a non-core tag is still rejected', () => {
      // Tag resolution failure is caught before the AST walk; the outcome is
      // still a generic parse failure with no parser text leaked.
      expectParseError(() =>
        engineFromYaml("version: '1.0'\nrules: []\nx: !!timestamp not-a-timestamp\n"),
      );
    });

    test('RC04-P-17: quoted anchor-like and alias-like text remains ordinary data', () => {
      // `&foo` inside quotes is literal text, never an anchor declaration.
      const engine = engineFromYaml(
        "version: '1.0'\nmetadata:\n  name: '&foo'\n  description: '*bar'\nrules: []\n",
      );
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
    });

    test('RC04-P-18: comments containing * and & do not trigger alias or anchor rejection', () => {
      const engine = engineFromYaml("version: '1.0'\n# *foo &bar << !tag *alias\nrules: []\n");
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
    });

    test('RC04-P-19: quoted scalar text containing << and ! is not mistaken for merge keys or tags', () => {
      const engine = engineFromYaml(
        "version: '1.0'\nmetadata:\n  name: '<<'\n  description: '!not-a-tag'\nrules: []\n",
      );
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
    });

    test('RC04-P-20: multiple YAML documents are rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\n---\nversion: '1.0'\nrules: []\n"),
        'MULTIPLE_DOCUMENTS',
      );
    });

    test('RC04-P-21: malformed YAML is rejected generically', () => {
      expectParseError(() => engineFromYaml("version: '1.0'\nrules: [\n"));
      expectParseError(() => engineFromYaml('version: "1.0"\n\tbad: indent\nrules: []\n'));
    });

    test('RC04-P-22: YAML 1.2 core schema keeps unquoted timestamps and booleans deterministic', () => {
      // An unquoted ISO timestamp must stay a string. Under a YAML 1.1 schema it
      // would resolve to a Date and be rejected as a non-JSON scalar value.
      const engine = engineFromYaml(
        "version: '1.0'\nmetadata:\n  lastModified: 2026-09-18T12:00:00Z\nrules: []\n",
      );
      assert.equal(engine.getSourceMode(), 'EXTERNAL');

      // Unquoted `yes` must remain the STRING 'yes', not the boolean true.
      // Under YAML 1.1 it would coerce to a boolean and fail as INVALID_MATCHER;
      // as a string it is simply an unknown tool name.
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nrules:\n  - id: r\n    effect: ALLOW\n    tools:\n      - yes\n",
          ),
        'UNKNOWN_TOOL_NAME',
      );
    });

    test('RC04-P-23: self-referential alias structures cannot be constructed', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: &self\n  - *self\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-P-23b: a billion-laughs alias expansion is rejected before any expansion occurs', () => {
      const laughs = `a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
version: '1.0'
e: [*d,*d,*d,*d,*d,*d,*d,*d,*d]
rules: []
`;
      const started = Date.now();
      expectParseError(() => engineFromYaml(laughs));
      const elapsed = Date.now() - started;
      // Rejection must come from structure, long before expansion could occur.
      assert.ok(elapsed < 2000, `alias rejection took ${elapsed}ms`);
    });

    test('RC04-P-23c: prototype-polluting mapping keys are rejected without polluting prototypes', () => {
      const sources = [
        "version: '1.0'\nrules: []\n__proto__: {polluted: 1}\n",
        "version: '1.0'\nrules: []\nconstructor: 1\n",
        "version: '1.0'\nrules: []\nprototype: 1\n",
        "version: '1.0'\nrules:\n  - id: r\n    effect: ALLOW\n    __proto__: {x: 1}\n",
      ];
      for (const source of sources) {
        expectParseError(() => engineFromYaml(source), 'FORBIDDEN_MAPPING_KEY');
      }
      expectParseError(
        () => engineFromJson('{"version":"1.0","rules":[],"__proto__":{"polluted":1}}'),
        'FORBIDDEN_MAPPING_KEY',
      );
      assert.equal({}.polluted, undefined, 'Object.prototype was polluted');
    });

    test('RC04-P-23d: non-finite numeric scalars are rejected', () => {
      for (const literal of ['.inf', '-.inf', '.nan', '.NaN']) {
        expectParseError(
          () => engineFromYaml(`version: '1.0'\nrules: []\nx: ${literal}\n`),
          'INVALID_SCALAR_VALUE',
        );
      }
    });

    test('RC04-P-23e: verbatim and language-specific tag forms are rejected', () => {
      const hostileTags = [
        '!!python/object:os.system',
        '!<tag:yaml.org,2002:python/name:os.system>',
        '!!js/function',
        '!<tag:example.com,2000:run>',
      ];
      for (const tag of hostileTags) {
        expectParseError(
          () => engineFromYaml(`version: '1.0'\nrules: []\nx: ${tag} []\n`),
          'FORBIDDEN_YAML_TAG',
        );
      }
    });
  });

  // =========================================================================
  // 3b. Mapping KEY node hardening (RC-04 Task 2.1)
  //
  // A mapping key is a YAML node in its own right. Node-level anchor/tag
  // validation must apply to keys exactly as it applies to values, sequence
  // items, and collection nodes — an otherwise-valid resolved key name such as
  // `version`, `rules`, `id`, or `effect` must not launder a forbidden node.
  // =========================================================================

  describe('Mapping key node hardening', () => {
    test('RC04-K-01: anchor on a top-level mapping key is rejected', () => {
      expectParseError(
        () => engineFromYaml("&keyAnchor version: '1.0'\nrules: []\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-K-02: an anchored key does not bypass via its valid resolved name', () => {
      // Each of these resolves to a legitimate schema key after parsing.
      const anchoredKeys = [
        "&k version: '1.0'\nrules: []\n",
        "version: '1.0'\n&k rules: []\n",
        "version: '1.0'\n&k metadata:\n  name: x\nrules: []\n",
      ];
      for (const source of anchoredKeys) {
        expectParseError(() => engineFromYaml(source), 'FORBIDDEN_YAML_ANCHOR');
      }
    });

    test('RC04-K-03: anchor on a nested mapping key inside a rule is rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules:\n  - id: r\n    &e effect: 'ALLOW'\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nrules:\n  - id: r\n    effect: 'ALLOW'\n    &t tools: ['read_file']\n",
          ),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-K-04: anchor on a nested mapping key inside metadata is rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nmetadata:\n  &n name: 'x'\nrules: []\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-K-05: anchor on a mapping key in explicit-key form is rejected', () => {
      expectParseError(
        () => engineFromYaml("? &a version\n: '1.0'\nrules: []\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-K-06: anchor on a flow-mapping key is rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nmetadata: {&n name: x}\nrules: []\n"),
        'FORBIDDEN_YAML_ANCHOR',
      );
    });

    test('RC04-K-07: an alias used as a mapping key is rejected without expansion', () => {
      // Explicit-key form: the parser accepts it cleanly and the alias node
      // reaches the AST walk, so this genuinely exercises the key-level check.
      expectParseError(
        () => engineFromYaml("version: '1.0'\n? *ghost\n: 2\nrules: []\n"),
        'FORBIDDEN_YAML_ALIAS',
      );
      expectParseError(
        () => engineFromYaml("version: '1.0'\n? *a\n: 2\nx: &a 1\nrules: []\n"),
        'FORBIDDEN_YAML_ALIAS',
      );
    });

    test('RC04-K-08: a custom tag on a mapping key is rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\n!custom rules: []\n"),
        'FORBIDDEN_YAML_TAG',
      );
      expectParseError(
        () => engineFromYaml("version: '1.0'\n!env rules: []\n"),
        'FORBIDDEN_YAML_TAG',
      );
      expectParseError(
        () => engineFromYaml("? !custom version\n: '1.0'\nrules: []\n"),
        'FORBIDDEN_YAML_TAG',
      );
    });

    test('RC04-K-09: the value-node tag policy is unchanged for keys (core tags still allowed)', () => {
      // Not broadened, not relaxed: explicitly-tagged core keys still parse.
      const engine = engineFromYaml("!!str version: '1.0'\n!!str rules: []\n");
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
      assert.equal(evaluate(engine, 'read_file').effect, 'DENY');
    });

    test('RC04-K-10: non-scalar mapping keys are rejected', () => {
      for (const source of [
        "version: '1.0'\n? [a, b]\n: value\nrules: []\n",
        "version: '1.0'\n? {a: 1}\n: value\nrules: []\n",
      ]) {
        expectParseError(() => engineFromYaml(source));
      }
    });

    test('RC04-K-11: forbidden literal mapping keys remain rejected', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\n<<: {}\n"),
        'FORBIDDEN_YAML_MERGE_KEY',
      );
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\n__proto__: {}\n"),
        'FORBIDDEN_MAPPING_KEY',
      );
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\nconstructor: 1\n"),
        'FORBIDDEN_MAPPING_KEY',
      );
    });

    test('RC04-K-12: ordinary untagged keys continue to parse and evaluate', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'plain-key-rule', effect: 'DENY', tools: ['read_file'] }]),
      );
      assert.equal(evaluate(engine, 'read_file').effect, 'DENY');
      assert.equal(evaluate(engine, 'read_file').matchingRuleId, 'plain-key-rule');
      assert.equal(engine.getNormalizedPolicy().rules[0].id, 'plain-key-rule');
    });

    test('RC04-K-13: anchor-like characters in quoted values and comments still do not false-positive', () => {
      const engine = engineFromYaml(
        [
          "version: '1.0'",
          'metadata:',
          "  name: '&foo'",
          "  description: '*bar'",
          '# &ref *ref << !tag',
          'rules:',
          "  - id: 'r'",
          "    effect: 'ALLOW'",
          "    description: '<< !notatag *notalias &notanchor'",
          "    tools: ['read_file']",
        ].join('\n') + '\n',
      );
      assert.equal(evaluate(engine, 'read_file').effect, 'ALLOW');
    });

    test('RC04-K-14: duplicate-key detection still works after key-node hardening', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\nrules: []\n"),
        'DUPLICATE_MAPPING_KEY',
      );
      expectParseError(
        () => engineFromJson('{"version": "1.0", "rules": [], "rules": []}'),
        'DUPLICATE_MAPPING_KEY',
      );
    });

    test('RC04-K-15: JSON parsing behavior is unchanged', () => {
      const engine = engineFromJson(
        jsonPolicy([{ id: 'json-rule', effect: 'DENY', tools: ['read_file'] }]),
      );
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
      assert.equal(evaluate(engine, 'read_file').effect, 'DENY');
      // JSON has no anchors, aliases, or tags: none of these are JSON syntax.
      expectParseError(() => engineFromJson('{"version": "1.0", "&k rules": []}'));
    });

    test('RC04-K-16: equivalent YAML and JSON policies still hash identically', () => {
      const rules = [
        { id: 'k-alpha', effect: 'DENY', tools: ['write_file'], paths: { patterns: ['src/**'] } },
        { id: 'k-beta', effect: 'ALLOW', tools: ['read_file'] },
      ];
      assert.equal(
        engineFromYaml(yamlPolicy(rules)).getPolicyHash(),
        engineFromJson(jsonPolicy(rules)).getPolicyHash(),
      );
    });
  });

  // =========================================================================
  // 4. Resource bounds
  // =========================================================================

  describe('Resource bounds', () => {
    test('RC04-P-24: document exceeding 256 KiB UTF-8 is rejected', () => {
      const oversized = `version: '1.0'\nrules: []\n# ${'x'.repeat(MAX_POLICY_BYTES)}\n`;
      assert.ok(Buffer.byteLength(oversized, 'utf8') > MAX_POLICY_BYTES);
      expectParseError(() => engineFromYaml(oversized), 'DOCUMENT_SIZE_LIMIT_EXCEEDED');
    });

    test('RC04-P-25: multibyte UTF-8 overflow is caught by byte length, not character length', () => {
      // 100_000 x U+20AC (3 bytes each) = 300_000 bytes but ~100_030 characters.
      const multibyte = '€'.repeat(100_000);
      const source = `version: '1.0'\nrules: []\n# ${multibyte}\n`;
      assert.ok(source.length < MAX_POLICY_BYTES, 'character length is below the limit');
      assert.ok(
        Buffer.byteLength(source, 'utf8') > MAX_POLICY_BYTES,
        'byte length exceeds the limit',
      );
      expectParseError(() => engineFromYaml(source), 'DOCUMENT_SIZE_LIMIT_EXCEEDED');
    });

    test('RC04-P-26: nesting depth 32 is accepted by the depth guard', () => {
      const atLimit = '['.repeat(MAX_POLICY_DEPTH) + ']'.repeat(MAX_POLICY_DEPTH);
      // The depth guard passes; the document is then rejected as a non-mapping.
      expectParseError(() => engineFromYaml(atLimit), 'MALFORMED_DOCUMENT');
      expectParseError(() => engineFromJson(atLimit), 'MALFORMED_DOCUMENT');
    });

    test('RC04-P-27: nesting depth 33 is rejected as a depth violation', () => {
      const overLimit = '['.repeat(MAX_POLICY_DEPTH + 1) + ']'.repeat(MAX_POLICY_DEPTH + 1);
      expectParseError(() => engineFromYaml(overLimit), 'DEPTH_LIMIT_EXCEEDED');
      expectParseError(() => engineFromJson(overLimit), 'DEPTH_LIMIT_EXCEEDED');
    });

    test('RC04-P-28: deeply nested hostile documents fail cleanly without stack exhaustion', () => {
      // Far beyond any plausible stack limit: a recursive, unbounded walk would
      // overflow before reaching the depth guard.
      const hostile = '['.repeat(20_000) + ']'.repeat(20_000);
      assert.ok(Buffer.byteLength(hostile, 'utf8') <= MAX_POLICY_BYTES);
      expectParseError(() => engineFromYaml(hostile));
      expectParseError(() => engineFromJson(hostile));
    });

    test('RC04-P-29: more than 256 rules is rejected', () => {
      const rules = [];
      for (let i = 0; i < MAX_POLICY_RULES + 1; i++) {
        rules.push({ id: `rule-${i}`, effect: 'ALLOW', tools: ['read_file'] });
      }
      expectParseError(() => engineFromYaml(yamlPolicy(rules)), 'TOO_MANY_RULES');
    });

    test('RC04-P-30: exactly 256 rules is accepted', () => {
      const rules = [];
      for (let i = 0; i < MAX_POLICY_RULES; i++) {
        rules.push({ id: `rule-${i}`, effect: 'ALLOW', tools: ['read_file'] });
      }
      const engine = engineFromYaml(yamlPolicy(rules));
      assert.equal(engine.getNormalizedPolicy().rules.length, MAX_POLICY_RULES);
    });

    test('RC04-P-31: matcher arrays beyond 128 source items are rejected before deduplication', () => {
      const tooMany = [];
      for (let i = 0; i < MAX_MATCHER_ITEMS + 1; i++) {
        tooMany.push('read_file');
      }
      expectParseError(
        () => engineFromYaml(yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: tooMany }])),
        'TOO_MANY_MATCHER_ITEMS',
      );
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([
              { id: 'r', effect: 'DENY', paths: { patterns: tooMany.map(() => 'src/**') } },
            ]),
          ),
        'TOO_MANY_MATCHER_ITEMS',
      );
    });

    test('RC04-P-32: duplicate matcher entries cannot be used to bypass the item limit', () => {
      // 127 unique values padded with an enormous number of duplicates still
      // exceeds the raw-source bound.
      const entries = [];
      for (let i = 0; i < MAX_MATCHER_ITEMS * 4; i++) {
        entries.push('read_file');
      }
      expectParseError(
        () => engineFromYaml(yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: entries }])),
        'TOO_MANY_MATCHER_ITEMS',
      );
    });

    test('RC04-P-33: path patterns beyond 1024 characters are rejected', () => {
      const longPattern = `${'a'.repeat(MAX_PATTERN_LENGTH + 1)}`;
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([{ id: 'r', effect: 'ALLOW', paths: { patterns: [longPattern] } }]),
          ),
        'INVALID_PATH_PATTERN',
      );
    });

    test('RC04-P-34: matcher array entries must be strings with no coercion', () => {
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nrules:\n  - id: r\n    effect: ALLOW\n    tools:\n      - 1\n",
          ),
        'INVALID_MATCHER',
      );
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nrules:\n  - id: r\n    effect: ALLOW\n    tools:\n      - true\n",
          ),
        'INVALID_MATCHER',
      );
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nrules:\n  - id: r\n    effect: ALLOW\n    tools:\n      - null\n",
          ),
        'INVALID_MATCHER',
      );
    });
  });

  // =========================================================================
  // 5. Strict closed schema
  // =========================================================================

  describe('Strict closed schema', () => {
    test('RC04-P-35: unknown properties are rejected at every object level', () => {
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\nextra: 1\n"),
        'UNKNOWN_PROPERTY',
      );
      expectParseError(
        () => engineFromYaml("version: '1.0'\nmetadata:\n  name: 'x'\n  other: 'y'\nrules: []\n"),
        'UNKNOWN_PROPERTY',
      );
      expectParseError(
        () => engineFromYaml(yamlPolicy([{ id: 'r', effect: 'ALLOW', unknownRuleField: true }])),
        'UNKNOWN_PROPERTY',
      );
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([{ id: 'r', effect: 'ALLOW', paths: { patterns: ['a'], extra: 1 } }]),
          ),
        'UNKNOWN_PROPERTY',
      );
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([
              { id: 'r', effect: 'DENY', commands: { blockedBinaries: ['curl'], x: 1 } },
            ]),
          ),
        'UNKNOWN_PROPERTY',
      );
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([{ id: 'r', effect: 'DENY', git: { actions: ['push'], z: 1 } }]),
          ),
        'UNKNOWN_PROPERTY',
      );
    });

    test('RC04-P-36: invalid versions are rejected', () => {
      expectParseError(() => engineFromYaml("version: '2.0'\nrules: []\n"), 'INVALID_VERSION');
      expectParseError(() => engineFromYaml('version: 1.0\nrules: []\n'), 'INVALID_VERSION');
      expectParseError(() => engineFromYaml("version: '1'\nrules: []\n"), 'INVALID_VERSION');
      expectParseError(() => engineFromYaml('version: true\nrules: []\n'), 'INVALID_VERSION');
    });

    test('RC04-P-37: version is required', () => {
      expectParseError(() => engineFromYaml('rules: []\n'), 'INVALID_VERSION');
    });

    test('RC04-P-38: rules is required and must be an array', () => {
      expectParseError(() => engineFromYaml("version: '1.0'\n"), 'INVALID_RULES');
      expectParseError(() => engineFromYaml("version: '1.0'\nrules: {}\n"), 'INVALID_RULES');
      expectParseError(() => engineFromYaml("version: '1.0'\nrules: 'x'\n"), 'INVALID_RULES');
    });

    test('RC04-P-39: null, scalar, and array top-level documents are rejected', () => {
      expectParseError(() => engineFromYaml('null\n'), 'MALFORMED_DOCUMENT');
      expectParseError(() => engineFromYaml('just-a-scalar\n'), 'MALFORMED_DOCUMENT');
      expectParseError(() => engineFromYaml("['version']\n"), 'MALFORMED_DOCUMENT');
      expectParseError(() => engineFromYaml(''), 'MALFORMED_DOCUMENT');
    });

    test('RC04-P-40: invalid rule IDs are rejected', () => {
      const invalidIds = [
        '',
        'has space',
        'has.dot',
        'has/slash',
        'has:colon',
        'a'.repeat(65),
        'rule\n',
        'rule\\name',
        'emoji-😀',
      ];
      for (const id of invalidIds) {
        expectParseError(
          () => engineFromYaml(yamlPolicy([{ id, effect: 'ALLOW', tools: ['read_file'] }])),
          'INVALID_RULE_ID',
        );
      }
    });

    test('RC04-P-41: valid rule ID characters are accepted', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'A-b_9-z', effect: 'ALLOW', tools: ['read_file'] }]),
      );
      assert.equal(evaluate(engine, 'read_file').matchingRuleId, 'A-b_9-z');
    });

    test('RC04-P-42: duplicate rule IDs are rejected rather than silently overwritten', () => {
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([
              { id: 'same', effect: 'ALLOW', tools: ['read_file'] },
              { id: 'same', effect: 'DENY', tools: ['read_file'] },
            ]),
          ),
        'DUPLICATE_RULE_ID',
      );
    });

    test('RC04-P-43: rule effects are case-sensitive and closed', () => {
      for (const effect of [
        'deny',
        'Allow',
        'REQUIRE-APPROVAL',
        'require_approval',
        'PERMIT',
        '',
      ]) {
        expectParseError(() => engineFromYaml(yamlPolicy([{ id: 'r', effect }])), 'INVALID_EFFECT');
      }
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules:\n  - id: r\n    effect: 5\n"),
        'INVALID_EFFECT',
      );
    });

    test('RC04-P-44: rule descriptions over 256 characters are rejected', () => {
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([
              {
                id: 'r',
                effect: 'ALLOW',
                description: 'd'.repeat(MAX_RULE_DESCRIPTION_LENGTH + 1),
                tools: ['read_file'],
              },
            ]),
          ),
        'INVALID_DESCRIPTION',
      );
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'r',
            effect: 'ALLOW',
            description: 'd'.repeat(MAX_RULE_DESCRIPTION_LENGTH),
            tools: ['read_file'],
          },
        ]),
      );
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
    });

    test('RC04-P-45: unknown tool names are rejected at policy load time', () => {
      for (const tool of ['nonexistent_tool', 'read_file_v2', 'exec', 'Read_File']) {
        expectParseError(
          () => engineFromYaml(yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: [tool] }])),
          'UNKNOWN_TOOL_NAME',
        );
      }
    });

    test('RC04-P-46: all 18 registered tool names are accepted', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'REQUIRE_APPROVAL', tools: [...RC03_REGISTERED_TOOLS] }]),
      );
      assert.equal(
        engine.getNormalizedPolicy().rules[0].tools.length,
        RC03_REGISTERED_TOOLS.length,
      );
    });

    test('RC04-P-47: workspace assertions reject path, rootPath, and directory', () => {
      for (const forbidden of ['path', 'rootPath', 'directory']) {
        expectParseError(
          () =>
            engineFromYaml(
              `version: '1.0'\nworkspaces:\n  - id: 'primary'\n    ${forbidden}: '/etc'\nrules: []\n`,
            ),
          'UNKNOWN_PROPERTY',
        );
      }
    });

    test('RC04-P-48: workspace assertions allow only id and rootHash', () => {
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nworkspaces:\n  - id: 'primary'\n    name: 'x'\nrules: []\n",
          ),
        'UNKNOWN_PROPERTY',
      );
      expectParseError(
        () => engineFromYaml("version: '1.0'\nworkspaces:\n  - rootHash: 'a'\nrules: []\n"),
        'INVALID_WORKSPACE_ASSERTION',
      );
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nworkspaces:\n  - id: 'primary'\n    rootHash: 'xyz'\nrules: []\n",
          ),
        'INVALID_WORKSPACE_ASSERTION',
      );
    });

    test('RC04-P-49: duplicate workspace assertion IDs are rejected', () => {
      expectParseError(
        () =>
          engineFromYaml(
            "version: '1.0'\nworkspaces:\n  - id: 'primary'\n  - id: 'primary'\nrules: []\n",
          ),
        'DUPLICATE_WORKSPACE_ID',
      );
    });
  });

  // =========================================================================
  // 6. Command matcher contract
  // =========================================================================

  describe('Command matcher contract', () => {
    test('RC04-P-50: allowedBinaries with blockedBinaries in one rule is rejected', () => {
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([
              {
                id: 'r',
                effect: 'DENY',
                commands: { allowedBinaries: ['npm'], blockedBinaries: ['curl'] },
              },
            ]),
          ),
        'INVALID_COMMAND_MATCHER',
      );
    });

    test('RC04-P-51: allowedBinaries on a DENY rule is rejected', () => {
      expectParseError(
        () =>
          engineFromYaml(
            yamlPolicy([{ id: 'r', effect: 'DENY', commands: { allowedBinaries: ['npm'] } }]),
          ),
        'INVALID_COMMAND_MATCHER',
      );
    });

    test('RC04-P-52: blockedBinaries on ALLOW and REQUIRE_APPROVAL rules is rejected', () => {
      for (const effect of ['ALLOW', 'REQUIRE_APPROVAL']) {
        expectParseError(
          () =>
            engineFromYaml(
              yamlPolicy([{ id: 'r', effect, commands: { blockedBinaries: ['curl'] } }]),
            ),
          'INVALID_COMMAND_MATCHER',
        );
      }
    });

    test('RC04-P-53: binary matchers containing path separators are rejected', () => {
      for (const binary of ['/usr/bin/curl', 'bin/curl', 'bin\\curl', 'C:\\curl.exe']) {
        expectParseError(
          () =>
            engineFromYaml(
              yamlPolicy([{ id: 'r', effect: 'DENY', commands: { blockedBinaries: [binary] } }]),
            ),
          'INVALID_COMMAND_MATCHER',
        );
      }
    });

    test('RC04-P-54: valid binary matchers are accepted for the correct effects', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'allow-npm',
            effect: 'REQUIRE_APPROVAL',
            commands: { allowedBinaries: ['npm', 'pnpm'] },
          },
          { id: 'deny-curl', effect: 'DENY', commands: { blockedBinaries: ['curl', 'wget'] } },
        ]),
      );
      assert.equal(evaluate(engine, 'run_command', { executableBasename: 'curl' }).effect, 'DENY');
      assert.equal(
        evaluate(engine, 'run_command', { executableBasename: 'pnpm' }).effect,
        'REQUIRE_APPROVAL',
      );
    });
  });

  // =========================================================================
  // 7. Workspace assertion binding
  // =========================================================================

  describe('Workspace assertion binding', () => {
    test('RC04-P-55: unknown asserted workspace ID fails with POLICY_LOAD_ERROR', () => {
      expectLoadError(
        () => engineFromYaml("version: '1.0'\nworkspaces:\n  - id: 'ghost'\nrules: []\n"),
        'UNKNOWN_WORKSPACE_ID',
      );
    });

    test('RC04-P-56: incorrect rootHash fails with POLICY_LOAD_ERROR', () => {
      const wrong = 'a'.repeat(64);
      expectLoadError(
        () =>
          engineFromYaml(
            `version: '1.0'\nworkspaces:\n  - id: 'primary'\n    rootHash: '${wrong}'\nrules: []\n`,
          ),
        'WORKSPACE_ROOT_HASH_MISMATCH',
      );
    });

    test('RC04-P-57: correct rootHash is accepted', () => {
      const engine = engineFromYaml(
        `version: '1.0'\nworkspaces:\n  - id: 'primary'\n    rootHash: '${workspaceRootHash}'\nrules: []\n`,
      );
      assert.equal(engine.getNormalizedPolicy().workspaces.length, 1);
      assert.equal(engine.getNormalizedPolicy().workspaces[0].rootHash, workspaceRootHash);
    });

    test('RC04-P-58: rootHash is computed over the canonical registered workspace root', () => {
      const canonical = registry.getWorkspace('primary').rootPath;
      const expected = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
      assert.equal(expected, workspaceRootHash);
    });

    test('RC04-P-59: workspace assertions never register or authorize a root', () => {
      const isolated = new WorkspaceRegistry();
      const isolatedRoot = path.join(tempDir, 'isolated');
      fs.mkdirSync(isolatedRoot, { recursive: true });
      isolated.registerWorkspace('only', isolatedRoot);

      expectLoadError(
        () =>
          DeclarativePolicyEngine.fromExternalText(
            isolated,
            "version: '1.0'\nworkspaces:\n  - id: 'primary'\nrules: []\n",
            'yaml',
          ),
        'UNKNOWN_WORKSPACE_ID',
      );
      assert.equal(isolated.getWorkspace('primary'), undefined);
    });
  });

  // =========================================================================
  // 8. Restricted glob matcher — direct tests
  // =========================================================================

  describe('Restricted glob matcher', () => {
    const validPatterns = [
      'src/**',
      'src/**/test.ts',
      '*.config.js',
      'src/?est.ts',
      'docs/!',
      '**',
    ];
    const invalidPatterns = [
      '/src/**',
      '../src/**',
      'src/../secret',
      'src\\a.txt',
      'src/a**b.ts',
      'src/**a.ts',
      'src/a**.ts',
      'src/***.ts',
      'src/[ab].ts',
      'src/{a,b}.ts',
      'src/@(a).ts',
      'src/!(a).ts',
      'src/+(a).ts',
      'src/?(a).ts',
      'src/a.txt',
    ];

    test('RC04-G-01: documented valid patterns are accepted', () => {
      for (const pattern of validPatterns) {
        assert.equal(validatePathPattern(pattern), null, `expected valid: ${pattern}`);
      }
    });

    test('RC04-G-02: documented invalid patterns are rejected', () => {
      // 'src/a.txt' appears in the valid list above only to keep ordering clear.
      for (const pattern of invalidPatterns.filter((p) => p !== 'src/a.txt')) {
        assert.notEqual(validatePathPattern(pattern), null, `expected invalid: ${pattern}`);
      }
    });

    test('RC04-G-03: pattern validators report specific reasons', () => {
      assert.equal(validatePathPattern('/src/**'), 'LEADING_SLASH');
      assert.equal(validatePathPattern('src/../secret'), 'TRAVERSAL_SEGMENT');
      assert.equal(validatePathPattern('src\\a.txt'), 'BACKSLASH_FORBIDDEN');
      assert.equal(validatePathPattern('src/a**b.ts'), 'EMBEDDED_DOUBLE_STAR');
      assert.equal(validatePathPattern('src/[ab].ts'), 'UNSUPPORTED_SYNTAX');
      assert.equal(validatePathPattern('src/{a,b}.ts'), 'UNSUPPORTED_SYNTAX');
      assert.equal(validatePathPattern('src/@(a).ts'), 'UNSUPPORTED_SYNTAX');
      assert.equal(validatePathPattern('src/!(a).ts'), 'UNSUPPORTED_SYNTAX');
      assert.equal(validatePathPattern(''), 'EMPTY_PATTERN');
      assert.equal(validatePathPattern(5), 'NOT_A_STRING');
      assert.equal(validatePathPattern('src//a.ts'), 'EMPTY_SEGMENT');
    });

    test('RC04-G-04: * never crosses a path separator', () => {
      assert.equal(matchPathGlob('*.ts', 'a.ts'), true);
      assert.equal(matchPathGlob('*.ts', 'a/b.ts'), false);
      assert.equal(matchPathGlob('src/*.ts', 'src/a.ts'), true);
      assert.equal(matchPathGlob('src/*.ts', 'src/nested/a.ts'), false);
      assert.equal(matchPathGlob('*', 'a/b'), false);
    });

    test('RC04-G-05: ? matches exactly one non-separator character', () => {
      assert.equal(matchPathGlob('?.ts', 'a.ts'), true);
      assert.equal(matchPathGlob('?.ts', 'ab.ts'), false);
      assert.equal(matchPathGlob('?.ts', '.ts'), false);
      assert.equal(matchPathGlob('?/b.ts', 'a/b.ts'), true);
      assert.equal(matchPathGlob('?', 'a/b'), false);
    });

    test('RC04-G-06: ** matches zero complete path segments', () => {
      assert.equal(matchPathGlob('src/**/test.ts', 'src/test.ts'), true);
      assert.equal(matchPathGlob('src/**', 'src'), true);
      assert.equal(matchPathGlob('**/test.ts', 'test.ts'), true);
    });

    test('RC04-G-07: ** matches one or more complete path segments', () => {
      assert.equal(matchPathGlob('src/**/test.ts', 'src/a/test.ts'), true);
      assert.equal(matchPathGlob('src/**/test.ts', 'src/a/b/test.ts'), true);
      assert.equal(matchPathGlob('src/**/test.ts', 'src/a/b/c/d/test.ts'), true);
      assert.equal(matchPathGlob('src/**', 'src/a/b/c.ts'), true);
    });

    test('RC04-G-08: ** never matches a partial segment', () => {
      assert.equal(matchPathGlob('src/**', 'src2/a.ts'), false);
      assert.equal(matchPathGlob('src/**/test.ts', 'src/atest.ts'), false);
      assert.equal(matchPathGlob('src/**/test.ts', 'src/a/test.tsx'), false);
    });

    test('RC04-G-09: ! is an ordinary literal character with no negation semantics', () => {
      assert.equal(validatePathPattern('docs/!'), null);
      assert.equal(validatePathPattern('!important.txt'), null);
      assert.equal(matchPathGlob('docs/!', 'docs/!'), true);
      assert.equal(matchPathGlob('docs/!', 'docs/secret.txt'), false);
      assert.equal(matchPathGlob('!a.txt', '!a.txt'), true);
      assert.equal(matchPathGlob('!a.txt', 'b.txt'), false);
    });

    test('RC04-G-10: matching is case-sensitive', () => {
      assert.equal(matchPathGlob('src/**', 'SRC/a.ts'), false);
      assert.equal(matchPathGlob('README.md', 'readme.md'), false);
    });

    test('RC04-G-11: unsafe target paths fail closed', () => {
      const unsafe = ['/etc/passwd', '../secret', 'src/../../etc', 'src\\a.ts', '', 'a/../b'];
      for (const target of unsafe) {
        assert.equal(normalizeTargetPath(target), null, `expected unsafe: ${target}`);
        assert.equal(matchPathGlob('**', target), false, `expected no match: ${target}`);
      }
    });

    test('RC04-G-12: hostile patterns do not cause runaway matching', () => {
      // Long, star-dense pattern against a long target: bounded DP, no backtracking.
      const pattern = `src/${'*a'.repeat(200)}*`;
      const target = `src/${'a'.repeat(1500)}`;
      const started = Date.now();
      const result = matchPathGlob(pattern, target);
      const elapsed = Date.now() - started;
      assert.equal(typeof result, 'boolean');
      assert.ok(elapsed < 5000, `matching took ${elapsed}ms`);
    });

    test('RC04-G-13: matcher performs no filesystem access', () => {
      // Pure string evaluation: a pattern referencing an existing file must not
      // consult the filesystem, and a nonexistent path must behave identically.
      assert.equal(matchPathGlob('workspace/secret.txt', 'workspace/secret.txt'), true);
      assert.equal(matchPathGlob('workspace/nope.txt', 'workspace/secret.txt'), false);
    });
  });

  // =========================================================================
  // 9. Rule evaluation, precedence, and order independence
  // =========================================================================

  describe('Rule evaluation and precedence', () => {
    test('RC04-E-01: tools matcher uses exact case-sensitive matching', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'DENY', tools: ['read_file'] }]),
      );
      assert.equal(evaluate(engine, 'read_file').effect, 'DENY');
      assert.equal(evaluate(engine, 'READ_FILE').effect, 'DENY'); // no match -> default deny
      assert.equal(evaluate(engine, 'read_file').matchingRuleId, 'r');
      assert.equal(evaluate(engine, 'system_status').matchingRuleId, DEFAULT_DENY_NO_RULE_MATCHED);
    });

    test('RC04-E-02: path matching is applied per target path', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'r', effect: 'DENY', tools: ['write_file'], paths: { patterns: ['src/**'] } },
        ]),
      );
      assert.equal(evaluate(engine, 'write_file', { path: 'src/a.ts' }).effect, 'DENY');
      assert.equal(evaluate(engine, 'write_file', { path: 'docs/a.ts' }).effect, 'DENY');
      assert.equal(
        evaluate(engine, 'write_file', { path: 'docs/a.ts' }).matchingRuleId,
        DEFAULT_DENY_NO_RULE_MATCHED,
      );
    });

    test('RC04-E-03: command basename matching', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'DENY', commands: { blockedBinaries: ['curl'] } }]),
      );
      assert.equal(evaluate(engine, 'run_command', { executableBasename: 'curl' }).effect, 'DENY');
      assert.equal(
        evaluate(engine, 'run_command', { executableBasename: 'wget' }).matchingRuleId,
        DEFAULT_DENY_NO_RULE_MATCHED,
      );
    });

    test('RC04-E-04: git branch and action matching', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'r',
            effect: 'DENY',
            git: { protectedBranches: ['main', 'release/**'], actions: ['push'] },
          },
        ]),
      );
      assert.equal(
        evaluate(engine, 'git_push', { gitBranch: 'main', gitAction: 'push' }).effect,
        'DENY',
      );
      assert.equal(
        evaluate(engine, 'git_push', { gitBranch: 'release/1.0', gitAction: 'push' }).effect,
        'DENY',
      );
      // branch matches but action does not -> AND fails
      assert.equal(
        evaluate(engine, 'git_push', { gitBranch: 'main', gitAction: 'pull' }).matchingRuleId,
        DEFAULT_DENY_NO_RULE_MATCHED,
      );
      // action matches but branch does not -> AND fails
      assert.equal(
        evaluate(engine, 'git_push', { gitBranch: 'feature/x', gitAction: 'push' }).matchingRuleId,
        DEFAULT_DENY_NO_RULE_MATCHED,
      );
    });

    test('RC04-E-05: matcher categories combine with AND', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'r',
            effect: 'DENY',
            tools: ['run_command'],
            commands: { blockedBinaries: ['curl'] },
          },
        ]),
      );
      // tool matches AND command matches
      assert.equal(evaluate(engine, 'run_command', { executableBasename: 'curl' }).effect, 'DENY');
      // tool matches but command does not
      assert.equal(
        evaluate(engine, 'run_command', { executableBasename: 'ls' }).matchingRuleId,
        DEFAULT_DENY_NO_RULE_MATCHED,
      );
      // command matches but tool does not
      assert.equal(
        evaluate(engine, 'read_file', { executableBasename: 'curl' }).matchingRuleId,
        DEFAULT_DENY_NO_RULE_MATCHED,
      );
    });

    test('RC04-E-06: entries within one matcher array combine with OR', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'DENY', tools: ['read_file', 'write_file'] }]),
      );
      assert.equal(evaluate(engine, 'read_file').effect, 'DENY');
      assert.equal(evaluate(engine, 'write_file').effect, 'DENY');
      assert.equal(evaluate(engine, 'git_status').matchingRuleId, DEFAULT_DENY_NO_RULE_MATCHED);
    });

    test('RC04-E-07: an absent runtime context means the rule does not match', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'p', effect: 'DENY', paths: { patterns: ['src/**'] } },
          { id: 'c', effect: 'DENY', commands: { blockedBinaries: ['curl'] } },
          { id: 'g', effect: 'DENY', git: { actions: ['push'] } },
        ]),
      );
      // No path, no basename, no git context supplied.
      const decision = evaluate(engine, 'read_file');
      assert.equal(decision.matchingRuleId, DEFAULT_DENY_NO_RULE_MATCHED);
    });

    test('RC04-E-08: no matching rule in an external policy is default deny', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }]),
      );
      const decision = evaluate(engine, 'git_status');
      assert.equal(decision.effect, 'DENY');
      assert.equal(decision.matchingRuleId, DEFAULT_DENY_NO_RULE_MATCHED);
    });

    test('RC04-E-09: DENY beats REQUIRE_APPROVAL beats ALLOW', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'a-allow', effect: 'ALLOW', tools: ['read_file'] },
          { id: 'b-approval', effect: 'REQUIRE_APPROVAL', tools: ['read_file'] },
          { id: 'c-deny', effect: 'DENY', tools: ['read_file'] },
        ]),
      );
      const decision = evaluate(engine, 'read_file');
      assert.equal(decision.effect, 'DENY');
      assert.equal(decision.matchingRuleId, 'c-deny');
    });

    test('RC04-E-10: REQUIRE_APPROVAL beats ALLOW when no DENY matches', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'a-allow', effect: 'ALLOW', tools: ['read_file'] },
          { id: 'b-approval', effect: 'REQUIRE_APPROVAL', tools: ['read_file'] },
        ]),
      );
      assert.equal(evaluate(engine, 'read_file').effect, 'REQUIRE_APPROVAL');
      assert.equal(evaluate(engine, 'read_file').matchingRuleId, 'b-approval');
    });

    test('RC04-E-11: the lexicographically smallest winning rule ID is selected', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'zzz-deny', effect: 'DENY', tools: ['read_file'] },
          { id: 'aaa-deny', effect: 'DENY', tools: ['read_file'] },
          { id: 'mmm-deny', effect: 'DENY', tools: ['read_file'] },
        ]),
      );
      assert.equal(evaluate(engine, 'read_file').matchingRuleId, 'aaa-deny');
    });

    test('RC04-E-12: physical rule ordering never changes the decision', () => {
      const baseRules = [
        { id: 'r-allow', effect: 'ALLOW', tools: ['read_file', 'write_file'] },
        { id: 'r-approval', effect: 'REQUIRE_APPROVAL', tools: ['write_file'] },
        { id: 'r-deny', effect: 'DENY', tools: ['read_file'] },
      ];

      const permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
      ];

      const decisions = permutations.map((order) => {
        const engine = engineFromYaml(yamlPolicy(order.map((i) => baseRules[i])));
        return {
          readFile: evaluate(engine, 'read_file'),
          writeFile: evaluate(engine, 'write_file'),
          hash: engine.getPolicyHash(),
        };
      });

      for (const decision of decisions) {
        assert.equal(decision.readFile.effect, 'DENY');
        assert.equal(decision.readFile.matchingRuleId, 'r-deny');
        assert.equal(decision.writeFile.effect, 'REQUIRE_APPROVAL');
        assert.equal(decision.writeFile.matchingRuleId, 'r-approval');
      }
      // Rule ordering is not semantics: every permutation hashes identically.
      assert.equal(new Set(decisions.map((d) => d.hash)).size, 1);
    });

    test('RC04-E-13: unsafe target inputs fail closed', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'DENY', paths: { patterns: ['**'] } }]),
      );
      for (const badPath of ['/etc/passwd', '../x', 'a\\b', 'a/../b']) {
        const decision = evaluate(engine, 'read_file', { path: badPath });
        assert.equal(decision.effect, 'DENY');
        assert.equal(decision.matchingRuleId, 'deny-invalid-target-path');
      }
      for (const badBasename of ['bin/curl', 'bin\\curl']) {
        const decision = evaluate(engine, 'run_command', { executableBasename: badBasename });
        assert.equal(decision.effect, 'DENY');
        assert.equal(decision.matchingRuleId, 'deny-invalid-executable-basename');
      }
    });

    test('RC04-E-14: policy matching never normalizes an unsafe host path into an authorized relative path', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'allow-src',
            effect: 'ALLOW',
            tools: ['read_file'],
            paths: { patterns: ['src/**'] },
          },
        ]),
      );
      for (const traversal of ['src/../../etc/passwd', '/src/a.ts', 'src\\a.ts', '../src/a.ts']) {
        const decision = evaluate(engine, 'read_file', { path: traversal });
        assert.equal(decision.effect, 'DENY', `expected deny for ${traversal}`);
      }
    });
  });

  // =========================================================================
  // 10. Mutation approval floor
  // =========================================================================

  describe('Mutation approval floor', () => {
    test('RC04-M-01: ALLOW on each mutation tool is clamped to REQUIRE_APPROVAL', () => {
      for (const tool of RC03_MUTATION_TOOLS) {
        const engine = engineFromYaml(
          yamlPolicy([{ id: 'allow-mutation', effect: 'ALLOW', tools: [tool] }]),
        );
        const decision = evaluate(engine, tool);
        assert.equal(decision.effect, 'REQUIRE_APPROVAL', `${tool} must be clamped`);
        assert.equal(decision.matchingRuleId, 'allow-mutation');
        assert.match(decision.reason, /mutation approval floor/i);
      }
    });

    test('RC04-M-02: the floor preserves the canonical winning ALLOW rule ID', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'zz-allow', effect: 'ALLOW', tools: ['write_file'] },
          { id: 'aa-allow', effect: 'ALLOW', tools: ['write_file'] },
        ]),
      );
      const decision = evaluate(engine, 'write_file');
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'aa-allow');
    });

    test('RC04-M-03: DENY on a mutation tool remains DENY', () => {
      for (const tool of RC03_MUTATION_TOOLS) {
        const engine = engineFromYaml(
          yamlPolicy([{ id: 'deny-mutation', effect: 'DENY', tools: [tool] }]),
        );
        assert.equal(evaluate(engine, tool).effect, 'DENY', `${tool} DENY must win`);
      }
    });

    test('RC04-M-04: explicit REQUIRE_APPROVAL on a mutation tool is unchanged', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'approve-mutation', effect: 'REQUIRE_APPROVAL', tools: ['apply_patch'] },
        ]),
      );
      const decision = evaluate(engine, 'apply_patch');
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'approve-mutation');
    });

    test('RC04-M-05: the floor does not elevate non-mutation tools', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'allow-read', effect: 'ALLOW', tools: ['read_file', 'run_command'] }]),
      );
      assert.equal(evaluate(engine, 'read_file').effect, 'ALLOW');
      assert.equal(evaluate(engine, 'run_command').effect, 'ALLOW');
    });

    test('RC04-M-06: a mutation tool with no matching rule is denied, not approved', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }]),
      );
      const decision = evaluate(engine, 'write_file');
      assert.equal(decision.effect, 'DENY');
      assert.equal(decision.matchingRuleId, DEFAULT_DENY_NO_RULE_MATCHED);
    });

    test('RC04-M-07: the floor cannot be bypassed by a wildcard-like path matcher', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'allow-all-paths',
            effect: 'ALLOW',
            tools: ['write_file'],
            paths: { patterns: ['**'] },
          },
        ]),
      );
      const decision = evaluate(engine, 'write_file', { path: 'src/deep/nested.ts' });
      assert.equal(decision.effect, 'REQUIRE_APPROVAL');
      assert.equal(decision.matchingRuleId, 'allow-all-paths');
    });

    test('RC04-M-08: a catch-all ALLOW rule with no matchers cannot authorize mutations', () => {
      // The most permissive possible declarative rule, still clamped.
      const engine = engineFromYaml(yamlPolicy([{ id: 'allow-everything', effect: 'ALLOW' }]));
      for (const tool of RC03_MUTATION_TOOLS) {
        const decision = evaluate(engine, tool);
        assert.equal(decision.effect, 'REQUIRE_APPROVAL', `${tool} was not clamped`);
        assert.equal(decision.matchingRuleId, 'allow-everything');
      }
      // Non-mutation tools are authorised by the same rule.
      assert.equal(evaluate(engine, 'read_file').effect, 'ALLOW');
    });
  });

  // =========================================================================
  // 11. Built-in compatibility policy
  // =========================================================================

  describe('Built-in compatibility policy', () => {
    test('RC04-B-01: built-in policy allows every RC-01 inspection tool', () => {
      const engine = DeclarativePolicyEngine.builtIn(registry);
      for (const tool of RC01_ALLOWED_TOOLS) {
        const decision = evaluate(engine, tool);
        assert.equal(decision.effect, 'ALLOW', `${tool} must be ALLOW at Layer 2`);
      }
    });

    test('RC04-B-02: built-in policy allows every RC-02 execution tool at Layer 2', () => {
      const engine = DeclarativePolicyEngine.builtIn(registry);
      const rc02Only = RC02_ALLOWED_TOOLS.filter((t) => !RC01_ALLOWED_TOOLS.includes(t));
      assert.ok(rc02Only.length > 0);
      for (const tool of rc02Only) {
        assert.equal(evaluate(engine, tool).effect, 'ALLOW', `${tool} must be ALLOW at Layer 2`);
      }
    });

    test('RC04-B-03: built-in policy requires approval for every RC-03 mutation tool', () => {
      const engine = DeclarativePolicyEngine.builtIn(registry);
      for (const tool of RC03_MUTATION_TOOLS) {
        const decision = evaluate(engine, tool);
        assert.equal(decision.effect, 'REQUIRE_APPROVAL', `${tool} must REQUIRE_APPROVAL`);
      }
    });

    test('RC04-B-04: built-in policy denies unknown tools', () => {
      const engine = DeclarativePolicyEngine.builtIn(registry);
      for (const tool of ['unregistered_tool', 'exec', 'Read_File', '', 'delete_everything']) {
        const decision = engine.evaluate({ toolName: tool });
        assert.equal(decision.effect, 'DENY', `${tool} must be DENY`);
        assert.equal(decision.matchingRuleId, DEFAULT_DENY_UNREGISTERED_TOOL);
      }
    });

    test('RC04-B-05: built-in policy covers every registered tool', () => {
      const engine = DeclarativePolicyEngine.builtIn(registry);
      for (const tool of RC03_REGISTERED_TOOLS) {
        const decision = evaluate(engine, tool);
        assert.notEqual(
          decision.matchingRuleId,
          DEFAULT_DENY_UNREGISTERED_TOOL,
          `${tool} must be covered by the built-in policy`,
        );
        assert.notEqual(decision.matchingRuleId, DEFAULT_DENY_NO_RULE_MATCHED);
      }
    });

    test('RC04-B-06: built-in policyHash is reproducible across constructions', () => {
      const first = DeclarativePolicyEngine.builtIn(registry).getPolicyHash();
      const second = DeclarativePolicyEngine.builtIn(registry).getPolicyHash();
      assert.equal(first, second);
      assert.match(first, /^[0-9a-f]{64}$/);
    });

    test('RC04-B-07: built-in policy uses the same normalization pipeline as external policies', () => {
      // The semantic content of the built-in policy, expressed as operator
      // policy text, must produce the identical policyHash.
      const equivalent = engineFromYaml(
        yamlPolicy([
          { id: 'builtin-allow-rc01-inspection', effect: 'ALLOW', tools: [...RC01_ALLOWED_TOOLS] },
          {
            id: 'builtin-allow-rc02-controlled-execution',
            effect: 'ALLOW',
            tools: RC02_ALLOWED_TOOLS.filter((t) => !RC01_ALLOWED_TOOLS.includes(t)),
          },
          {
            id: 'builtin-require-approval-file-mutation',
            effect: 'REQUIRE_APPROVAL',
            tools: [...RC03_MUTATION_TOOLS],
          },
          {
            id: 'builtin-allow-rc07-read-only',
            effect: 'ALLOW',
            tools: ['arc_repo_status', 'arc_worktree_status'],
          },
        ]),
      );
      assert.equal(
        DeclarativePolicyEngine.builtIn(registry).getPolicyHash(),
        equivalent.getPolicyHash(),
      );
    });

    test('RC04-B-08: built-in Layer-2 ALLOW does not bypass Layer 1', () => {
      // This suite asserts Layer 2 semantics only. The built-in policy carries
      // no command, path, or workspace security: Layer 1 SecurityKernel remains
      // authoritative for RC-02 command safety and workspace admission.
      const engine = DeclarativePolicyEngine.builtIn(registry);
      assert.equal(evaluate(engine, 'run_command').effect, 'ALLOW');
      assert.equal(engine.getSourceMode(), 'BUILTIN');
    });
  });

  // =========================================================================
  // 12. Normalization and immutability
  // =========================================================================

  describe('Normalization and immutability', () => {
    test('RC04-N-01: metadata and descriptions are excluded from the normalized policy', () => {
      const engine = engineFromYaml(`
version: '1.0'
metadata:
  name: 'name'
  description: 'description'
  lastModified: '2026-09-18T12:00:00Z'
rules:
  - id: 'r'
    effect: 'ALLOW'
    description: 'rule description'
    tools: ['read_file']
`);
      const normalized = engine.getNormalizedPolicy();
      assert.deepEqual(Object.keys(normalized).sort(), ['rules', 'schemaVersion', 'workspaces']);
      assert.equal(normalized.rules[0].description, undefined);
      assert.ok(!JSON.stringify(normalized).includes('rule description'));
      assert.ok(!JSON.stringify(normalized).includes('lastModified'));
    });

    test('RC04-N-02: rules and workspaces are sorted by id', () => {
      const engine = engineFromYaml(`
version: '1.0'
workspaces:
  - id: 'secondary'
  - id: 'primary'
rules:
  - id: 'zeta'
    effect: 'ALLOW'
    tools: ['read_file']
  - id: 'alpha'
    effect: 'ALLOW'
    tools: ['read_file']
  - id: 'middle'
    effect: 'ALLOW'
    tools: ['read_file']
`);
      const normalized = engine.getNormalizedPolicy();
      assert.deepEqual(
        normalized.rules.map((r) => r.id),
        ['alpha', 'middle', 'zeta'],
      );
      assert.deepEqual(
        normalized.workspaces.map((w) => w.id),
        ['primary', 'secondary'],
      );
    });

    test('RC04-N-03: matcher arrays are sorted and deduplicated', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'r',
            effect: 'DENY',
            tools: ['write_file', 'read_file', 'write_file', 'apply_patch'],
          },
        ]),
      );
      const normalized = engine.getNormalizedPolicy();
      assert.deepEqual(normalized.rules[0].tools, ['apply_patch', 'read_file', 'write_file']);
    });

    test('RC04-N-04: omitted and empty matcher arrays normalize identically', () => {
      // A rule with no matcher categories at all...
      const omitted = engineFromYaml(yamlPolicy([{ id: 'r', effect: 'ALLOW' }]));
      // ...must be identical to the same rule with every matcher written out empty.
      const empty = engineFromYaml(
        yamlPolicy([
          {
            id: 'r',
            effect: 'ALLOW',
            tools: [],
            paths: { patterns: [] },
            commands: {},
            git: {},
          },
        ]),
      );
      assert.equal(omitted.getPolicyHash(), empty.getPolicyHash());
      assert.deepEqual(empty.getNormalizedPolicy().rules[0], { id: 'r', effect: 'ALLOW' });

      // An explicitly empty matcher must not silently behave like a populated one.
      const populated = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }]),
      );
      assert.notEqual(populated.getPolicyHash(), omitted.getPolicyHash());
    });

    test('RC04-N-05: empty matcher structures disappear consistently', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          {
            id: 'r',
            effect: 'DENY',
            commands: { blockedBinaries: [] },
            git: { protectedBranches: [], actions: [] },
          },
        ]),
      );
      const rule = engine.getNormalizedPolicy().rules[0];
      assert.equal(rule.commands, undefined);
      assert.equal(rule.git, undefined);
      assert.deepEqual(Object.keys(rule).sort(), ['effect', 'id']);
    });

    test('RC04-N-06: mutating a returned normalized policy cannot affect engine state', () => {
      const engine = engineFromYaml(
        yamlPolicy([
          { id: 'r-one', effect: 'ALLOW', tools: ['read_file', 'git_status'] },
          { id: 'r-two', effect: 'DENY', tools: ['write_file'] },
        ]),
      );
      const hashBefore = engine.getPolicyHash();
      const decisionBefore = JSON.stringify(evaluate(engine, 'read_file'));

      const borrowed = engine.getNormalizedPolicy();
      borrowed.rules[0].id = 'HACKED';
      borrowed.rules[0].tools.push('delete_file');
      borrowed.rules.push({ id: 'injected', effect: 'ALLOW', tools: ['write_file'] });
      borrowed.workspaces.push({ id: 'injected-workspace' });
      borrowed.schemaVersion = '9.9';

      const fresh = engine.getNormalizedPolicy();
      assert.equal(fresh.rules[0].id, 'r-one');
      assert.deepEqual(fresh.rules[0].tools, ['git_status', 'read_file']);
      assert.equal(fresh.rules.length, 2);
      assert.deepEqual(fresh.workspaces, []);
      assert.equal(fresh.schemaVersion, '1.0');
      assert.equal(engine.getPolicyHash(), hashBefore);
      assert.equal(JSON.stringify(evaluate(engine, 'read_file')), decisionBefore);
    });

    test('RC04-N-07: engine-internal normalized policy is deeply frozen', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }]),
      );
      const first = engine.getNormalizedPolicy();
      // The returned value is a fresh clone, not the frozen internal object.
      assert.notEqual(Object.isFrozen(first), true);
      first.rules[0].id = 'mutated';
      assert.equal(engine.getNormalizedPolicy().rules[0].id, 'r');
    });

    test('RC04-N-08: evaluation decisions do not expose mutable engine state', () => {
      const engine = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }]),
      );
      const decision = evaluate(engine, 'read_file');
      decision.matchingRuleId = 'HACKED';
      decision.effect = 'DENY';
      assert.equal(evaluate(engine, 'read_file').matchingRuleId, 'r');
      assert.equal(evaluate(engine, 'read_file').effect, 'ALLOW');
    });
  });

  // =========================================================================
  // 13. Canonical JSON and policyHash
  // =========================================================================

  describe('Canonical JSON and policyHash', () => {
    test('RC04-H-01: canonical JSON sorts object keys recursively', () => {
      assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
      assert.equal(canonicalJson({ z: { y: 1, x: 2 } }), '{"z":{"x":2,"y":1}}');
      assert.equal(canonicalJson([3, 1, 2]), '[3,1,2]');
      assert.equal(canonicalJson('x'), '"x"');
      assert.equal(canonicalJson(null), 'null');
      assert.equal(canonicalJson(true), 'true');
    });

    test('RC04-H-02: canonical JSON is independent of insertion order', () => {
      const a = { one: 1, two: { x: 'x', y: 'y' }, three: [1, 2] };
      const b = { three: [1, 2], two: { y: 'y', x: 'x' }, one: 1 };
      assert.equal(canonicalJson(a), canonicalJson(b));
    });

    test('RC04-H-03: policyHash is SHA-256 over canonical JSON of the normalized policy', () => {
      const normalized = {
        schemaVersion: '1.0',
        workspaces: [],
        rules: [{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }],
      };
      const expected = crypto
        .createHash('sha256')
        .update(canonicalJson(normalized), 'utf8')
        .digest('hex');
      assert.equal(computePolicyHash(normalized), expected);
    });

    test('RC04-H-04: semantics-identical policies hash identically across formatting differences', () => {
      const canonical = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'DENY', tools: ['read_file', 'git_status'] }]),
      ).getPolicyHash();

      const variants = [
        // whitespace / indentation differences
        "version: '1.0'\nrules:\n  - id: 'r'\n    effect: 'DENY'\n    tools: [ 'read_file', 'git_status' ]\n",
        "version: '1.0'\nrules:\n- id: 'r'\n  effect: 'DENY'\n  tools:\n  - read_file\n  - git_status\n",
        // comments
        "version: '1.0'\n# a comment\nrules:\n  - id: 'r' # inline\n    effect: 'DENY'\n    tools: ['read_file', 'git_status']\n",
        // matcher array reordering and duplicates
        "version: '1.0'\nrules:\n  - id: 'r'\n    effect: 'DENY'\n    tools: ['git_status', 'read_file', 'read_file']\n",
        // JSON form of the same policy
        jsonPolicy([{ id: 'r', effect: 'DENY', tools: ['read_file', 'git_status'] }]),
      ];

      for (const variant of variants) {
        const format = variant.startsWith('{') ? 'json' : 'yaml';
        const engine = DeclarativePolicyEngine.fromExternalText(registry, variant, format);
        assert.equal(engine.getPolicyHash(), canonical);
      }
    });

    test('RC04-H-05: metadata changes never affect policyHash', () => {
      const base = engineFromYaml(
        "version: '1.0'\nmetadata:\n  name: 'a'\nrules:\n  - id: 'r'\n    effect: 'ALLOW'\n    tools: ['read_file']\n",
      ).getPolicyHash();

      const variants = [
        "version: '1.0'\nmetadata:\n  name: 'b'\n  description: 'new'\nrules:\n  - id: 'r'\n    effect: 'ALLOW'\n    tools: ['read_file']\n",
        "version: '1.0'\nmetadata:\n  lastModified: '2030-01-01T00:00:00Z'\nrules:\n  - id: 'r'\n    effect: 'ALLOW'\n    tools: ['read_file']\n",
      ];
      for (const variant of variants) {
        assert.equal(engineFromYaml(variant).getPolicyHash(), base);
      }
    });

    test('RC04-H-06: rule description changes never affect policyHash', () => {
      const base = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }]),
      ).getPolicyHash();
      const described = engineFromYaml(
        yamlPolicy([
          {
            id: 'r',
            effect: 'ALLOW',
            description: 'a completely different rationale',
            tools: ['read_file'],
          },
        ]),
      ).getPolicyHash();
      assert.equal(described, base);
    });

    test('RC04-H-07: workspace assertion reordering never affects policyHash', () => {
      const primaryFirst = engineFromYaml(
        `version: '1.0'\nworkspaces:\n  - id: 'primary'\n  - id: 'secondary'\nrules: []\n`,
      ).getPolicyHash();
      const secondaryFirst = engineFromYaml(
        `version: '1.0'\nworkspaces:\n  - id: 'secondary'\n  - id: 'primary'\nrules: []\n`,
      ).getPolicyHash();
      assert.equal(primaryFirst, secondaryFirst);

      // A rootHash assertion is semantic, so it must change the digest.
      const withHash = engineFromYaml(
        `version: '1.0'\nworkspaces:\n  - id: 'primary'\n    rootHash: '${workspaceRootHash}'\n  - id: 'secondary'\nrules: []\n`,
      ).getPolicyHash();
      assert.notEqual(withHash, primaryFirst);
    });

    test('RC04-H-08: semantic changes alter policyHash', () => {
      const base = engineFromYaml(
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['read_file'] }]),
      ).getPolicyHash();

      const changed = [
        yamlPolicy([{ id: 'r', effect: 'DENY', tools: ['read_file'] }]),
        yamlPolicy([{ id: 'r2', effect: 'ALLOW', tools: ['read_file'] }]),
        yamlPolicy([{ id: 'r', effect: 'ALLOW', tools: ['git_status'] }]),
        yamlPolicy([
          { id: 'r', effect: 'ALLOW', tools: ['read_file'], paths: { patterns: ['src/**'] } },
        ]),
        yamlPolicy([{ id: 'r', effect: 'DENY', commands: { blockedBinaries: ['curl'] } }]),
        yamlPolicy([{ id: 'r', effect: 'DENY', git: { actions: ['push'] } }]),
        yamlPolicy([
          { id: 'r', effect: 'ALLOW', tools: ['read_file'] },
          { id: 's', effect: 'DENY', tools: ['read_file'] },
        ]),
      ];
      for (const variant of changed) {
        assert.notEqual(engineFromYaml(variant).getPolicyHash(), base);
      }
    });

    test('RC04-H-09: workspace assertion changes alter policyHash', () => {
      const none = engineFromYaml("version: '1.0'\nrules: []\n").getPolicyHash();
      const asserted = engineFromYaml(
        `version: '1.0'\nworkspaces:\n  - id: 'primary'\n    rootHash: '${workspaceRootHash}'\nrules: []\n`,
      ).getPolicyHash();
      assert.notEqual(none, asserted);
    });

    test('RC04-H-10: string comparison is code-unit based and locale independent', () => {
      assert.ok(compareStrings('a', 'b') < 0);
      assert.ok(compareStrings('b', 'a') > 0);
      assert.equal(compareStrings('a', 'a'), 0);
      // Uppercase sorts before lowercase by code unit (unlike localeCompare).
      assert.ok(compareStrings('A', 'a') < 0);
    });
  });

  // =========================================================================
  // 14. Fail-closed behavior and error redaction
  // =========================================================================

  describe('Fail-closed behavior and error redaction', () => {
    const PRIVATE_MARKER = 'RC04_POLICY_PRIVATE_MARKER_7291';

    test('RC04-F-01: an invalid external policy never falls back to the built-in policy', () => {
      const malformedPolicies = [
        "version: '1.0'\nrules: [\n",
        "version: '2.0'\nrules: []\n",
        `version: '1.0'\nrules: []\n# ${PRIVATE_MARKER}\n<<: {}\n`,
        "version: '1.0'\nrules: []\nunknown: 1\n",
      ];
      for (const source of malformedPolicies) {
        assert.throws(
          () => engineFromYaml(source),
          (err) => {
            assert.ok(err instanceof ArcError);
            assert.equal(err.code, 'POLICY_PARSE_ERROR');
            return true;
          },
        );
      }

      // Exhaustive proof: no failure path can return an engine at all.
      const builtInHash = DeclarativePolicyEngine.builtIn(registry).getPolicyHash();
      let produced;
      try {
        produced = engineFromYaml("version: '1.0'\nrules: [\n");
      } catch {
        produced = undefined;
      }
      assert.equal(produced, undefined);
      assert.notEqual(produced === undefined ? undefined : produced.getPolicyHash(), builtInHash);
    });

    test('RC04-F-02: parse errors never leak raw policy source', () => {
      const sources = [
        `version: '2.0'\nmarker: ${PRIVATE_MARKER}\nrules: []\n`,
        `version: '1.0'\nmarker: ${PRIVATE_MARKER}\nrules: []\n`,
        `version: '1.0'\nrules:\n  - id: '${PRIVATE_MARKER}'\n    effect: 'BAD'\n`,
        `version: '1.0'\nrules: [\nmarker: ${PRIVATE_MARKER}\n`,
      ];
      for (const source of sources) {
        const err = expectParseError(() => engineFromYaml(source));
        assert.ok(!JSON.stringify(err).includes(PRIVATE_MARKER), 'marker leaked');
        assert.ok(!String(err.message).includes(PRIVATE_MARKER));
        assert.ok(!JSON.stringify(err.details ?? {}).includes(PRIVATE_MARKER));
      }
    });

    test('RC04-F-03: load errors never leak the canonical workspace root path', () => {
      const canonicalRoot = registry.getWorkspace('primary').rootPath;
      const sources = [
        `version: '1.0'\nworkspaces:\n  - id: 'ghost-${PRIVATE_MARKER}'\nrules: []\n`,
        `version: '1.0'\nworkspaces:\n  - id: 'primary'\n    rootHash: '${'b'.repeat(64)}'\nrules: []\n`,
      ];
      for (const source of sources) {
        const err = expectLoadError(() => engineFromYaml(source));
        const serialized = JSON.stringify(err);
        assert.ok(!serialized.includes(canonicalRoot), 'workspace root path leaked');
        assert.ok(!serialized.includes(PRIVATE_MARKER), 'marker leaked');
        assert.ok(!serialized.includes(tempDir), 'temp directory leaked');
      }
    });

    test('RC04-F-04: errors expose no third-party parser text or stack traces', () => {
      const sources = [
        // malformed YAML (unterminated flow sequence)
        "version: '1.0'\nrules: [\n",
        // wrong node type for rules
        "version: '1.0'\nrules: {a: 1}\n",
        // invalid effect value
        "version: '1.0'\nrules:\n  - id: 'r'\n    effect: 'NOPE'\n",
        // unknown tool name
        "version: '1.0'\nrules:\n  - id: 'r'\n    effect: 'ALLOW'\n    tools: ['ghost']\n",
        // unknown workspace binding
        "version: '1.0'\nworkspaces:\n  - id: 'ghost'\nrules: []\n",
      ];
      for (const source of sources) {
        let err;
        try {
          engineFromYaml(source);
        } catch (caught) {
          err = caught;
        }
        assert.ok(err instanceof ArcError);
        const serialized = JSON.stringify(err);
        for (const forbidden of [
          'at Object',
          'node_modules',
          '/home/',
          'yaml:',
          'Stack',
          'stack',
        ]) {
          assert.ok(!serialized.includes(forbidden), `leaked ${forbidden} in ${serialized}`);
        }
        assert.equal(err.details?.stack, undefined);
        assert.equal(err.details?.source, undefined);
      }
    });

    test('RC04-F-05: error details contain only coarse reason codes', () => {
      const err = expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\nunknownField: 'secret-value'\n"),
        'UNKNOWN_PROPERTY',
      );
      assert.deepEqual(Object.keys(err.details).sort(), ['reason']);
      assert.ok(!err.details.reason.includes('secret-value'));
    });

    test('RC04-F-06: the engine does not retain or expose raw policy source', () => {
      const engine = engineFromYaml(
        `version: '1.0'\nmetadata:\n  name: '${PRIVATE_MARKER}'\nrules: []\n`,
      );
      const surface = JSON.stringify({
        hash: engine.getPolicyHash(),
        mode: engine.getSourceMode(),
        normalized: engine.getNormalizedPolicy(),
      });
      assert.ok(
        !surface.includes(PRIVATE_MARKER),
        'raw metadata leaked through the engine surface',
      );
      assert.equal(engine.rawSource, undefined);
      assert.equal(engine.getRawSource, undefined);
    });

    test('RC04-F-07: invalid construction arguments fail closed', () => {
      assert.throws(
        () => DeclarativePolicyEngine.fromExternalText(registry, null, 'yaml'),
        (err) => err instanceof ArcError && err.code === 'POLICY_PARSE_ERROR',
      );
      assert.throws(
        () =>
          DeclarativePolicyEngine.fromExternalText(registry, "version: '1.0'\nrules: []\n", 'toml'),
        (err) => err instanceof ArcError && err.code === 'POLICY_PARSE_ERROR',
      );
    });

    test('RC04-F-08: policy contains no environment interpolation, includes, or remote loading', () => {
      // `${...}`, `$VAR`, `!include`, and URLs are inert literal text or rejected
      // custom tags — never resolved.
      expectParseError(
        () => engineFromYaml("version: '1.0'\nrules: []\ninclude: !include './other.yml'\n"),
        'FORBIDDEN_YAML_TAG',
      );
      const engine = engineFromYaml(
        "version: '1.0'\nmetadata:\n  name: '${HOME}'\n  description: 'https://example.com/policy.yml'\nrules: []\n",
      );
      assert.equal(engine.getSourceMode(), 'EXTERNAL');
    });
  });
});
