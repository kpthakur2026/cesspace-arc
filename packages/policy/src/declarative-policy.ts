/**
 * RC-04 Declarative Policy Engine (Task 2)
 *
 * Implements the frozen RC-04 declarative policy contract
 * (docs/architecture/rc04-scope-acceptance.md §7 - §12, §18.1).
 *
 * This module is deliberately standalone: it is NOT wired into SecurityKernel
 * and performs no MCP, filesystem, process, or approval-state work. Task 4 is
 * responsible for composing Layer 1 (SecurityKernel) + Layer 2 (this engine) +
 * ApprovalStateManager.
 */

import { createHash } from 'node:crypto';
import { parseAllDocuments, isMap, isSeq, isScalar, isAlias, isPair } from 'yaml';

import {
  ArcError,
  PolicyOutcome,
  type NormalizedPolicy,
  type PolicyDecisionResult,
  type PolicyEffect,
} from '@cesspace-arc/protocol';

import {
  RC01_ALLOWED_TOOLS,
  RC03_MUTATION_TOOLS,
  ALL_POLICY_TOOLS,
  RC07_READ_ONLY_TOOLS,
  RC07_TASK4_EXECUTION_TOOLS,
} from './index.js';
import {
  MAX_PATTERN_LENGTH,
  compilePathPattern,
  matchCompiledPattern,
  normalizeTargetPath,
  validatePathPattern,
} from './restricted-glob.js';

// ---------------------------------------------------------------------------
// Resource bounds (rc04 §8.2)
// ---------------------------------------------------------------------------

/** Maximum declarative policy document size in UTF-8 bytes (256 KiB). */
export const MAX_POLICY_BYTES = 262_144;
/** Maximum parsed object/array nesting depth for both YAML and JSON. */
export const MAX_POLICY_DEPTH = 32;
/** Maximum number of rules in a declarative policy document. */
export const MAX_POLICY_RULES = 256;
/** Maximum number of source items in any single matcher array. */
export const MAX_MATCHER_ITEMS = 128;
/** Maximum length of a rule description. */
export const MAX_RULE_DESCRIPTION_LENGTH = 256;

/** Explicit source format. The policy format is never guessed heuristically. */
export type PolicySourceFormat = 'json' | 'yaml';

/** Whether an engine instance carries the built-in or an operator policy. */
export type PolicySourceMode = 'BUILTIN' | 'EXTERNAL';

/** Canonical default-deny rule identifier for external policies (rc04 §11.1). */
export const DEFAULT_DENY_NO_RULE_MATCHED = 'default-deny-no-rule-matched';
/** Canonical default-deny rule identifier for the built-in policy (rc04 §11.2). */
export const DEFAULT_DENY_UNREGISTERED_TOOL = 'default-deny-unregistered-tool';

/**
 * Coarse machine-readable failure categories.
 *
 * These describe only the shape of the operator's own document. They are never
 * derived from third-party parser exception text and never contain raw policy
 * source, absolute host paths, or stack traces.
 */
export type PolicyParseReason =
  | 'DOCUMENT_SIZE_LIMIT_EXCEEDED'
  | 'DEPTH_LIMIT_EXCEEDED'
  | 'MALFORMED_DOCUMENT'
  | 'MULTIPLE_DOCUMENTS'
  | 'DUPLICATE_MAPPING_KEY'
  | 'FORBIDDEN_YAML_ANCHOR'
  | 'FORBIDDEN_YAML_ALIAS'
  | 'FORBIDDEN_YAML_MERGE_KEY'
  | 'FORBIDDEN_YAML_TAG'
  | 'FORBIDDEN_MAPPING_KEY'
  | 'INVALID_SCALAR_VALUE'
  | 'UNKNOWN_PROPERTY'
  | 'INVALID_VERSION'
  | 'INVALID_RULES'
  | 'TOO_MANY_RULES'
  | 'DUPLICATE_RULE_ID'
  | 'INVALID_RULE_ID'
  | 'INVALID_EFFECT'
  | 'INVALID_DESCRIPTION'
  | 'INVALID_MATCHER'
  | 'TOO_MANY_MATCHER_ITEMS'
  | 'UNKNOWN_TOOL_NAME'
  | 'INVALID_PATH_PATTERN'
  | 'INVALID_COMMAND_MATCHER'
  | 'INVALID_WORKSPACE_ASSERTION'
  | 'DUPLICATE_WORKSPACE_ID';

export type PolicyLoadReason = 'UNKNOWN_WORKSPACE_ID' | 'WORKSPACE_ROOT_HASH_MISMATCH';

// ---------------------------------------------------------------------------
// Tool classification
//
// NOTE: RC01_ALLOWED_TOOLS / RC03_MUTATION_TOOLS / RC03_REGISTERED_TOOLS are
// defined in ./index.js, which re-exports this module. Reading those bindings at
// module evaluation time would hit the temporal dead zone, so every access goes
// through a lazily memoized accessor invoked at call time, after both modules
// have finished evaluating.
// ---------------------------------------------------------------------------

let cachedRegisteredTools: ReadonlySet<string> | null = null;
let cachedMutationTools: ReadonlySet<string> | null = null;

function registeredToolSet(): ReadonlySet<string> {
  if (cachedRegisteredTools === null) {
    cachedRegisteredTools = new Set<string>(ALL_POLICY_TOOLS);
  }
  return cachedRegisteredTools;
}

function mutationToolSet(): ReadonlySet<string> {
  if (cachedMutationTools === null) {
    cachedMutationTools = new Set<string>(RC03_MUTATION_TOOLS);
  }
  return cachedMutationTools;
}

// ---------------------------------------------------------------------------
// Canonical serialization & hashing (rc04 §18.1)
// ---------------------------------------------------------------------------

/**
 * Deterministic canonical JSON serializer.
 *
 * Object keys are sorted lexicographically by JavaScript code unit at every
 * level. Array order is preserved exactly as supplied (arrays are already in
 * post-normalization semantic order). No locale-dependent comparison is used.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  const type = typeof value;
  if (type === 'string') {
    return JSON.stringify(value);
  }
  if (type === 'number') {
    if (!Number.isFinite(value as number)) {
      throw new Error('canonicalJson: non-finite number');
    }
    return JSON.stringify(value);
  }
  if (type === 'boolean') {
    return value === true ? 'true' : 'false';
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalJson(item));
    return `[${items.join(',')}]`;
  }
  if (type === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort(compareStrings);
    const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`);
    return `{${parts.join(',')}}`;
  }
  throw new Error('canonicalJson: unsupported value type');
}

/**
 * Deterministic lexicographic comparison by code unit.
 * Intentionally NOT localeCompare, which is locale-dependent (rc04 §18.1.3).
 */
export function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/** SHA-256 digest of a UTF-8 string, as 64 lowercase hexadecimal characters. */
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Canonical policy hash: SHA-256 over canonicalJson(normalizedPolicy).
 * Unkeyed — no HMAC, no secret.
 */
export function computePolicyHash(normalizedPolicy: NormalizedPolicy): string {
  return sha256Hex(canonicalJson(normalizedPolicy));
}

// ---------------------------------------------------------------------------
// Internal document shapes
// ---------------------------------------------------------------------------

/** Plain JSON-compatible value produced by the hardened parsers. */
type PolicyJsonValue =
  null | boolean | number | string | PolicyJsonValue[] | { [key: string]: PolicyJsonValue };

interface ParsedRule {
  id: string;
  effect: PolicyEffect;
  description?: string;
  tools?: string[];
  paths?: { patterns: string[] };
  commands?: { allowedBinaries?: string[]; blockedBinaries?: string[] };
  git?: { protectedBranches?: string[]; actions?: string[] };
}

interface ParsedWorkspaceAssertion {
  id: string;
  rootHash?: string;
}

interface ParsedDocument {
  version: '1.0';
  metadata?: { name?: string; description?: string; lastModified?: string };
  workspaces: ParsedWorkspaceAssertion[];
  rules: ParsedRule[];
}

interface CompiledRule {
  id: string;
  effect: PolicyEffect;
  tools: ReadonlySet<string> | null;
  pathPatterns: readonly string[][] | null;
  commandBinaries: ReadonlySet<string> | null;
  gitBranchPatterns: readonly string[][] | null;
  gitActions: ReadonlySet<string> | null;
}

/**
 * Structural view of the authorized workspace registry.
 *
 * A structural type (rather than a direct import of WorkspaceRegistry) keeps
 * this module free of a runtime import cycle back into ./index.js, and keeps
 * Layer 2 dependent only on the lookup capability it actually needs.
 */
export interface WorkspaceRegistryLookup {
  getWorkspace(id: string): { id: string; rootPath: string; isGitRepo: boolean } | undefined;
}

// ---------------------------------------------------------------------------
// Error construction
//
// Every message is a fixed, generic string. Reason codes are coarse categories
// describing the operator's own document shape.
// ---------------------------------------------------------------------------

function parseError(reason: PolicyParseReason): ArcError {
  return ArcError.policyParseError(
    'Declarative policy document could not be parsed: invalid structure.',
    { reason },
  );
}

function loadError(reason: PolicyLoadReason): ArcError {
  return ArcError.policyLoadError(
    'Declarative policy could not be loaded into the policy engine.',
    { reason },
  );
}

// ---------------------------------------------------------------------------
// Hardened YAML/JSON parsing (rc04 §8, §10, §11, §12)
// ---------------------------------------------------------------------------

/**
 * Tags resolvable from the YAML 1.2 core schema.
 *
 * With `schema: 'core'` the composer does not assign a tag to implicitly
 * resolved scalars, so any tag actually present on a node was written
 * explicitly by the author. Allowing only this closed set therefore rejects
 * `!!timestamp`, `!!binary`, `!!set`, `!!merge`, and every custom/local tag
 * (`!run`, `!include`, `!env`, ...) while accepting plain `!!str`/`!!int`/etc.
 */
const ALLOWED_EXPLICIT_TAGS = new Set<string>([
  'tag:yaml.org,2002:str',
  'tag:yaml.org,2002:int',
  'tag:yaml.org,2002:float',
  'tag:yaml.org,2002:bool',
  'tag:yaml.org,2002:null',
  'tag:yaml.org,2002:map',
  'tag:yaml.org,2002:seq',
]);

/**
 * Mapping keys that must never be constructed, independent of schema closure.
 *
 * `<<` is the YAML merge key: with `merge: false` it survives as an ordinary
 * key and is rejected here. The prototype names would otherwise be able to
 * reach into an object prototype during conversion.
 */
const FORBIDDEN_MAPPING_KEYS = new Set<string>(['<<', '__proto__', 'constructor', 'prototype']);

/** Parser options: core schema, unique keys, no merge, no alias expansion. */
const YAML_PARSE_OPTIONS = {
  schema: 'core' as const,
  uniqueKeys: true,
  merge: false,
  maxAliasCount: 0,
};

/**
 * Checks node-level structures that are forbidden by rc04 §8.1.
 *
 * Accepts any value so it can be applied at EVERY AST position that can carry
 * node properties — mapping keys included, not only values, sequence items, and
 * collection nodes. Operates on parser AST nodes only, never on raw source
 * text, so quoted scalar text and comments can never be mistaken for
 * anchor/alias syntax.
 */
function assertNodePermitted(node: unknown): void {
  if (node === null || typeof node !== 'object') {
    return;
  }
  const candidate = node as { anchor?: unknown; tag?: unknown };
  if (typeof candidate.anchor === 'string' && candidate.anchor.length > 0) {
    throw parseError('FORBIDDEN_YAML_ANCHOR');
  }
  if (typeof candidate.tag === 'string' && candidate.tag.length > 0) {
    if (!ALLOWED_EXPLICIT_TAGS.has(candidate.tag)) {
      throw parseError('FORBIDDEN_YAML_TAG');
    }
  }
}

/**
 * Converts a YAML AST node into a plain JSON-compatible value.
 *
 * Never calls toJS(): walking the AST directly means aliases are never expanded
 * and recursive structures are structurally impossible to construct.
 *
 * The recursion is self-bounding: the depth check runs before any descent, so
 * the stack cannot exceed MAX_POLICY_DEPTH + 1 frames even for hostile input.
 */
function astToJsonValue(node: unknown, depth: number): PolicyJsonValue {
  if (depth > MAX_POLICY_DEPTH) {
    throw parseError('DEPTH_LIMIT_EXCEEDED');
  }

  if (isAlias(node)) {
    throw parseError('FORBIDDEN_YAML_ALIAS');
  }

  if (isScalar(node)) {
    assertNodePermitted(node);
    const value = node.value;
    if (value === null || typeof value === 'string' || typeof value === 'boolean') {
      return value;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw parseError('INVALID_SCALAR_VALUE');
      }
      return value;
    }
    // Date, Buffer, BigInt, Map, Set, undefined, ...
    throw parseError('INVALID_SCALAR_VALUE');
  }

  if (isSeq(node)) {
    assertNodePermitted(node);
    const items: PolicyJsonValue[] = [];
    for (const item of node.items) {
      items.push(astToJsonValue(item, depth + 1));
    }
    return items;
  }

  if (isMap(node)) {
    assertNodePermitted(node);
    const result: { [key: string]: PolicyJsonValue } = {};
    for (const item of node.items) {
      if (!isPair(item)) {
        throw parseError('MALFORMED_DOCUMENT');
      }

      // A mapping key is a YAML node in its own right and must receive exactly
      // the same fail-closed inspection as a mapping value. An anchor or a
      // forbidden tag attached to a key is rejected here, and is never accepted
      // merely because the key's resolved text happens to be an otherwise-valid
      // schema key such as `version`, `rules`, `id`, or `effect`.
      const keyNode = item.key;
      if (isAlias(keyNode)) {
        // Rejected without expanding the alias.
        throw parseError('FORBIDDEN_YAML_ALIAS');
      }
      assertNodePermitted(keyNode);
      if (!isScalar(keyNode) || typeof keyNode.value !== 'string') {
        throw parseError('MALFORMED_DOCUMENT');
      }
      const key = keyNode.value;
      if (FORBIDDEN_MAPPING_KEYS.has(key)) {
        throw parseError(key === '<<' ? 'FORBIDDEN_YAML_MERGE_KEY' : 'FORBIDDEN_MAPPING_KEY');
      }
      result[key] = astToJsonValue(item.value, depth + 1);
    }
    return result;
  }

  throw parseError('MALFORMED_DOCUMENT');
}

/**
 * Bounded depth assertion for an already-materialized JSON value.
 * Throws before descending past the bound, so the stack stays bounded.
 */
function assertJsonDepth(value: PolicyJsonValue, depth: number): void {
  if (depth > MAX_POLICY_DEPTH) {
    throw parseError('DEPTH_LIMIT_EXCEEDED');
  }
  if (value === null || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      assertJsonDepth(item, depth + 1);
    }
    return;
  }
  const record = value as { [key: string]: PolicyJsonValue };
  for (const key of Object.keys(record)) {
    assertJsonDepth(record[key], depth + 1);
  }
}

/** Parses YAML text into a plain value, rejecting all forbidden structures. */
function parseYamlValue(sourceText: string): PolicyJsonValue {
  const documents = parseDocuments(sourceText);
  const document = documents[0];
  for (const error of document.errors) {
    // Third-party parser text is intentionally not propagated.
    throw parseError(
      error.code === 'DUPLICATE_KEY' ? 'DUPLICATE_MAPPING_KEY' : 'MALFORMED_DOCUMENT',
    );
  }
  if (document.contents === null || document.contents === undefined) {
    throw parseError('MALFORMED_DOCUMENT');
  }
  return astToJsonValue(document.contents, 1);
}

/**
 * Parses JSON text under strict JSON grammar plus independent duplicate-key
 * detection.
 *
 * JSON.parse silently accepts duplicate keys (last one wins), so grammar alone
 * is insufficient. The same text is independently re-parsed through the YAML
 * document/AST facilities (JSON is a subset of YAML flow syntax), which are
 * configured with unique mapping keys and no alias expansion; that pass is used
 * purely as a structural validator.
 */
function parseJsonValue(sourceText: string): PolicyJsonValue {
  let parsed: unknown;
  try {
    parsed = JSON.parse(sourceText);
  } catch {
    throw parseError('MALFORMED_DOCUMENT');
  }

  const documents = parseDocuments(sourceText);
  const document = documents[0];
  for (const error of document.errors) {
    throw parseError(
      error.code === 'DUPLICATE_KEY' ? 'DUPLICATE_MAPPING_KEY' : 'MALFORMED_DOCUMENT',
    );
  }
  if (document.contents !== null && document.contents !== undefined) {
    // Structural validator pass: forbidden nodes and depth. Result discarded;
    // JSON.parse remains the authoritative source of JSON value semantics.
    astToJsonValue(document.contents, 1);
  }

  assertJsonDepth(parsed as PolicyJsonValue, 1);
  return parsed as PolicyJsonValue;
}

/**
 * Parses the source into exactly one YAML document.
 *
 * The third-party parser is fully contained here: any exception it raises is
 * converted into a generic ArcError so no parser text, source excerpt, or stack
 * trace can reach a client.
 */
function parseDocuments(sourceText: string): ReturnType<typeof parseAllDocuments> {
  let documents: ReturnType<typeof parseAllDocuments>;
  try {
    documents = parseAllDocuments(sourceText, YAML_PARSE_OPTIONS);
  } catch {
    throw parseError('MALFORMED_DOCUMENT');
  }
  if (documents.length === 0) {
    throw parseError('MALFORMED_DOCUMENT');
  }
  if (documents.length > 1) {
    // Multi-document streams are forbidden: a policy is strictly one document.
    throw parseError('MULTIPLE_DOCUMENTS');
  }
  return documents;
}

/** Entry point used by {@link DeclarativePolicyEngine.fromExternalText}. */
function parseSourceText(sourceText: unknown, format: unknown): PolicyJsonValue {
  if (typeof sourceText !== 'string') {
    throw parseError('MALFORMED_DOCUMENT');
  }
  // The format is explicit and closed. An unrecognised format fails closed
  // rather than falling through to a default parser.
  if (format !== 'json' && format !== 'yaml') {
    throw parseError('MALFORMED_DOCUMENT');
  }
  if (Buffer.byteLength(sourceText, 'utf8') > MAX_POLICY_BYTES) {
    throw parseError('DOCUMENT_SIZE_LIMIT_EXCEEDED');
  }
  if (format === 'json') {
    return parseJsonValue(sourceText);
  }
  return parseYamlValue(sourceText);
}

// ---------------------------------------------------------------------------
// Strict closed schema validation (rc04 §7.3, §8.3, §14 - §20)
// ---------------------------------------------------------------------------

const TOP_LEVEL_KEYS = new Set(['version', 'metadata', 'workspaces', 'rules']);
const METADATA_KEYS = new Set(['name', 'description', 'lastModified']);
const WORKSPACE_KEYS = new Set(['id', 'rootHash']);
const RULE_KEYS = new Set(['id', 'effect', 'description', 'tools', 'paths', 'commands', 'git']);
const PATHS_KEYS = new Set(['patterns']);
const COMMANDS_KEYS = new Set(['allowedBinaries', 'blockedBinaries']);
const GIT_KEYS = new Set(['protectedBranches', 'actions']);

const VALID_EFFECTS = new Set<string>(['DENY', 'REQUIRE_APPROVAL', 'ALLOW']);
const ROOT_HASH_PATTERN = /^[0-9a-f]{64}$/;

function isPlainObject(value: PolicyJsonValue): value is { [key: string]: PolicyJsonValue } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Rejects any property outside the closed schema (rc04 §8.3). */
function assertClosedObject(
  value: { [key: string]: PolicyJsonValue },
  allowed: ReadonlySet<string>,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw parseError('UNKNOWN_PROPERTY');
    }
  }
}

/**
 * Rule identifier contract: `^[a-zA-Z0-9_-]{1,64}$`.
 *
 * Implemented as an explicit character scan rather than a RegExp because
 * JavaScript `$` also matches immediately before a trailing newline, which
 * would admit identifiers such as "rule\n" — and because it keeps the
 * validation free of any backtracking engine.
 */
function isValidRuleId(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const length = value.length;
  if (length < 1 || length > 64) return false;
  for (let i = 0; i < length; i++) {
    const code = value.charCodeAt(i);
    const isUpper = code >= 0x41 && code <= 0x5a;
    const isLower = code >= 0x61 && code <= 0x7a;
    const isDigit = code >= 0x30 && code <= 0x39;
    const isUnderscore = code === 0x5f;
    const isHyphen = code === 0x2d;
    if (!isUpper && !isLower && !isDigit && !isUnderscore && !isHyphen) {
      return false;
    }
  }
  return true;
}

/**
 * Validates a matcher array.
 *
 * The item-count bound is applied to the raw source array BEFORE any
 * normalization or deduplication, so a document cannot bypass it by supplying
 * many duplicate values. Entries must be strings; no coercion is performed.
 */
function validateMatcherArray(value: PolicyJsonValue): string[] {
  if (!Array.isArray(value)) {
    throw parseError('INVALID_MATCHER');
  }
  if (value.length > MAX_MATCHER_ITEMS) {
    throw parseError('TOO_MANY_MATCHER_ITEMS');
  }
  const items: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string') {
      throw parseError('INVALID_MATCHER');
    }
    items.push(item);
  }
  return items;
}

/** Bound applied to any single matcher string (glob pattern or exact value). */
function assertMatcherStringLength(value: string): void {
  if (value.length === 0 || value.length > MAX_PATTERN_LENGTH) {
    throw parseError('INVALID_MATCHER');
  }
}

function validateToolsMatcher(value: PolicyJsonValue): string[] {
  const tools = validateMatcherArray(value);
  const registered = registeredToolSet();
  for (const tool of tools) {
    assertMatcherStringLength(tool);
    if (!registered.has(tool)) {
      // Policy files may not pre-authorize hypothetical future tool names.
      throw parseError('UNKNOWN_TOOL_NAME');
    }
  }
  return tools;
}

function validatePathPatterns(value: PolicyJsonValue): string[] {
  const patterns = validateMatcherArray(value);
  for (const pattern of patterns) {
    if (validatePathPattern(pattern) !== null) {
      throw parseError('INVALID_PATH_PATTERN');
    }
  }
  return patterns;
}

function validateBinaryMatcher(value: PolicyJsonValue): string[] {
  const binaries = validateMatcherArray(value);
  for (const binary of binaries) {
    assertMatcherStringLength(binary);
    // Binary matchers are executable BASENAMES: no path separators, no shell
    // text, no regex, no glob syntax.
    if (binary.includes('/') || binary.includes('\\')) {
      throw parseError('INVALID_COMMAND_MATCHER');
    }
  }
  return binaries;
}

function validateExactStringMatcher(value: PolicyJsonValue): string[] {
  const items = validateMatcherArray(value);
  for (const item of items) {
    assertMatcherStringLength(item);
  }
  return items;
}

function validateRule(value: PolicyJsonValue, seenRuleIds: Set<string>): ParsedRule {
  if (!isPlainObject(value)) {
    throw parseError('INVALID_RULES');
  }
  assertClosedObject(value, RULE_KEYS);

  if (!isValidRuleId(value.id)) {
    throw parseError('INVALID_RULE_ID');
  }
  if (seenRuleIds.has(value.id)) {
    throw parseError('DUPLICATE_RULE_ID');
  }
  seenRuleIds.add(value.id);

  if (typeof value.effect !== 'string' || !VALID_EFFECTS.has(value.effect)) {
    // Effects are case-sensitive: 'deny', 'Allow', 'REQUIRE-APPROVAL' are invalid.
    throw parseError('INVALID_EFFECT');
  }
  const effect = value.effect as PolicyEffect;

  const rule: ParsedRule = { id: value.id, effect };

  if (value.description !== undefined) {
    if (
      typeof value.description !== 'string' ||
      value.description.length > MAX_RULE_DESCRIPTION_LENGTH
    ) {
      throw parseError('INVALID_DESCRIPTION');
    }
    rule.description = value.description;
  }

  if (value.tools !== undefined) {
    rule.tools = validateToolsMatcher(value.tools);
  }

  if (value.paths !== undefined) {
    if (!isPlainObject(value.paths)) {
      throw parseError('INVALID_MATCHER');
    }
    assertClosedObject(value.paths, PATHS_KEYS);
    if (value.paths.patterns !== undefined) {
      rule.paths = { patterns: validatePathPatterns(value.paths.patterns) };
    }
  }

  if (value.commands !== undefined) {
    if (!isPlainObject(value.commands)) {
      throw parseError('INVALID_COMMAND_MATCHER');
    }
    assertClosedObject(value.commands, COMMANDS_KEYS);
    const hasAllowed = value.commands.allowedBinaries !== undefined;
    const hasBlocked = value.commands.blockedBinaries !== undefined;
    if (hasAllowed && hasBlocked) {
      throw parseError('INVALID_COMMAND_MATCHER');
    }
    if (hasBlocked && effect !== 'DENY') {
      // Negative matcher is valid ONLY on DENY rules.
      throw parseError('INVALID_COMMAND_MATCHER');
    }
    if (hasAllowed && effect === 'DENY') {
      // Positive matcher is valid ONLY on ALLOW / REQUIRE_APPROVAL rules.
      throw parseError('INVALID_COMMAND_MATCHER');
    }
    const commands: { allowedBinaries?: string[]; blockedBinaries?: string[] } = {};
    if (hasAllowed) {
      commands.allowedBinaries = validateBinaryMatcher(
        value.commands.allowedBinaries as PolicyJsonValue,
      );
    }
    if (hasBlocked) {
      commands.blockedBinaries = validateBinaryMatcher(
        value.commands.blockedBinaries as PolicyJsonValue,
      );
    }
    rule.commands = commands;
  }

  if (value.git !== undefined) {
    if (!isPlainObject(value.git)) {
      throw parseError('INVALID_MATCHER');
    }
    assertClosedObject(value.git, GIT_KEYS);
    const git: { protectedBranches?: string[]; actions?: string[] } = {};
    if (value.git.protectedBranches !== undefined) {
      // Protected branches use the same restricted wildcard grammar with `/`
      // segment semantics. No regex, extglob, or brace expansion.
      git.protectedBranches = validatePathPatterns(value.git.protectedBranches);
    }
    if (value.git.actions !== undefined) {
      // Git actions are exact case-sensitive strings, not globs.
      git.actions = validateExactStringMatcher(value.git.actions);
    }
    rule.git = git;
  }

  return rule;
}

function validateWorkspaceAssertion(
  value: PolicyJsonValue,
  seenIds: Set<string>,
): ParsedWorkspaceAssertion {
  if (!isPlainObject(value)) {
    throw parseError('INVALID_WORKSPACE_ASSERTION');
  }
  // `path`, `rootPath`, `directory` and any other property are rejected here.
  assertClosedObject(value, WORKSPACE_KEYS);

  if (typeof value.id !== 'string' || value.id.length === 0) {
    throw parseError('INVALID_WORKSPACE_ASSERTION');
  }
  if (seenIds.has(value.id)) {
    throw parseError('DUPLICATE_WORKSPACE_ID');
  }
  seenIds.add(value.id);

  const assertion: ParsedWorkspaceAssertion = { id: value.id };

  if (value.rootHash !== undefined) {
    if (typeof value.rootHash !== 'string' || !ROOT_HASH_PATTERN.test(value.rootHash)) {
      throw parseError('INVALID_WORKSPACE_ASSERTION');
    }
    assertion.rootHash = value.rootHash;
  }

  return assertion;
}

function validateDocument(value: PolicyJsonValue): ParsedDocument {
  if (!isPlainObject(value)) {
    // Rejects null, scalars, and arrays.
    throw parseError('MALFORMED_DOCUMENT');
  }
  assertClosedObject(value, TOP_LEVEL_KEYS);

  if (value.version !== '1.0') {
    throw parseError('INVALID_VERSION');
  }

  if (!Array.isArray(value.rules)) {
    throw parseError('INVALID_RULES');
  }
  if (value.rules.length > MAX_POLICY_RULES) {
    throw parseError('TOO_MANY_RULES');
  }

  const document: ParsedDocument = { version: '1.0', workspaces: [], rules: [] };

  if (value.metadata !== undefined) {
    if (!isPlainObject(value.metadata)) {
      throw parseError('UNKNOWN_PROPERTY');
    }
    assertClosedObject(value.metadata, METADATA_KEYS);
    const metadata: { name?: string; description?: string; lastModified?: string } = {};
    for (const key of ['name', 'description', 'lastModified'] as const) {
      const entry = value.metadata[key];
      if (entry !== undefined) {
        if (typeof entry !== 'string') {
          throw parseError('UNKNOWN_PROPERTY');
        }
        metadata[key] = entry;
      }
    }
    document.metadata = metadata;
  }

  if (value.workspaces !== undefined) {
    if (!Array.isArray(value.workspaces)) {
      throw parseError('INVALID_WORKSPACE_ASSERTION');
    }
    const seenWorkspaceIds = new Set<string>();
    for (const entry of value.workspaces) {
      document.workspaces.push(validateWorkspaceAssertion(entry, seenWorkspaceIds));
    }
  }

  const seenRuleIds = new Set<string>();
  for (const entry of value.rules) {
    document.rules.push(validateRule(entry, seenRuleIds));
  }

  return document;
}

// ---------------------------------------------------------------------------
// Canonical normalization (rc04 §18.1)
// ---------------------------------------------------------------------------

function sortedUnique(values: readonly string[]): string[] {
  const unique = Array.from(new Set(values));
  unique.sort(compareStrings);
  return unique;
}

/**
 * Produces the canonical normalized policy representation.
 *
 * Metadata and rule descriptions are excluded entirely. Workspaces and rules
 * are sorted by id. Every OR-based matcher array is sorted and deduplicated.
 * Omitted and empty optional matcher structures normalize identically to
 * omission (rc04 §28).
 */
export function normalizePolicy(document: ParsedDocument): NormalizedPolicy {
  const workspaces = document.workspaces
    .map((workspace) => {
      const normalized: { id: string; rootHash?: string } = { id: workspace.id };
      if (workspace.rootHash !== undefined) {
        normalized.rootHash = workspace.rootHash;
      }
      return normalized;
    })
    .sort((a, b) => compareStrings(a.id, b.id));

  const rules = document.rules
    .map((rule) => {
      const normalized: NormalizedPolicy['rules'][number] = {
        id: rule.id,
        effect: rule.effect,
      };
      if (rule.tools !== undefined && rule.tools.length > 0) {
        normalized.tools = sortedUnique(rule.tools);
      }
      if (rule.paths !== undefined && rule.paths.patterns.length > 0) {
        normalized.paths = { patterns: sortedUnique(rule.paths.patterns) };
      }
      if (rule.commands !== undefined) {
        const commands: { allowedBinaries?: string[]; blockedBinaries?: string[] } = {};
        if (
          rule.commands.allowedBinaries !== undefined &&
          rule.commands.allowedBinaries.length > 0
        ) {
          commands.allowedBinaries = sortedUnique(rule.commands.allowedBinaries);
        }
        if (
          rule.commands.blockedBinaries !== undefined &&
          rule.commands.blockedBinaries.length > 0
        ) {
          commands.blockedBinaries = sortedUnique(rule.commands.blockedBinaries);
        }
        if (Object.keys(commands).length > 0) {
          normalized.commands = commands;
        }
      }
      if (rule.git !== undefined) {
        const git: { protectedBranches?: string[]; actions?: string[] } = {};
        if (rule.git.protectedBranches !== undefined && rule.git.protectedBranches.length > 0) {
          git.protectedBranches = sortedUnique(rule.git.protectedBranches);
        }
        if (rule.git.actions !== undefined && rule.git.actions.length > 0) {
          git.actions = sortedUnique(rule.git.actions);
        }
        if (Object.keys(git).length > 0) {
          normalized.git = git;
        }
      }
      return normalized;
    })
    .sort((a, b) => compareStrings(a.id, b.id));

  return { schemaVersion: '1.0', workspaces, rules };
}

/** Deep-frozen clone used to guarantee engine-internal immutability. */
function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      deepFreeze(item);
    }
  } else {
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      deepFreeze(record[key]);
    }
  }
  return Object.freeze(value);
}

/** Deep clone returned to callers so engine state cannot be mutated externally. */
function deepClone<T>(value: T): T {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => deepClone(item)) as unknown as T;
  }
  const record = value as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const key of Object.keys(record)) {
    result[key] = deepClone(record[key]);
  }
  return result as T;
}

// ---------------------------------------------------------------------------
// Built-in compatibility policy (rc04 §11.2, §32, §33)
// ---------------------------------------------------------------------------

/**
 * The 4 RC-02 controlled-execution / process supervision tools.
 * Layer 1 SecurityKernel remains authoritative for RC-02 command safety.
 */
const RC02_ADDITIONAL_TOOLS = [
  'run_command',
  'process_status',
  'process_output',
  'terminate_process',
] as const;

/**
 * Canonical built-in compatibility policy.
 *
 * Expressed as a policy document and pushed through the exact same
 * normalize -> canonicalJson -> SHA-256 pipeline as operator policies, so its
 * hash is reproducible rather than hard-coded.
 */
function buildBuiltInDocument(): ParsedDocument {
  return {
    version: '1.0',
    workspaces: [],
    rules: [
      {
        id: 'builtin-allow-rc01-inspection',
        effect: 'ALLOW',
        tools: [...RC01_ALLOWED_TOOLS],
      },
      {
        id: 'builtin-allow-rc02-controlled-execution',
        effect: 'ALLOW',
        tools: [...RC02_ADDITIONAL_TOOLS],
      },
      {
        id: 'builtin-require-approval-file-mutation',
        effect: 'REQUIRE_APPROVAL',
        tools: [...RC03_MUTATION_TOOLS],
      },
      {
        id: 'builtin-require-approval-rc07-verify',
        effect: 'REQUIRE_APPROVAL',
        tools: [...RC07_TASK4_EXECUTION_TOOLS],
      },
      {
        id: 'builtin-allow-rc07-read-only',
        effect: 'ALLOW',
        tools: [...RC07_READ_ONLY_TOOLS],
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// Rule compilation
// ---------------------------------------------------------------------------

function compileRule(rule: NormalizedPolicy['rules'][number]): CompiledRule {
  return {
    id: rule.id,
    effect: rule.effect,
    tools: rule.tools ? new Set(rule.tools) : null,
    pathPatterns: rule.paths?.patterns
      ? rule.paths.patterns.map((pattern) => compilePathPattern(pattern))
      : null,
    commandBinaries:
      rule.commands?.allowedBinaries || rule.commands?.blockedBinaries
        ? new Set(rule.commands.allowedBinaries ?? rule.commands.blockedBinaries)
        : null,
    gitBranchPatterns: rule.git?.protectedBranches
      ? rule.git.protectedBranches.map((pattern) => compilePathPattern(pattern))
      : null,
    gitActions: rule.git?.actions ? new Set(rule.git.actions) : null,
  };
}

// ---------------------------------------------------------------------------
// Evaluation (rc04 §9, §10, §11, §31)
// ---------------------------------------------------------------------------

/** Inputs for a single-target Layer 2 evaluation. */
export interface PolicyMatchTarget {
  toolName: string;
  path?: string;
  executableBasename?: string;
  gitBranch?: string;
  gitAction?: string;
}

const EFFECT_RANK: Record<PolicyEffect, number> = {
  DENY: 0,
  REQUIRE_APPROVAL: 1,
  ALLOW: 2,
};

function effectToOutcome(effect: PolicyEffect): PolicyOutcome {
  if (effect === 'DENY') return PolicyOutcome.DENY;
  if (effect === 'REQUIRE_APPROVAL') return PolicyOutcome.REQUIRE_APPROVAL;
  return PolicyOutcome.ALLOW;
}

function denyDecision(matchingRuleId: string, reason: string): PolicyDecisionResult {
  return {
    outcome: PolicyOutcome.DENY,
    effect: 'DENY',
    matchingRuleId,
    reason,
  };
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/**
 * Immutable Layer 2 declarative policy engine.
 *
 * An instance holds exactly one validated, immutable policy: the parsed
 * document, its normalized form, its policyHash, and its source mode. There is
 * no hot reload and no mutation path.
 */
export class DeclarativePolicyEngine {
  private readonly compiledRules: readonly CompiledRule[];

  private constructor(
    private readonly mode: PolicySourceMode,
    private readonly normalizedPolicy: NormalizedPolicy,
    private readonly policyHash: string,
  ) {
    this.compiledRules = Object.freeze(
      normalizedPolicy.rules.map((rule) => Object.freeze(compileRule(rule))),
    );
    deepFreeze(this.normalizedPolicy);
  }

  /**
   * Builds an engine from explicitly formatted operator policy text.
   *
   * Fails closed on any parse, schema, resource, or workspace-binding failure.
   * An explicitly configured invalid policy NEVER degrades to the built-in
   * compatibility policy (rc04 §12.4).
   */
  public static fromExternalText(
    workspaceRegistry: WorkspaceRegistryLookup,
    sourceText: string,
    format: PolicySourceFormat,
  ): DeclarativePolicyEngine {
    if (typeof workspaceRegistry !== 'object' || workspaceRegistry === null) {
      throw loadError('UNKNOWN_WORKSPACE_ID');
    }

    const parsedValue = parseSourceText(sourceText, format);
    const document = validateDocument(parsedValue);
    const normalized = normalizePolicy(document);
    const hash = computePolicyHash(normalized);

    // Workspace assertions are verified against the trusted registry. Policy
    // never registers or authorizes a filesystem root (rc04 §7.1, §34, §36).
    for (const assertion of document.workspaces) {
      let record: { id: string; rootPath: string } | undefined;
      try {
        record = workspaceRegistry.getWorkspace(assertion.id);
      } catch {
        record = undefined;
      }
      if (!record) {
        throw loadError('UNKNOWN_WORKSPACE_ID');
      }
      if (assertion.rootHash !== undefined) {
        // Expected digest of the canonical registered root path. The raw host
        // path is never included in the error.
        if (sha256Hex(record.rootPath) !== assertion.rootHash) {
          throw loadError('WORKSPACE_ROOT_HASH_MISMATCH');
        }
      }
    }

    return new DeclarativePolicyEngine('EXTERNAL', normalized, hash);
  }

  /** Builds the canonical built-in compatibility policy engine. */
  public static builtIn(workspaceRegistry: WorkspaceRegistryLookup): DeclarativePolicyEngine {
    if (typeof workspaceRegistry !== 'object' || workspaceRegistry === null) {
      throw loadError('UNKNOWN_WORKSPACE_ID');
    }
    const normalized = normalizePolicy(buildBuiltInDocument());
    return new DeclarativePolicyEngine('BUILTIN', normalized, computePolicyHash(normalized));
  }

  /** Returns the source mode of this engine. */
  public getSourceMode(): PolicySourceMode {
    return this.mode;
  }

  /** Returns the canonical policy hash (64 lowercase hexadecimal characters). */
  public getPolicyHash(): string {
    return this.policyHash;
  }

  /**
   * Returns a defensive deep copy of the normalized policy.
   * Mutating the result cannot affect engine state.
   */
  public getNormalizedPolicy(): NormalizedPolicy {
    return deepClone(this.normalizedPolicy);
  }

  /**
   * Evaluates a single normalized target against the loaded policy.
   *
   * Order-independent: physical rule order never influences the decision.
   * Precedence is DENY > REQUIRE_APPROVAL > ALLOW, with the lexicographically
   * smallest winning rule id as the deterministic tie-break.
   */
  public evaluate(target: PolicyMatchTarget): PolicyDecisionResult {
    if (typeof target !== 'object' || target === null) {
      return denyDecision(DEFAULT_DENY_UNREGISTERED_TOOL, 'Invalid evaluation target.');
    }

    const toolName = target.toolName;
    if (typeof toolName !== 'string' || toolName.length === 0) {
      return denyDecision(DEFAULT_DENY_UNREGISTERED_TOOL, 'Invalid evaluation target.');
    }

    // Target admission. Ambiguous or unsafe target inputs fail closed rather
    // than being reinterpreted into an authorized relative form (rc04 §24/§25).
    let normalizedPath: string | undefined;
    if (target.path !== undefined) {
      const candidate = normalizeTargetPath(target.path);
      if (candidate === null) {
        return denyDecision(
          'deny-invalid-target-path',
          'Target path is not a safe normalized workspace-relative path.',
        );
      }
      normalizedPath = candidate;
    }

    let normalizedBasename: string | undefined;
    if (target.executableBasename !== undefined) {
      const basename = target.executableBasename;
      if (
        typeof basename !== 'string' ||
        basename.length === 0 ||
        basename.includes('/') ||
        basename.includes('\\')
      ) {
        return denyDecision(
          'deny-invalid-executable-basename',
          'Executable basename is not a valid basename value.',
        );
      }
      normalizedBasename = basename;
    }

    // Collect every matching rule, then resolve by precedence.
    let winningEffect: PolicyEffect | null = null;
    let winningRuleId = '';

    for (const rule of this.compiledRules) {
      if (!this.ruleMatches(rule, toolName, normalizedPath, normalizedBasename, target)) {
        continue;
      }
      if (
        winningEffect === null ||
        EFFECT_RANK[rule.effect] < EFFECT_RANK[winningEffect] ||
        (EFFECT_RANK[rule.effect] === EFFECT_RANK[winningEffect] &&
          compareStrings(rule.id, winningRuleId) < 0)
      ) {
        winningEffect = rule.effect;
        winningRuleId = rule.id;
      }
    }

    if (winningEffect === null) {
      // Default deny. External policies use the canonical no-match id; the
      // built-in policy reports an unregistered tool.
      return this.mode === 'BUILTIN'
        ? denyDecision(
            DEFAULT_DENY_UNREGISTERED_TOOL,
            `Tool '${toolName}' is not permitted by the built-in policy.`,
          )
        : denyDecision(
            DEFAULT_DENY_NO_RULE_MATCHED,
            'No declarative policy rule matched the request.',
          );
    }

    // Mandatory mutation approval floor (rc04 §5, §10.1.4, §31).
    if (winningEffect === 'ALLOW' && mutationToolSet().has(toolName)) {
      return {
        outcome: PolicyOutcome.REQUIRE_APPROVAL,
        effect: 'REQUIRE_APPROVAL',
        matchingRuleId: winningRuleId,
        reason: `Rule '${winningRuleId}' allowed tool '${toolName}', but the RC-03 mutation approval floor elevates file mutations to REQUIRE_APPROVAL.`,
      };
    }

    return {
      outcome: effectToOutcome(winningEffect),
      effect: winningEffect,
      matchingRuleId: winningRuleId,
      reason:
        winningEffect === 'ALLOW'
          ? `Explicit declarative rule '${winningRuleId}' allows tool '${toolName}'.`
          : `Declarative rule '${winningRuleId}' resolved tool '${toolName}' to ${winningEffect}.`,
    };
  }

  /**
   * Matcher semantics (rc04 §9): categories combine with AND, entries within a
   * category combine with OR. A category that is defined but whose runtime
   * context is absent does not match.
   */
  private ruleMatches(
    rule: CompiledRule,
    toolName: string,
    normalizedPath: string | undefined,
    normalizedBasename: string | undefined,
    target: PolicyMatchTarget,
  ): boolean {
    if (rule.tools !== null && !rule.tools.has(toolName)) {
      return false;
    }

    if (rule.pathPatterns !== null) {
      if (normalizedPath === undefined) {
        return false;
      }
      let matched = false;
      for (const pattern of rule.pathPatterns) {
        if (matchCompiledPattern(pattern, normalizedPath)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return false;
      }
    }

    if (rule.commandBinaries !== null) {
      if (normalizedBasename === undefined || !rule.commandBinaries.has(normalizedBasename)) {
        return false;
      }
    }

    if (rule.gitBranchPatterns !== null) {
      const branch = target.gitBranch;
      if (typeof branch !== 'string' || normalizeTargetPath(branch) === null) {
        return false;
      }
      let matched = false;
      for (const pattern of rule.gitBranchPatterns) {
        if (matchCompiledPattern(pattern, branch)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return false;
      }
    }

    if (rule.gitActions !== null) {
      const action = target.gitAction;
      if (typeof action !== 'string' || !rule.gitActions.has(action)) {
        return false;
      }
    }

    return true;
  }
}
