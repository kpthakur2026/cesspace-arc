/**
 * MCP Tool definitions and parameter interfaces.
 */

// ============================================================================
// Tier 1: Read-Only Tools (RC-01 Target)
// ============================================================================

export interface HealthRequest {}

export interface HealthResponse {
  status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
  version: string;
  stage: string;
  policyEngineActive: boolean;
  auditActive: boolean;
  authorizedWorkspacesCount: number;
  /**
   * The single active transport mode for this process (§4 L-4). Exactly one
   * mode runs per process: stdio and remote are mutually exclusive.
   */
  transportMode: 'stdio' | 'remote';
  /** True only while the remote TLS listener is bound and serving. */
  remoteGatewayActive: boolean;
  /**
   * True when the remote gateway is running but cannot admit new sessions.
   * Absent when the gateway is absent, stdio-only, or healthy.
   */
  remoteGatewayDegraded?: boolean;
  /**
   * Bounded reason for gateway degradation. Never certificate material, key
   * material, file paths, pins, or peer addresses (§19).
   */
  remoteGatewayDegradedReason?: 'certificate_expired';
}

export interface ListDirectoryRequest {
  path?: string;
  recursive?: boolean;
  maxDepth?: number;
  includeHidden?: boolean;
}

export interface DirectoryEntry {
  name: string;
  relativePath: string;
  type: 'file' | 'directory' | 'symlink' | 'other';
  sizeBytes?: number;
  modifiedTime?: string;
}

export interface ListDirectoryResponse {
  entries: DirectoryEntry[];
  totalCount: number;
}

export interface ReadFileRequest {
  path: string;
  offset?: number;
  length?: number;
}

export interface ReadFileResponse {
  content: string;
  bytesRead: number;
  totalSize: number;
  truncated: boolean;
}

export interface SearchFilesRequest {
  pattern: string;
  subPath?: string;
  maxResults?: number;
}

export interface SearchFilesResponse {
  matches: string[];
  totalMatches: number;
}

export interface SearchTextRequest {
  query: string;
  isRegex?: boolean;
  filePattern?: string;
  maxMatches?: number;
}

export interface TextMatchItem {
  path: string;
  lineNumber: number;
  lineContent: string;
}

export interface SearchTextResponse {
  matches: TextMatchItem[];
  totalMatches: number;
}

export interface GitStatusRequest {
  workspaceRoot?: string;
}

export interface GitStatusResponse {
  branch: string;
  commitHash: string;
  isClean: boolean;
  stagedFiles: string[];
  unstagedFiles: string[];
  untrackedFiles: string[];
}

export interface GitDiffRequest {
  target?: string;
  path?: string;
  cached?: boolean;
}

export interface GitDiffResponse {
  diff: string;
  truncated: boolean;
}

export interface GitLogRequest {
  maxCount?: number;
  revision?: string;
  path?: string;
}

export interface GitCommitItem {
  hash: string;
  author: string;
  date: string;
  message: string;
}

export interface GitLogResponse {
  commits: GitCommitItem[];
}

export interface SystemStatusRequest {}

export interface SystemStatusResponse {
  os: string;
  arch: string;
  cpuCount: number;
  memoryTotalBytes: number;
  memoryFreeBytes: number;
  workspaceDiskFreeBytes: number;
}

// ============================================================================
// Tier 2: Controlled Execution & Mutation Tools (RC-02 & RC-03 Targets)
// ============================================================================

export interface RunCommandRequest {
  executable: string;
  args?: string[];
  cwd?: string;
  timeoutMs?: number;
  env?: Record<string, string>;
  workspaceId?: string;
  runInBackground?: boolean;
}

export interface RunCommandResponse {
  processId: string;
  state: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'TIMED_OUT' | 'TERMINATED';
  exitCode?: number | null;
  signal?: string | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
}

export interface ProcessStatusRequest {
  processId: string;
  workspaceId?: string;
}

export interface ProcessStatusResponse {
  processId: string;
  state: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'TIMED_OUT' | 'TERMINATED';
  startedAt: string;
  durationMs: number;
  exitCode?: number | null;
  signal?: string | null;
  timedOut: boolean;
  outputAvailable: boolean;
  truncated: boolean;
}

export interface ProcessOutputRequest {
  processId: string;
  offset?: number;
  stdoutCursor?: number;
  stderrCursor?: number;
  maxBytes?: number;
  workspaceId?: string;
}

export interface ProcessOutputResponse {
  processId: string;
  stdoutChunk: string;
  stderrChunk: string;
  nextOffset: number;
  stdoutCursor: number;
  stderrCursor: number;
  complete: boolean;
  truncated: boolean;
}

export interface TerminateProcessRequest {
  processId: string;
  signal?: 'SIGTERM' | 'SIGKILL';
  workspaceId?: string;
}

export interface TerminateProcessResponse {
  processId: string;
  terminated: boolean;
  signal: string;
}

export interface CreateFileRequest {
  path: string;
  content: string;
}

export interface CreateFileResponse {
  path: string;
  bytesWritten: number;
  contentHash: string;
  created: true;
}

export interface WriteFileRequest {
  path: string;
  content: string;
  expectedHash: string;
  overwrite: true;
}

export interface WriteFileResponse {
  path: string;
  bytesWritten: number;
  contentHash: string;
  previousHash: string;
}

export interface DeleteFileRequest {
  path: string;
  expectedHash: string;
}

export interface DeleteFileResponse {
  path: string;
  deleted: true;
  contentHash: string;
}

export interface MoveFileRequest {
  sourcePath: string;
  destinationPath: string;
  expectedSourceHash: string;
}

export interface MoveFileResponse {
  sourcePath: string;
  destinationPath: string;
  moved: true;
}

export interface ApplyPatchRequest {
  patch: string;
  dryRun?: boolean;
  fuzz?: number;
}

export interface ApplyPatchResponse {
  success: true;
  modifiedFiles: string[];
  stats: {
    filesChanged: number;
    insertions: number;
    deletions: number;
  };
  dryRun: boolean;
}
