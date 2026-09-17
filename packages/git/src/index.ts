import type {
  GitStatusRequest,
  GitStatusResponse,
  GitDiffRequest,
  GitDiffResponse,
  GitLogRequest,
  GitLogResponse,
} from '@cesspace-arc/protocol';

/**
 * Interface definition for Sandboxed Git Subsystem.
 * Implementation target: RC-01 (read-only) & RC-04 (branch protection).
 */
export interface IGitSubsystem {
  getStatus(workspaceRoot: string, request: GitStatusRequest): Promise<GitStatusResponse>;
  getDiff(workspaceRoot: string, request: GitDiffRequest): Promise<GitDiffResponse>;
  getLog(workspaceRoot: string, request: GitLogRequest): Promise<GitLogResponse>;
  assertBranchWritable(workspaceRoot: string, targetBranch: string): Promise<void>;
}
