/**
 * CesSpace ARC — RC-07 Task 6
 * Local CI Simulation Status Tool Implementation (arc_ci_status)
 *
 * Implements the frozen RC-07 Task-6 contract:
 * - Read-only inspection of .github/workflows/, Git status, and Git log
 * - Zero-network hard boundary (zero outbound network requests, zero CI API queries)
 * - Credential isolation (zero inspection of GITHUB_TOKEN, GH_TOKEN, or ambient credentials)
 * - Workflow path confinement to .github/workflows/ via FilesystemSubsystem
 * - Non-execution of workflow actions/steps (pure inert YAML inspection)
 * - Safe parsing of YAML; malformed YAML fails closed with sanitized INTERNAL_ERROR
 * - 64 KiB (65,536 bytes) maximum response payload cap; fails closed with PAYLOAD_TOO_LARGE
 * - Truthful local reporting: localSimulationMode: true, remoteQueryDeferred: true,
 *   localVerificationMatch: false
 */

import {
  ArcError,
  type ArcCiStatusRequest,
  type ArcCiStatusResponse,
  type ArcCiWorkflowInfo,
} from '@cesspace-arc/protocol';
import type { GitSubsystem } from '@cesspace-arc/git';
import type { FilesystemSubsystem } from '@cesspace-arc/filesystem';
import YAML from 'yaml';

/**
 * Maximum serialized response size for RC-07 CI status tool: 64 KiB (65,536 bytes).
 */
export const MAX_CI_STATUS_RESPONSE_BYTES = 64 * 1024;

/**
 * Deterministic fixed remote notice for RC-07 local simulation mode.
 */
export const REMOTE_NOTICE_DEFERRED =
  'Remote CI status was not queried. RC-07 reports local simulation only.';

export interface CiStatusHandlerParams {
  targetWorkspace: {
    workspaceId: string;
    rootPath: string;
    isGitRepo: boolean;
  };
  validatedParams: ArcCiStatusRequest;
  gitSubsystem: GitSubsystem;
  filesystemSubsystem: FilesystemSubsystem;
}

/**
 * Handles execution of the read-only arc_ci_status tool.
 */
export async function handleArcCiStatus(
  params: CiStatusHandlerParams,
): Promise<ArcCiStatusResponse> {
  const { targetWorkspace, validatedParams, gitSubsystem, filesystemSubsystem } = params;

  // 1. Target must be a valid Git repository
  if (!targetWorkspace.isGitRepo) {
    throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
  }

  // 2. Discover workflow files strictly confined to .github/workflows/
  const workflowFilePaths = await filesystemSubsystem.listWorkflowFiles(targetWorkspace.rootPath);

  // 3. Inspect each workflow YAML file as inert data
  const workflowsFound: ArcCiWorkflowInfo[] = [];

  for (const relPath of workflowFilePaths) {
    const fileRes = await filesystemSubsystem.readFile(targetWorkspace.rootPath, {
      path: relPath,
    });

    let doc: unknown;
    try {
      doc = YAML.parse(fileRes.content);
    } catch {
      throw ArcError.internalError('CI workflow YAML could not be parsed.');
    }

    if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
      throw ArcError.internalError('CI workflow YAML could not be parsed.');
    }

    const docRecord = doc as Record<string, unknown>;

    // Extract workflow name (fallback to file path if missing or not string)
    let workflowName = relPath;
    if (typeof docRecord.name === 'string' && docRecord.name.trim().length > 0) {
      workflowName = docRecord.name.trim();
    }

    // Extract job count
    let jobCount = 0;
    const rawJobs = docRecord.jobs;
    if (rawJobs && typeof rawJobs === 'object' && !Array.isArray(rawJobs)) {
      jobCount = Object.keys(rawJobs).length;
    }

    // Extract triggers
    const triggersSet = new Set<string>();
    const rawOn = docRecord.on !== undefined ? docRecord.on : docRecord[true as unknown as string];

    if (typeof rawOn === 'string') {
      const trimmed = rawOn.trim();
      if (trimmed.length > 0) {
        triggersSet.add(trimmed);
      }
    } else if (Array.isArray(rawOn)) {
      for (const item of rawOn) {
        if (typeof item === 'string') {
          const trimmed = item.trim();
          if (trimmed.length > 0) {
            triggersSet.add(trimmed);
          }
        }
      }
    } else if (rawOn && typeof rawOn === 'object') {
      for (const key of Object.keys(rawOn)) {
        const trimmed = key.trim();
        if (trimmed.length > 0) {
          triggersSet.add(trimmed);
        }
      }
    }

    const triggers = Array.from(triggersSet).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    workflowsFound.push({
      name: workflowName,
      path: relPath,
      jobCount,
      triggers,
    });
  }

  // 4. Filter by workflowName if provided
  let filteredWorkflows = workflowsFound;
  if (
    validatedParams.workflowName !== undefined &&
    typeof validatedParams.workflowName === 'string'
  ) {
    const filter = validatedParams.workflowName.trim();
    filteredWorkflows = workflowsFound.filter((w) => w.name === filter);
  }

  // 5. Gather Git status and verify head commit hash against Git log
  const statusRes = await gitSubsystem.getStatus(targetWorkspace.rootPath);
  let headHash = statusRes.commitHash || '';

  if (headHash && headHash !== 'unknown') {
    const logRes = await gitSubsystem.getLog(targetWorkspace.rootPath, { maxCount: 1 });
    if (!logRes.commits || logRes.commits.length === 0 || logRes.commits[0].hash !== headHash) {
      throw ArcError.internalError('Git HEAD commit hash mismatch between status and log.');
    }
  } else {
    headHash = '';
  }

  // 6. Construct response adhering to strict frozen contract
  const response: ArcCiStatusResponse = {
    localSimulationMode: true,
    workflowsFound: filteredWorkflows,
    localBranch: statusRes.branch || '',
    headSha: headHash,
    workingTreeClean: Boolean(statusRes.isClean),
    localVerificationMatch: false,
    remoteQueryDeferred: true,
    remoteNotice: REMOTE_NOTICE_DEFERRED,
  };

  // 7. Enforce 64 KiB wire payload cap
  const serialized = JSON.stringify(response, null, 2);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_CI_STATUS_RESPONSE_BYTES) {
    throw ArcError.payloadTooLarge('CI status response exceeds maximum 64 KiB limit.');
  }

  return response;
}
