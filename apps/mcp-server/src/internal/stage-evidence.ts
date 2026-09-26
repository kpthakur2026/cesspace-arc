/**
 * CesSpace ARC — RC-07 Task 7
 * Stage Evidence Aggregation Tool Implementation (arc_stage_evidence)
 *
 * Implements the frozen RC-07 Task-7 contract:
 * - Read-only aggregation of already-existing, machine-verifiable local evidence from:
 *   - GitSubsystem (branch, commit hash, isClean, tracked verify script presence at HEAD)
 *   - Persistent audit runtime state & packages/audit verification
 * - Closed stage catalog: RC-00 through RC-07; unknown stages reject with STAGE_NOT_FOUND
 * - Zero subprocess spawning in arc_stage_evidence
 * - Zero filesystem direct imports (fully respects security kernel / subsystem boundaries)
 * - Missing audit runtime or zero records rejects with EVIDENCE_NOT_MET
 * - Tampered ledger or invalid checkpoint signature sets integrity: 'FAILED', omits checkpointHash
 * - Anti-fabrication invariant: never synthesize approval; verifiedLocally is false;
 *   acceptanceMet is false; deterministic disclaimer included
 * - 512 KiB (524,288 bytes) maximum response payload cap; fails closed with PAYLOAD_TOO_LARGE
 */

import {
  ArcError,
  RC07_STAGE_CATALOG,
  type ArcStageEvidenceRequest,
  type ArcStageEvidenceResponse,
  type Rc07Stage,
} from '@cesspace-arc/protocol';
import type { GitSubsystem } from '@cesspace-arc/git';
import type { AuditRuntime } from '@cesspace-arc/audit';

/**
 * Maximum serialized response size for RC-07 stage evidence tool: 512 KiB (524,288 bytes).
 */
export const MAX_STAGE_EVIDENCE_RESPONSE_BYTES = 512 * 1024;

/**
 * Deterministic fixed disclaimer for RC-07 stage evidence aggregation.
 */
export const STAGE_EVIDENCE_DISCLAIMER =
  'Machine-verifiable local evidence only. This does not constitute human, governance, merge, or release approval.';

export interface StageEvidenceHandlerParams {
  targetWorkspace: {
    workspaceId: string;
    rootPath: string;
    isGitRepo: boolean;
  };
  validatedParams: ArcStageEvidenceRequest;
  gitSubsystem: GitSubsystem;
  auditRuntime?: AuditRuntime;
}

/**
 * Handles execution of the read-only arc_stage_evidence tool.
 */
export async function handleArcStageEvidence(
  params: StageEvidenceHandlerParams,
): Promise<ArcStageEvidenceResponse> {
  const { targetWorkspace, validatedParams, gitSubsystem, auditRuntime } = params;

  // 1. Target must be a valid Git repository
  if (!targetWorkspace.isGitRepo) {
    throw ArcError.gitRepositoryNotFound('Directory is not a valid Git repository.');
  }

  // 2. Validate targetStage against closed catalog (RC-00 .. RC-07)
  const targetStage = validatedParams.targetStage;
  if (!targetStage || !RC07_STAGE_CATALOG.includes(targetStage as Rc07Stage)) {
    throw ArcError.stageNotFound(
      `Target stage '${targetStage}' not found in closed catalog: ${RC07_STAGE_CATALOG.join(', ')}.`,
    );
  }

  // 3. Inspect persistent audit ledger
  if (auditRuntime === undefined) {
    throw ArcError.evidenceNotMet('Persistent audit runtime is not available or configured.');
  }

  const auditEvidence = await auditRuntime.inspectStageEvidence();

  // 4. Gather Git repository status and verify HEAD commit hash against Git log
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

  // 5. Check stage verification script presence at HEAD
  // Naming convention: scripts/verify-rc00.sh .. scripts/verify-rc07.sh
  const stageSlug = targetStage.toLowerCase().replace(/[^a-z0-9]/g, '');
  const candidateScriptPath = `scripts/verify-${stageSlug}.sh`;
  const scriptPresent = await gitSubsystem.isTrackedFileAtHead(
    targetWorkspace.rootPath,
    candidateScriptPath,
  );

  // 6. Build response adhering to frozen contract & anti-fabrication invariants
  const references: ArcStageEvidenceResponse['references'] = {
    auditStoreId: auditEvidence.storeId,
    terminalRecordHash: auditEvidence.terminalRecordHash,
    ...(auditEvidence.checkpointHash !== undefined
      ? { checkpointHash: auditEvidence.checkpointHash }
      : {}),
  };

  const response: ArcStageEvidenceResponse = {
    stage: targetStage,
    timestamp: new Date().toISOString(),
    repository: {
      branch: statusRes.branch || '',
      headSha: headHash,
      isClean: Boolean(statusRes.isClean),
    },
    auditLedger: {
      sequence: auditEvidence.sequence,
      integrity: auditEvidence.integrity,
      lastCheckpointSequence: auditEvidence.lastCheckpointSequence,
      storeId: auditEvidence.storeId,
    },
    verification: {
      scriptPresent,
      ...(scriptPresent ? { scriptPath: candidateScriptPath } : {}),
      verifiedLocally: false,
    },
    acceptanceMet: false,
    references,
    disclaimer: STAGE_EVIDENCE_DISCLAIMER,
  };

  // 7. Enforce 512 KiB wire payload cap
  const serialized = JSON.stringify(response, null, 2);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_STAGE_EVIDENCE_RESPONSE_BYTES) {
    throw ArcError.payloadTooLarge('Stage evidence response exceeds maximum 512 KiB limit.');
  }

  return response;
}
