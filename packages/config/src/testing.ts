/** @internal Deterministic Task-2 migration fault seam. Not exported by package.json. */
import { migrateCoreState, type MigrationResult } from './index.js';
import { withPreCommitFault } from './internal-test-seam.js';

export async function migrateCoreStateWithPreCommitFault(root: string): Promise<MigrationResult> {
  return withPreCommitFault(() => migrateCoreState(root));
}
