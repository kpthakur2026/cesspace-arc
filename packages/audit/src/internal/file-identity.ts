/**
 * The single definition of "this pathname still names the artifact I validated"
 * (RC-06 Task 3).
 *
 * A pathname is a name, not a handle. Descriptor authority is authoritative
 * while a descriptor is held, but two steps in the rotation path must act on a
 * pathname after the descriptor that proved it has been closed: installing the
 * rotated segment under its archive name, and removing the plain source once
 * its compressed twin has been verified. Both would otherwise trust that the
 * name still points where it pointed a moment ago.
 *
 * The rule is therefore implemented once and re-proved at every such step:
 *
 *  - the pathname must still exist (a vanished path is a failure, never a
 *    vacuous success),
 *  - it must not be a symbolic link, and
 *  - its dev/inode/size must equal the identity observed on the descriptor.
 *
 * `size` is part of the identity on purpose. A same-inode growth or shrink is a
 * modification of the artifact, so it is a mismatch even though dev and inode
 * still agree. Reporting it as one consistent failure with one code keeps the
 * fail-closed contract simple: nothing is archived, nothing is unlinked, and
 * the storage ends in its terminal failed state.
 *
 * @internal
 */

import fs from 'node:fs';

import { createCodedError } from './errors.js';
import type { FileIdentity } from './rotation-capability.js';

/**
 * Throws unless `filePath` still resolves to exactly `identity`.
 *
 * `label` names the artifact in the error message so an operator can tell which
 * pathname was replaced without reading the stack.
 */
export function assertPathIdentity(
  filePath: string,
  identity: FileIdentity,
  label: string,
): fs.Stats {
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (err: unknown) {
    throw createCodedError(
      'AUDIT_ROTATION_FAILED',
      `${label} pathname disappeared before it could be revalidated`,
      { cause: err },
    );
  }

  if (stats.isSymbolicLink()) {
    throw createCodedError('SYMLINK_DETECTED', `${label} pathname is a symbolic link`);
  }

  if (stats.dev !== identity.dev || stats.ino !== identity.ino || stats.size !== identity.size) {
    throw createCodedError(
      'AUDIT_ROTATION_FAILED',
      `${label} pathname no longer refers to the validated artifact`,
    );
  }

  return stats;
}
