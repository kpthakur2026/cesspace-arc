/**
 * Package-internal seam for ArcMcpServer internal composition and test harness attachment.
 * STRICTLY package-internal and NEVER exported from public package root or exports map.
 * @internal
 */

import type { ArcMcpServer } from '../index.js';
import type { IInternalDeterministicExecutor } from '@cesspace-arc/terminal';
import type { DeterministicExecutionRegistry } from '../composite-framework.js';
import type { TestCompositeHarness } from './composite-testing.js';

export interface ServerInternalAccess {
  setTestCompositeHarness(harness?: TestCompositeHarness): void;
  getTestCompositeHarness(): TestCompositeHarness | undefined;
  setInternalDeterministicExecutor(executor?: IInternalDeterministicExecutor): void;
  getInternalDeterministicExecutor(): IInternalDeterministicExecutor | undefined;
  setDeterministicRegistry(registry: DeterministicExecutionRegistry): void;
  getDeterministicRegistry(): DeterministicExecutionRegistry;
  setTask2TimeoutMs?(timeoutMs: number): void;
  getTask2TimeoutMs?(): number;
}

export const SERVER_INTERNAL_ACCESS = new WeakMap<ArcMcpServer, ServerInternalAccess>();
