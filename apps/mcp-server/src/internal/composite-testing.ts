/**
 * Test-only composite framework testing harnesses and seams.
 *
 * This module is STRICTLY for internal repository tests and is NEVER exported
 * on the production package surface or exports map.
 * @internal
 */

import { z } from 'zod';
import type { ArcMcpServer } from '../index.js';
import type { IInternalDeterministicExecutor } from '@cesspace-arc/terminal';
import {
  DeterministicExecutionRegistry,
  TEST_NODE_VERSION_ENTRY,
  TEST_NODE_VERSION_REGISTRY_ID,
  type CanonicalCompositePlan,
  type DeterministicRegistryEntry,
  type PlanMaterializer,
} from '../composite-framework.js';
import { SERVER_INTERNAL_ACCESS } from './server-seam.js';

export { TEST_NODE_VERSION_REGISTRY_ID, TEST_NODE_VERSION_ENTRY };

export const TEST_COMPOSITE_HARNESS_TOKEN = Symbol('arc.test.composite.framework.harness');

export interface TestCompositeHarness {
  readonly [TEST_COMPOSITE_HARNESS_TOKEN]: true;
  readonly toolName: string;
  readonly schema: z.ZodTypeAny;
  readonly materializer: PlanMaterializer;
  readonly registry: DeterministicExecutionRegistry;
  readonly testPostAdmissionMutationHook?: (
    plan: CanonicalCompositePlan,
  ) => CanonicalCompositePlan | void;
}

export function createTestDeterministicRegistry(
  extraEntries: readonly DeterministicRegistryEntry[] = [],
): DeterministicExecutionRegistry {
  return new DeterministicExecutionRegistry([TEST_NODE_VERSION_ENTRY, ...extraEntries]);
}

export function createTestCompositeHarness(options: {
  toolName: string;
  schema: z.ZodTypeAny;
  materializer: PlanMaterializer;
  registry?: DeterministicExecutionRegistry;
  testPostAdmissionMutationHook?: (plan: CanonicalCompositePlan) => CanonicalCompositePlan | void;
}): TestCompositeHarness {
  return {
    [TEST_COMPOSITE_HARNESS_TOKEN]: true,
    toolName: options.toolName,
    schema: options.schema,
    materializer: options.materializer,
    registry: options.registry ?? createTestDeterministicRegistry(),
    testPostAdmissionMutationHook: options.testPostAdmissionMutationHook,
  };
}

export function attachTestCompositeHarness(
  server: ArcMcpServer,
  harness: TestCompositeHarness,
): void {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  access.setTestCompositeHarness(harness);
  access.setDeterministicRegistry(harness.registry);
}

export function detachInternalExecutorForTest(server: ArcMcpServer): void {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (access) {
    access.setInternalDeterministicExecutor(undefined);
  }
}

export function getInternalExecutorForTest(
  server: ArcMcpServer,
): IInternalDeterministicExecutor | undefined {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  return access ? access.getInternalDeterministicExecutor() : undefined;
}

export function getDeterministicRegistryForTest(
  server: ArcMcpServer,
): DeterministicExecutionRegistry | undefined {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  return access ? access.getDeterministicRegistry() : undefined;
}
