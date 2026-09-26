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
  setTask2TimeoutMs(timeoutMs: number): void;
  getTask2TimeoutMs(): number;
  setTask3TimeoutMs(timeoutMs: number): void;
  getTask3TimeoutMs(): number;
  setTask4StepTimeoutMs(timeoutMs: number): void;
  getTask4StepTimeoutMs(): number;
  setTask4AggregateTimeoutMs(timeoutMs: number): void;
  getTask4AggregateTimeoutMs(): number;
}

export const SERVER_INTERNAL_ACCESS = new WeakMap<ArcMcpServer, ServerInternalAccess>();

export function setTask2TimeoutForTest(server: ArcMcpServer, timeoutMs: number): void {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  access.setTask2TimeoutMs(timeoutMs);
}

export function getTask2TimeoutForTest(server: ArcMcpServer): number {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  return access.getTask2TimeoutMs();
}

export function setTask3TimeoutForTest(server: ArcMcpServer, timeoutMs: number): void {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  access.setTask3TimeoutMs(timeoutMs);
}

export function getTask3TimeoutForTest(server: ArcMcpServer): number {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  return access.getTask3TimeoutMs();
}

export function setTask4StepTimeoutForTest(server: ArcMcpServer, timeoutMs: number): void {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  access.setTask4StepTimeoutMs(timeoutMs);
}

export function getTask4StepTimeoutForTest(server: ArcMcpServer): number {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  return access.getTask4StepTimeoutMs();
}

export function setTask4AggregateTimeoutForTest(server: ArcMcpServer, timeoutMs: number): void {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  access.setTask4AggregateTimeoutMs(timeoutMs);
}

export function getTask4AggregateTimeoutForTest(server: ArcMcpServer): number {
  const access = SERVER_INTERNAL_ACCESS.get(server);
  if (!access) {
    throw new Error('Invalid ArcMcpServer instance: internal test access unavailable');
  }
  return access.getTask4AggregateTimeoutMs();
}
