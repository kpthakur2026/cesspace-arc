/**
 * Package-internal execution authority for deterministic composite steps.
 *
 * This module and its symbols are STRICTLY package-internal and NEVER exported
 * from the public package root or package exports map.
 * @internal
 */

import { ArcError, type PolicyEvaluationContext } from '@cesspace-arc/protocol';
import type {
  ControlledProcessRunner,
  DeterministicExecutionStep,
  DeterministicStepResult,
  IInternalDeterministicExecutor,
} from '@cesspace-arc/terminal';
import {
  executeDeterministicStepCore,
  TERMINAL_EXECUTION_SEAM_TOKEN,
} from '@cesspace-arc/terminal/internal/execution-seam';

import {
  AUTHORIZED_INTERNAL_EXECUTORS,
  getActiveCompositeAdmissionTicket,
  isValidServerAdmissionTicket,
} from '../composite-framework.js';

export class ServerDeterministicExecutor implements IInternalDeterministicExecutor {
  constructor(private readonly runner: ControlledProcessRunner) {
    AUTHORIZED_INTERNAL_EXECUTORS.add(this);
  }

  public async executeDeterministicStep(
    step: DeterministicExecutionStep,
    actor: PolicyEvaluationContext['actor'],
    targetWorkspace: PolicyEvaluationContext['targetWorkspace'],
  ): Promise<DeterministicStepResult> {
    // 0. Active Server Admission Ticket verification (Proof D, Proof E)
    const activeTicket = getActiveCompositeAdmissionTicket();
    if (!activeTicket || !isValidServerAdmissionTicket(activeTicket) || activeTicket.consumed) {
      throw ArcError.policyDenied(
        'Access denied: privileged deterministic execution requires active server admission ticket.',
      );
    }
    if (activeTicket.workspaceId !== targetWorkspace.workspaceId) {
      throw ArcError.policyDenied('Access denied: composite admission ticket workspace mismatch.');
    }

    return executeDeterministicStepCore(
      this.runner,
      step,
      actor,
      targetWorkspace,
      TERMINAL_EXECUTION_SEAM_TOKEN,
    );
  }
}

export function createServerDeterministicExecutor(
  runner: ControlledProcessRunner,
): IInternalDeterministicExecutor {
  return new ServerDeterministicExecutor(runner);
}
