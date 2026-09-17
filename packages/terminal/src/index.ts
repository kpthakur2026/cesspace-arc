import type { RunCommandRequest, RunCommandResponse } from '@cesspace-arc/protocol';

/**
 * Interface definition for Controlled Terminal Subsystem.
 * Implementation target: RC-02.
 */
export interface ITerminalSubsystem {
  executeCommand(request: RunCommandRequest): Promise<RunCommandResponse>;
  cancelCommand(taskId: string): Promise<boolean>;
}
