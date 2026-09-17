/**
 * Interface definition for Process Tracking and Supervision Subsystem.
 * Implementation target: RC-02.
 */
export interface ProcessInfo {
  pid: number;
  command: string;
  cpuPercent: number;
  memoryBytes: number;
  startedAt: string;
}

export interface IProcessSubsystem {
  listChildProcesses(): Promise<ProcessInfo[]>;
  terminateProcess(pid: number, force?: boolean): Promise<boolean>;
}
