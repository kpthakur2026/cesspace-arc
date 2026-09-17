import { randomUUID } from 'node:crypto';
import type { ChildProcess } from 'node:child_process';
import {
  ArcError,
  type ProcessStatusResponse,
  type ProcessOutputResponse,
  type TerminateProcessResponse,
} from '@cesspace-arc/protocol';

export type ProcessState = 'RUNNING' | 'COMPLETED' | 'FAILED' | 'TIMED_OUT' | 'TERMINATED';

/**
 * Maximum buffer retention per process in bytes (512 KiB).
 * Prevents memory exhaustion from runaway process output.
 */
export const MAX_PROCESS_BUFFER_BYTES = 512 * 1024;

/**
 * Maximum bytes returned per single process_output call (128 KiB).
 */
export const MAX_OUTPUT_READ_BYTES = 128 * 1024;

/**
 * Default bytes returned per process_output call (64 KiB).
 */
export const DEFAULT_OUTPUT_READ_BYTES = 64 * 1024;

/**
 * Concurrency limits to prevent resource exhaustion.
 */
export const CONCURRENCY_LIMITS = {
  maxGlobalRunning: 10,
  maxPerSessionRunning: 4,
  maxPerWorkspaceRunning: 4,
} as const;

export interface ProcessRecord {
  processId: string;
  workspaceId: string;
  actor: {
    clientId: string;
    sessionId: string;
  };
  executable: string;
  sanitizedArgs: string[];
  cwd: string;
  startedAt: string;
  completedAt?: string;
  durationMs: number;
  state: ProcessState;
  exitCode?: number | null;
  signal?: string | null;
  timedOut: boolean;
  totalStdoutBytes: number;
  totalStderrBytes: number;
  truncated: boolean;

  // Private internals
  _child?: ChildProcess;
  _timeoutTimer?: NodeJS.Timeout;
  _killTimer?: NodeJS.Timeout;
  _stdoutChunks: Buffer[];
  _stderrChunks: Buffer[];
}

export interface IProcessRegistry {
  registerProcess(
    record: Omit<
      ProcessRecord,
      | 'processId'
      | '_stdoutChunks'
      | '_stderrChunks'
      | 'totalStdoutBytes'
      | 'totalStderrBytes'
      | 'truncated'
      | 'durationMs'
    >,
  ): ProcessRecord;
  getProcess(processId: string): ProcessRecord | undefined;
  listProcesses(filter?: {
    sessionId?: string;
    workspaceId?: string;
    state?: ProcessState;
  }): ProcessRecord[];
  appendOutput(processId: string, stream: 'stdout' | 'stderr', chunk: Buffer): void;
  getProcessStatus(processId: string, sessionId?: string): ProcessStatusResponse;
  getProcessOutput(
    processId: string,
    offset?: number,
    maxBytes?: number,
    sessionId?: string,
  ): ProcessOutputResponse;
  terminateProcess(
    processId: string,
    signal?: 'SIGTERM' | 'SIGKILL',
    sessionId?: string,
  ): Promise<TerminateProcessResponse>;
  markCompleted(processId: string, exitCode: number | null, signal: string | null): void;
  markTimedOut(processId: string): void;
  checkConcurrency(sessionId: string, workspaceId: string): void;
  clear(): void;
}

/**
 * High-confidence secret scrubbing patterns for process output.
 */
const HIGH_CONFIDENCE_SECRET_PATTERNS = [
  /AKIA[0-9A-Z]{16}/g,
  /ghp_[a-zA-Z0-9]{36}/g,
  /gho_[a-zA-Z0-9]{36}/g,
  /sk-[a-zA-Z0-9]{20,}/g,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g,
  /Bearer\s+[a-zA-Z0-9._-]+/gi,
];

export function scrubOutput(text: string): string {
  let result = text;
  for (const pattern of HIGH_CONFIDENCE_SECRET_PATTERNS) {
    result = result.replace(pattern, '[REDACTED_SECRET]');
  }
  return result;
}

/**
 * In-memory thread-safe Process Registry.
 * Enforces opaque IDs, session ownership, output bounds, and concurrency limits.
 */
export class ProcessRegistry implements IProcessRegistry {
  private processes = new Map<string, ProcessRecord>();

  public registerProcess(
    init: Omit<
      ProcessRecord,
      | 'processId'
      | '_stdoutChunks'
      | '_stderrChunks'
      | 'totalStdoutBytes'
      | 'totalStderrBytes'
      | 'truncated'
      | 'durationMs'
    >,
  ): ProcessRecord {
    this.checkConcurrency(init.actor.sessionId, init.workspaceId);

    const processId = `arc-proc-${randomUUID()}`;
    const record: ProcessRecord = {
      ...init,
      processId,
      durationMs: 0,
      totalStdoutBytes: 0,
      totalStderrBytes: 0,
      truncated: false,
      _stdoutChunks: [],
      _stderrChunks: [],
    };

    this.processes.set(processId, record);
    return record;
  }

  public getProcess(processId: string): ProcessRecord | undefined {
    return this.processes.get(processId);
  }

  public listProcesses(filter?: {
    sessionId?: string;
    workspaceId?: string;
    state?: ProcessState;
  }): ProcessRecord[] {
    let result = Array.from(this.processes.values());
    if (filter?.sessionId) {
      result = result.filter((p) => p.actor.sessionId === filter.sessionId);
    }
    if (filter?.workspaceId) {
      result = result.filter((p) => p.workspaceId === filter.workspaceId);
    }
    if (filter?.state) {
      result = result.filter((p) => p.state === filter.state);
    }
    return result;
  }

  public countRunning(filter?: { sessionId?: string; workspaceId?: string }): number {
    return this.listProcesses({
      state: 'RUNNING',
      sessionId: filter?.sessionId,
      workspaceId: filter?.workspaceId,
    }).length;
  }

  public checkConcurrency(sessionId: string, workspaceId: string): void {
    const globalRunning = this.countRunning();
    if (globalRunning >= CONCURRENCY_LIMITS.maxGlobalRunning) {
      throw ArcError.resourceExhausted(
        `Global process limit reached (max ${CONCURRENCY_LIMITS.maxGlobalRunning} active processes).`,
      );
    }

    const sessionRunning = this.countRunning({ sessionId });
    if (sessionRunning >= CONCURRENCY_LIMITS.maxPerSessionRunning) {
      throw ArcError.resourceExhausted(
        `Session process limit reached (max ${CONCURRENCY_LIMITS.maxPerSessionRunning} active processes).`,
      );
    }

    const workspaceRunning = this.countRunning({ workspaceId });
    if (workspaceRunning >= CONCURRENCY_LIMITS.maxPerWorkspaceRunning) {
      throw ArcError.resourceExhausted(
        `Workspace process limit reached (max ${CONCURRENCY_LIMITS.maxPerWorkspaceRunning} active processes).`,
      );
    }
  }

  public appendOutput(processId: string, stream: 'stdout' | 'stderr', chunk: Buffer): void {
    const record = this.processes.get(processId);
    if (!record) return;

    const currentTotal = record.totalStdoutBytes + record.totalStderrBytes;
    if (currentTotal >= MAX_PROCESS_BUFFER_BYTES) {
      record.truncated = true;
      return;
    }

    const available = MAX_PROCESS_BUFFER_BYTES - currentTotal;
    const slice = chunk.length > available ? chunk.subarray(0, available) : chunk;

    if (stream === 'stdout') {
      record._stdoutChunks.push(slice);
      record.totalStdoutBytes += slice.length;
    } else {
      record._stderrChunks.push(slice);
      record.totalStderrBytes += slice.length;
    }

    if (chunk.length > available) {
      record.truncated = true;
    }
  }

  public assertOwnership(processId: string, sessionId?: string): ProcessRecord {
    // Validate format: must be an opaque ARC processId
    if (!processId || typeof processId !== 'string' || !processId.startsWith('arc-proc-')) {
      throw ArcError.processNotFound('Process not found: Invalid process identifier.');
    }

    const record = this.processes.get(processId);
    if (!record) {
      throw ArcError.processNotFound(`Process not found: '${processId}'.`);
    }

    if (sessionId && record.actor.sessionId !== sessionId) {
      throw ArcError.policyDenied(
        'Access denied: Caller is not authorized to access or control this process.',
      );
    }

    return record;
  }

  public getProcessStatus(processId: string, sessionId?: string): ProcessStatusResponse {
    const record = this.assertOwnership(processId, sessionId);

    const now = Date.now();
    const start = new Date(record.startedAt).getTime();
    const durationMs = record.completedAt ? record.durationMs : Math.max(0, now - start);

    return {
      processId: record.processId,
      state: record.state,
      startedAt: record.startedAt,
      durationMs,
      exitCode: record.exitCode,
      signal: record.signal,
      timedOut: record.timedOut,
      outputAvailable: record.totalStdoutBytes > 0 || record.totalStderrBytes > 0,
      truncated: record.truncated,
    };
  }

  public getProcessOutput(
    processId: string,
    offset = 0,
    maxBytes = DEFAULT_OUTPUT_READ_BYTES,
    sessionId?: string,
  ): ProcessOutputResponse {
    const record = this.assertOwnership(processId, sessionId);

    const boundedMaxBytes = Math.min(Math.max(1, maxBytes), MAX_OUTPUT_READ_BYTES);
    const startOffset = Math.max(0, offset);

    const stdoutFull = Buffer.concat(record._stdoutChunks);
    const stderrFull = Buffer.concat(record._stderrChunks);

    const stdoutSlice = stdoutFull.subarray(startOffset, startOffset + boundedMaxBytes);
    const stderrSlice = stderrFull.subarray(startOffset, startOffset + boundedMaxBytes);

    const bytesRead = Math.max(stdoutSlice.length, stderrSlice.length);
    const nextOffset = startOffset + bytesRead;

    const maxTotalBytes = Math.max(record.totalStdoutBytes, record.totalStderrBytes);
    const complete = record.state !== 'RUNNING' && nextOffset >= maxTotalBytes;

    return {
      processId: record.processId,
      stdoutChunk: scrubOutput(stdoutSlice.toString('utf8')),
      stderrChunk: scrubOutput(stderrSlice.toString('utf8')),
      nextOffset,
      complete,
      truncated: record.truncated,
    };
  }

  public async terminateProcess(
    processId: string,
    signal: 'SIGTERM' | 'SIGKILL' = 'SIGTERM',
    sessionId?: string,
  ): Promise<TerminateProcessResponse> {
    const record = this.assertOwnership(processId, sessionId);

    if (record.state !== 'RUNNING' || !record._child) {
      return {
        processId: record.processId,
        terminated: false,
        signal: 'NONE',
      };
    }

    if (record._timeoutTimer) {
      clearTimeout(record._timeoutTimer);
      record._timeoutTimer = undefined;
    }

    const child = record._child;
    try {
      child.kill(signal);
    } catch {
      // Child may have already exited
    }

    if (signal === 'SIGTERM') {
      record._killTimer = setTimeout(() => {
        try {
          if (child.exitCode === null && child.signalCode === null) {
            child.kill('SIGKILL');
          }
        } catch {
          // ignore
        }
      }, 1000);
      record._killTimer.unref();
    }

    record.state = 'TERMINATED';
    record.signal = signal;
    record.completedAt = new Date().toISOString();
    record.durationMs = Math.max(
      0,
      new Date(record.completedAt).getTime() - new Date(record.startedAt).getTime(),
    );

    return {
      processId: record.processId,
      terminated: true,
      signal,
    };
  }

  public markCompleted(processId: string, exitCode: number | null, signal: string | null): void {
    const record = this.processes.get(processId);
    if (!record) return;

    if (record._timeoutTimer) {
      clearTimeout(record._timeoutTimer);
      record._timeoutTimer = undefined;
    }
    if (record._killTimer) {
      clearTimeout(record._killTimer);
      record._killTimer = undefined;
    }

    record.state = exitCode === 0 ? 'COMPLETED' : 'FAILED';
    record.exitCode = exitCode;
    record.signal = signal;
    record.completedAt = new Date().toISOString();
    record.durationMs = Math.max(
      0,
      new Date(record.completedAt).getTime() - new Date(record.startedAt).getTime(),
    );
  }

  public markTimedOut(processId: string): void {
    const record = this.processes.get(processId);
    if (!record) return;

    if (record._timeoutTimer) {
      clearTimeout(record._timeoutTimer);
      record._timeoutTimer = undefined;
    }
    if (record._killTimer) {
      clearTimeout(record._killTimer);
      record._killTimer = undefined;
    }

    record.state = 'TIMED_OUT';
    record.timedOut = true;
    record.completedAt = new Date().toISOString();
    record.durationMs = Math.max(
      0,
      new Date(record.completedAt).getTime() - new Date(record.startedAt).getTime(),
    );
  }

  public clear(): void {
    for (const record of this.processes.values()) {
      if (record._timeoutTimer) clearTimeout(record._timeoutTimer);
      if (record._killTimer) clearTimeout(record._killTimer);
      if (record.state === 'RUNNING' && record._child) {
        try {
          record._child.kill('SIGKILL');
        } catch {
          // ignore
        }
      }
    }
    this.processes.clear();
  }
}
