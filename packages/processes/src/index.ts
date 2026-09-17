import { randomUUID } from 'node:crypto';
import type { ChildProcess } from 'node:child_process';
import {
  ArcError,
  type ProcessStatusResponse,
  type ProcessOutputResponse,
  type TerminateProcessResponse,
} from '@cesspace-arc/protocol';

export type ProcessState =
  'RUNNING' | 'TERMINATING' | 'COMPLETED' | 'FAILED' | 'TIMED_OUT' | 'TERMINATED';

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

export interface ProcessOwnerIdentity {
  clientId: string;
  sessionId: string;
  workspaceId?: string;
}

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

export type ProcessLifecycleEventType =
  | 'PROCESS_SPAWN_SUCCEEDED'
  | 'PROCESS_SPAWN_FAILED'
  | 'PROCESS_EXITED'
  | 'PROCESS_TIMEOUT'
  | 'PROCESS_TERMINATION_REQUESTED'
  | 'PROCESS_SIGTERM_SENT'
  | 'PROCESS_SIGKILL_ESCALATED'
  | 'PROCESS_TERMINATED';

export interface ProcessLifecycleEvent {
  eventType: ProcessLifecycleEventType;
  timestamp: string;
  processId: string;
  workspaceId: string;
  actor: {
    clientId: string;
    sessionId: string;
  };
  executable: string;
  exitCode?: number | null;
  signal?: string | null;
  durationMs?: number;
  error?: string;
}

export interface IProcessLifecycleSink {
  onProcessEvent(event: ProcessLifecycleEvent): Promise<void> | void;
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
    clientId?: string;
    sessionId?: string;
    workspaceId?: string;
    state?: ProcessState;
  }): ProcessRecord[];
  appendOutput(processId: string, stream: 'stdout' | 'stderr', chunk: Buffer): void;
  getProcessStatus(processId: string, owner?: ProcessOwnerIdentity): ProcessStatusResponse;
  getProcessOutput(
    processId: string,
    offset?: number,
    maxBytes?: number,
    owner?: ProcessOwnerIdentity,
  ): ProcessOutputResponse;
  terminateProcess(
    processId: string,
    signal?: 'SIGTERM' | 'SIGKILL',
    owner?: ProcessOwnerIdentity,
  ): Promise<TerminateProcessResponse>;
  markCompleted(processId: string, exitCode: number | null, signal: string | null): void;
  markTimedOut(processId: string): void;
  notifySpawnSuccess(processId: string): void;
  markSpawnFailed(processId: string, error?: string): void;
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
 * Safely slice a Buffer to ensure it does not split a multi-byte UTF-8 character sequence at the end.
 */
export function sliceUtf8Safe(
  buf: Buffer,
  start: number,
  end: number,
): { slice: Buffer; adjustedEnd: number } {
  const boundedEnd = Math.min(end, buf.length);
  const boundedStart = Math.min(start, boundedEnd);
  if (boundedStart >= boundedEnd) {
    return { slice: Buffer.alloc(0), adjustedEnd: boundedStart };
  }

  // If the byte at boundedEnd is a continuation byte, back up to find the start of the UTF-8 sequence
  let cut = boundedEnd;
  while (cut > boundedStart && (buf[cut] & 0xc0) === 0x80) {
    cut--;
  }

  // Check if character starting at `cut` completes before boundedEnd
  if (cut > boundedStart) {
    const lead = buf[cut];
    let charLen = 1;
    if ((lead & 0xe0) === 0xc0) charLen = 2;
    else if ((lead & 0xf0) === 0xe0) charLen = 3;
    else if ((lead & 0xf8) === 0xf0) charLen = 4;

    if (cut + charLen <= boundedEnd) {
      // It fits completely
      return { slice: buf.subarray(boundedStart, boundedEnd), adjustedEnd: boundedEnd };
    } else {
      // Multi-byte sequence is truncated at boundedEnd, so back up to `cut`
      return { slice: buf.subarray(boundedStart, cut), adjustedEnd: cut };
    }
  }

  return { slice: buf.subarray(boundedStart, cut), adjustedEnd: cut };
}

/**
 * In-memory thread-safe Process Registry.
 * Enforces opaque IDs, strict client/session/workspace ownership, output bounds, and concurrency limits.
 */
export class ProcessRegistry implements IProcessRegistry {
  private processes = new Map<string, ProcessRecord>();
  private lifecycleSinks: IProcessLifecycleSink[] = [];

  constructor(sinks?: IProcessLifecycleSink[]) {
    if (sinks) {
      this.lifecycleSinks = [...sinks];
    }
  }

  public registerLifecycleSink(sink: IProcessLifecycleSink): void {
    this.lifecycleSinks.push(sink);
  }

  private emitLifecycleEvent(event: ProcessLifecycleEvent): void {
    for (const sink of this.lifecycleSinks) {
      try {
        void sink.onProcessEvent(event);
      } catch {
        // Sink failure must not throw in registry
      }
    }
  }

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

  public notifySpawnSuccess(processId: string): void {
    const record = this.processes.get(processId);
    if (!record) return;
    this.emitLifecycleEvent({
      eventType: 'PROCESS_SPAWN_SUCCEEDED',
      timestamp: record.startedAt,
      processId: record.processId,
      workspaceId: record.workspaceId,
      actor: record.actor,
      executable: record.executable,
    });
  }

  public markSpawnFailed(processId: string, error?: string): void {
    const record = this.processes.get(processId);
    if (!record) return;
    record.state = 'FAILED';
    record.completedAt = new Date().toISOString();
    this.emitLifecycleEvent({
      eventType: 'PROCESS_SPAWN_FAILED',
      timestamp: record.completedAt,
      processId: record.processId,
      workspaceId: record.workspaceId,
      actor: record.actor,
      executable: record.executable,
      error,
    });
  }

  public getProcess(processId: string): ProcessRecord | undefined {
    return this.processes.get(processId);
  }

  public listProcesses(filter?: {
    clientId?: string;
    sessionId?: string;
    workspaceId?: string;
    state?: ProcessState;
  }): ProcessRecord[] {
    let result = Array.from(this.processes.values());
    if (filter?.clientId) {
      result = result.filter((p) => p.actor.clientId === filter.clientId);
    }
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
    return Array.from(this.processes.values()).filter((p) => {
      const isAlive = p.state === 'RUNNING' || p.state === 'TERMINATING';
      if (!isAlive) return false;
      if (filter?.sessionId && p.actor.sessionId !== filter.sessionId) return false;
      if (filter?.workspaceId && p.workspaceId !== filter.workspaceId) return false;
      return true;
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

  public assertOwnership(processId: string, owner?: ProcessOwnerIdentity): ProcessRecord {
    // Validate format: must be an opaque ARC processId
    if (!processId || typeof processId !== 'string' || !processId.startsWith('arc-proc-')) {
      throw ArcError.processNotFound('Process not found: Invalid process identifier.');
    }

    const record = this.processes.get(processId);
    if (!record) {
      throw ArcError.processNotFound(`Process not found: '${processId}'.`);
    }

    if (!owner || !owner.clientId || !owner.sessionId) {
      throw ArcError.policyDenied(
        'Access denied: Process control requires verified caller identity (clientId and sessionId).',
      );
    }

    if (record.actor.clientId !== owner.clientId) {
      throw ArcError.policyDenied('Access denied: Caller clientId does not match process owner.');
    }

    if (record.actor.sessionId !== owner.sessionId) {
      throw ArcError.policyDenied(
        'Access denied: Caller sessionId does not match process owner session.',
      );
    }

    if (
      owner.workspaceId &&
      owner.workspaceId !== 'unbound' &&
      record.workspaceId !== owner.workspaceId
    ) {
      throw ArcError.policyDenied(
        'Access denied: Caller workspace does not match process workspace.',
      );
    }

    return record;
  }

  public getProcessStatus(processId: string, owner?: ProcessOwnerIdentity): ProcessStatusResponse {
    const record = this.assertOwnership(processId, owner);

    const now = Date.now();
    const start = new Date(record.startedAt).getTime();
    const durationMs = record.completedAt ? record.durationMs : Math.max(0, now - start);

    // Map TERMINATING to RUNNING in external response contract if needed, or return state
    const externalState: ProcessStatusResponse['state'] =
      record.state === 'TERMINATING' ? 'RUNNING' : record.state;

    return {
      processId: record.processId,
      state: externalState,
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
    owner?: ProcessOwnerIdentity,
  ): ProcessOutputResponse {
    const record = this.assertOwnership(processId, owner);

    const boundedMaxBytes = Math.min(Math.max(1, maxBytes), MAX_OUTPUT_READ_BYTES);
    const startOffset = Math.max(0, offset);

    const stdoutFull = Buffer.concat(record._stdoutChunks);
    const stderrFull = Buffer.concat(record._stderrChunks);

    const stdoutResult = sliceUtf8Safe(stdoutFull, startOffset, startOffset + boundedMaxBytes);
    const stderrResult = sliceUtf8Safe(stderrFull, startOffset, startOffset + boundedMaxBytes);

    const bytesRead = Math.max(stdoutResult.slice.length, stderrResult.slice.length);
    const nextOffset =
      startOffset +
      Math.max(
        stdoutResult.adjustedEnd - startOffset,
        stderrResult.adjustedEnd - startOffset,
        bytesRead,
      );

    const maxTotalBytes = Math.max(record.totalStdoutBytes, record.totalStderrBytes);
    const isStillActive = record.state === 'RUNNING' || record.state === 'TERMINATING';
    const complete = !isStillActive && nextOffset >= maxTotalBytes;

    return {
      processId: record.processId,
      stdoutChunk: scrubOutput(stdoutResult.slice.toString('utf8')),
      stderrChunk: scrubOutput(stderrResult.slice.toString('utf8')),
      nextOffset,
      complete,
      truncated: record.truncated,
    };
  }

  public async terminateProcess(
    processId: string,
    signal: 'SIGTERM' | 'SIGKILL' = 'SIGTERM',
    owner?: ProcessOwnerIdentity,
  ): Promise<TerminateProcessResponse> {
    const record = this.assertOwnership(processId, owner);

    const isAlive = record.state === 'RUNNING' || record.state === 'TERMINATING';
    if (!isAlive || !record._child) {
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
    const pid = child.pid;

    this.emitLifecycleEvent({
      eventType: 'PROCESS_TERMINATION_REQUESTED',
      timestamp: new Date().toISOString(),
      processId: record.processId,
      workspaceId: record.workspaceId,
      actor: record.actor,
      executable: record.executable,
      signal,
    });

    // Mark as TERMINATING while termination grace period is active
    record.state = 'TERMINATING';

    // Terminate process tree using process group if available (-pid), else child.kill
    const killTarget = (sig: 'SIGTERM' | 'SIGKILL') => {
      try {
        if (pid && process.platform !== 'win32') {
          process.kill(-pid, sig);
        } else {
          child.kill(sig);
        }
      } catch {
        try {
          child.kill(sig);
        } catch {
          // Child may have already exited
        }
      }
    };

    killTarget(signal);

    this.emitLifecycleEvent({
      eventType: signal === 'SIGKILL' ? 'PROCESS_SIGKILL_ESCALATED' : 'PROCESS_SIGTERM_SENT',
      timestamp: new Date().toISOString(),
      processId: record.processId,
      workspaceId: record.workspaceId,
      actor: record.actor,
      executable: record.executable,
      signal,
    });

    if (signal === 'SIGTERM') {
      record._killTimer = setTimeout(() => {
        try {
          if (child.exitCode === null && child.signalCode === null) {
            this.emitLifecycleEvent({
              eventType: 'PROCESS_SIGKILL_ESCALATED',
              timestamp: new Date().toISOString(),
              processId: record.processId,
              workspaceId: record.workspaceId,
              actor: record.actor,
              executable: record.executable,
              signal: 'SIGKILL',
            });
            killTarget('SIGKILL');
          }
        } catch {
          // ignore
        }
      }, 1000);
      record._killTimer.unref();
    }

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

    const wasTerminating = record.state === 'TERMINATING';
    record.state = wasTerminating ? 'TERMINATED' : exitCode === 0 ? 'COMPLETED' : 'FAILED';
    record.exitCode = exitCode;
    record.signal = signal;
    record.completedAt = new Date().toISOString();
    record.durationMs = Math.max(
      0,
      new Date(record.completedAt).getTime() - new Date(record.startedAt).getTime(),
    );

    this.emitLifecycleEvent({
      eventType: wasTerminating ? 'PROCESS_TERMINATED' : 'PROCESS_EXITED',
      timestamp: record.completedAt,
      processId: record.processId,
      workspaceId: record.workspaceId,
      actor: record.actor,
      executable: record.executable,
      exitCode,
      signal,
      durationMs: record.durationMs,
    });
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

    this.emitLifecycleEvent({
      eventType: 'PROCESS_TIMEOUT',
      timestamp: record.completedAt,
      processId: record.processId,
      workspaceId: record.workspaceId,
      actor: record.actor,
      executable: record.executable,
      durationMs: record.durationMs,
    });
  }

  public clear(): void {
    for (const record of this.processes.values()) {
      if (record._timeoutTimer) clearTimeout(record._timeoutTimer);
      if (record._killTimer) clearTimeout(record._killTimer);
      const isAlive = record.state === 'RUNNING' || record.state === 'TERMINATING';
      if (isAlive && record._child) {
        try {
          if (record._child.pid && process.platform !== 'win32') {
            process.kill(-record._child.pid, 'SIGKILL');
          } else {
            record._child.kill('SIGKILL');
          }
        } catch {
          // ignore
        }
      }
    }
    this.processes.clear();
  }
}
