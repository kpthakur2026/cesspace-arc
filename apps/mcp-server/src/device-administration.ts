/**
 * CesSpace ARC — RC-05 Task 9 Operator Device and Session Administration
 *
 * The server-side half of the authenticated LOCAL admin channel's device and
 * session administration surface. It adds no listener, no transport, and no
 * authentication mechanism: every operation here is reached only through
 * `AdminIpcServer`, and only after that channel's existing Ed25519
 * challenge-response proof has been verified against the trusted operator key.
 *
 * Design invariants:
 * - ONE authoritative trust store. Every read and every mutation goes through
 *   the gateway's `EnrollmentBootstrap`, which owns the SAME in-memory
 *   `DeviceTrustStore` that remote request admission reads. No second store is
 *   loaded, no shadow device table is retained, and the trust-store file is
 *   never read or written directly from here.
 * - ONE session authority and ONE transport registry. Session listing and
 *   revocation use the existing `SessionManager` primitives, and transport
 *   teardown uses the Task-8 `RemoteMcpSurface` registry — the same objects the
 *   remote gateway serves from. There is no second session registry.
 * - Mutations are durable transactions. Nothing is reported as successful until
 *   the candidate state has been persisted, verified, and swapped in; see
 *   `EnrollmentBootstrap.applyTrustStoreMutation`.
 * - Snapshots, never internal objects. Every view is rebuilt field by field, so
 *   no caller can mutate trust state through a returned record and no mutable
 *   internal object escapes.
 * - Bounded, non-secret output. No raw session token, token digest, private key,
 *   certificate bytes, enrollment secret, authorization header, limiter key, or
 *   trust-store path appears in any result or error. Public SPKI pins appear
 *   only in `devices.inspect`, which is the view pin administration requires.
 *
 * This module contains NO MCP-facing schema and is reachable from NO remote
 * surface: it is not an MCP tool, an HTTP endpoint, or a WebSocket channel.
 */

import { ArcError, type AdminErrorCode } from '@cesspace-arc/protocol';
import type {
  AdminDeviceInspectResult,
  AdminDevicePinMutationResult,
  AdminDeviceRenameResult,
  AdminDeviceRevokeResult,
  AdminDeviceSummary,
  AdminDevicesListResult,
  AdminSessionRevokeResult,
  AdminSessionSummary,
  AdminSessionsListResult,
} from '@cesspace-arc/protocol';
import type { DeviceTrustStore, EnrolledDeviceRecord, SessionManager } from '@cesspace-arc/auth';

import type { EnrollmentBootstrap, TrustStoreMutationOutcome } from './enrollment-bootstrap.js';
import type { RemoteMcpSurface } from './remote-mcp-surface.js';
import type { GatewayAuditSink } from './gateway-audit.js';

/**
 * The slice of the gateway's `EnrollmentBootstrap` that administration needs.
 *
 * Deliberately NARROWER than the bootstrap itself: the administration facade
 * receives the durable-transaction primitive and the frozen snapshot accessors,
 * and nothing that could re-attach a transport or reach the mutable store. The
 * return value of `applyTrustStoreMutation` already reports whether storage
 * failed and whether the fail-closed latch engaged, so no separate latch
 * accessor is exposed.
 */
export type DeviceTrustAuthority = Pick<
  EnrollmentBootstrap,
  'snapshotDeviceRecords' | 'applyTrustStoreMutation'
>;

/**
 * Bounded result of one administrative operation.
 *
 * The failure arm carries an already-bounded `AdminErrorCode`, so the IPC layer
 * performs no translation and cannot invent operator-visible detail out of an
 * internal error. There is no third arm: an operation either happened or it did
 * not, and a caller can never mistake "not attempted" for success.
 */
export type AdministrationOutcome<T> =
  { ok: true; result: T } | { ok: false; code: AdminErrorCode };

/**
 * The device/session administration authority consumed by `AdminIpcServer`.
 *
 * Declared as an interface so the IPC server depends on the CAPABILITY rather
 * than on the gateway: a channel with no composed authority refuses every
 * administration request instead of loading a second trust store of its own.
 */
export interface DeviceAdministrationAuthority {
  listDevices(): AdministrationOutcome<AdminDevicesListResult>;
  inspectDevice(deviceId: string): AdministrationOutcome<AdminDeviceInspectResult>;
  revokeDevice(deviceId: string): Promise<AdministrationOutcome<AdminDeviceRevokeResult>>;
  renameDevice(
    deviceId: string,
    displayLabel: string,
  ): AdministrationOutcome<AdminDeviceRenameResult>;
  addPin(deviceId: string, spkiPin: string): AdministrationOutcome<AdminDevicePinMutationResult>;
  removePin(deviceId: string, spkiPin: string): AdministrationOutcome<AdminDevicePinMutationResult>;
  listSessions(): AdministrationOutcome<AdminSessionsListResult>;
  revokeSession(sessionId: string): Promise<AdministrationOutcome<AdminSessionRevokeResult>>;
}

/**
 * The ONE refusal used when no authoritative composition can answer.
 *
 * It covers "no remote composition exists" and "durable storage can no longer
 * be proven" identically and deliberately: an operator learns that the
 * authority is not usable right now, and nothing about whether a trust store
 * exists, where it lives, or what happened to it.
 */
function unavailable<T>(): AdministrationOutcome<T> {
  return { ok: false, code: 'ADMINISTRATION_UNAVAILABLE' };
}

/**
 * Maps a domain refusal to a bounded admin code. Never leaks domain detail.
 *
 * `DEVICE_NOT_ENROLLED` and `NOT_FOUND_OR_NOT_PENDING` are the same operator
 * fact — the named device is not there — and are reported identically, so the
 * response is not an oracle for whether a device ever existed.
 */
function mapDomainError(err: ArcError): AdminErrorCode {
  if (err.code === 'DEVICE_NOT_ENROLLED') {
    return 'NOT_FOUND_OR_NOT_PENDING';
  }
  if (err.code === 'RESOURCE_EXHAUSTED') {
    return 'RESOURCE_EXHAUSTED';
  }
  if (err.code === 'INVALID_REQUEST_SCHEMA') {
    return 'INVALID_ADMIN_REQUEST';
  }
  return 'INTERNAL_ERROR';
}

/** Projects one authoritative record into the bounded list view. */
function toDeviceSummary(device: EnrolledDeviceRecord): AdminDeviceSummary {
  return {
    deviceId: device.deviceId,
    clientId: device.clientId,
    clientType: device.clientType,
    displayLabel: device.displayLabel,
    enrolledAt: device.enrolledAt,
    revoked: device.revoked,
    activePinCount: device.pins.length,
  };
}

/**
 * Composition of the gateway's authoritative trust state, the process session
 * authority, and the Task-8 transport registry.
 *
 * Constructed by `RemoteGateway` and handed to `AdminIpcServer`; it is never
 * constructed from configuration, the environment, the CLI, or a request.
 */
export class GatewayDeviceAdministration implements DeviceAdministrationAuthority {
  constructor(
    private readonly bootstrap: DeviceTrustAuthority,
    private readonly sessionManager: SessionManager,
    /** Resolved per call: the surface is attached before the listener binds. */
    private readonly getMcpSurface: () => RemoteMcpSurface | undefined,
    /**
     * The ONE gateway lifecycle audit sink (rc05 §24).
     *
     * Optional so a caller that composes administration over a trust store with
     * no audit chain — as the focused administration tests do — can construct
     * the authority directly; the server composition always supplies it.
     */
    private readonly auditSink?: GatewayAuditSink,
  ) {}

  /**
   * True when the composition can answer SESSION administration requests.
   *
   * The transport registry is required for those: a session revocation that
   * could not tear down its Task-8 transport would be a partial revocation, so
   * its absence is a refusal rather than a degraded answer.
   */
  private hasTransportRegistry(): boolean {
    return this.getMcpSurface() !== undefined;
  }

  public listDevices(): AdministrationOutcome<AdminDevicesListResult> {
    // Device READS deliberately require neither the transport registry nor an
    // unlatched store.
    //
    // They perform no teardown, and the authoritative in-memory store is what
    // remote admission is actually serving from — so reporting it is truthful
    // about the running trust root even while its durability is in question,
    // which is exactly when an operator most needs to see it. MUTATIONS below
    // consult the latch and refuse.
    const devices = this.bootstrap.snapshotDeviceRecords().map(toDeviceSummary);
    return { ok: true, result: { devices } };
  }

  public inspectDevice(deviceId: string): AdministrationOutcome<AdminDeviceInspectResult> {
    const device = this.bootstrap
      .snapshotDeviceRecords()
      .find((record) => record.deviceId === deviceId);
    if (device === undefined) {
      return { ok: false, code: 'NOT_FOUND_OR_NOT_PENDING' };
    }
    // The exact ACTIVE pin set is disclosed here and only here: the
    // authenticated operator needs the verbatim values to manage the §7 P-7
    // rotation overlap window. Pins are public values and at most two are
    // returned.
    return { ok: true, result: { ...toDeviceSummary(device), pins: [...device.pins] } };
  }

  /**
   * `device.revoke` — the frozen §9 sequence.
   *
   * The trust-store mutation is committed FIRST, and only a `COMMITTED` outcome
   * proceeds to session revocation. A refused or non-durable mutation therefore
   * cannot revoke a single session, which is what keeps "the operator was told
   * the device is revoked" and "the device's sessions are gone" inseparable.
   */
  public async revokeDevice(
    deviceId: string,
  ): Promise<AdministrationOutcome<AdminDeviceRevokeResult>> {
    const surface = this.getMcpSurface();
    if (surface === undefined) {
      return unavailable();
    }

    const mutation = this.applyMutation((candidate) => {
      candidate.revokeDevice(deviceId);
    });
    if (!mutation.ok) {
      return mutation;
    }

    // §24 DEVICE_REVOKED, emitted AFTER the durable transaction committed, so a
    // refused or non-durable revocation is never recorded as one. It precedes
    // the session records the next step emits, which is the order the §9
    // sequence actually performs them in: the device trust state changes first,
    // and its sessions are torn down as a consequence.
    this.auditSink?.emit({ eventType: 'DEVICE_REVOKED', deviceId });

    // Steps 7-8, and they are AWAITED: the Task-5 sessions are removed and the
    // matching Task-8 transport registry entries are closed BEFORE success is
    // reported, so device revocation is immediate rather than deferred to the
    // client's next request.
    const { sessionsRevoked, transportsClosed } =
      await surface.revokeDeviceSessionsForAdmin(deviceId);

    return { ok: true, result: { deviceId, revoked: true, sessionsRevoked, transportsClosed } };
  }

  public renameDevice(
    deviceId: string,
    displayLabel: string,
  ): AdministrationOutcome<AdminDeviceRenameResult> {
    const mutation = this.applyMutation((candidate) => {
      candidate.renameDevice(deviceId, displayLabel);
    });
    if (!mutation.ok) {
      return mutation;
    }
    return { ok: true, result: { deviceId, displayLabel } };
  }

  public addPin(
    deviceId: string,
    spkiPin: string,
  ): AdministrationOutcome<AdminDevicePinMutationResult> {
    const mutation = this.applyMutation((candidate) => {
      candidate.addPinToDevice(deviceId, spkiPin);
    });
    if (!mutation.ok) {
      return mutation;
    }
    return { ok: true, result: { deviceId, activePinCount: this.activePinCount(deviceId) } };
  }

  public removePin(
    deviceId: string,
    spkiPin: string,
  ): AdministrationOutcome<AdminDevicePinMutationResult> {
    const mutation = this.applyMutation((candidate) => {
      candidate.removePinFromDevice(deviceId, spkiPin);
    });
    if (!mutation.ok) {
      return mutation;
    }
    return { ok: true, result: { deviceId, activePinCount: this.activePinCount(deviceId) } };
  }

  public listSessions(): AdministrationOutcome<AdminSessionsListResult> {
    if (!this.hasTransportRegistry()) {
      return unavailable();
    }
    // `listSessions()` purges expired state first, so every entry returned is
    // live and there is no expired or revoked state to report.
    const sessions: AdminSessionSummary[] = this.sessionManager.listSessions().map((session) => ({
      sessionId: session.sessionId,
      deviceId: session.deviceId,
      clientId: session.clientId,
      clientType: session.clientType,
      issuedAt: session.issuedAt,
      state: 'ACTIVE' as const,
    }));
    return { ok: true, result: { sessions } };
  }

  /**
   * `session revoke` — exactly one session.
   *
   * An unknown, expired, or already-revoked identifier is a bounded refusal
   * that mutates nothing and can never reach another session's transport.
   */
  public async revokeSession(
    sessionId: string,
  ): Promise<AdministrationOutcome<AdminSessionRevokeResult>> {
    const surface = this.getMcpSurface();
    if (surface === undefined) {
      return unavailable();
    }
    const { revoked, transportClosed } = await surface.revokeSessionForAdmin(sessionId);
    if (!revoked) {
      return { ok: false, code: 'NOT_FOUND_OR_NOT_PENDING' };
    }
    return { ok: true, result: { sessionId, state: 'REVOKED', transportClosed } };
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  /** Applies ONE durable trust-store mutation, or reports why it did not. */
  private applyMutation(
    mutate: (candidate: DeviceTrustStore) => void,
  ): AdministrationOutcome<null> {
    const outcome: TrustStoreMutationOutcome = this.bootstrap.applyTrustStoreMutation(mutate);
    if (outcome.outcome === 'COMMITTED') {
      return { ok: true, result: null };
    }
    if (outcome.outcome === 'REJECTED') {
      return { ok: false, code: mapDomainError(outcome.error) };
    }
    // A non-durable mutation is never reported as success. The fail-closed
    // storage latch is deliberately NOT distinguished for the operator.
    return unavailable();
  }

  private activePinCount(deviceId: string): number {
    const device = this.bootstrap
      .snapshotDeviceRecords()
      .find((record) => record.deviceId === deviceId);
    return device === undefined ? 0 : device.pins.length;
  }
}
