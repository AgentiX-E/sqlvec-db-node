/**
 * ReplicationProtocol — PG physical replication protocol message handlers.
 *
 * Implements handlers for the core PG replication protocol messages:
 *   - IDENTIFY_SYSTEM
 *   - START_REPLICATION
 *   - CREATE_REPLICATION_SLOT
 *   - DROP_REPLICATION_SLOT
 *   - READ_REPLICATION_SLOT
 *
 * Delegates slot management to ReplicationSlotManager and WAL position
 * tracking to WALStateManager.
 *
 * @module ReplicationProtocol
 */

import { WALStreamContext } from './WALStreamContext';
import { ReplicationSlotManager } from '../replication/ReplicationSlotManager';
import { WALStateManager } from '../storage/WALStateManager';

// ── Types ───────────────────────────────────────────────────────────

export interface ReplicationSlot {
  slotName: string;
  plugin: string | null;
  slotType: 'physical' | 'logical';
  datoid: number;
  database: string;
  active: boolean;
  xmin: number;
  catalogXmin: number;
  restartLsn: number;
  confirmedFlushLsn: number;
}

export interface IdentifySystemResult {
  systemId: string;
  timeline: number;
  xlogPos: string;
  dbOid: number;
}

// ── ReplicationProtocol ──────────────────────────────────────────────

export class ReplicationProtocol {
  private slotManager: ReplicationSlotManager;
  private walState: WALStateManager;
  private nodeId: string;

  constructor(slotManager?: ReplicationSlotManager, nodeId?: string) {
    this.slotManager = slotManager ?? new ReplicationSlotManager();
    this.walState = WALStateManager.getInstance();
    this.nodeId = nodeId ?? '1';
  }

  /**
   * Handle IDENTIFY_SYSTEM.
   *
   * Returns the system identity: system_id, timeline, xlogpos, and db_oid.
   * The system_id and db_oid are deterministic placeholders derived from
   * the node ID for reproducibility.
   */
  identifySystem(): IdentifySystemResult {
    let lsn = '0/0';
    try {
      lsn = this.walState.getCurrentLSN() ?? '0/0';
    } catch {
      // WALStateManager may not be initialized
    }

    // Derive a deterministic system_id from the node ID
    const systemId = (BigInt(parseInt(this.nodeId, 10) || 1) + BigInt('1111111111111111111')).toString();

    // Derive a deterministic db_oid from the node ID
    const dbOid = parseInt(this.nodeId, 10) || 1;

    return {
      systemId,
      timeline: 1,
      xlogPos: lsn,
      dbOid,
    };
  }

  /**
   * Handle START_REPLICATION.
   *
   * Creates a WAL streaming context starting at the given LSN.
   * In production, this would be consumed by WALSender to stream
   * WAL records over a persistent TCP/ZeroMQ connection.
   *
   * @param params  Object with `lsn` (starting LSN) and `timeline`
   * @returns       WALStreamContext with streaming metadata
   */
  startReplication(params: { lsn: string; timeline: number }): WALStreamContext {
    const currentLsn = this.walState.getCurrentLSN() || '0/0';

    const context: WALStreamContext = {
      startLsn: params.lsn || '0/0',
      endLsn: currentLsn,
      timeline: params.timeline || 1,
      sessionId: `stream_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      startedAt: Date.now(),
      active: true,
    };

    return context;
  }

  /**
   * Handle CREATE_REPLICATION_SLOT.
   *
   * Creates a replication slot of the specified type.
   * For logical slots, the plugin name is required.
   *
   * @param slotName  Name of the slot to create
   * @param slotType  'physical' or 'logical'
   * @param plugin    Plugin name (required for logical slots)
   * @returns         The created ReplicationSlot
   * @throws          If the slot already exists or plugin missing for logical
   */
  createReplicationSlot(slotName: string, slotType: 'physical' | 'logical', plugin?: string): ReplicationSlot {
    return this.slotManager.create(slotName, slotType, plugin);
  }

  /**
   * Handle DROP_REPLICATION_SLOT.
   *
   * @param slotName  Name of the slot to drop
   * @returns         `true` if the slot was found and dropped, `false` otherwise
   */
  dropReplicationSlot(slotName: string): boolean {
    return this.slotManager.drop(slotName);
  }

  /**
   * List all replication slots.
   */
  listReplicationSlots(): ReplicationSlot[] {
    return this.slotManager.list();
  }

  /**
   * Get a specific replication slot by name.
   *
   * @param slotName  Name of the slot to retrieve
   * @returns         The slot, or `null` if not found
   */
  getReplicationSlot(slotName: string): ReplicationSlot | null {
    return this.slotManager.get(slotName) ?? null;
  }

  /**
   * Get the underlying ReplicationSlotManager.
   */
  getSlotManager(): ReplicationSlotManager {
    return this.slotManager;
  }
}
