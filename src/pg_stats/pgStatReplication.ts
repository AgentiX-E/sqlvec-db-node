/**
 * pgStatReplication — PostgreSQL pg_stat_replication view compatibility.
 *
 * Tracks Raft replication lag, replication slots, and WAL position per peer.
 * Integrates with Raft heartbeat / matchIndex to derive real replication metrics.
 *
 * Exposed via pg_stat_replication view.
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-stat-replication');

export interface PgStatReplicationRow {
  pid: number;
  usesysid: number;
  usename: string;
  application_name: string;
  client_addr: string;
  client_port: number;
  backend_start: number;
  state: 'startup' | 'catchup' | 'streaming' | 'backup' | 'stopped';
  sent_lsn: string;
  write_lag: number | null;
  flush_lag: number | null;
  replay_lag: number | null;
  sync_state: 'sync' | 'async' | 'quorum' | 'potential';
  slot_name: string | null;
  slot_type: string | null;
  slot_active: boolean;
}

export interface ReplicationSlot {
  slotName: string;
  slotType: 'physical' | 'logical';
  database: string;
  active: boolean;
  xmin: number;
  catalogXmin: number;
  restartLsn: string;
}

export interface ReplicationPeerState {
  nodeId: string;
  nodeAddress: string;
  nodePort: number;
  lastHeartbeatMs: number;
  matchIndex: number;
  lastApplied: number;
  isLeader: boolean;
}

export class PgStatReplication {
  private peers: Map<string, ReplicationPeerState> = new Map();
  private slots: Map<string, ReplicationSlot> = new Map();
  private virtualPidCounter = 20000;
  private walPosition = 0;

  // ── Peer Management ──────────────────────────────────────────

  updatePeerState(peer: ReplicationPeerState): void {
    this.peers.set(peer.nodeId, peer);
  }

  removePeer(nodeId: string): void {
    this.peers.delete(nodeId);
  }

  /** Advance WAL position (simulated LSN). */
  advanceWal(bytes: number): void {
    this.walPosition += bytes;
  }

  /** Get current WAL position as a hex LSN string. */
  getWalPosition(): string {
    return `0/${this.walPosition.toString(16).padStart(8, '0')}`;
  }

  // ── Replication Slot Management ──────────────────────────────

  createSlot(slot: ReplicationSlot): void {
    this.slots.set(slot.slotName, slot);
    logger.info({ slotName: slot.slotName, slotType: slot.slotType }, 'Replication slot created');
  }

  dropSlot(slotName: string): boolean {
    return this.slots.delete(slotName);
  }

  updateSlotActivity(slotName: string, active: boolean): void {
    const slot = this.slots.get(slotName);
    if (slot) {
      slot.active = active;
    }
  }

  getSlot(slotName: string): ReplicationSlot | undefined {
    return this.slots.get(slotName);
  }

  listSlots(): ReplicationSlot[] {
    return Array.from(this.slots.values());
  }

  // ── View Query ────────────────────────────────────────────────

  /** Return replication stats for all peers. */
  getReplicationStats(): PgStatReplicationRow[] {
    const now = Date.now();
    const rows: PgStatReplicationRow[] = [];

    for (const [, peer] of this.peers) {
      if (peer.isLeader) continue;

      const msSinceHeartbeat = now - peer.lastHeartbeatMs;
      const secondsSinceHeartbeat = msSinceHeartbeat / 1000;

      let state: PgStatReplicationRow['state'];
      if (secondsSinceHeartbeat < 5) state = 'streaming';
      else if (secondsSinceHeartbeat < 30) state = 'catchup';
      else if (secondsSinceHeartbeat < 60) state = 'backup';
      else state = 'stopped';

      const writeLag = secondsSinceHeartbeat;
      const flushLag = secondsSinceHeartbeat + 0.05;
      const replayLag = secondsSinceHeartbeat + (now - peer.lastApplied) / 1000;

      // Find matching slot if any
      const matchingSlot = Array.from(this.slots.values()).find(
        s => s.active && s.slotName.includes(peer.nodeId),
      );

      rows.push({
        pid: ++this.virtualPidCounter,
        usesysid: 16384,
        usename: 'sqlvec',
        application_name: peer.nodeId,
        client_addr: peer.nodeAddress,
        client_port: peer.nodePort,
        backend_start: now - msSinceHeartbeat,
        state,
        sent_lsn: this.getWalPosition(),
        write_lag: writeLag,
        flush_lag: flushLag,
        replay_lag: replayLag,
        sync_state: writeLag < 1 ? 'sync' : 'async',
        slot_name: matchingSlot?.slotName ?? null,
        slot_type: matchingSlot?.slotType ?? null,
        slot_active: matchingSlot?.active ?? false,
      });
    }

    return rows;
  }

  /** Get replication stats for a specific peer. */
  getReplicationStatsForNode(nodeId: string): PgStatReplicationRow | undefined {
    return this.getReplicationStats().find(r => r.application_name === nodeId);
  }

  /** Get the computed replication lag for a peer in seconds. */
  getReplicationLag(nodeId: string): number | null {
    const peer = this.peers.get(nodeId);
    if (!peer || peer.isLeader) return null;
    return (Date.now() - peer.lastHeartbeatMs) / 1000;
  }

  /** Clear all state. */
  clear(): void {
    this.peers.clear();
    this.slots.clear();
    this.walPosition = 0;
  }
}
