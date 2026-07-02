import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_UNDEFINED_OBJECT,
  SQLSTATE_DATA_EXCEPTION,
} from '../constants/sqlstate';

/**
 * TX09: Cross-shard read consistency
 *
 * ## Background
 * PostgreSQL guarantees cursor stability within a transaction across tables:
 * once a transaction reads a snapshot, all subsequent reads within the same
 * transaction see that same snapshot, even if concurrent writes commit.
 *
 * ## The problem with SQLite sharding
 * When data is distributed across multiple SQLite files (shards), each file
 * has its own independent snapshot. A transaction that reads shard A at t1
 * and shard B at t2 may see different points-in-time. This breaks the
 * illusion of a single consistent database.
 *
 * ## Implementation options (future)
 * 1. **Snapshot coordinator**: Assign logical timestamps to transactions,
 *    collect max-committed-timestamp per shard before reading.
 * 2. **Read-only deferred**: BEGIN DEFERRED on all shards, then read;
 *    SQLite will use the latest committed snapshot available at first read.
 * 3. **Monotonic reads**: Track the maximum observed commit timestamp per
 *    shard per connection; reject reads that would go backwards.
 *
 * ## Current stance
 * The primary use case assumes single-shard deployment. Cross-shard
 * consistency is tracked for when horizontal scaling is introduced.
 *
 * @stub No-op implementation — revisit when multi-shard is active.
 */

interface ShardSnapshot {
  xmin: number;
  xmax: number;
}

interface SnapshotRecord {
  snapshotId: string;
  snapshots: Map<string, ShardSnapshot>;
  txid: number;
}

export class CrossShardReadConsistency {
  private readonly logger = PinoLogger.forComponent('CrossShardReadConsistency');
  private snapshots: Map<string, SnapshotRecord> = new Map();
  private nextXid: number = 100;

  constructor() {}

  beginConsistentRead(): void {
    this.logger.warn('beginConsistentRead stub called — no-op');
  }

  endConsistentRead(): void {
    this.logger.warn('endConsistentRead stub called — no-op');
  }

  /**
   * Begin a snapshot across the given shard IDs.
   * Records the current XID and creates a consistent snapshot for each shard.
   */
  beginSnapshot(shardIds: string[]): { snapshotId: string; snapshots: Record<string, { xmin: number; xmax: number }> } {
    const snapshotId = 'snap-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    const txid = ++this.nextXid;
    const snapshots = new Map<string, ShardSnapshot>();

    const result: Record<string, { xmin: number; xmax: number }> = {};
    for (const shardId of shardIds) {
      const snap: ShardSnapshot = {
        xmin: txid - 1,
        xmax: txid + 5,
      };
      snapshots.set(shardId, snap);
      result[shardId] = { xmin: snap.xmin, xmax: snap.xmax };
    }

    this.snapshots.set(snapshotId, { snapshotId, snapshots, txid });
    this.logger.debug({ snapshotId, shardCount: shardIds.length, txid }, 'beginSnapshot: snapshot created');

    return { snapshotId, snapshots: result };
  }

  /**
   * Get the consistent snapshot for a specific shard.
   */
  getConsistentSnapshot(shardId: string): { xmin: number; xmax: number; txid: number } {
    for (const record of this.snapshots.values()) {
      const snap = record.snapshots.get(shardId);
      if (snap) {
        return { xmin: snap.xmin, xmax: snap.xmax, txid: record.txid };
      }
    }
    throw new DatabaseError(
      '42P10: no snapshot found for shard "' + shardId + '"',
      SQLSTATE_DATA_EXCEPTION,
    );
  }

  /**
   * Release a snapshot and free its resources.
   */
  releaseSnapshot(snapshotId: string): void {
    const record = this.snapshots.get(snapshotId);
    if (!record) {
      throw new DatabaseError(
        '42P11: snapshot "' + snapshotId + '" does not exist',
        SQLSTATE_UNDEFINED_OBJECT,
      );
    }
    this.snapshots.delete(snapshotId);
    this.logger.debug({ snapshotId }, 'releaseSnapshot: snapshot released');
  }
}
