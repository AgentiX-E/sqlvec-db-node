/**
 * PITRWalBridge — Bridges PgWalWriter (binary WAL) to PITR archive.
 *
 * Subscribes to PgWalWriter's wal:record callbacks and writes
 * enriched PitrWALEntry records to PITRWriter. Records carry the
 * real PG-style LSN (pgLsn) for LSN-precision PITR recovery.
 *
 * This is the key interconnect that closes the gap between the two
 * WAL pipelines:
 *   1. PgWalWriter binary segments (LSN-precision, MVCC semantics)
 *   2. PITRWriter JSONL+gzip archive (raft-entry-precision)
 *
 * Usage:
 *   const pitrWriter = new PITRWriter(archiveDir);
 *   const bridge = new PITRWalBridge(pitrWriter, 'shard-0');
 *   bridge.attach();  // subscribes to PgWalWriter
 *
 * @module pitr/PITRWalBridge
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import type { PgWalWriter, WalRecord } from '../storage/PgWalWriter';
import type { PITRWriter } from './PITRWriter';

const logger = PinoLogger.forComponent('PITRWalBridge');

// ── Resource manager mapping ───────────────────────────────────────

const WAL_RECORD_TYPES: Record<string, 'heap_insert' | 'heap_delete' | 'heap_update' | 'commit' | 'abort' | 'checkpoint' | 'switch' | 'other'> = {
  INSERT: 'heap_insert',
  DELETE: 'heap_delete',
  UPDATE: 'heap_update',
  COMMIT: 'commit',
  ABORT: 'abort',
  CHECKPOINT_SHUTDOWN: 'checkpoint',
  CHECKPOINT_ONLINE: 'checkpoint',
  SWITCH: 'switch',
};

/**
 * Bridge that connects PgWalWriter binary WAL records to PITRWriter
 * archive entries, enriching them with PG-style LSNs.
 */
export class PITRWalBridge {
  private pitrWriter: PITRWriter;
  private shardId: string;
  private attached = false;
  private recordCount = 0;
  /** Bound callback reference for detach */
  private boundCallback: ((record: any) => void) | null = null;
  /** Reference to the PgWalWriter for detach */
  private walWriter: PgWalWriter | null = null;

  constructor(pitrWriter: PITRWriter, shardId: string = 'shard-0') {
    this.pitrWriter = pitrWriter;
    this.shardId = shardId;
  }

  /**
   * Subscribe to PgWalWriter's record callbacks.
   * Must be called after PgWalWriter is configured.
   */
  attach(walWriter: PgWalWriter): void {
    if (this.attached) {
      logger.warn('PITRWalBridge already attached');
      return;
    }
    this.attached = true;
    this.walWriter = walWriter;

    this.boundCallback = (record: any) => {
      this.onWalRecord(record);
    };

    walWriter.onRecord(this.boundCallback);

    logger.info({ shardId: this.shardId }, 'PITRWalBridge attached to PgWalWriter');
  }

  /**
   * Handle a single WalRecord from PgWalWriter.
   * Creates a PitrWALEntry with the real PG-style LSN and writes it
   * to PITRWriter.
   */
  private onWalRecord(record: WalRecord): void {
    this.recordCount++;

    // Build a meaningful data representation from the record
    const entryData = JSON.stringify({
      type: this.mapRecordType(record.resourceManager, record.recordType),
      lsn: record.lsn,
      prevLsn: record.prevLsn,
      xid: record.xid,
      resourceManager: record.resourceManager,
      recordType: record.recordType,
      table: (record as any).table,
      timestamp: record.timestamp,
    });

    // Use PG LSN to derive segment index and entry offset
    const lsnBytes = this.lsnToBytes(record.lsn);

    this.pitrWriter.append(
      lsnBytes,        // raftIndex: use LSN bytes as proxy (unique, monotonically increasing)
      record.xid,      // raftTerm: use xid
      this.shardId,
      entryData,
    );
  }

  /**
   * Get the total number of records processed.
   */
  get processedCount(): number {
    return this.recordCount;
  }

  /**
   * Disconnect from PgWalWriter.
   */
  detach(): void {
    if (!this.attached || !this.walWriter || !this.boundCallback) return;
    this.attached = false;
    this.walWriter.removeRecordListener(this.boundCallback);
    this.walWriter = null;
    this.boundCallback = null;
    logger.info({ shardId: this.shardId, processed: this.recordCount }, 'PITRWalBridge detached');
  }

  /**
   * Map a resource manager + record type to a human-readable label.
   */
  private mapRecordType(rm: string, type: number): string {
    // Heap records: 0=INSERT, 1=DELETE, 2=UPDATE, 3=HOT_UPDATE
    if (rm === 'Heap' || rm === 'Heap2') {
      const heapNames = ['heap_insert', 'heap_delete', 'heap_update', 'heap_hot_update'];
      return heapNames[type] ?? 'heap_unknown';
    }
    // Transaction records: 0=COMMIT, 1=ABORT
    if (rm === 'Transaction') {
      return type === 0 ? 'commit' : 'abort';
    }
    // XLOG records
    if (rm === 'XLOG') {
      const xlogNames = ['checkpoint_shutdown', 'checkpoint_online', 'switch'];
      return xlogNames[type] ?? 'xlog_unknown';
    }
    return 'other';
  }

  /**
   * Convert a PG-style LSN string to a numeric value.
   */
  private lsnToBytes(lsn: string): number {
    const parts = lsn.split('/');
    if (parts.length !== 2) return 0;
    const upper = parseInt(parts[0], 16);
    const lower = parseInt(parts[1], 16);
    if (isNaN(upper) || isNaN(lower)) return 0;
    return upper * 0x100000000 + lower;
  }
}
