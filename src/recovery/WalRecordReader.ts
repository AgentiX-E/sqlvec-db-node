/**
 * WalRecordReader — WAL segment discovery, sorting, and reading.
 *
 * Provides high-level utilities for reading WAL records from segment files
 * on disk.  Uses PgWalWriter.parseSegment() as the underlying parser.
 *
 * Capabilities:
 *   - Read a single segment file → WalRecord[]
 *   - Read from a specific LSN onward across all segments
 *   - Find the latest checkpoint record in a segment directory
 *   - List all segment files sorted by LSN
 *   - Gracefully handle empty directories and corrupted segments
 *
 * @module recovery/WalRecordReader
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PinoLogger } from '../monitoring/PinoLogger';
import { PgWalWriter as RecoveryWalWriter, type WalRecord as StorageWalRecord } from '../recovery/PgWalWriter';

// ── Recovery WalRecord type ─────────────────────────────────────

export type RecoveryWalRecordType = 'INSERT' | 'UPDATE' | 'DELETE' | 'COMMIT' | 'ABORT' | 'CHECKPOINT';

export interface RecoveryWalRecord {
  lsn: string;
  xid: number;
  type: RecoveryWalRecordType;
  table?: string;
  rowId?: any;
  data?: any;
  timestamp: number;
  activeXids?: number[];
  dirtyTables?: string[];
  prevLsn?: string;
}

export interface CheckpointRecord {
  /** LSN at the time the checkpoint was taken */
  lsn: string;
  /** The checkpoint's XID (usually 0, or the committing txn's XID) */
  xid: number;
  /** Unix timestamp (ms since epoch) */
  timestamp: number;
  /** Active (in-progress) XIDs at checkpoint time */
  activeXids: number[];
  /** Tables that had uncommitted modifications at checkpoint time */
  dirtyTables: string[];
}

// ── Logger ────────────────────────────────────────────────────────

const logger = PinoLogger.forComponent('WalRecordReader');

/** Convert PG LSN string (e.g. "0/1") to a numeric value for comparison. */
function lsnToNumeric(lsn: string): number {
  const [hi, lo] = lsn.split('/');
  return (parseInt(hi, 16) * 0x100000000) + parseInt(lo, 16);
}

// ── WalRecordReader ─────────────────────────────────────────────

export class WalRecordReader {
  /**
   * Read all records from a single WAL segment file (JSON-line format).
   *
   * @param segmentPath  Path to the .wal JSON-line segment file
   * @returns  Array of RecoveryWalRecord (empty if file does not exist or corrupted)
   */
  readSegment(segmentPath: string): RecoveryWalRecord[] {
    const rawRecords = RecoveryWalWriter.parseSegment(segmentPath);
    return rawRecords.map(r => this.formatToRecovery(r)).filter(Boolean) as RecoveryWalRecord[];
  }

  /**
   * Convert a JSON-line WalRecord into recovery-format WalRecord.
   */
  private formatToRecovery(r: StorageWalRecord): RecoveryWalRecord | null {
    const type = r.type as RecoveryWalRecordType;
    if (!['INSERT', 'UPDATE', 'DELETE', 'COMMIT', 'ABORT', 'CHECKPOINT'].includes(type)) {
      return null;
    }

    const base: RecoveryWalRecord = {
      lsn: r.lsn,
      xid: r.xid,
      type,
      timestamp: r.timestamp || Date.now(),
    };

    if (r.table !== undefined) base.table = r.table;
    if (r.rowId !== undefined) base.rowId = r.rowId;
    if (r.data !== undefined) base.data = r.data;
    if (r.activeXids !== undefined) base.activeXids = r.activeXids;
    if (r.dirtyTables !== undefined) base.dirtyTables = r.dirtyTables;

    return base;
  }

  /**
   * Read all WAL records starting from a given LSN across all segment files.
   *
   * @param segmentDir  Directory containing .wal segment files
   * @param startLSN    Starting LSN (PG format, e.g. "0/1")
   * @returns  Array of RecoveryWalRecord in chronological order
   */
  readFromLSN(segmentDir: string, startLSN: string): RecoveryWalRecord[] {
    const segments = this.listSegments(segmentDir);
    const startValue = lsnToNumeric(startLSN);

    const result: RecoveryWalRecord[] = [];

    for (const segPath of segments) {
      const records = this.readSegment(segPath);
      for (const record of records) {
        const lsnValue = lsnToNumeric(record.lsn);
        if (lsnValue >= startValue) {
          result.push(record);
        }
      }
    }

    return result;
  }

  /**
   * Find the latest CHECKPOINT record in a segment directory.
   *
   * Scans all segment files and returns the checkpoint with the highest
   * LSN value.  Returns `null` if no checkpoint exists.
   *
   * @param segmentDir  Directory containing .wal segment files
   * @returns  The latest CheckpointRecord, or null if none found
   */
  findLatestCheckpoint(segmentDir: string): CheckpointRecord | null {
    const segments = this.listSegments(segmentDir);

    let latestCheckpoint: CheckpointRecord | null = null;
    let latestLSN: number = -1;

    for (const segPath of segments) {
      const records = this.readSegment(segPath);
      for (const record of records) {
        if (record.type !== 'CHECKPOINT') continue;

        const checkpoint: CheckpointRecord = {
          lsn: record.lsn,
          xid: record.xid,
          timestamp: record.timestamp,
          activeXids: record.activeXids || [],
          dirtyTables: record.dirtyTables || [],
        };

        const lsnValue = lsnToNumeric(record.lsn);
        if (lsnValue > latestLSN) {
          latestLSN = lsnValue;
          latestCheckpoint = checkpoint;
        }
      }
    }

    return latestCheckpoint;
  }

  /**
   * List all WAL segment files in a directory, sorted by their
   * starting LSN (numeric value derived from file name order).
   *
   * @param segmentDir  Directory to scan
   * @returns  Array of absolute paths to .wal files, sorted
   */
  listSegments(segmentDir: string): string[] {
    if (!fs.existsSync(segmentDir)) {
      return [];
    }

    let entries: string[];
    try {
      entries = fs.readdirSync(segmentDir);
    } catch (err: any) {
      logger.warn({ segmentDir, error: err.message }, 'Failed to list WAL segment directory');
      return [];
    }

    const walFiles = entries
      .filter(entry => entry.endsWith('.wal'))
      .map(entry => path.join(segmentDir, entry));

    // Sort by the LSN embedded in the file name
    // PG format: TTTTTTTTLLLLLLLLSSSSSSSS.wal
    walFiles.sort((a, b) => {
      const aBase = path.basename(a);
      const bBase = path.basename(b);
      // Extract the hex segment identifier portion (first 24 chars before .wal)
      const aId = aBase.substring(0, 24);
      const bId = bBase.substring(0, 24);
      return aId.localeCompare(bId);
    });

    return walFiles;
  }

  /**
   * Check if a segment file is valid (non-empty and contains parseable binary records).
   *
   * @param segmentPath  Path to the .wal file
   * @returns  true if the file exists and has at least one valid record
   */
  isValidSegment(segmentPath: string): boolean {
    if (!fs.existsSync(segmentPath)) return false;
    const stats = fs.statSync(segmentPath);
    if (stats.size === 0) return false;

    try {
      const records = this.readSegment(segmentPath);
      return records.length > 0;
    } catch {
      return false;
    }
  }
}

export default WalRecordReader;
