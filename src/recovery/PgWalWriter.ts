/**
 * PgWalWriter — PostgreSQL-compatible WAL record writer and parser.
 *
 * Writes transaction log records as JSON lines to WAL segment files.
 * Each record describes one DML operation (INSERT/UPDATE/DELETE) or
 * transaction boundary (COMMIT/ABORT), with enough metadata for crash
 * recovery replay.
 *
 * ## Record Format
 *
 * Each segment file is a sequence of JSON lines (one per record):
 *
 * ```json
 * {"lsn":"0/1","xid":1,"type":"INSERT","table":"users","rowId":42,"data":{...},"timestamp":1700000000000}
 * {"lsn":"0/2","xid":1,"type":"COMMIT","timestamp":1700000001000}
 * ```
 *
 * ## Checkpoint Record
 *
 * Special record type "CHECKPOINT" marks a consistent recovery point:
 *
 * ```json
 * {"lsn":"0/3","xid":0,"type":"CHECKPOINT","activeXids":[1],"dirtyTables":["users"],"timestamp":...}
 * ```
 *
 * @module recovery/PgWalWriter
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PinoLogger } from '../monitoring/PinoLogger';

// ── Types ────────────────────────────────────────────────────────

export type WalRecordType = 'INSERT' | 'UPDATE' | 'DELETE' | 'COMMIT' | 'ABORT' | 'CHECKPOINT';

export interface WalRecord {
  /** Log Sequence Number (monotonic within a segment) */
  lsn: string;
  /** Transaction ID */
  xid: number;
  /** Record type */
  type: WalRecordType;
  /** Table name (for DML records) */
  table?: string;
  /** Primary key value (for DML records) */
  rowId?: any;
  /** Row data payload (for INSERT/UPDATE) */
  data?: any;
  /** List of active XIDs at checkpoint time (for CHECKPOINT records) */
  activeXids?: number[];
  /** List of dirty tables at checkpoint time (for CHECKPOINT records) */
  dirtyTables?: string[];
  /** Unix timestamp (ms since epoch) */
  timestamp: number;
}

// ── Constants ────────────────────────────────────────────────────

const DEFAULT_SEGMENT_SIZE = 16 * 1024 * 1024; // 16 MB

// ── Logger ────────────────────────────────────────────────────────

const logger = PinoLogger.forComponent('PgWalWriter');

// ── PgWalWriter ─────────────────────────────────────────────────

export class PgWalWriter {
  private _segmentDir: string;
  private _currentSegmentPath: string | null = null;
  private _currentLSN: number = 0;
  private _segmentSize: number;

  constructor(segmentDir: string, segmentSize: number = DEFAULT_SEGMENT_SIZE) {
    this._segmentDir = segmentDir;
    this._segmentSize = segmentSize;
  }

  // ── Configuration ────────────────────────────

  get segmentDir(): string {
    return this._segmentDir;
  }

  get segmentSize(): number {
    return this._segmentSize;
  }

  get currentLSN(): number {
    return this._currentLSN;
  }

  // ── Segment management ───────────────────────

  /**
   * Open a new WAL segment file for writing.
   * If a segment is already open, it is finalized first.
   */
  openSegment(): string {
    if (this._currentSegmentPath) {
      this.finalizeSegment();
    }

    const segName = this.formatSegmentName(this._currentLSN);
    const segPath = path.join(this._segmentDir, segName);

    // Ensure directory exists
    fs.mkdirSync(this._segmentDir, { recursive: true });

    this._currentSegmentPath = segPath;
    return segPath;
  }

  /**
   * Finalize (close) the current segment file.
   */
  finalizeSegment(): void {
    this._currentSegmentPath = null;
  }

  /**
   * Get the path to the current open segment.
   */
  get currentSegmentPath(): string | null {
    return this._currentSegmentPath;
  }

  // ── Writing ──────────────────────────────────

  /**
   * Write a WAL record to the current segment file.
   * Automatically opens a new segment if none is open.
   *
   * @returns The LSN assigned to this record
   */
  writeRecord(record: Omit<WalRecord, 'lsn'>): string {
    const lsn = this.allocateLSN();

    if (!this._currentSegmentPath) {
      this.openSegment();
    }

    const fullRecord: WalRecord = {
      ...record,
      lsn,
    };

    const line = JSON.stringify(fullRecord) + '\n';
    fs.appendFileSync(this._currentSegmentPath!, line, 'utf-8');

    logger.debug({ lsn, type: record.type, xid: record.xid }, 'WAL record written');

    return lsn;
  }

  /**
   * Write an INSERT record.
   */
  writeInsert(xid: number, table: string, rowId: any, data?: any): string {
    return this.writeRecord({ xid, type: 'INSERT', table, rowId, data, timestamp: Date.now() });
  }

  /**
   * Write an UPDATE record.
   */
  writeUpdate(xid: number, table: string, rowId: any, data?: any): string {
    return this.writeRecord({ xid, type: 'UPDATE', table, rowId, data, timestamp: Date.now() });
  }

  /**
   * Write a DELETE record.
   */
  writeDelete(xid: number, table: string, rowId: any): string {
    return this.writeRecord({ xid, type: 'DELETE', table, rowId, timestamp: Date.now() });
  }

  /**
   * Write a COMMIT record.
   */
  writeCommit(xid: number): string {
    return this.writeRecord({ xid, type: 'COMMIT', timestamp: Date.now() });
  }

  /**
   * Write an ABORT record.
   */
  writeAbort(xid: number): string {
    return this.writeRecord({ xid, type: 'ABORT', timestamp: Date.now() });
  }

  /**
   * Write a CHECKPOINT record.
   */
  writeCheckpoint(activeXids: number[], dirtyTables: string[]): string {
    return this.writeRecord({
      xid: 0,
      type: 'CHECKPOINT',
      activeXids,
      dirtyTables,
      timestamp: Date.now(),
    });
  }

  // ── Parsing ──────────────────────────────────

  /**
   * Parse a WAL segment file and return all records.
   *
   * @param segmentPath  Path to the segment file
   * @returns  Array of WalRecords
   */
  static parseSegment(segmentPath: string): WalRecord[] {
    if (!fs.existsSync(segmentPath)) {
      return [];
    }

    const content = fs.readFileSync(segmentPath, 'utf-8');
    
    // If the content starts with binary WAL magic bytes (not '{'),
    // this is likely a binary-format WAL segment, not JSON lines.
    if (content.length > 0 && content.charCodeAt(0) !== 0x7B /* '{' */) {
      logger.warn({ segmentPath }, 'Skipping binary WAL segment (expected JSON lines format)');
      return [];
    }

    const lines = content.split('\n').filter(line => line.trim().length > 0);

    const records: WalRecord[] = [];
    for (const line of lines) {
      try {
        const record = JSON.parse(line) as WalRecord;
        // Validate required fields
        if (typeof record.lsn !== 'string' || typeof record.xid !== 'number' || typeof record.type !== 'string') {
          logger.warn({ line }, 'Skipping malformed WAL record');
          continue;
        }
        records.push(record);
      } catch (err: any) {
        logger.warn({ line, error: err.message }, 'Skipping unparseable WAL line');
      }
    }

    return records;
  }

  /**
   * Parse a segment file up to a given LSN.
   * Returns records whose LSN (numeric) is <= the stopLSN.
   */
  static parseSegmentUpTo(segmentPath: string, stopLSN: string): WalRecord[] {
    const all = PgWalWriter.parseSegment(segmentPath);
    const stopValue = PgWalWriter.lsnToNumeric(stopLSN);
    return all.filter(r => PgWalWriter.lsnToNumeric(r.lsn) <= stopValue);
  }

  // ── LSN helpers ──────────────────────────────

  /**
   * Convert LSN string to numeric value for comparison.
   * LSN format: "XXXXXXXX/YYYYYYYY" (two 32-bit hex values).
   */
  static lsnToNumeric(lsn: string): number {
    const parts = lsn.split('/');
    if (parts.length !== 2) {
      throw new Error(`Invalid LSN format: "${lsn}"`);
    }
    const upper = parseInt(parts[0], 16);
    const lower = parseInt(parts[1], 16);
    return upper * 0x100000000 + lower;
  }

  /**
   * Convert numeric LSN to string format.
   */
  static numericToLSN(value: number): string {
    const upper = Math.floor(value / 0x100000000);
    const lower = value % 0x100000000;
    return `${upper.toString(16).toUpperCase()}/${lower.toString(16).toUpperCase()}`;
  }

  /**
   * Allocate the next sequential LSN.
   * Each call increments the internal counter by 1.
   */
  private allocateLSN(): string {
    const lsn = PgWalWriter.numericToLSN(this._currentLSN);
    this._currentLSN++;
    return lsn;
  }

  // ── Segment naming ───────────────────────────

  /**
   * Format a PG-style WAL segment file name from a numeric LSN base.
   * Format: TTTTTTTTLLLLLLLLSSSSSSSS.wal
   */
  private formatSegmentName(lsnBase: number): string {
    const upper = Math.floor(lsnBase / 0x100000000);
    const lower = lsnBase % 0x100000000;
    const segmentNum = Math.floor(lsnBase / this._segmentSize);

    const timeline = '00000001';
    const logId = upper.toString(16).toUpperCase().padStart(8, '0');
    const seg = segmentNum.toString(16).toUpperCase().padStart(8, '0');

    return `${timeline}${logId}${seg}.wal`;
  }
}

export default PgWalWriter;
