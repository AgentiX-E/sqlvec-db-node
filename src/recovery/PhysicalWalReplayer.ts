/**
 * PhysicalWalReplayer — Reads WAL records from segment files and applies
 * them (redo) to a SQLite database using MVCC _xmin/_xmax semantics.
 *
 * ## State machine
 * ```
 * IDLE → replay() → REPLAYING → PAUSED → resume() → REPLAYING → COMPLETE
 *                                                    → replay() → IDLE → ...
 * ```
 *
 * ## WAL record → SQL mapping
 * | Record type              | SQL action                                      |
 * |--------------------------|-------------------------------------------------|
 * | Heap / HEAP_INSERT       | REPLACE INTO <tbl> (...) VALUES (...)           |
 * | Heap / HEAP_DELETE       | UPDATE <tbl> SET _xmax = ? WHERE ...            |
 * | Heap / HEAP_UPDATE       | REPLACE new + UPDATE old _xmax                  |
 * | Transaction / XACT_COMMIT| CommitLog.commit(xid)                           |
 * | Transaction / XACT_ABORT | CommitLog.abort(xid)                            |
 * | XLOG / CHECKPOINT_*      | Record redo starting point                      |
 *
 * ## Payload format
 * Heap records have a table name prefix: [tableLen:2][tableName:tableLen][rest...]
 * Transaction and XLOG records have no table prefix.
 *
 * @module recovery/PhysicalWalReplayer
 */

import * as fs from 'node:fs';
import { PinoLogger } from '../monitoring/PinoLogger';
import { PgWalWriter, type WalRecord } from '../storage/PgWalWriter';
import { WALStateManager } from '../storage/WALStateManager';
import {
  verifyCrc32c,
  computeCrc32c,
  parseLsn,
  formatLsn,
  type WalBinaryRecord,
  type WalRecordType,
} from '../pitr/WalBinaryFormat';

// ── Constants ────────────────────────────────────────────────────

/** ResourceManager values */
const RM = {
  XLOG: 0,
  TRANSACTION: 10,
  HEAP2: 11,
  HEAP: 12,
} as const;

/** RM_XACT record subtypes */
const XACT = {
  XACT_COMMIT: 0,
  XACT_ABORT: 1,
} as const;

/** RM_XLOG record subtypes */
const XLOG_TYPES = {
  CHECKPOINT_SHUTDOWN: 0,
  CHECKPOINT_ONLINE: 1,
  SWITCH: 2,
} as const;

/** RM_HEAP record subtypes */
const HEAP = {
  HEAP_INSERT: 0,
  HEAP_DELETE: 1,
  HEAP_UPDATE: 2,
  HEAP_HOT_UPDATE: 3,
} as const;

/** Table name prefix size in bytes (2-byte length) */
const TABLE_NAME_PREFIX_SIZE = 2;

const logger = PinoLogger.forComponent('PhysicalWalReplayer');

// ── Types ────────────────────────────────────────────────────────

export enum ReplayState {
  IDLE = 'idle',
  REPLAYING = 'replaying',
  PAUSED = 'paused',
  COMPLETE = 'complete',
}

/**
 * Minimal SQLite database interface compatible with better-sqlite3.
 */
export interface ReplayerDatabase {
  exec(sql: string): void;
  prepare(sql: string): {
    run(...params: unknown[]): { changes: number };
    get(...params: unknown[]): Record<string, unknown> | undefined;
    all(...params: unknown[]): Array<Record<string, unknown>>;
  };
}

export interface ReplayerOptions {
  /** SQLite database for applying DML changes */
  db: ReplayerDatabase;
  /** CommitLog instance for tracking tx state */
  clog: { commit(xid: number, commitTime?: number): void; abort(xid: number): void };
  /** Directory containing .wal segment files */
  segmentDir: string;
  /** Optional WALStateManager for LSN tracking */
  walState?: WALStateManager;
}

export interface ReplayStatus {
  state: ReplayState;
  replayed: number;
  total: number;
  currentLSN: string;
  lastCheckpointLSN: string;
}

// ── LSN utilities ────────────────────────────────────────────────

/**
 * Convert an LSN string (XXXXXXXX/YYYYYYYY) to a numeric value.
 */
export function lsnToNumber(lsn: string): number {
  const parts = lsn.split('/');
  if (parts.length !== 2) {
    throw new Error(`Invalid LSN format: "${lsn}"`);
  }
  const upper = parseInt(parts[0], 16);
  const lower = parseInt(parts[1], 16);
  if (isNaN(upper) || isNaN(lower)) {
    throw new Error(`Invalid LSN hex parts in: "${lsn}"`);
  }
  return upper * 0x100000000 + lower;
}

/**
 * Convert a numeric LSN to string format (XXXXXXXX/YYYYYYYY).
 */
export function numberToLSN(n: number): string {
  const upper = Math.floor(n / 0x100000000);
  const lower = n % 0x100000000;
  return `${upper.toString(16).toUpperCase()}/${lower.toString(16).toUpperCase()}`;
}

// ── Binary payload helpers ───────────────────────────────────────

/**
 * Decode a table name from a buffer at the given offset.
 * Returns [tableName, offset after the table name bytes].
 */
export function decodeTableName(buf: Buffer, offset: number = 0): [string, number] {
  const tableLen = buf.readUInt16BE(offset);
  const name = buf.toString(
    'utf-8',
    offset + TABLE_NAME_PREFIX_SIZE,
    offset + TABLE_NAME_PREFIX_SIZE + tableLen,
  );
  return [name, offset + TABLE_NAME_PREFIX_SIZE + tableLen];
}

/**
 * Parse a Heap INSERT payload.
 * Format: [tableLen:2][tableName:tableLen][offnum:4][flags:4][xmin:4][xmax:4][jsonData:N]
 */
export function parseHeapInsertPayload(buf: Buffer): {
  table: string;
  offnum: number;
  flags: number;
  xmin: number;
  xmax: number;
  data: any;
} {
  let offset = 0;
  const [table, afterTable] = decodeTableName(buf, offset);
  offset = afterTable;

  const offnum = buf.readUInt32BE(offset); offset += 4;
  const flags = buf.readUInt32BE(offset); offset += 4;
  const xmin = buf.readUInt32BE(offset); offset += 4;
  const xmax = buf.readUInt32BE(offset); offset += 4;

  // JSON data starts here, goes to the end
  const jsonStr = buf.toString('utf-8', offset);
  const data = JSON.parse(jsonStr);

  return { table, offnum, flags, xmin, xmax, data };
}

/**
 * Parse a Heap DELETE payload.
 * Format: [tableLen:2][tableName:tableLen][offnum:4][flags:4][xmax:4][jsonData:N]
 */
export function parseHeapDeletePayload(buf: Buffer): {
  table: string;
  offnum: number;
  flags: number;
  xmax: number;
  oldData: any;
} {
  let offset = 0;
  const [table, afterTable] = decodeTableName(buf, offset);
  offset = afterTable;

  const offnum = buf.readUInt32BE(offset); offset += 4;
  const flags = buf.readUInt32BE(offset); offset += 4;
  const xmax = buf.readUInt32BE(offset); offset += 4;

  const jsonStr = buf.toString('utf-8', offset);
  const oldData = JSON.parse(jsonStr);

  return { table, offnum, flags, xmax, oldData };
}

/**
 * Parse a Heap UPDATE payload.
 * Format: [tableLen:2][tableName:tableLen][offnum:4][newOffnum:4][flags:4][newXmax:4]
 *         [oldLen:4][oldData:N][newLen:4][newData:M]
 */
export function parseHeapUpdatePayload(buf: Buffer): {
  table: string;
  offnum: number;
  newOffnum: number;
  flags: number;
  newXmax: number;
  oldData: any;
  newData: any;
} {
  let offset = 0;
  const [table, afterTable] = decodeTableName(buf, offset);
  offset = afterTable;

  const offnum = buf.readUInt32BE(offset); offset += 4;
  const newOffnum = buf.readUInt32BE(offset); offset += 4;
  const flags = buf.readUInt32BE(offset); offset += 4;
  const newXmax = buf.readUInt32BE(offset); offset += 4;

  const oldLen = buf.readUInt32BE(offset); offset += 4;
  const oldJson = buf.toString('utf-8', offset, offset + oldLen); offset += oldLen;

  const newLen = buf.readUInt32BE(offset); offset += 4;
  const newJson = buf.toString('utf-8', offset, offset + newLen);

  return {
    table,
    offnum,
    newOffnum,
    flags,
    newXmax,
    oldData: JSON.parse(oldJson),
    newData: JSON.parse(newJson),
  };
}

/**
 * Parse a Transaction COMMIT payload.
 * Format: [xactTime:8][nsubxacts:4]
 */
export function parseCommitPayload(buf: Buffer): { xactTime: number; nsubxacts: number } {
  const xactTime = Number(buf.readBigUInt64BE(0));
  const nsubxacts = buf.readUInt32BE(8);
  return { xactTime, nsubxacts };
}

/**
 * Parse a Transaction ABORT payload.
 * Format: [xactTime:8][nsubxacts:4]
 */
export function parseAbortPayload(buf: Buffer): { xactTime: number; nsubxacts: number } {
  const xactTime = Number(buf.readBigUInt64BE(0));
  const nsubxacts = buf.readUInt32BE(8);
  return { xactTime, nsubxacts };
}

/**
 * Parse an XLOG CHECKPOINT payload.
 * Format: [redoLSN:8][checkpointTime:8]
 */
export function parseCheckpointPayload(buf: Buffer): { redoLSN: number; checkpointTime: number } {
  const redoLSN = Number(buf.readBigUInt64BE(0));
  const checkpointTime = Number(buf.readBigUInt64BE(8));
  return { redoLSN, checkpointTime };
}

// ── SQL building helpers ─────────────────────────────────────────

/**
 * Build a REPLACE INTO statement for the given table and data object.
 * Includes _xmin and _xmax system columns.
 */
function buildReplaceSQL(table: string, data: Record<string, unknown>): {
  sql: string;
  params: unknown[];
} {
  const keys = Object.keys(data);
  const allColumns = [...keys, '_xmin', '_xmax'];
  const placeholders = allColumns.map(() => '?');
  const sql = `REPLACE INTO "${table}" (${allColumns.map(c => `"${c}"`).join(', ')}) VALUES (${placeholders.join(', ')})`;
  const params = [...keys.map(k => data[k])];
  return { sql, params };
}

/**
 * Build an UPDATE statement that matches a row by all its column values.
 * Sets _xmax to the given xid.
 */
function buildDeleteSQL(table: string, oldData: Record<string, unknown>, xmax: number): {
  sql: string;
  params: unknown[];
} {
  const keys = Object.keys(oldData);
  const whereClauses = keys.map(k => `"${k}" = ?`);
  const sql = `UPDATE "${table}" SET "_xmax" = ? WHERE ${whereClauses.join(' AND ')}`;
  const params = [xmax, ...keys.map(k => oldData[k])];
  return { sql, params };
}

/**
 * Build SQL for an UPDATE: mark old row with _xmax and insert new version.
 */
function buildUpdateSQL(
  table: string,
  oldData: Record<string, unknown>,
  newData: Record<string, unknown>,
  newXmax: number,
): { updateSQL: string; updateParams: unknown[]; insertSQL: string; insertParams: unknown[] } {
  // Mark old row: SET _xmax = newXmax
  const oldKeys = Object.keys(oldData);
  const whereClauses = oldKeys.map(k => `"${k}" = ?`);
  const updateSQL = `UPDATE "${table}" SET "_xmax" = ? WHERE ${whereClauses.join(' AND ')}`;
  const updateParams = [newXmax, ...oldKeys.map(k => oldData[k])];

  // Insert new version: REPLACE INTO with _xmin = newXmax, _xmax = 0
  const newKeys = Object.keys(newData);
  const allColumns = [...newKeys, '_xmin', '_xmax'];
  const placeholders = allColumns.map(() => '?');
  const insertSQL = `REPLACE INTO "${table}" (${allColumns.map(c => `"${c}"`).join(', ')}) VALUES (${placeholders.join(', ')})`;
  const insertParams = [...newKeys.map(k => newData[k]), newXmax, 0];

  return { updateSQL, updateParams, insertSQL, insertParams };
}

// ── PhysicalWalReplayer ──────────────────────────────────────────

export class PhysicalWalReplayer {
  private db: ReplayerDatabase;
  private clog: { commit(xid: number, commitTime?: number): void; abort(xid: number): void };
  private segmentDir: string;
  private walState?: WALStateManager;

  private _state: ReplayState = ReplayState.IDLE;
  private _replayedLSN: number = 0;
  private _lastCheckpointLSN: number = 0;
  private _recordsReplayed: number = 0;
  private _totalRecords: number = 0;

  constructor(options: ReplayerOptions) {
    this.db = options.db;
    this.clog = options.clog;
    this.segmentDir = options.segmentDir;
    this.walState = options.walState;
  }

  // ── Public API ──────────────────────────────────

  /**
   * Replay WAL records from startLSN (inclusive) to endLSN (exclusive).
   *
   * If endLSN is omitted, replays all records from startLSN to the end
   * of the WAL.
   *
   * @param startLsn  Starting LSN (PG format, e.g. "0/1")
   * @param endLsn    Optional ending LSN (exclusive)
   * @returns         Number of records successfully replayed
   */
  replay(startLsn: string, endLsn?: string): number {
    // Use a private getter to avoid TS property narrowing issues
    if (this.isReplaying()) {
      throw new Error('Replay is already in progress');
    }

    this.assignState(ReplayState.REPLAYING);
    const startNum = lsnToNumber(startLsn);
    const endNum = endLsn ? lsnToNumber(endLsn) : Number.MAX_SAFE_INTEGER;

    // Gather all records within the LSN range
    const allRecords = this.collectRecordsInRange(startNum, endNum);
    this._totalRecords = allRecords.length;
    this._recordsReplayed = 0;

    logger.info(
      { startLSN: startLsn, endLSN: endLsn ?? 'end', totalRecords: allRecords.length },
      'Replay started',
    );

    // Replay each record
    for (const record of allRecords) {
      if (this.isPaused()) {
        logger.info('Replay paused');
        break;
      }

      try {
        this.replaySingleRecord(record);
        this._recordsReplayed++;

        // Track replayed LSN
        const lsnNum = lsnToNumber(record.lsn);
        if (lsnNum > this._replayedLSN) {
          this._replayedLSN = lsnNum;
        }

        // Update WALStateManager if available
        if (this.walState) {
          this.updateWALStateLSN(record.lsn);
        }
      } catch (err: any) {
        logger.error(
          { lsn: record.lsn, rm: record.resourceManager, type: record.recordType, error: err.message },
          'Failed to replay WAL record',
        );
        // Continue with next record (best-effort replay)
      }
    }

    // Determine final state
    if (this.isPaused()) {
      // Stay paused
    } else if (this._recordsReplayed >= this._totalRecords) {
      this.assignState(ReplayState.COMPLETE);
    } else {
      this.assignState(ReplayState.IDLE);
    }

    logger.info(
      { replayed: this._recordsReplayed, total: this._totalRecords, state: this._state },
      'Replay completed',
    );

    return this._recordsReplayed;
  }

  /**
   * Replay binary WAL records on a SQLite database.
   *
   * Each record is CRC32C-verified before replay. Corrupted records are
   * skipped with a warning log. The method applies the same MVCC _xmin/_xmax
   * semantics as the regular WAL replay, translating binary WalRecordType
   * into corresponding SQL operations.
   *
   * @param db - SQLite database instance
   * @param records - Array of WalBinaryRecords to replay
   * @returns true if all records were replayed successfully, false if any
   *          records were skipped due to corruption or errors
   */
  replayBinaryWal(db: any, records: WalBinaryRecord[]): boolean {
    let allSuccess = true;

    for (const record of records) {
      // Serialize the record for CRC verification (everything except the CRC field)
      const serialized = this.serializeBinaryRecordForCrcCheck(record);
      const crcExpected = record.crc32c;

      if (!verifyCrc32c(serialized, crcExpected)) {
        logger.warn(
          { lsn: record.lsn, type: record.recordType },
          'CRC32C verification failed for binary WAL record — skipping',
        );
        allSuccess = false;
        continue;
      }

      try {
        this.applyBinaryRecordToDb(db, record);
      } catch (err: any) {
        logger.error(
          { lsn: record.lsn, type: record.recordType, error: err.message },
          'Failed to replay binary WAL record',
        );
        allSuccess = false;
      }
    }

    if (allSuccess) {
      logger.info({ count: records.length }, 'All binary WAL records replayed successfully');
    } else {
      logger.warn({ total: records.length }, 'Some binary WAL records had issues');
    }

    return allSuccess;
  }

  /**
   * Serialize a binary record for CRC verification (header fields + body only,
   * without the CRC field).
   */
  private serializeBinaryRecordForCrcCheck(record: WalBinaryRecord): Buffer {
    const lsnBuf = Buffer.from(record.lsn, 'utf-8');
    const prevLsnBuf = Buffer.from(record.prevLsn, 'utf-8');
    const body = record.body;

    // Map record type to enum value
    const recordTypeValue = this.getRecordTypeValue(record.recordType);

    const totalSize = 2 + 2 + lsnBuf.length + 2 + prevLsnBuf.length + 4 + 2 + 4 + 8 + body.length;
    const buf = Buffer.alloc(totalSize);
    let offset = 0;

    // Magic
    buf.writeUInt16BE(0xA8E1, offset); offset += 2;
    // LSN length
    buf.writeUInt16BE(lsnBuf.length, offset); offset += 2;
    // LSN
    lsnBuf.copy(buf, offset); offset += lsnBuf.length;
    // PrevLSN length
    buf.writeUInt16BE(prevLsnBuf.length, offset); offset += 2;
    // PrevLSN
    prevLsnBuf.copy(buf, offset); offset += prevLsnBuf.length;
    // XID
    buf.writeUInt32BE(record.xid, offset); offset += 4;
    // Record type
    buf.writeUInt16BE(recordTypeValue, offset); offset += 2;
    // Body length
    buf.writeUInt32BE(record.recordLength, offset); offset += 4;
    // Timestamp
    buf.writeBigUInt64BE(BigInt(record.timestamp), offset); offset += 8;
    // Body
    body.copy(buf, offset);

    return buf;
  }

  /**
   * Get numeric value for a WalRecordType string.
   */
  private getRecordTypeValue(recordType: WalRecordType): number {
    const values: Record<string, number> = {
      XLOG_CHECKPOINT_SHUTDOWN: 0,
      XLOG_CHECKPOINT_ONLINE: 1,
      XLOG_SWITCH: 2,
      XLOG_PAGE_IMAGE: 3,
      XLOG_INSERT: 4,
      XLOG_UPDATE: 5,
      XLOG_DELETE: 6,
      XLOG_DDL: 7,
      XLOG_TRUNCATE: 8,
      XLOG_HEAP2_CLEAN: 9,
      XLOG_HEAP2_FREEZE: 10,
    };
    return values[recordType] ?? 0;
  }

  /**
   * Apply a single binary WAL record to the database.
   * Translates WalRecordType to the appropriate SQL operation.
   */
  private applyBinaryRecordToDb(db: any, record: WalBinaryRecord): void {
    switch (record.recordType) {
      case 'XLOG_INSERT':
        this.applyBinaryInsert(db, record);
        break;

      case 'XLOG_UPDATE':
        this.applyBinaryUpdate(db, record);
        break;

      case 'XLOG_DELETE':
        this.applyBinaryDelete(db, record);
        break;

      case 'XLOG_DDL':
        this.applyBinaryDdl(db, record);
        break;

      case 'XLOG_TRUNCATE':
        this.applyBinaryTruncate(db, record);
        break;

      case 'XLOG_CHECKPOINT_SHUTDOWN':
      case 'XLOG_CHECKPOINT_ONLINE':
      case 'XLOG_SWITCH':
      case 'XLOG_PAGE_IMAGE':
        // These are metadata records — no SQL to apply
        logger.trace({ lsn: record.lsn, type: record.recordType }, 'Binary WAL metadata record skipped');
        break;

      case 'XLOG_HEAP2_CLEAN':
      case 'XLOG_HEAP2_FREEZE':
        // Heap2 operations — currently no-op in replay
        logger.trace({ lsn: record.lsn, type: record.recordType }, 'Heap2 binary record skipped');
        break;

      default:
        logger.warn({ type: record.recordType }, 'Unknown binary WAL record type, skipping');
    }
  }

  /**
   * Apply a binary INSERT record: REPLACE INTO with _xmin = xid, _xmax = 0.
   * Body format: [tableLen:2][tableName:N][jsonData:M]
   */
  private applyBinaryInsert(db: any, record: WalBinaryRecord): void {
    const body = record.body;
    if (body.length < 3) {
      logger.warn({ lsn: record.lsn }, 'Binary INSERT record too short');
      return;
    }

    const tableLen = body.readUInt16BE(0);
    if (2 + tableLen > body.length) {
      logger.warn({ lsn: record.lsn }, 'Binary INSERT record has invalid table name length');
      return;
    }

    const tableName = body.toString('utf-8', 2, 2 + tableLen);
    const jsonStr = body.toString('utf-8', 2 + tableLen);
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(jsonStr);
    } catch {
      logger.warn({ lsn: record.lsn }, 'Binary INSERT record has invalid JSON data');
      return;
    }

    const keys = Object.keys(data);
    const allColumns = [...keys, '_xmin', '_xmax'];
    const placeholders = allColumns.map(() => '?');
    const sql = `REPLACE INTO "${tableName}" (${allColumns.map(c => `"${c}"`).join(', ')}) VALUES (${placeholders.join(', ')})`;
    const params = [...keys.map(k => data[k]), record.xid, 0];

    db.prepare(sql).run(...params);
    logger.trace({ lsn: record.lsn, table: tableName, xid: record.xid }, 'Binary INSERT applied');
  }

  /**
   * Apply a binary UPDATE record: mark old row with _xmax and insert new version.
   * Body format: [tableLen:2][tableName:N][oldJsonLen:4][oldJson:M][newJsonLen:4][newJson:P]
   */
  private applyBinaryUpdate(db: any, record: WalBinaryRecord): void {
    const body = record.body;
    if (body.length < 10) {
      logger.warn({ lsn: record.lsn }, 'Binary UPDATE record too short');
      return;
    }

    const tableLen = body.readUInt16BE(0);
    if (2 + tableLen + 4 > body.length) {
      logger.warn({ lsn: record.lsn }, 'Binary UPDATE record has invalid table name length');
      return;
    }

    const tableName = body.toString('utf-8', 2, 2 + tableLen);
    let offset = 2 + tableLen;

    const oldJsonLen = body.readUInt32BE(offset); offset += 4;
    if (offset + oldJsonLen + 4 > body.length) {
      logger.warn({ lsn: record.lsn }, 'Binary UPDATE record has invalid old data length');
      return;
    }

    const oldJsonStr = body.toString('utf-8', offset, offset + oldJsonLen); offset += oldJsonLen;
    const newJsonLen = body.readUInt32BE(offset); offset += 4;
    if (offset + newJsonLen > body.length) {
      logger.warn({ lsn: record.lsn }, 'Binary UPDATE record has invalid new data length');
      return;
    }

    const newJsonStr = body.toString('utf-8', offset, offset + newJsonLen);

    let oldData: Record<string, unknown>;
    let newData: Record<string, unknown>;
    try {
      oldData = JSON.parse(oldJsonStr);
      newData = JSON.parse(newJsonStr);
    } catch {
      logger.warn({ lsn: record.lsn }, 'Binary UPDATE record has invalid JSON data');
      return;
    }

    // Mark old row
    const oldKeys = Object.keys(oldData);
    const whereClauses = oldKeys.map(k => `"${k}" = ?`);
    const updateSQL = `UPDATE "${tableName}" SET "_xmax" = ? WHERE ${whereClauses.join(' AND ')}`;
    const updateParams = [record.xid, ...oldKeys.map(k => oldData[k])];
    db.prepare(updateSQL).run(...updateParams);

    // Insert new version
    const newKeys = Object.keys(newData);
    const allColumns = [...newKeys, '_xmin', '_xmax'];
    const placeholders = allColumns.map(() => '?');
    const insertSQL = `INSERT INTO "${tableName}" (${allColumns.map(c => `"${c}"`).join(', ')}) VALUES (${placeholders.join(', ')})`;
    const insertParams = [...newKeys.map(k => newData[k]), record.xid, 0];
    db.prepare(insertSQL).run(...insertParams);

    logger.trace({ lsn: record.lsn, table: tableName, xid: record.xid }, 'Binary UPDATE applied');
  }

  /**
   * Apply a binary DELETE record: UPDATE SET _xmax = xid WHERE matching row.
   * Body format: [tableLen:2][tableName:N][jsonData:M]
   */
  private applyBinaryDelete(db: any, record: WalBinaryRecord): void {
    const body = record.body;
    if (body.length < 3) {
      logger.warn({ lsn: record.lsn }, 'Binary DELETE record too short');
      return;
    }

    const tableLen = body.readUInt16BE(0);
    if (2 + tableLen > body.length) {
      logger.warn({ lsn: record.lsn }, 'Binary DELETE record has invalid table name length');
      return;
    }

    const tableName = body.toString('utf-8', 2, 2 + tableLen);
    const jsonStr = body.toString('utf-8', 2 + tableLen);
    let oldData: Record<string, unknown>;
    try {
      oldData = JSON.parse(jsonStr);
    } catch {
      logger.warn({ lsn: record.lsn }, 'Binary DELETE record has invalid JSON data');
      return;
    }

    const keys = Object.keys(oldData);
    const whereClauses = keys.map(k => `"${k}" = ?`);
    const sql = `UPDATE "${tableName}" SET "_xmax" = ? WHERE ${whereClauses.join(' AND ')}`;
    const params = [record.xid, ...keys.map(k => oldData[k])];
    db.prepare(sql).run(...params);

    logger.trace({ lsn: record.lsn, table: tableName, xid: record.xid }, 'Binary DELETE applied');
  }

  /**
   * Apply a binary DDL record: execute SQL directly.
   * Body format: [sqlLen:2][sql:N]
   */
  private applyBinaryDdl(db: any, record: WalBinaryRecord): void {
    const body = record.body;
    if (body.length < 3) {
      logger.warn({ lsn: record.lsn }, 'Binary DDL record too short');
      return;
    }

    const sqlLen = body.readUInt16BE(0);
    if (2 + sqlLen > body.length) {
      logger.warn({ lsn: record.lsn }, 'Binary DDL record has invalid SQL length');
      return;
    }

    const sql = body.toString('utf-8', 2, 2 + sqlLen);
    db.exec(sql);
    logger.trace({ lsn: record.lsn, sql: sql.slice(0, 80) }, 'Binary DDL applied');
  }

  /**
   * Apply a binary TRUNCATE record: DELETE FROM table.
   * Body format: [tableLen:2][tableName:N]
   */
  private applyBinaryTruncate(db: any, record: WalBinaryRecord): void {
    const body = record.body;
    if (body.length < 3) {
      logger.warn({ lsn: record.lsn }, 'Binary TRUNCATE record too short');
      return;
    }

    const tableLen = body.readUInt16BE(0);
    if (2 + tableLen > body.length) {
      logger.warn({ lsn: record.lsn }, 'Binary TRUNCATE record has invalid table name length');
      return;
    }

    const tableName = body.toString('utf-8', 2, 2 + tableLen);
    db.exec(`DELETE FROM "${tableName}"`);
    logger.trace({ lsn: record.lsn, table: tableName }, 'Binary TRUNCATE applied');
  }

  /**
   * Replay a single WAL record, dispatching to the appropriate redo method
   * based on the record's resource manager and record type.
   */
  replaySingleRecord(record: WalRecord): void {
    const rmName = record.resourceManager;

    switch (rmName) {
      case 'Heap':
      case 'Heap2':
        this.replayHeapRecord(record);
        break;

      case 'Transaction':
        this.replayTransactionRecord(record);
        break;

      case 'XLOG':
        this.replayXLogRecord(record);
        break;

      default:
        logger.warn(
          { resourceManager: rmName, recordType: record.recordType, lsn: record.lsn },
          'Unknown resource manager, skipping',
        );
    }
  }

  // ── Heap record redo ────────────────────────────

  /**
   * Replay a Heap/Heap2 WAL record.
   */
  private replayHeapRecord(record: WalRecord): void {
    switch (record.recordType) {
      case HEAP.HEAP_INSERT:
        this.redoHeapInsert(record);
        break;
      case HEAP.HEAP_DELETE:
        this.redoHeapDelete(record);
        break;
      case HEAP.HEAP_UPDATE:
      case HEAP.HEAP_HOT_UPDATE:
        this.redoHeapUpdate(record);
        break;
      default:
        logger.warn(
          { recordType: record.recordType, lsn: record.lsn },
          'Unknown Heap record type, skipping',
        );
    }
  }

  /**
   * Redo a Heap INSERT: REPLACE INTO with _xmin = record.xid, _xmax = 0.
   */
  redoHeapInsert(record: WalRecord): void {
    const parsed = parseHeapInsertPayload(record.data);
    const { sql, params } = buildReplaceSQL(parsed.table, parsed.data);

    // Append _xmin and _xmax (must not overwrite existing data values)
    params.push(record.xid, 0);

    this.db.prepare(sql).run(...params);
    logger.trace({ lsn: record.lsn, table: parsed.table, xid: record.xid }, 'Redo INSERT');
  }

  /**
   * Redo a Heap DELETE: UPDATE SET _xmax = record.xid.
   */
  redoHeapDelete(record: WalRecord): void {
    const parsed = parseHeapDeletePayload(record.data);
    const { sql, params } = buildDeleteSQL(parsed.table, parsed.oldData, record.xid);

    const result = this.db.prepare(sql).run(...params);
    if (result.changes === 0) {
      logger.warn(
        { lsn: record.lsn, table: parsed.table, xid: record.xid },
        'Redo DELETE: no matching row found',
      );
    } else {
      logger.trace({ lsn: record.lsn, table: parsed.table, xid: record.xid }, 'Redo DELETE');
    }
  }

  /**
   * Redo a Heap UPDATE: REPLACE new version + UPDATE old version's _xmax.
   */
  redoHeapUpdate(record: WalRecord): void {
    const parsed = parseHeapUpdatePayload(record.data);
    const { updateSQL, updateParams, insertSQL, insertParams } = buildUpdateSQL(
      parsed.table,
      parsed.oldData,
      parsed.newData,
      record.xid,
    );

    // Mark old row as deleted by this xid
    const updateResult = this.db.prepare(updateSQL).run(...updateParams);
    if (updateResult.changes === 0) {
      logger.warn(
        { lsn: record.lsn, table: parsed.table, xid: record.xid },
        'Redo UPDATE: no matching old row found',
      );
    }

    // Insert new version
    this.db.prepare(insertSQL).run(...insertParams);
    logger.trace({ lsn: record.lsn, table: parsed.table, xid: record.xid }, 'Redo UPDATE');
  }

  // ── Transaction record redo ──────────────────────

  /**
   * Replay a Transaction WAL record (COMMIT or ABORT).
   */
  private replayTransactionRecord(record: WalRecord): void {
    switch (record.recordType) {
      case XACT.XACT_COMMIT:
        this.redoXactCommit(record);
        break;
      case XACT.XACT_ABORT:
        this.redoXactAbort(record);
        break;
      default:
        logger.warn(
          { recordType: record.recordType, lsn: record.lsn },
          'Unknown Transaction record type, skipping',
        );
    }
  }

  /**
   * Redo a Transaction COMMIT: record in CommitLog.
   */
  redoXactCommit(record: WalRecord): void {
    const payload = parseCommitPayload(record.data);
    this.clog.commit(record.xid, payload.xactTime);
    logger.trace({ lsn: record.lsn, xid: record.xid, xactTime: payload.xactTime }, 'Redo COMMIT');
  }

  /**
   * Redo a Transaction ABORT: record in CommitLog.
   */
  redoXactAbort(record: WalRecord): void {
    const payload = parseAbortPayload(record.data);
    this.clog.abort(record.xid);
    logger.trace({ lsn: record.lsn, xid: record.xid, xactTime: payload.xactTime }, 'Redo ABORT');
  }

  // ── XLOG record redo ────────────────────────────

  /**
   * Replay an XLOG WAL record (CHECKPOINT, SWITCH, etc.).
   */
  private replayXLogRecord(record: WalRecord): void {
    switch (record.recordType) {
      case XLOG_TYPES.CHECKPOINT_SHUTDOWN:
      case XLOG_TYPES.CHECKPOINT_ONLINE:
        this.redoCheckpoint(record);
        break;
      case XLOG_TYPES.SWITCH:
        this.redoXlogSwitch(record);
        break;
      default:
        logger.trace({ recordType: record.recordType, lsn: record.lsn }, 'XLOG record skipped');
    }
  }

  /**
   * Redo a CHECKPOINT: record the redo starting point.
   */
  redoCheckpoint(record: WalRecord): void {
    const payload = parseCheckpointPayload(record.data);
    const lsnNum = lsnToNumber(record.lsn);
    this._lastCheckpointLSN = lsnNum;
    logger.trace({ lsn: record.lsn, redoLSN: numberToLSN(payload.redoLSN), checkpointTime: payload.checkpointTime }, 'Redo CHECKPOINT');
  }

  /**
   * Redo an XLOG SWITCH: log the segment switch.
   */
  private redoXlogSwitch(_record: WalRecord): void {
    logger.trace('Redo XLOG SWITCH (segment switch)');
  }

  // ── Controls ─────────────────────────────────────

  /**
   * Pause an ongoing replay.  The replay() call will finish the current
   * record and return early.
   */
  pause(): void {
    if (this.isReplaying()) {
      this.assignState(ReplayState.PAUSED);
      logger.info('Replay paused by user');
    }
  }

  /**
   * Resume a paused replay.  Call replay() again to continue from the
   * last replayed position.
   */
  resume(): void {
    if (this.isPaused()) {
      this.assignState(ReplayState.IDLE);
      logger.info('Replay resumed');
    }
  }

  /**
   * Check if replay is currently paused.
   */
  isPaused(): boolean {
    return this._state === ReplayState.PAUSED;
  }

  /**
   * Check if replay is currently in progress.
   */
  private isReplaying(): boolean {
    return this._state === ReplayState.REPLAYING;
  }

  /**
   * Assign a new state (private helper to avoid TS narrowing issues).
   */
  private assignState(newState: ReplayState): void {
    this._state = newState;
  }

  // ── Accessors ────────────────────────────────────

  /**
   * Get the current replayed LSN as a PG-format string.
   */
  getReplayLSN(): string {
    return numberToLSN(this._replayedLSN);
  }

  /**
   * Get the last checkpoint LSN as a PG-format string.
   */
  getLastCheckpoint(): string {
    return numberToLSN(this._lastCheckpointLSN);
  }

  /**
   * Get the current replay state.
   */
  get state(): ReplayState {
    return this._state;
  }

  /**
   * Get a comprehensive status snapshot.
   */
  status(): ReplayStatus {
    return {
      state: this._state,
      replayed: this._recordsReplayed,
      total: this._totalRecords,
      currentLSN: this.getReplayLSN(),
      lastCheckpointLSN: this.getLastCheckpoint(),
    };
  }

  /**
   * Reset the replayer to initial state (for testing).
   */
  reset(): void {
    this._state = ReplayState.IDLE;
    this._replayedLSN = 0;
    this._lastCheckpointLSN = 0;
    this._recordsReplayed = 0;
    this._totalRecords = 0;
    logger.debug('PhysicalWalReplayer reset');
  }

  // ── Private helpers ──────────────────────────────

  /**
   * Collect all WAL records in a given LSN range from segment files.
   */
  private collectRecordsInRange(startNum: number, endNum: number): WalRecord[] {
    const segmentDir = this.segmentDir;

    // List and sort segment files
    let entries: string[];
    try {
      entries = fs.readdirSync(segmentDir);
    } catch {
      logger.warn({ segmentDir }, 'Segment directory not found or not accessible');
      return [];
    }

    const walFiles = entries
      .filter(entry => entry.endsWith('.wal'))
      .map(entry => `${segmentDir}/${entry}`)
      .sort();

    const allRecords: WalRecord[] = [];

    for (const segPath of walFiles) {
      let segData: Buffer;
      try {
        segData = fs.readFileSync(segPath);
      } catch {
        logger.warn({ path: segPath }, 'Cannot read segment file, skipping');
        continue;
      }

      const records = PgWalWriter.parseSegment(segData);

      for (const record of records) {
        const lsnNum = lsnToNumber(record.lsn);
        if (lsnNum >= startNum && lsnNum < endNum) {
          allRecords.push(record);
        }
      }
    }

    return allRecords;
  }

  /**
   * Update WALStateManager with the current replayed LSN.
   */
  private updateWALStateLSN(lsn: string): void {
    if (!this.walState) return;
    try {
      // Try to use setReplayedLSN if available (injected by modification)
      const ws = this.walState as any;
      if (typeof ws.setReplayedLSN === 'function') {
        ws.setReplayedLSN(lsn);
      }
    } catch {
      // Silently ignore — WALState may not have the method
    }
  }
}

export default PhysicalWalReplayer;
