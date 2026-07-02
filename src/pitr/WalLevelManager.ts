/**
 * WalLevelManager — wal_level 分层行为实现
 *
 * 控制 WAL 写入的内容级别:
 *   - `minimal`: 只写入 checkpoint 记录, 跳过 DML 的 WAL 写入
 *   - `replica` (default): 写入所有 DML 物理记录 (现有行为)
 *   - `logical`: 在 replica 基础上, 额外写入行级逻辑记录
 *
 * 逻辑 WAL 记录格式 (LogicalWalRecord):
 *   记录每个 DML 操作的行级变更, 写入 {archiveDir}/logical/ 子目录。
 *   每行一条 JSON 记录, 追加到按日滚动的 logical-wal-{YYYYMMDD}.log 文件。
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('WalLevelManager');

// ── Types ────────────────────────────────────────────────────────────────────

/** WAL level enum matching PG semantics */
export type WalLevel = 'minimal' | 'replica' | 'logical';

/** DML operation types supported for logical WAL */
export type DmlOperation = 'INSERT' | 'UPDATE' | 'DELETE';

/**
 * Logical WAL record format — records row-level changes for logical replication.
 * Written to {archiveDir}/logical/ as JSON Lines.
 */
export interface LogicalWalRecord {
  /** DML operation type */
  operation: DmlOperation;
  /** Target table name */
  table: string;
  /** Row data BEFORE the operation (for UPDATE/DELETE) */
  old?: Record<string, any>;
  /** Row data AFTER the operation (for INSERT/UPDATE) */
  new?: Record<string, any>;
  /** Transaction ID */
  xid: number;
  /** Log Sequence Number */
  lsn: string;
  /** Epoch timestamp in milliseconds */
  timestamp: number;
}

// ── WalLevelManager ──────────────────────────────────────────────────────────

export class WalLevelManager {
  private _walLevel: WalLevel = 'replica';
  private archiveDir: string;
  private logicalDir: string;
  private currentLogDate: string = '';
  private logFd: number | null = null;

  constructor(archiveDir?: string) {
    this.archiveDir = path.resolve(archiveDir || './pg_wal_archive');
    this.logicalDir = path.join(this.archiveDir, 'logical');
    fs.mkdirSync(this.logicalDir, { recursive: true });
  }

  /**
   * Set the current wal_level.
   * Changing at runtime takes effect immediately for subsequent WAL writes.
   */
  setWalLevel(level: WalLevel): void {
    const prev = this._walLevel;
    this._walLevel = level;
    logger.info({ from: prev, to: level }, 'wal_level changed');

    // If switching TO logical, ensure logical dir exists
    if (level === 'logical') {
      fs.mkdirSync(this.logicalDir, { recursive: true });
    }
  }

  /**
   * Get the current wal_level.
   */
  getWalLevel(): WalLevel {
    return this._walLevel;
  }

  /**
   * Check whether this wal_level should write DML physical WAL entries.
   *
   * - `minimal`: false — DML WAL is skipped, only checkpoint records
   * - `replica` / `logical`: true — DML WAL is written
   */
  shouldWritePhysicalDML(): boolean {
    return this._walLevel !== 'minimal';
  }

  /**
   * Check whether this wal_level should write logical WAL records.
   * Only `logical` mode produces logical records.
   */
  shouldWriteLogical(): boolean {
    return this._walLevel === 'logical';
  }

  /**
   * Write a logical WAL record to the logical log file.
   *
   * Only writes if wal_level is 'logical'. Records are appended to a
   * daily-rotated file: logical-wal-{YYYYMMDD}.log in {archiveDir}/logical/.
   *
   * @returns The LSN assigned to this record, or null if not in logical mode
   */
  writeLogicalRecord(record: LogicalWalRecord): string | null {
    if (this._walLevel !== 'logical') return null;

    const lsn = this.assignLSN();
    record.lsn = lsn;

    const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const logFile = path.join(this.logicalDir, `logical-wal-${dateStr}.log`);

    const line = JSON.stringify(record) + '\n';

    try {
      // Fast path: append to existing file
      fs.appendFileSync(logFile, line, 'utf-8');
      logger.debug(
        { operation: record.operation, table: record.table, lsn },
        'Logical WAL record written',
      );
      return lsn;
    } catch (err: any) {
      logger.error({ err: err.message }, 'Failed to write logical WAL record');
      return null;
    }
  }

  /**
   * Read all logical WAL records for a specific date.
   * Date format: YYYYMMDD (e.g. '20260603')
   */
  readLogicalRecords(dateStr: string): LogicalWalRecord[] {
    const logFile = path.join(this.logicalDir, `logical-wal-${dateStr}.log`);
    if (!fs.existsSync(logFile)) return [];

    try {
      const content = fs.readFileSync(logFile, 'utf-8').trim();
      if (!content) return [];

      return content
        .split('\n')
        .map((line) => {
          try {
            return JSON.parse(line) as LogicalWalRecord;
          } catch {
            return null;
          }
        })
        .filter((r): r is LogicalWalRecord => r !== null);
    } catch (err: any) {
      logger.error({ err: err.message, dateStr }, 'Failed to read logical WAL records');
      return [];
    }
  }

  /**
   * List all available logical WAL log files.
   */
  listLogicalFiles(): string[] {
    try {
      if (!fs.existsSync(this.logicalDir)) return [];
      return fs
        .readdirSync(this.logicalDir)
        .filter((f) => /^logical-wal-\d{8}\.log$/.test(f))
        .sort();
    } catch {
      return [];
    }
  }

  /**
   * Get the count of logical WAL records for a date range.
   * If no dates given, counts ALL records.
   */
  countLogicalRecords(startDate?: string, endDate?: string): number {
    const files = this.listLogicalFiles();
    let count = 0;

    for (const file of files) {
      const match = file.match(/logical-wal-(\d{8})\.log/);
      if (!match) continue;
      const fileDate = match[1];

      if (startDate && fileDate < startDate) continue;
      if (endDate && fileDate > endDate) continue;

      const records = this.readLogicalRecords(fileDate);
      count += records.length;
    }

    return count;
  }

  /**
   * Reset state (for testing).
   */
  reset(): void {
    this._walLevel = 'replica';
    if (this.logFd !== null) {
      try { fs.closeSync(this.logFd); } catch { /* ignore */ }
      this.logFd = null;
    }
    this.currentLogDate = '';
  }

  // ════════════════════════════════════════════════════════════
  //  Private helpers
  // ════════════════════════════════════════════════════════════

  private lsnCounter = 0;

  /**
   * Assign a monotonically increasing LSN.
   * Format: "SEGMENT/OFFSET" where segment increments on counter overflow.
   */
  private assignLSN(): string {
    this.lsnCounter++;
    const segment = Math.floor(this.lsnCounter / 0x10000);
    const offset = this.lsnCounter % 0x10000;
    return `${segment.toString(16).padStart(8, '0')}/${offset.toString(16).padStart(8, '0')}`;
  }

  /**
   * Format today's date as YYYYMMDD.
   */
  private todayDateStr(): string {
    return new Date().toISOString().slice(0, 10).replace(/-/g, '');
  }
}
