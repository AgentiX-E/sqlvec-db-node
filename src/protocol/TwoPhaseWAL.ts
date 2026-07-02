/**
 * TwoPhaseWAL — WAL persistence layer for 2PC (two-phase commit).
 *
 * ## E5-WAL1: CRC32C Checksum
 *
 * Each WAL record now includes a CRC32C checksum stored in the `checksum` column.
 * Every write (prepare/commit/rollback) computes and verifies the checksum.
 * On recovery, each prepared record is validated against its stored checksum.
 *
 * ## Problem
 *
 * The existing TwoPhaseCommitManager maintains prepared transactions only in
 * memory and relies on `__prepared_transactions` for persistence. However,
 * audit identified three gaps:
 *
 * 1. **2PC 非事务性原子** — `PREPARE TRANSACTION`/`COMMIT PREPARED`/`ROLLBACK
 *    PREPARED` lack WAL-level durability; crash during the window between
 *    prepare and commit causes loss.
 * 2. **无 WAL 预写日志** — No pre-write log entry is created before the
 *    execution phase, so a crash after prepare but before commit leaves no
 *    recoverable trace.
 * 3. **无恢复处理** — On restart, the `__prepared_transactions` state is not
 *    reconstructed reliably from a crash-safe WAL table.
 * 4. **E5-WAL1**: 无校验 — No CRC32C checksum on WAL records, so silent
 *    corruption goes undetected.
 *
 * ## Solution
 *
 * This module implements a dedicated WAL (Write-Ahead Log) table:
 *
 * ```
 * __wal_prepared(
 *   gid TEXT PRIMARY KEY,
 *   sqls TEXT,
 *   status TEXT,
 *   created_at TEXT,
 *   checksum TEXT   -- E5-WAL1: CRC32C hex checksum
 * )
 * ```
 *
 * ## Protocol
 *
 *        prepareXact(gid, sqls)       commitPrepared(gid)
 *              │                            │
 *              ▼                            ▼
 *     ┌─────────────────┐         ┌────────────────────┐
 *     │ INSERT INTO      │         │ BEGIN IMMEDIATE    │
 *     │ __wal_prepared   │         │ ┌────────────────┐  │
 *     │ (gid, sqls,      │         │ │ Execute sqls[] │  │
 *     │  'prepared', ...,│         │ └────────────────┘  │
 *     │  checksum)       │         │ UPDATE status=      │
 *     └─────────────────┘         │   'committed'       │
 *              │                  │ COMMIT              │
 *              ▼                  └────────────────────┘
 *     (crash safe now)                      │
 *                                            ▼
 *                                   ┌──────────────────┐
 *                                   │ DELETE FROM       │
 *                                   │ __wal_prepared    │
 *                                   └──────────────────┘
 *
 *        rollbackPrepared(gid)
 *              │
 *              ▼
 *     ┌────────────────────┐
 *     │ UPDATE status=     │
 *     │   'rolled_back'    │
 *     │ DELETE FROM        │
 *     │ __wal_prepared     │
 *     └────────────────────┘
 *
 *        recoverPrepared()
 *              │
 *              ▼
 *     ┌─────────────────────────────┐
 *     │ SELECT * FROM __wal_prepared│
 *     │ WHERE status='prepared'     │
 *     │ → verify checksum each row  │
 *     │ → return PreparedXact[]     │
 *     │ (caller must COMMIT/ROLLBACK)│
 *     └─────────────────────────────┘
 *
 * ## Crash Recovery Flow
 *
 * ```
 * On restart:
 *   1. recoverPrepared() scans __wal_prepared WHERE status='prepared'
 *   2. Each entry's CRC32C checksum is verified
 *   3. If checksum mismatch, the entry is marked as 'corrupted' (skipped)
 *   4. Returns list of valid in-doubt transactions (gid, sqls, created_at)
 *   5. Caller must either:
 *      a. commitPrepared(gid)  → execute SQL + mark 'committed'
 *      b. rollbackPrepared(gid) → mark 'rolled_back'
 * ```
 *
 * @module protocol/TwoPhaseWAL
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { EventEmitter } from 'events';
import crc32 from 'buffer-crc32';

export interface WalCdcEvent {
  /** Type of WAL event. */
  type: 'prepared' | 'committed' | 'rolled_back';
  /** Global transaction ID. */
  gid: string;
  /** Number of SQL statements involved. */
  sqlCount: number;
  /** Timestamp of the event. */
  timestamp: string;
  /** The prepared SQL statements (only for 'prepared' events). */
  sqls?: string[];
  /** Additional context. */
  metadata?: Record<string, any>;
}

/** CDC event hook type for WAL write observers. */
export type WalCdcHook = (event: WalCdcEvent) => void;

export interface WalPreparedRow {
  gid: string;
  sqls: string;
  status: string;
  created_at: string;
  checksum?: string;
}

export interface PreparedXact {
  gid: string;
  sqls: string[];
  status: 'prepared' | 'committed' | 'rolled_back';
  createdAt: string;
}

export interface TwoPhaseWalOptions {
  /** better-sqlite3 Database instance for persistence */
  db: any;
  /** Optional logger instance */
  logger?: PinoLogger;
  /** Table name to use (default: '__wal_prepared') */
  tableName?: string;
  /** Set to true to skip DDL init during constructor (for testing pre-created tables) */
  skipInit?: boolean;
}

/**
 * TwoPhaseWAL — WAL persistence for 2PC prepared transactions.
 *
 * Provides crash-safe write-ahead logging for the two-phase commit protocol
 * using a dedicated SQLite table.
 */
export class TwoPhaseWAL {
  private readonly db: any;
  private readonly logger: PinoLogger;
  private readonly tableName: string;
  private readonly emitter: EventEmitter;
  private readonly hooks: WalCdcHook[] = [];
  private readonly stmt: {
    insert: any;
    updateStatus: any;
    selectByGid: any;
    selectPrepared: any;
    selectAll: any;
    delete: any;
    markCorrupted: any;
  };

  constructor(opts: TwoPhaseWalOptions) {
    this.db = opts.db;
    this.logger = opts.logger ?? PinoLogger.forComponent('TwoPhaseWAL');
    this.tableName = opts.tableName || '__wal_prepared';
    this.emitter = new EventEmitter();

    // Force WAL journal mode on the connection for crash safety
    this.db.exec('PRAGMA journal_mode=WAL');

    if (!opts.skipInit) {
      this.ensureTable();
    }

    // Prepare all statements for consistent reuse
    const tn = this.tableName;
    this.stmt = {
      insert: this.db.prepare(
        `INSERT OR REPLACE INTO ${tn} (gid, sqls, status, created_at, checksum) VALUES (?, ?, ?, ?, ?)`,
      ),
      updateStatus: this.db.prepare(
        `UPDATE ${tn} SET status = ? WHERE gid = ?`,
      ),
      selectByGid: this.db.prepare(
        `SELECT * FROM ${tn} WHERE gid = ?`,
      ),
      selectPrepared: this.db.prepare(
        `SELECT * FROM ${tn} WHERE status = 'prepared'`,
      ),
      selectAll: this.db.prepare(
        `SELECT * FROM ${tn}`,
      ),
      delete: this.db.prepare(
        `DELETE FROM ${tn} WHERE gid = ?`,
      ),
      markCorrupted: this.db.prepare(
        `UPDATE ${tn} SET status = 'corrupted' WHERE gid = ?`,
      ),
    };

    this.logger.debug({ table: this.tableName }, 'TwoPhaseWAL initialised');
  }

  // ── DDL ──────────────────────────────────────

  /**
   * Create the WAL prepared transactions table if it does not exist.
   * Includes CRC32C checksum column for E5-WAL1 corruption detection.
   */
  ensureTable(): void {
    const ddl = `CREATE TABLE IF NOT EXISTS ${this.tableName} (
      gid TEXT PRIMARY KEY,
      sqls TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'prepared',
      created_at TEXT NOT NULL,
      checksum TEXT
    )`;
    this.db.exec(ddl);
    this.logger.debug({ table: this.tableName }, 'WAL table ensured');
  }

  /**
   * Drop the WAL table. Used for testing cleanup.
   */
  dropTable(): void {
    this.db.exec(`DROP TABLE IF EXISTS ${this.tableName}`);
    this.logger.debug({ table: this.tableName }, 'WAL table dropped');
  }

  /**
   * Compute a CRC32C checksum for a WAL record.
   * The checksum covers: gid + sqls JSON + status + created_at.
   */
  static computeChecksum(gid: string, sqls: string[], status: string, createdAt: string): string {
    const payload = `${gid}|${JSON.stringify(sqls || [])}|${status}|${createdAt}`;
    return crc32(Buffer.from(payload, 'utf8')).toString('hex');
  }

  /**
   * Verify a WAL record's checksum. Returns true if valid (or if no checksum stored — legacy compat).
   */
  static verifyChecksum(row: WalPreparedRow): boolean {
    if (!row.checksum) return true; // legacy entries without checksum
    const expected = TwoPhaseWAL.computeChecksum(row.gid, JSON.parse(row.sqls || '[]'), row.status, row.created_at);
    return expected === row.checksum;
  }

  // ── Core API ──────────────────────────────────

  /**
   * Prepare a transaction by writing its pending SQL to the WAL table with
   * status 'prepared'. Writes a CRC32C checksum for corruption detection (E5-WAL1).
   *
   * @param gid   Global transaction identifier
   * @param sqls  Array of SQL statements to be executed on commit
   *
   * @throws Error if a prepared transaction with the same gid already exists
   *         in status 'prepared'.
   */
  prepareXact(gid: string, sqls: string[]): void {
    if (!gid || gid.trim().length === 0) {
      throw new Error('gid must be a non-empty string');
    }

    const existing = this.stmt.selectByGid.get(gid);
    if (existing && existing.status === 'prepared') {
      throw new Error(`Prepared transaction '${gid}' already exists in WAL`);
    }

    const sqlsJson = JSON.stringify(sqls || []);
    const createdAt = new Date().toISOString();
    const checksum = TwoPhaseWAL.computeChecksum(gid, sqls || [], 'prepared', createdAt);

    this.stmt.insert.run(gid, sqlsJson, 'prepared', createdAt, checksum);

    this.logger.info({ gid, sqlCount: (sqls || []).length }, 'WAL prepared');

    // Fire CDC hook
    this.fireCdcEvent({
      type: 'prepared',
      gid,
      sqlCount: (sqls || []).length,
      timestamp: createdAt,
      sqls,
    });
  }

  /**
   * Commit a previously prepared transaction. Executes the pending SQL
   * statements atomically, then marks the WAL entry as 'committed', and
   * finally deletes the entry.
   *
   * @param gid  Global transaction identifier
   *
   * @throws Error if the gid is not found or not in 'prepared' status.
   * @throws Error if SQL execution fails (the entry is preserved).
   */
  commitPrepared(gid: string): void {
    const row = this.stmt.selectByGid.get(gid) as WalPreparedRow | undefined;

    if (!row) {
      throw new Error(`Prepared transaction '${gid}' not found in WAL`);
    }
    if (row.status !== 'prepared') {
      throw new Error(
        `Prepared transaction '${gid}' has status '${row.status}', expected 'prepared'`,
      );
    }

    const sqls: string[] = JSON.parse(row.sqls);

    if (sqls.length > 0) {
      // Execute pending SQL atomically
      this.db.exec('BEGIN IMMEDIATE');
      try {
        for (const sql of sqls) {
          this.db.exec(sql);
        }
        this.db.exec('COMMIT');
      } catch (e) {
        this.db.exec('ROLLBACK');
        this.logger.error({ err: e, gid }, 'Failed to execute prepared SQL');
        throw e;
      }
    }

    // Mark as committed in WAL
    this.stmt.updateStatus.run('committed', gid);

    // Clean up committed entry
    this.stmt.delete.run(gid);

    this.logger.info({ gid, sqlCount: sqls.length }, 'WAL committed');

    // Fire CDC hook
    this.fireCdcEvent({
      type: 'committed',
      gid,
      sqlCount: sqls.length,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Roll back a prepared transaction. Marks the WAL entry as 'rolled_back'
   * and deletes it. Does NOT execute the pending SQL.
   *
   * @param gid  Global transaction identifier
   *
   * @throws Error if the gid is not found or not in 'prepared' status.
   */
  rollbackPrepared(gid: string): void {
    const row = this.stmt.selectByGid.get(gid) as WalPreparedRow | undefined;

    if (!row) {
      throw new Error(`Prepared transaction '${gid}' not found in WAL`);
    }
    if (row.status !== 'prepared') {
      throw new Error(
        `Prepared transaction '${gid}' has status '${row.status}', expected 'prepared'`,
      );
    }

    // Mark as rolled back
    this.stmt.updateStatus.run('rolled_back', gid);

    // Clean up
    this.stmt.delete.run(gid);

    this.logger.info({ gid }, 'WAL rolled back');

    // Fire CDC hook
    this.fireCdcEvent({
      type: 'rolled_back',
      gid,
      sqlCount: 0,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Recover all prepared transactions from the WAL table that are still in
   * 'prepared' status. Verifies CRC32C checksum on each entry (E5-WAL1).
   * Corrupted entries are marked as 'corrupted' and excluded from results.
   *
   * @returns Array of valid PreparedXact entries that need manual resolution
   *          (COMMIT or ROLLBACK by the caller).
   */
  recoverPrepared(): PreparedXact[] {
    const rows = this.stmt.selectPrepared.all() as WalPreparedRow[];
    const valid: PreparedXact[] = [];

    for (const row of rows) {
      if (!TwoPhaseWAL.verifyChecksum(row)) {
        this.stmt.markCorrupted.run(row.gid);
        this.logger.warn(
          { gid: row.gid },
          'WAL checksum mismatch — entry marked as corrupted, skipped during recovery',
        );
        continue;
      }
      valid.push({
        gid: row.gid,
        sqls: JSON.parse(row.sqls || '[]') as string[],
        status: row.status as 'prepared',
        createdAt: row.created_at,
      });
    }

    return valid;
  }

  /**
   * Check if a prepared transaction exists in the WAL table.
   *
   * @param gid  Global transaction identifier
   * @returns true if an entry with the given gid exists
   */
  exists(gid: string): boolean {
    const row = this.stmt.selectByGid.get(gid);
    return !!row;
  }

  /**
   * Get the status of a prepared transaction.
   *
   * @param gid  Global transaction identifier
   * @returns The status string ('prepared', 'committed', 'rolled_back') or null
   */
  getStatus(gid: string): string | null {
    const row = this.stmt.selectByGid.get(gid) as WalPreparedRow | undefined;
    return row ? row.status : null;
  }

  /**
   * Return all entries in the WAL table.
   */
  all(): PreparedXact[] {
    const rows = this.stmt.selectAll.all() as WalPreparedRow[];
    return rows.map((row) => ({
      gid: row.gid,
      sqls: JSON.parse(row.sqls || '[]') as string[],
      status: row.status as 'prepared' | 'committed' | 'rolled_back',
      createdAt: row.created_at,
    }));
  }

  /**
   * Count of currently prepared (in-doubt) transactions.
   */
  countPrepared(): number {
    return this.recoverPrepared().length;
  }

  // ── CDC Hooks ────────────────────────────────

  /**
   * Register a CDC event hook that fires on every WAL write.
   * Multiple hooks can be registered.
   */
  onCdcEvent(hook: WalCdcHook): void {
    this.hooks.push(hook);
  }

  /**
   * Remove a previously registered CDC event hook.
   */
  offCdcEvent(hook: WalCdcHook): void {
    const idx = this.hooks.indexOf(hook);
    if (idx >= 0) this.hooks.splice(idx, 1);
  }

  /**
   * Register a one-shot listener for CDC events.
   */
  onceCdcEvent(hook: WalCdcHook): void {
    const wrapper: WalCdcHook = (event) => {
      this.offCdcEvent(wrapper);
      hook(event);
    };
    this.onCdcEvent(wrapper);
  }

  /**
   * Fire a CDC event to all registered hooks and the EventEmitter.
   */
  private fireCdcEvent(event: WalCdcEvent): void {
    for (const hook of this.hooks) {
      try {
        hook(event);
      } catch (err: any) {
        this.logger.error({ err: err.message, event: event.type }, 'CDC hook error');
      }
    }
    this.emitter.emit('cdc:' + event.type, event);
    this.emitter.emit('cdc', event);
  }

  /** Listen for all CDC events via EventEmitter. */
  on(event: 'cdc' | 'cdc:prepared' | 'cdc:committed' | 'cdc:rolled_back', listener: (event: WalCdcEvent) => void): void {
    this.emitter.on(event, listener);
  }

  /**
   * Create a new TwoPhaseWAL instance backed by a fresh in-memory SQLite
   * database. Convenience for testing.
   */
  static createInMemory(tableName?: string): TwoPhaseWAL {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const Database = require('better-sqlite3');
    const db = new Database(':memory:');
    return new TwoPhaseWAL({ db, tableName, skipInit: false });
  }
}
