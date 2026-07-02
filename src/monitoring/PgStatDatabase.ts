/**
 * PgStatDatabase — pg_stat_database-equivalent per-database statistics tracker
 *
 * Phase B #3b: Monitors database-level counters mirroring PostgreSQL's
 * pg_stat_database system view.
 *
 * Features:
 *   - Per-database transaction commit/rollback counters
 *   - Tuple I/O: returned/fetched/inserted/updated/deleted
 *   - Buffer cache: blocks read vs. hit
 *   - Deadlock, conflict, temp file tracking
 *   - Checksum failure tracking
 *   - I/O timing (blk_read_time / blk_write_time)
 *   - Backed by SQLite `__pg_stat_database` table for persistence
 *   - PG-compatible toQueryResult() output
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PgStatDatabase');

// ── Types ────────────────────────────────────────────────────────

export interface PgStatDatabaseRow {
  datid: string;
  datname: string;
  numbackends: number;
  xact_commit: number;
  xact_rollback: number;
  blks_read: number;
  blks_hit: number;
  tup_returned: number;
  tup_fetched: number;
  tup_inserted: number;
  tup_updated: number;
  tup_deleted: number;
  conflicts: number;
  temp_files: number;
  temp_bytes: number;
  deadlocks: number;
  checksum_failures: number;
  checksum_last_failure: string | null;
  blk_read_time: number;
  blk_write_time: number;
  stats_reset: string;
}

// ── PgStatDatabaseCollector ──────────────────────────────────────

export class PgStatDatabaseCollector {
  private db: any; // better-sqlite3 Database
  private tableName = '__pg_stat_database';
  private cache: Map<string, PgStatDatabaseRow> = new Map();
  private statsResetTime: string;

  constructor(db: any) {
    this.db = db;
    this.statsResetTime = new Date().toISOString();
    this.ensureTable();

    // Load persisted rows into cache
    this.loadFromDb();
  }

  /**
   * Create the SQLite backing table if it doesn't exist.
   */
  private ensureTable(): void {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS ${this.tableName} (
          datname TEXT PRIMARY KEY,
          datid TEXT NOT NULL,
          numbackends INTEGER NOT NULL DEFAULT 0,
          xact_commit INTEGER NOT NULL DEFAULT 0,
          xact_rollback INTEGER NOT NULL DEFAULT 0,
          blks_read INTEGER NOT NULL DEFAULT 0,
          blks_hit INTEGER NOT NULL DEFAULT 0,
          tup_returned INTEGER NOT NULL DEFAULT 0,
          tup_fetched INTEGER NOT NULL DEFAULT 0,
          tup_inserted INTEGER NOT NULL DEFAULT 0,
          tup_updated INTEGER NOT NULL DEFAULT 0,
          tup_deleted INTEGER NOT NULL DEFAULT 0,
          conflicts INTEGER NOT NULL DEFAULT 0,
          temp_files INTEGER NOT NULL DEFAULT 0,
          temp_bytes INTEGER NOT NULL DEFAULT 0,
          deadlocks INTEGER NOT NULL DEFAULT 0,
          checksum_failures INTEGER NOT NULL DEFAULT 0,
          checksum_last_failure TEXT,
          blk_read_time REAL NOT NULL DEFAULT 0,
          blk_write_time REAL NOT NULL DEFAULT 0,
          stats_reset TEXT NOT NULL
        )
      `);
    } catch (err: any) {
      logger.warn({ err: err.message }, 'Failed to create pg_stat_database table');
    }
  }

  /**
   * Load all persisted rows into the in-memory cache.
   */
  private loadFromDb(): void {
    try {
      const rows = this.db.prepare(`SELECT * FROM ${this.tableName}`).all() as any[];
      for (const row of rows) {
        this.cache.set(String(row.datname), {
          datid: String(row.datid),
          datname: String(row.datname),
          numbackends: Number(row.numbackends),
          xact_commit: Number(row.xact_commit),
          xact_rollback: Number(row.xact_rollback),
          blks_read: Number(row.blks_read),
          blks_hit: Number(row.blks_hit),
          tup_returned: Number(row.tup_returned),
          tup_fetched: Number(row.tup_fetched),
          tup_inserted: Number(row.tup_inserted),
          tup_updated: Number(row.tup_updated),
          tup_deleted: Number(row.tup_deleted),
          conflicts: Number(row.conflicts),
          temp_files: Number(row.temp_files),
          temp_bytes: Number(row.temp_bytes),
          deadlocks: Number(row.deadlocks),
          checksum_failures: Number(row.checksum_failures),
          checksum_last_failure: row.checksum_last_failure ? String(row.checksum_last_failure) : null,
          blk_read_time: Number(row.blk_read_time),
          blk_write_time: Number(row.blk_write_time),
          stats_reset: String(row.stats_reset),
        });
      }
    } catch {
      // Table may not exist yet
    }
  }

  /**
   * Persist a database row to SQLite.
   */
  private persistRow(datname: string): void {
    const row = this.cache.get(datname);
    if (!row) return;

    try {
      this.db.prepare(`
        INSERT OR REPLACE INTO ${this.tableName}
          (datname, datid, numbackends, xact_commit, xact_rollback,
           blks_read, blks_hit, tup_returned, tup_fetched,
           tup_inserted, tup_updated, tup_deleted,
           conflicts, temp_files, temp_bytes, deadlocks,
           checksum_failures, checksum_last_failure,
           blk_read_time, blk_write_time, stats_reset)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        row.datname, row.datid, row.numbackends,
        row.xact_commit, row.xact_rollback,
        row.blks_read, row.blks_hit,
        row.tup_returned, row.tup_fetched,
        row.tup_inserted, row.tup_updated, row.tup_deleted,
        row.conflicts, row.temp_files, row.temp_bytes,
        row.deadlocks,
        row.checksum_failures, row.checksum_last_failure,
        row.blk_read_time, row.blk_write_time,
        row.stats_reset,
      );
    } catch (err: any) {
      logger.warn({ err: err.message }, 'Failed to persist pg_stat_database row');
    }
  }

  /**
   * Get or create the row for a given database.
   * Uses the current database by default.
   */
  private getOrCreateRow(databaseName?: string): PgStatDatabaseRow {
    const datname = databaseName || 'sqlvec';
    let row = this.cache.get(datname);
    if (!row) {
      row = {
        datid: this.computeDatId(datname),
        datname,
        numbackends: 0,
        xact_commit: 0,
        xact_rollback: 0,
        blks_read: 0,
        blks_hit: 0,
        tup_returned: 0,
        tup_fetched: 0,
        tup_inserted: 0,
        tup_updated: 0,
        tup_deleted: 0,
        conflicts: 0,
        temp_files: 0,
        temp_bytes: 0,
        deadlocks: 0,
        checksum_failures: 0,
        checksum_last_failure: null,
        blk_read_time: 0,
        blk_write_time: 0,
        stats_reset: this.statsResetTime,
      };
      this.cache.set(datname, row);
      this.persistRow(datname);
    }
    return row;
  }

  /**
   * Compute a deterministic OID from the database name.
   */
  private computeDatId(datname: string): string {
    let hash = 0;
    for (let i = 0; i < datname.length; i++) {
      const char = datname.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0; // Convert to 32bit integer
    }
    return String(Math.abs(hash));
  }

  // ── Record Operations ─────────────────────────────────────────

  /**
   * Record a transaction commit.
   */
  recordTransactionCommit(databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.xact_commit++;
    this.persistRow(row.datname);
  }

  /**
   * Record a transaction rollback.
   */
  recordTransactionRollback(databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.xact_rollback++;
    this.persistRow(row.datname);
  }

  /**
   * Record tuples inserted.
   */
  recordTupleInserted(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.tup_inserted += count;
    this.persistRow(row.datname);
  }

  /**
   * Record tuples updated.
   */
  recordTupleUpdated(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.tup_updated += count;
    this.persistRow(row.datname);
  }

  /**
   * Record tuples deleted.
   */
  recordTupleDeleted(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.tup_deleted += count;
    this.persistRow(row.datname);
  }

  /**
   * Record blocks read (from disk).
   */
  recordBlocksRead(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.blks_read += count;
    this.persistRow(row.datname);
  }

  /**
   * Record blocks hit (from cache).
   */
  recordBlocksHit(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.blks_hit += count;
    this.persistRow(row.datname);
  }

  /**
   * Record a deadlock event.
   */
  recordDeadlock(databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.deadlocks++;
    this.persistRow(row.datname);
  }

  /**
   * Record a temporary file usage.
   */
  recordTempFile(sizeBytes: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.temp_files++;
    row.temp_bytes += sizeBytes;
    this.persistRow(row.datname);
  }

  /**
   * Record a recovery conflict.
   */
  recordConflict(databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.conflicts++;
    this.persistRow(row.datname);
  }

  /**
   * Record a checksum failure.
   */
  recordChecksumFailure(databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.checksum_failures++;
    row.checksum_last_failure = new Date().toISOString();
    this.persistRow(row.datname);
  }

  /**
   * Add I/O timing (in milliseconds).
   */
  recordIoTime(readTimeMs: number, writeTimeMs: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.blk_read_time += readTimeMs;
    row.blk_write_time += writeTimeMs;
    this.persistRow(row.datname);
  }

  // ── Backend Tracking ──────────────────────────────────────────

  /**
   * Update the number of active backends.
   */
  setNumBackends(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.numbackends = count;
    this.persistRow(row.datname);
  }

  /**
   * Record tuple returned (for sequential/index scans).
   */
  recordTupleReturned(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.tup_returned += count;
    this.persistRow(row.datname);
  }

  /**
   * Record tuple fetched (via index).
   */
  recordTupleFetched(count: number, databaseName?: string): void {
    const row = this.getOrCreateRow(databaseName);
    row.tup_fetched += count;
    this.persistRow(row.datname);
  }

  // ── Query ─────────────────────────────────────────────────────

  /**
   * Get statistics row for a specific database.
   */
  getRow(databaseName: string): PgStatDatabaseRow {
    return { ...this.getOrCreateRow(databaseName) };
  }

  /**
   * Get all database statistics rows.
   */
  getAllRows(): PgStatDatabaseRow[] {
    return Array.from(this.cache.values()).map(r => ({ ...r }));
  }

  // ── Reset ─────────────────────────────────────────────────────

  /**
   * Reset all tracked statistics.
   */
  resetStats(): void {
    this.cache.clear();
    this.statsResetTime = new Date().toISOString();
    try {
      this.db.exec(`DELETE FROM ${this.tableName}`);
    } catch {
      // Non-fatal
    }
  }

  // ── PG-compatible output ─────────────────────────────────────

  /**
   * Return rows matching the pg_stat_database column schema.
   * Called when a user queries pg_stat_database.
   */
  toQueryResult(): any[] {
    return this.getAllRows().map(r => ({
      datid: r.datid,
      datname: r.datname,
      numbackends: r.numbackends,
      xact_commit: r.xact_commit,
      xact_rollback: r.xact_rollback,
      blks_read: r.blks_read,
      blks_hit: r.blks_hit,
      tup_returned: r.tup_returned,
      tup_fetched: r.tup_fetched,
      tup_inserted: r.tup_inserted,
      tup_updated: r.tup_updated,
      tup_deleted: r.tup_deleted,
      conflicts: r.conflicts,
      temp_files: r.temp_files,
      temp_bytes: r.temp_bytes,
      deadlocks: r.deadlocks,
      checksum_failures: r.checksum_failures,
      checksum_last_failure: r.checksum_last_failure,
      blk_read_time: r.blk_read_time,
      blk_write_time: r.blk_write_time,
      stats_reset: r.stats_reset,
    }));
  }
}
