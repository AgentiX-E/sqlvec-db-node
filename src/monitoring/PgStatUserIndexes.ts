/**
 * PgStatUserIndexes — pg_stat_user_indexes-equivalent index usage tracker
 *
 * Phase B #3b: Monitors index-level statistics mirroring PostgreSQL's
 * pg_stat_user_indexes system view.
 *
 * Features:
 *   - Per-index scan counts
 *   - Tuple read/fetch tracking via index
 *   - Buffer cache hit/miss tracking per index
 *   - Backed by SQLite `__pg_stat_user_indexes` table for persistence
 *   - PG-compatible toQueryResult() output
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PgStatUserIndexes');

// ── Types ────────────────────────────────────────────────────────

export interface PgStatUserIndexRow {
  /** Table OID */
  relid: string;
  /** Index OID */
  indexrelid: string;
  /** Schema name */
  schemaname: string;
  /** Table name */
  relname: string;
  /** Index name */
  indexrelname: string;
  /** Number of index scans */
  idx_scan: number;
  /** Number of tuples read by index scans */
  idx_tup_read: number;
  /** Number of tuples fetched from the table via index */
  idx_tup_fetch: number;
  /** Number of index block reads (disk I/O) */
  idx_blks_read: number;
  /** Number of index block hits (cache) */
  idx_blks_hit: number;
}

// ── Default instance for global use ──────────────────────────────

let defaultInstance: PgStatUserIndexCollector | null = null;

/**
 * Set the default collector instance for use by PlanExecutor and index executors.
 */
export function setDefaultCollector(collector: PgStatUserIndexCollector): void {
  defaultInstance = collector;
}

/**
 * Get the default collector instance.
 */
export function getDefaultCollector(): PgStatUserIndexCollector | null {
  return defaultInstance;
}

// ── PgStatUserIndexCollector ─────────────────────────────────────

export class PgStatUserIndexCollector {
  private db: any; // better-sqlite3 Database
  private tableName = '__pg_stat_user_indexes';
  private cache: Map<string, PgStatUserIndexRow> = new Map();
  private oidCounter: number = 0;

  constructor(db: any) {
    this.db = db;
    this.ensureTable();
    this.loadFromDb();
  }

  /**
   * Create the SQLite backing table if it doesn't exist.
   */
  private ensureTable(): void {
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS ${this.tableName} (
          indexrelname TEXT PRIMARY KEY,
          relid TEXT NOT NULL,
          indexrelid TEXT NOT NULL,
          schemaname TEXT NOT NULL DEFAULT 'public',
          relname TEXT NOT NULL,
          idx_scan INTEGER NOT NULL DEFAULT 0,
          idx_tup_read INTEGER NOT NULL DEFAULT 0,
          idx_tup_fetch INTEGER NOT NULL DEFAULT 0,
          idx_blks_read INTEGER NOT NULL DEFAULT 0,
          idx_blks_hit INTEGER NOT NULL DEFAULT 0
        )
      `);
    } catch (err: any) {
      logger.warn({ err: err.message }, 'Failed to create pg_stat_user_indexes table');
    }
  }

  /**
   * Load all persisted rows into the in-memory cache.
   */
  private loadFromDb(): void {
    try {
      const rows = this.db.prepare(`SELECT * FROM ${this.tableName}`).all() as any[];
      for (const row of rows) {
        this.cache.set(String(row.indexrelname), {
          relid: String(row.relid),
          indexrelid: String(row.indexrelid),
          schemaname: String(row.schemaname),
          relname: String(row.relname),
          indexrelname: String(row.indexrelname),
          idx_scan: Number(row.idx_scan),
          idx_tup_read: Number(row.idx_tup_read),
          idx_tup_fetch: Number(row.idx_tup_fetch),
          idx_blks_read: Number(row.idx_blks_read),
          idx_blks_hit: Number(row.idx_blks_hit),
        });
      }
    } catch {
      // Table may not exist yet
    }
  }

  /**
   * Persist a row to SQLite.
   */
  private persistRow(indexName: string): void {
    const row = this.cache.get(indexName);
    if (!row) return;

    try {
      this.db.prepare(`
        INSERT OR REPLACE INTO ${this.tableName}
          (indexrelname, relid, indexrelid, schemaname, relname,
           idx_scan, idx_tup_read, idx_tup_fetch,
           idx_blks_read, idx_blks_hit)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        row.indexrelname, row.relid, row.indexrelid,
        row.schemaname, row.relname,
        row.idx_scan, row.idx_tup_read, row.idx_tup_fetch,
        row.idx_blks_read, row.idx_blks_hit,
      );
    } catch (err: any) {
      logger.warn({ err: err.message }, 'Failed to persist pg_stat_user_indexes row');
    }
  }

  /**
   * Get or create a row for a given index.
   */
  private getOrCreateRow(
    indexName: string,
    tableName: string = '',
    schema: string = 'public',
  ): PgStatUserIndexRow {
    const key = indexName.toLowerCase();
    let row = this.cache.get(key);
    if (!row) {
      this.oidCounter++;
      row = {
        relid: this.computeOid(tableName),
        indexrelid: String(this.oidCounter + 100000),
        schemaname: schema,
        relname: tableName,
        indexrelname: indexName,
        idx_scan: 0,
        idx_tup_read: 0,
        idx_tup_fetch: 0,
        idx_blks_read: 0,
        idx_blks_hit: 0,
      };
      this.cache.set(key, row);
      this.persistRow(key);
    }
    return row;
  }

  /**
   * Compute a deterministic OID from a name.
   */
  private computeOid(name: string): string {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      const char = name.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return String(Math.abs(hash));
  }

  // ── Record Operations ─────────────────────────────────────────

  /**
   * Record an index scan occurrence.
   * Called by the index executor after performing an index scan.
   */
  recordIndexScan(indexName: string, tableName: string, schema: string = 'public'): void {
    const row = this.getOrCreateRow(indexName, tableName, schema);
    row.idx_scan++;
    this.persistRow(row.indexrelname.toLowerCase());
  }

  /**
   * Record tuples read via an index (during index scan).
   */
  recordIndexTuplesRead(indexName: string, count: number): void {
    const row = this.getOrCreateRow(indexName);
    row.idx_tup_read += count;
    this.persistRow(row.indexrelname.toLowerCase());
  }

  /**
   * Record tuples fetched from the table via the index.
   */
  recordIndexTuplesFetched(indexName: string, count: number): void {
    const row = this.getOrCreateRow(indexName);
    row.idx_tup_fetch += count;
    this.persistRow(row.indexrelname.toLowerCase());
  }

  /**
   * Record a block access for an index (hit = read from cache, not hit = disk I/O).
   */
  recordIndexBlock(indexName: string, hit: boolean): void {
    const row = this.getOrCreateRow(indexName);
    if (hit) {
      row.idx_blks_hit++;
    } else {
      row.idx_blks_read++;
    }
    this.persistRow(row.indexrelname.toLowerCase());
  }

  // ── Query ─────────────────────────────────────────────────────

  /**
   * Get statistics for a specific index.
   */
  getRow(indexName: string): PgStatUserIndexRow | undefined {
    const row = this.cache.get(indexName.toLowerCase());
    return row ? { ...row } : undefined;
  }

  /**
   * Get all index statistics.
   */
  getAllRows(): PgStatUserIndexRow[] {
    return Array.from(this.cache.values()).map(r => ({ ...r }));
  }

  /**
   * Get all indexes for a given table.
   */
  getByTable(tableName: string): PgStatUserIndexRow[] {
    const lower = tableName.toLowerCase();
    return Array.from(this.cache.values())
      .filter(r => r.relname.toLowerCase() === lower)
      .map(r => ({ ...r }));
  }

  // ── Reset ─────────────────────────────────────────────────────

  /**
   * Reset all tracked statistics.
   */
  resetStats(): void {
    this.cache.clear();
    this.oidCounter = 0;
    try {
      this.db.exec(`DELETE FROM ${this.tableName}`);
    } catch {
      // Non-fatal
    }
  }

  // ── PG-compatible output ─────────────────────────────────────

  /**
   * Return rows matching the pg_stat_user_indexes column schema.
   */
  toQueryResult(): any[] {
    return this.getAllRows().map(r => ({
      relid: r.relid,
      indexrelid: r.indexrelid,
      schemaname: r.schemaname,
      relname: r.relname,
      indexrelname: r.indexrelname,
      idx_scan: r.idx_scan,
      idx_tup_read: r.idx_tup_read,
      idx_tup_fetch: r.idx_tup_fetch,
      idx_blks_read: r.idx_blks_read,
      idx_blks_hit: r.idx_blks_hit,
    }));
  }
}
