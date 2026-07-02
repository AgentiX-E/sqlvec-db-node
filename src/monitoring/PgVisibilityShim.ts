/**
 * PgVisibilityShim — PostgreSQL pg_visibility extension compatibility shim.
 *
 * PostgreSQL's pg_visibility extension provides functions to inspect the
 * visibility map of relations. The visibility map tracks which pages have
 * all their tuples visible to all transactions (all_visible) and which
 * have all tuples frozen (all_frozen).
 *
 * Since SQLite doesn't have MVCC visibility maps natively, this shim:
 *   - Stores visibility data in a __pg_visibility_map auxiliary table
 *   - Provides all pg_visibility functions with compatible interfaces
 *   - Returns sensible defaults (all visible, none frozen for SQLite)
 *   - Supports detection and rewriting of pg_visibility function calls in SQL
 *
 * @module monitoring/PgVisibilityShim
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-visibility-shim');

// ── Constants ──────────────────────────────────────────────────

/** Name of the visibility map storage table */
const VISIBILITY_MAP_TABLE = '__pg_visibility_map';

/** Default page size for SQLite (same as PostgreSQL) */
const DEFAULT_PAGE_SIZE = 8192;

/** Regex to detect pg_visibility function calls in SQL */
const PG_VISIBILITY_FUNC_RE =
  /\b(pg_visibility_map|pg_visibility_map_rel|pg_visibility|pg_collect_visibility|pg_check_visible|pg_truncate_visibility_map)\s*\(/i;

// ── Types ──────────────────────────────────────────────────────

export interface VisibilityMapEntry {
  relname: string;
  relforknumber: number;
  blkno: number;
  all_visible: boolean;
  all_frozen: boolean;
  storage_type: string;
}

interface VisibilityMapRow {
  relname: string;
  relforknumber: number;
  blkno: number;
  all_visible: number; // SQLite uses 0/1
  all_frozen: number;
  storage_type: string;
}

// ── Helpers ────────────────────────────────────────────────────

/** Initialise the visibility map storage table if it doesn't exist */
function ensureVisibilityTable(db: any): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS "${VISIBILITY_MAP_TABLE}"(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      relname TEXT NOT NULL,
      relforknumber INTEGER NOT NULL DEFAULT 0,
      blkno INTEGER NOT NULL DEFAULT 0,
      all_visible INTEGER NOT NULL DEFAULT 1,
      all_frozen INTEGER NOT NULL DEFAULT 0,
      storage_type TEXT NOT NULL DEFAULT 'heap',
      updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(relname, relforknumber, blkno)
    )
  `);
}

/** Get page count for a table from SQLite metadata */
function getPageCount(db: any, relationName: string): number {
  try {
    const row = db.prepare(
      `SELECT page_count FROM pragma_page_count WHERE table_name = ?`,
    ).get(relationName) as { page_count: number } | undefined;

    if (row) return row.page_count;

    // Fallback: estimate from row count
    const count = db.prepare(
      // eslint-disable-next-line @typescript-eslint/no-dynamic-query
      `SELECT COUNT(*) AS cnt FROM "${relationName.replace(/"/g, '""')}"`,
    ).get() as { cnt: number };

    return Math.max(1, Math.ceil(count.cnt / 100));
  } catch {
    return 1;
  }
}

// ── PgVisibilityShim ───────────────────────────────────────────

export class PgVisibilityShim {
  private db: any;

  /**
   * @param db - better-sqlite3 database instance
   */
  constructor(db: any) {
    this.db = db;
    ensureVisibilityTable(this.db);
  }

  /**
   * pg_visibility_map(relation, blkno) → VisibilityMapEntry
   *
   * Returns the visibility map entry for a specific block of a relation.
   *
   * @param relationName - Table name
   * @param blkno - Block number
   * @returns VisibilityMapEntry for the specified block
   */
  visibilityMap(relationName: string, blkno: number): VisibilityMapEntry {
    const row = this.db.prepare(
      `SELECT relname, relforknumber, blkno, all_visible, all_frozen, storage_type
       FROM "${VISIBILITY_MAP_TABLE}"
       WHERE relname = ? AND blkno = ?`,
    ).get(relationName, blkno) as VisibilityMapRow | undefined;

    if (row) {
      return {
        relname: row.relname,
        relforknumber: row.relforknumber,
        blkno: row.blkno,
        all_visible: row.all_visible === 1,
        all_frozen: row.all_frozen === 1,
        storage_type: row.storage_type,
      };
    }

    // Default: block exists, all visible (SQLite behaviour), none frozen
    return {
      relname: relationName,
      relforknumber: 0,
      blkno,
      all_visible: true,
      all_frozen: false,
      storage_type: 'heap',
    };
  }

  /**
   * pg_visibility_map_rel(relation) → VisibilityMapEntry[]
   *
   * Returns visibility map entries for all blocks of a relation.
   *
   * @param relationName - Table name
   * @returns Array of VisibilityMapEntry for all blocks
   */
  visibilityMapRel(relationName: string): VisibilityMapEntry[] {
    const rows = this.db.prepare(
      `SELECT relname, relforknumber, blkno, all_visible, all_frozen, storage_type
       FROM "${VISIBILITY_MAP_TABLE}"
       WHERE relname = ?
       ORDER BY blkno ASC`,
    ).all(relationName) as VisibilityMapRow[];

    if (rows.length > 0) {
      return rows.map(row => ({
        relname: row.relname,
        relforknumber: row.relforknumber,
        blkno: row.blkno,
        all_visible: row.all_visible === 1,
        all_frozen: row.all_frozen === 1,
        storage_type: row.storage_type,
      }));
    }

    // No data in visibility map yet — return defaults for estimated pages
    const pageCount = getPageCount(this.db, relationName);
    const results: VisibilityMapEntry[] = [];

    for (let i = 0; i < pageCount; i++) {
      results.push({
        relname: relationName,
        relforknumber: 0,
        blkno: i,
        all_visible: true,
        all_frozen: false,
        storage_type: 'heap',
      });
    }

    return results;
  }

  /**
   * pg_visibility(relation) → tuple-level visibility info
   *
   * Returns detailed visibility information for each tuple in the relation.
   * Since SQLite has no MVCC dead tuples, all tuples are visible and none frozen.
   *
   * @param relationName - Table name
   * @returns Array of { ctid, all_visible, all_frozen }
   */
  visibility(relationName: string): { ctid: string; all_visible: boolean; all_frozen: boolean }[] {
    const results: { ctid: string; all_visible: boolean; all_frozen: boolean }[] = [];

    try {
      const rows = this.db.prepare(
        /* eslint-disable-next-line @typescript-eslint/no-dynamic-query */
        `SELECT rowid AS __rid FROM "${relationName.replace(/"/g, '""')}" ORDER BY rowid`,
      ).all() as { __rid: unknown }[];

      const pageSize = 100; // approximate tuples per page
      for (const row of rows) {
        const rid = Number(row.__rid);
        const pageNo = Math.floor((rid - 1) / pageSize);
        const tupleIndex = ((rid - 1) % pageSize) + 1;
        const ctid = `(${pageNo},${tupleIndex})`;

        // Check if this tuple's page is frozen
        const frozenRow = this.db.prepare(
          `SELECT all_frozen FROM "${VISIBILITY_MAP_TABLE}"
           WHERE relname = ? AND blkno = ?`,
        ).get(relationName, pageNo) as { all_frozen: number } | undefined;

        const isFrozen = frozenRow ? frozenRow.all_frozen === 1 : false;

        results.push({
          ctid,
          all_visible: true,
          all_frozen: isFrozen,
        });
      }
    } catch (err) {
      logger.error({ err, relationName }, 'pg_visibility failed');
    }

    return results;
  }

  /**
   * pg_collect_visibility(relation) → void
   *
   * Force collection of visibility map data. In this simulation, this
   * scans the table and marks all pages as all_visible (since SQLite
   * doesn't have MVCC dead tuples).
   *
   * @param relationName - Table name
   */
  collectVisibility(relationName: string): void {
    const pageCount = getPageCount(this.db, relationName);

    const upsert = this.db.prepare(
      `INSERT OR REPLACE INTO "${VISIBILITY_MAP_TABLE}"
       (relname, relforknumber, blkno, all_visible, all_frozen, storage_type, updated_at)
       VALUES (?, 0, ?, 1, 0, 'heap', datetime('now'))`,
    );

    const tx = this.db.transaction(() => {
      for (let i = 0; i < pageCount; i++) {
        upsert.run(relationName, i);
      }
    });

    tx();
    logger.info({ relationName, pageCount }, 'Visibility map collected');
  }

  /**
   * pg_check_visible(relation) → { correct, errors }
   *
   * Check if the visibility map is consistent with the actual data.
   * Since we approximate, this always returns correct for SQLite.
   *
   * @param relationName - Table name
   * @returns Check result with possible errors
   */
  checkVisible(relationName: string): { correct: boolean; errors: string[] } {
    const errors: string[] = [];

    try {
      const rows = this.db.prepare(
        `SELECT blkno, all_visible, all_frozen FROM "${VISIBILITY_MAP_TABLE}"
         WHERE relname = ?`,
      ).all(relationName) as { blkno: number; all_visible: number; all_frozen: number }[];

      for (const row of rows) {
        // In a real PG system, we'd scan the page to verify.
        // In SQLite, we trust the stored values.
        if (row.all_visible !== 1 && row.all_visible !== 0) {
          errors.push(`Block ${row.blkno}: invalid all_visible value ${row.all_visible}`);
        }
        if (row.all_frozen !== 0 && row.all_frozen !== 1) {
          errors.push(`Block ${row.blkno}: invalid all_frozen value ${row.all_frozen}`);
        }
      }
    } catch (err) {
      errors.push(`Error reading visibility map: ${(err as Error).message}`);
    }

    return {
      correct: errors.length === 0,
      errors,
    };
  }

  /**
   * pg_truncate_visibility_map(relation) → void
   *
   * Reset/truncate the visibility map for a relation.
   *
   * @param relationName - Table name
   */
  truncateVisibilityMap(relationName: string): void {
    this.db.prepare(
      `DELETE FROM "${VISIBILITY_MAP_TABLE}" WHERE relname = ?`,
    ).run(relationName);

    logger.info({ relationName }, 'Visibility map truncated');
  }

  /**
   * Detect whether a SQL string contains pg_visibility function calls.
   *
   * @param sql - SQL query to inspect
   * @returns true if any pg_visibility function is detected
   */
  detectPgVisibilityCall(sql: string): boolean {
    PG_VISIBILITY_FUNC_RE.lastIndex = 0;
    return PG_VISIBILITY_FUNC_RE.test(sql.trim());
  }

  /**
   * Rewrite a pg_visibility function call into the equivalent
   * internal method call. This is used by the SQL executor to
   * intercept pg_visibility functions and route them to this shim.
   *
   * @param sql - SQL query to rewrite
   * @returns Rewritten SQL (or original if no match)
   */
  rewritePgVisibilityCall(sql: string): string {
    let rewritten = sql;

    // pg_visibility_map(relation, blkno)
    rewritten = rewritten.replace(
      /\bpg_visibility_map\s*\(\s*'([^']+)'\s*,\s*(\d+)\s*\)/gi,
      (_, rel, blk) => {
        const result = this.visibilityMap(rel, parseInt(blk, 10));
        return `SELECT ${result.all_visible ? 1 : 0} AS all_visible, ${result.all_frozen ? 1 : 0} AS all_frozen`;
      },
    );

    // pg_visibility_map_rel(relation)
    rewritten = rewritten.replace(
      /\bpg_visibility_map_rel\s*\(\s*'([^']+)'\s*\)/gi,
      (_, rel) => {
        const entries = this.visibilityMapRel(rel);
        // Format as a VALUES list
        const values = entries.map(e =>
          `(${e.blkno}, ${e.all_visible ? 1 : 0}, ${e.all_frozen ? 1 : 0})`,
        ).join(', ');
        return `SELECT * FROM (VALUES ${values}) AS v(blkno, all_visible, all_frozen)`;
      },
    );

    // pg_collect_visibility(relation)
    rewritten = rewritten.replace(
      /\bpg_collect_visibility\s*\(\s*'([^']+)'\s*\)/gi,
      (_, rel) => {
        this.collectVisibility(rel);
        return 'SELECT 1 AS collected';
      },
    );

    // pg_truncate_visibility_map(relation)
    rewritten = rewritten.replace(
      /\bpg_truncate_visibility_map\s*\(\s*'([^']+)'\s*\)/gi,
      (_, rel) => {
        this.truncateVisibilityMap(rel);
        return 'SELECT 1 AS truncated';
      },
    );

    // pg_check_visible(relation)
    rewritten = rewritten.replace(
      /\bpg_check_visible\s*\(\s*'([^']+)'\s*\)/gi,
      (_, rel) => {
        const result = this.checkVisible(rel);
        return `SELECT ${result.correct ? 1 : 0} AS correct, '${result.errors.join('; ')}' AS errors`;
      },
    );

    // pg_visibility(relation)
    rewritten = rewritten.replace(
      /\bpg_visibility\s*\(\s*'([^']+)'\s*\)/gi,
      (_, rel) => {
        const tuples = this.visibility(rel);
        const values = tuples.map(t =>
          `('${t.ctid}', ${t.all_visible ? 1 : 0}, ${t.all_frozen ? 1 : 0})`,
        ).join(', ');
        return `SELECT * FROM (VALUES ${values}) AS v(ctid, all_visible, all_frozen)`;
      },
    );

    return rewritten;
  }
}
