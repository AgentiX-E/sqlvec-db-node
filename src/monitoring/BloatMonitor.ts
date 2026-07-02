/**
 * BloatMonitor — PostgreSQL bloat estimation shim for sqlvec-db.
 *
 * PostgreSQL's bloat monitoring estimates wasted space in tables and indexes
 * due to dead tuples, page fragmentation, and low fill factors.
 *
 * Since SQLite is append-only and has no dead tuples (no MVCC bloat),
 * this monitor estimates bloat by:
 *   1. Comparing actual file size (`page_count * page_size`) vs. logical
 *      size (row count × estimated avg row width)
 *   2. Using available autovacuum history for last vacuum timestamps
 *   3. Providing estimates (not exact values), just like PG does
 *
 * @module monitoring/BloatMonitor
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('bloat-monitor');

// ── Constants ──────────────────────────────────────────────────

/** Default PostgreSQL block/page size */
const DEFAULT_PAGE_SIZE = 8192;

/** Default estimated row width in bytes (used when no schema info available) */
const DEFAULT_AVG_ROW_WIDTH = 128;

/** Regex for extracting table name from SQL */
const TABLE_NAME_RE = /^"?(\w+)"?$/;

// ── Types ──────────────────────────────────────────────────────

export interface BloatEstimate {
  tableName: string;
  schemaName: string;
  realSizeBytes: number;
  estimatedSizeBytes: number;
  bloatBytes: number;
  bloatRatio: number;
  deadTupleEstimate: number;
  liveTupleEstimate: number;
  lastVacuum: number | null;
}

interface IndexInfo {
  name: string;
  tableName: string;
  rowCount: number;
  isUnique: boolean;
}

interface TableInfo {
  name: string;
  schema: string;
  rowCount: number;
  avgRowWidth: number;
  pageCount: number;
}

// ── BloatMonitor ───────────────────────────────────────────────

export class BloatMonitor {
  private db: any;

  /**
   * @param db - better-sqlite3 database instance
   */
  constructor(db: any) {
    this.db = db;
  }

  /**
   * Estimate bloat for all user tables in the database.
   *
   * @returns Array of BloatEstimate for each user table
   */
  estimateAllTables(): BloatEstimate[] {
    const tables = this.getUserTables();
    const estimates: BloatEstimate[] = [];

    for (const table of tables) {
      try {
        const estimate = this.estimateTable(table.name);
        estimates.push(estimate);
      } catch (err) {
        logger.error({ err, tableName: table.name }, 'Failed to estimate bloat for table');
      }
    }

    return estimates;
  }

  /**
   * Estimate bloat for a specific table.
   *
   * Bloat estimation strategy:
   *   - realSizeBytes = page_count × page_size (actual storage)
   *   - estimatedSizeBytes = row_count × avg_row_width (minimum needed)
   *   - bloatBytes = realSizeBytes - estimatedSizeBytes (capped at 0)
   *   - bloatRatio = bloatBytes / realSizeBytes
   *
   * @param tableName - Name of the table
   * @returns BloatEstimate for the specified table
   */
  estimateTable(tableName: string): BloatEstimate {
    const tableInfo = this.getTableInfo(tableName);

    const realSizeBytes = tableInfo.pageCount * DEFAULT_PAGE_SIZE;
    const estimatedSizeBytes = tableInfo.rowCount * tableInfo.avgRowWidth;
    const bloatBytes = Math.max(0, realSizeBytes - estimatedSizeBytes);
    const bloatRatio = realSizeBytes > 0 ? bloatBytes / realSizeBytes : 0;
    const deadTupleEstimate = this.getDeadTuples(tableName);

    return {
      tableName: tableInfo.name,
      schemaName: tableInfo.schema,
      realSizeBytes,
      estimatedSizeBytes,
      bloatBytes,
      bloatRatio: Math.round(bloatRatio * 10000) / 10000,
      deadTupleEstimate,
      liveTupleEstimate: tableInfo.rowCount,
      lastVacuum: this.getLastVacuumTime(tableName),
    };
  }

  /**
   * Estimate index bloat based on fill factor approximation.
   *
   * Strategy: default fill factor is 90%, meaning ~10% of index
   * pages may be wasted space. Estimate bloat proportional to index size.
   *
   * @param indexName - Name of the index
   * @returns BloatEstimate for the specified index
   */
  estimateIndexBloat(indexName: string): BloatEstimate {
    const indexInfo = this.getIndexInfo(indexName);

    // Estimate table size from getTableInfo
    const tableInfo = this.getTableInfo(indexInfo.tableName);
    const tableRealSize = tableInfo.pageCount * DEFAULT_PAGE_SIZE;

    // Estimate index size: approximately 60% of table size for a typical B-tree
    const estimatedIndexSize = Math.round(tableRealSize * 0.6);

    // B-tree fill factor is typically ~90%, so ~10% internal fragmentation
    const fillFactor = 0.9;
    const realSizeBytes = estimatedIndexSize;
    const estimatedSizeBytes = Math.round(realSizeBytes * fillFactor);
    const bloatBytes = realSizeBytes - estimatedSizeBytes;
    const bloatRatio = 1 - fillFactor; // ~0.10

    return {
      tableName: indexInfo.tableName,
      schemaName: 'public',
      realSizeBytes,
      estimatedSizeBytes,
      bloatBytes,
      bloatRatio: Math.round(bloatRatio * 10000) / 10000,
      deadTupleEstimate: 0,
      liveTupleEstimate: indexInfo.rowCount,
      lastVacuum: null,
    };
  }

  /**
   * pgstattuple(tableName) → PgStatTuple-compatible object
   *
   * Wraps bloat estimation into a pgstattuple-compatible return format.
   *
   * @param tableName - Name of the table
   * @returns Object with pgstattuple-compatible fields
   */
  pgstattuple(tableName: string): {
    table_len: number;
    tuple_count: number;
    tuple_len: number;
    tuple_percent: number;
    dead_tuple_count: number;
    dead_tuple_len: number;
    dead_tuple_percent: number;
    free_space: number;
    free_percent: number;
  } {
    const estimate = this.estimateTable(tableName);
    const tupleLen = estimate.liveTupleEstimate * DEFAULT_AVG_ROW_WIDTH;
    const deadTupleLen = estimate.deadTupleEstimate * DEFAULT_AVG_ROW_WIDTH;
    const totalLen = estimate.realSizeBytes;
    const freeSpace = estimate.bloatBytes;

    return {
      table_len: totalLen,
      tuple_count: estimate.liveTupleEstimate,
      tuple_len: tupleLen,
      tuple_percent: totalLen > 0 ? Math.round((tupleLen / totalLen) * 10000) / 100 : 0,
      dead_tuple_count: estimate.deadTupleEstimate,
      dead_tuple_len: deadTupleLen,
      dead_tuple_percent: totalLen > 0 ? Math.round((deadTupleLen / totalLen) * 10000) / 100 : 0,
      free_space: freeSpace,
      free_percent: totalLen > 0 ? Math.round((freeSpace / totalLen) * 10000) / 100 : 0,
    };
  }

  /**
   * pgstatindex(indexName) → PgStatIndex-compatible object
   *
   * @param indexName - Name of the index
   * @returns Object with pgstatindex-compatible fields
   */
  pgstatindex(indexName: string): {
    version: number;
    tree_level: number;
    index_size: number;
    root_block_no: number;
    internal_pages: number;
    leaf_pages: number;
    empty_pages: number;
    deleted_pages: number;
    avg_leaf_density: number;
    leaf_fragmentation: number;
  } {
    const estimate = this.estimateIndexBloat(indexName);

    // Approximate from index size
    const totalPages = Math.max(1, Math.ceil(estimate.realSizeBytes / DEFAULT_PAGE_SIZE));
    const leafPages = Math.max(1, Math.ceil(totalPages * 0.9));
    const internalPages = Math.max(1, totalPages - leafPages);
    const emptyPages = 0;
    const deletedPages = 0;
    const avgLeafDensity = 100 - (estimate.bloatRatio * 100);

    return {
      version: 4,
      tree_level: internalPages > 1 ? 2 : 1,
      index_size: estimate.realSizeBytes,
      root_block_no: 0,
      internal_pages: internalPages,
      leaf_pages: leafPages,
      empty_pages: emptyPages,
      deleted_pages: deletedPages,
      avg_leaf_density: Math.round(avgLeafDensity * 100) / 100,
      leaf_fragmentation: 0,
    };
  }

  /**
   * pg_relpages(tableName) → number
   *
   * Returns the estimated number of pages for a relation.
   *
   * @param tableName - Name of the table
   * @returns Estimated page count
   */
  pg_relpages(tableName: string): number {
    try {
      const pageCount = this.db.prepare(
        `SELECT page_count FROM pragma_page_count WHERE table_name = ?`,
      ).get(tableName) as { page_count: number } | undefined;

      if (pageCount) return pageCount.page_count;
    } catch {
      // Fallback
    }

    const tableInfo = this.getTableInfo(tableName);
    return Math.max(1, tableInfo.pageCount);
  }

  /**
   * Get the actual storage size of a table in bytes.
   *
   * Uses SQLite's page_count × page_size to estimate file-level size.
   *
   * @param tableName - Name of the table
   * @returns Size in bytes
   */
  getTableSize(tableName: string): number {
    const tableInfo = this.getTableInfo(tableName);
    return tableInfo.pageCount * DEFAULT_PAGE_SIZE;
  }

  /**
   * Get an approximate count of dead tuples for a table.
   *
   * Since SQLite has no MVCC dead tuples, this returns 0 unless the
   * table has autovacuum history indicating dead tuples were tracked.
   *
   * @param tableName - Name of the table
   * @returns Estimated dead tuple count (always 0 for pure SQLite)
   */
  getDeadTuples(tableName: string): number {
    try {
      // Check if autovacuum history table exists
      const histExists = this.db.prepare(
        `SELECT name FROM sqlite_master WHERE type='table' AND name='__autovacuum_history'`,
      ).get();

      if (histExists) {
        const row = this.db.prepare(
          `SELECT SUM(dead_tuples) AS total FROM __autovacuum_history
           WHERE table_name = ?`,
        ).get(tableName) as { total: number | null } | undefined;

        if (row && row.total != null && row.total > 0) {
          return row.total;
        }
      }
    } catch {
      // Autovacuum history not available
    }

    return 0;
  }

  // ── Private Helpers ─────────────────────────────────────────

  /** Get all user tables (excluding internal/sqlite_* tables) */
  private getUserTables(): { name: string; schema: string }[] {
    const tables = this.db.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' AND name NOT GLOB '__*'`,
    ).all() as { name: string }[];

    return tables.map(t => ({ name: t.name, schema: 'public' }));
  }

  /** Get table info: row count, avg row width, page count */
  private getTableInfo(tableName: string): TableInfo {
    const safeName = tableName.replace(/"/g, '""');

    // Get row count
    const countResult = this.db.prepare(
      // eslint-disable-next-line @typescript-eslint/no-dynamic-query
      `SELECT COUNT(*) AS cnt FROM "${safeName}"`,
    ).get() as { cnt: number };
    const rowCount = countResult?.cnt ?? 0;

    // Try to get page count from pragma
    let pageCount = 0;
    try {
      const pageResult = this.db.prepare(
        `SELECT page_count FROM pragma_page_count WHERE table_name = ?`,
      ).get(tableName) as { page_count: number } | undefined;
      if (pageResult) pageCount = pageResult.page_count;
    } catch {
      // pragma_page_count not available
    }

    // Estimate page count from row count if pragma not available
    if (pageCount <= 0) {
      pageCount = Math.max(1, Math.ceil(rowCount / 100));
    }

    // Estimate average row width from table schema
    let avgRowWidth = DEFAULT_AVG_ROW_WIDTH;
    try {
      const columns = this.db.pragma(`table_info('${safeName}')`) as any[];
      if (columns.length > 0) {
        // Estimate width from column types
        let totalWidth = 0;
        for (const col of columns) {
          const type = (col.type || '').toUpperCase();
          if (type.includes('INT')) totalWidth += 8;
          else if (type.includes('REAL') || type.includes('FLOAT') || type.includes('DOUBLE')) totalWidth += 8;
          else if (type.includes('TEXT') || type.includes('VARCHAR') || type.includes('CHAR')) totalWidth += 32;
          else if (type.includes('BLOB')) totalWidth += 64;
          else totalWidth += 16; // unknown type
        }
        if (totalWidth > 0) {
          avgRowWidth = totalWidth;
        }
      }
    } catch {
      // Use default
    }

    return {
      name: tableName,
      schema: 'public',
      rowCount,
      avgRowWidth,
      pageCount,
    };
  }

  /** Get index info */
  private getIndexInfo(indexName: string): IndexInfo {
    const safeName = indexName.replace(/"/g, '""');

    // Get index metadata from sqlite_master
    const row = this.db.prepare(
      `SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND name=?`,
    ).get(indexName) as { name: string; tbl_name: string; sql: string | null } | undefined;

    if (!row) {
      throw new Error(`Index '${indexName}' not found`);
    }

    const tableName = row.tbl_name;
    const isUnique = (row.sql || '').toUpperCase().includes('UNIQUE');

    // Estimate row count from the table
    const safeTableName = tableName.replace(/"/g, '""');
    const countResult = this.db.prepare(
      // eslint-disable-next-line @typescript-eslint/no-dynamic-query
      `SELECT COUNT(*) AS cnt FROM "${safeTableName}"`,
    ).get() as { cnt: number };

    return {
      name: indexName,
      tableName,
      rowCount: countResult?.cnt ?? 0,
      isUnique,
    };
  }

  /** Get last vacuum time from autovacuum history if available */
  private getLastVacuumTime(tableName: string): number | null {
    try {
      const row = this.db.prepare(
        `SELECT MAX(vacuumed_at) AS last_time FROM __autovacuum_history
         WHERE table_name = ?`,
      ).get(tableName) as { last_time: string | null } | undefined;

      if (row?.last_time) {
        const ts = new Date(row.last_time).getTime();
        return Number.isNaN(ts) ? null : ts;
      }
    } catch {
      // No history
    }

    return null;
  }
}
