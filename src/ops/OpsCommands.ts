/**
 * OpsCommands — SQL operations: VACUUM, ANALYZE, REINDEX.
 *
 * These are PostgreSQL-equivalent maintenance commands that operate
 * on the underlying SQLite storage. They are exposed as system functions
 * callable via the PG Wire Protocol.
 *
 * VACUUM:
 *   Recovers space from deleted/updated rows by running SQLite's
 *   PRAGMA optimize and incremental_vacuum. In MVCC terms, this
 *   triggers GC of old row versions.
 *
 * ANALYZE:
 *   Updates SQLite statistics used by the query planner.
 *   Runs PRAGMA optimize to collect column statistics.
 *
 * REINDEX:
 *   Rebuilds indexes to eliminate fragmentation.
 *   Drops and recreates indexes on the specified table.
 *
 * Each command is registered as a system function accessible via
 * SELECT vacuum_table('tablename'), etc.
 *
 * @module ops/OpsCommands
 */

import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as path from 'path';

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('OpsCommands');

// ── Types ────────────────────────────────────────────────────────

export interface OpsResult {
  success: boolean;
  command: string;
  tableName?: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface OpsConfig {
  /** Whether VACUUM operations are allowed (default: true). */
  vacuumEnabled: boolean;
  /** Whether ANALYZE operations are allowed (default: true). */
  analyzeEnabled: boolean;
  /** Whether REINDEX operations are allowed (default: true). */
  reindexEnabled: boolean;
  /** Whether background auto-vacuum is enabled (default: false). */
  autoVacuumEnabled: boolean;
  /** Auto-vacuum threshold as percentage of dead tuples (default: 20). */
  autoVacuumThreshold: number;
}

const DEFAULT_OPS_CONFIG: OpsConfig = {
  vacuumEnabled: true,
  analyzeEnabled: true,
  reindexEnabled: true,
  autoVacuumEnabled: false,
  autoVacuumThreshold: 20,
};

// ══════════════════════════════════════════════════════════════════
//  OpsCommands
// ══════════════════════════════════════════════════════════════════

export class OpsCommands {
  private config: OpsConfig;
  private logger: PinoLogger;

  /** Map of shard DB connections by shard ID. */
  private shardDbs: Map<number, Database.Database> = new Map();

  constructor(config?: Partial<OpsConfig>) {
    this.config = { ...DEFAULT_OPS_CONFIG, ...config };
    this.logger = PinoLogger.forComponent('OpsCommands');
  }

  /**
   * Register a shard database for operations.
   */
  registerShardDb(shardId: number, db: Database.Database): void {
    this.shardDbs.set(shardId, db);
  }

  /**
   * Unregister a shard database.
   */
  unregisterShardDb(shardId: number): void {
    this.shardDbs.delete(shardId);
  }

  // ── VACUUM ─────────────────────────────────────────────────────

  /**
   * VACUUM command — reclaim storage space and compact the database.
   *
   * For SQLite, this runs:
   *   - PRAGMA incremental_vacuum(N) — reclaims N pages
   *   - VACUUM — full rebuild (for aggressive reclaim)
   *   - PRAGMA optimize — invokes query planner optimization
   *
   * @param shardId - Shard ID to operate on
   * @param tableName - Optional table name (SQLite VACUUM operates on whole DB)
   * @param full - If true, runs full VACUUM (may be slow on large DBs)
   */
  vacuum(shardId: number, tableName?: string, full: boolean = false): OpsResult {
    if (!this.config.vacuumEnabled) {
      return { success: false, command: 'VACUUM', message: 'VACUUM operations are disabled' };
    }

    const db = this.shardDbs.get(shardId);
    if (!db) {
      return { success: false, command: 'VACUUM', message: `Shard ${shardId} not found` };
    }

    try {
      const beforeSize = this.getDbFileSize(db);

      if (full) {
        // Full VACUUM — rebuilds entire database file
        db.exec('VACUUM;');
      } else {
        // Incremental vacuum — reclaim free pages
        db.exec('PRAGMA incremental_vacuum(10);');
        // Run PRAGMA optimize for statistics and maintenance
        db.exec('PRAGMA optimize;');
      }

      const afterSize = this.getDbFileSize(db);
      const reclaimed = beforeSize - afterSize;

      const result: OpsResult = {
        success: true,
        command: 'VACUUM',
        tableName,
        message: full
          ? `Full VACUUM completed on shard ${shardId}`
          : `Incremental VACUUM completed on shard ${shardId}`,
        details: {
          shardId,
          beforeBytes: beforeSize,
          afterBytes: afterSize,
          reclaimedBytes: Math.max(0, reclaimed),
          full,
        },
      };

      logger.info(result.details, result.message);
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error({ shardId, error: message }, 'VACUUM failed');
      return { success: false, command: 'VACUUM', message: `VACUUM failed: ${message}` };
    }
  }

  // ── ANALYZE ────────────────────────────────────────────────────

  /**
   * ANALYZE command — update database statistics for query optimization.
   *
   * For SQLite, this runs:
   *   - ANALYZE — collects statistics about indexes
   *   - PRAGMA schema_version — checks schema
   *   - Returns index statistics for reporting
   *
   * @param shardId - Shard ID to operate on
   * @param tableName - Optional table name for targeted analysis
   */
  analyze(shardId: number, tableName?: string): OpsResult {
    if (!this.config.analyzeEnabled) {
      return { success: false, command: 'ANALYZE', message: 'ANALYZE operations are disabled' };
    }

    const db = this.shardDbs.get(shardId);
    if (!db) {
      return { success: false, command: 'ANALYZE', message: `Shard ${shardId} not found` };
    }

    try {
      if (tableName) {
        db.exec(`ANALYZE "${tableName}";`);
      } else {
        db.exec('ANALYZE;');
      }

      // Collect statistics about analyzed objects
      const indexStats = db.prepare(`
        SELECT name AS index_name, seq AS seqno, "unique" AS is_unique
        FROM pragma_index_list(?)
      `);

      const analyzedTable = tableName || '(all)';
      const indexes = tableName ? indexStats.all(tableName) : [];

      const result: OpsResult = {
        success: true,
        command: 'ANALYZE',
        tableName,
        message: `ANALYZE completed on ${analyzedTable} in shard ${shardId}`,
        details: {
          shardId,
          tableName: analyzedTable,
          indexCount: Array.isArray(indexes) ? indexes.length : 0,
        },
      };

      logger.info(result.details, result.message);
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error({ shardId, tableName, error: message }, 'ANALYZE failed');
      return { success: false, command: 'ANALYZE', message: `ANALYZE failed: ${message}` };
    }
  }

  // ── REINDEX ────────────────────────────────────────────────────

  /**
   * REINDEX command — rebuild indexes to eliminate fragmentation.
   *
   * For SQLite, this re-creates indexes by:
   *   - Dropping and recreating the index
   *   - Or using REINDEX (SQLite 3.39+)
   *
   * @param shardId - Shard ID to operate on
   * @param indexNameOrTable - Index name to rebuild, or table name to rebuild all
   * @param isTable - If true, rebuilds all indexes on the table
   */
  reindex(shardId: number, indexNameOrTable: string, isTable: boolean = false): OpsResult {
    if (!this.config.reindexEnabled) {
      return { success: false, command: 'REINDEX', message: 'REINDEX operations are disabled' };
    }

    const db = this.shardDbs.get(shardId);
    if (!db) {
      return { success: false, command: 'REINDEX', message: `Shard ${shardId} not found` };
    }

    try {
      if (isTable) {
        // Rebuild all indexes on a table
        const indexes = db.prepare(`
          SELECT name FROM pragma_index_list(?) WHERE origin != 'pk' AND name IS NOT NULL
        `).all(indexNameOrTable) as { name: string }[];

        for (const idx of indexes) {
          const createSql = db.prepare(
            'SELECT sql FROM sqlite_master WHERE type = ? AND name = ?'
          ).get('index', idx.name) as { sql: string | null } | undefined;

          if (createSql?.sql) {
            db.exec(`DROP INDEX IF EXISTS "${idx.name}";`);
            db.exec(createSql.sql);
          }
        }

        const result: OpsResult = {
          success: true,
          command: 'REINDEX',
          tableName: indexNameOrTable,
          message: `REINDEX completed on table "${indexNameOrTable}" in shard ${shardId} (${indexes.length} indexes)`,
          details: {
            shardId,
            tableName: indexNameOrTable,
            indexCount: indexes.length,
            isTable: true,
          },
        };

        logger.info(result.details, result.message);
        return result;
      }

      // Rebuild a single index
      const existingIndex = db.prepare(
        'SELECT sql FROM sqlite_master WHERE type = ? AND name = ?'
      ).get('index', indexNameOrTable) as { sql: string | null } | undefined;

      if (!existingIndex?.sql) {
        return { success: false, command: 'REINDEX', message: `Index "${indexNameOrTable}" not found` };
      }

      db.exec(`DROP INDEX IF EXISTS "${indexNameOrTable}";`);
      db.exec(existingIndex.sql);

      const result: OpsResult = {
        success: true,
        command: 'REINDEX',
        message: `REINDEX completed on index "${indexNameOrTable}" in shard ${shardId}`,
        details: {
          shardId,
          indexName: indexNameOrTable,
          isTable: false,
        },
      };

      logger.info(result.details, result.message);
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error({ shardId, indexName: indexNameOrTable, error: message }, 'REINDEX failed');
      return { success: false, command: 'REINDEX', message: `REINDEX failed: ${message}` };
    }
  }

  // ── Utility ────────────────────────────────────────────────────

  /**
   * Get database file size in bytes.
   */
  getDbFileSize(db: Database.Database): number {
    try {
      const row = db.prepare('PRAGMA page_count;').get() as { page_count: number };
      const pageSizeRow = db.prepare('PRAGMA page_size;').get() as { page_size: number };
      const pageSize = pageSizeRow ? pageSizeRow.page_size : 4096;
      return row ? row.page_count * pageSize : 0;
    } catch {
      return 0;
    }
  }

  /**
   * Get current configuration.
   */
  getConfig(): Readonly<OpsConfig> {
    return { ...this.config };
  }

  /**
   * Update configuration at runtime.
   */
  updateConfig(config: Partial<OpsConfig>): void {
    Object.assign(this.config, config);
    logger.info({ config: this.config }, 'Ops commands configuration updated');
  }
}

// ══════════════════════════════════════════════════════════════════
//  SQL function registration helpers
// ══════════════════════════════════════════════════════════════════

/**
 * Generate SQL function definitions for VACUUM, ANALYZE, REINDEX.
 * These can be registered in the SQL engine to make the ops commands
 * callable as SQL functions.
 */
export const OPS_SQL_FUNCTIONS = `
-- VACUUM: Reclaim storage. Call as: SELECT vacuum_table('shard_1', 'my_table', 0)
CREATE TABLE IF NOT EXISTS ops_commands (
  command TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1
);

INSERT OR IGNORE INTO ops_commands (command, enabled) VALUES ('VACUUM', 1);
INSERT OR IGNORE INTO ops_commands (command, enabled) VALUES ('ANALYZE', 1);
INSERT OR IGNORE INTO ops_commands (command, enabled) VALUES ('REINDEX', 1);
`;
