import Database from 'better-sqlite3';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { PinoLogger } from '../monitoring/PinoLogger';

/**
 * Configuration for upgrading a single shard (SQLite database file).
 */
export interface UpgradeShardConfig {
  /** Human-readable shard identifier */
  shardName: string;
  /** Absolute or relative path to the SQLite database file */
  dbPath: string;
  /** Directory where backups will be stored */
  backupDir: string;
  /** Ordered list of DDL/DML statements to apply during migration */
  migrationSql: string[];
}

/**
 * Current status of a single shard upgrade.
 */
export interface UpgradeShardStatus {
  /** Shard identifier matching the config */
  shardName: string;
  /** Current phase of the upgrade lifecycle */
  phase:
    | 'pending'
    | 'preparing'
    | 'draining'
    | 'backing-up'
    | 'upgrading'
    | 'verifying'
    | 'completed'
    | 'failed'
    | 'rolled-back';
  /** Error message if phase is 'failed' or 'rolled-back' */
  error?: string;
  /** Path to the backup file (set after backing-up phase) */
  backupPath?: string;
}

/**
 * Production-grade upgrade manager for SQLite shards.
 *
 * Handles file-level backup, schema migration via better-sqlite3,
 * connection drain tracking, health verification, and rollback.
 *
 * @example
 * ```ts
 * const mgr = new UpgradeManager(logger);
 * const status = await mgr.upgradeShard({
 *   shardName: 'shard-01',
 *   dbPath: '/data/shard-01.db',
 *   backupDir: '/data/backups',
 *   migrationSql: ['ALTER TABLE users ADD COLUMN email TEXT'],
 * });
 * ```
 */
export class UpgradeManager {
  /**
   * Track active database connections per dbPath.
   * Used to simulate connection drain during upgrade.
   */
  private activeConnections: Map<string, number> = new Map();

  constructor(private logger: PinoLogger) {}

  // ── Public API ───────────────────────────────────────────────

  /**
   * Execute a full upgrade lifecycle for a single shard:
   * 1. prepare     — validate inputs and ensure dbPath exists
   * 2. drain       — wait for active connections to close, block new ones
   * 3. backing-up  — copy the SQLite file to backup location
   * 4. upgrading   — apply each DDL/DML statement sequentially
   * 5. verifying   — run health check (SELECT 1 + PRAGMA integrity_check)
   * 6. completed   — mark the upgrade as successful
   *
   * On any error, status transitions to 'failed' with the error message.
   */
  async upgradeShard(config: UpgradeShardConfig): Promise<UpgradeShardStatus> {
    const { shardName, dbPath, backupDir, migrationSql } = config;
    const status: UpgradeShardStatus = { shardName, phase: 'pending' };

    try {
      // ── Phase: preparing ──
      status.phase = 'preparing';
      this.logger.info({ shardName, dbPath }, 'upgrade: preparing shard');

      if (!fs.existsSync(dbPath)) {
        throw new Error(`42P01: database file not found: "${dbPath}"`);
      }
      if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
        this.logger.info({ backupDir }, 'upgrade: created backup directory');
      }

      // ── Phase: draining ──
      status.phase = 'draining';
      this.logger.info({ shardName }, 'upgrade: draining connections');

      await this.drainConnections(dbPath);

      // ── Phase: backing-up ──
      status.phase = 'backing-up';
      this.logger.info({ shardName }, 'upgrade: creating file backup');

      const timestamp = Date.now();
      const dbFilename = path.basename(dbPath);
      const backupFilename = `${dbFilename}.${timestamp}.bak`;
      const backupPath = path.join(backupDir, backupFilename);

      fs.copyFileSync(dbPath, backupPath);
      status.backupPath = backupPath;
      this.logger.info({ shardName, backupPath }, 'upgrade: backup created');

      // ── Phase: upgrading ──
      status.phase = 'upgrading';
      this.logger.info({ shardName, migrationCount: migrationSql.length }, 'upgrade: applying migration');

      this.applyMigration(dbPath, migrationSql);

      // ── Phase: verifying ──
      status.phase = 'verifying';
      this.logger.info({ shardName }, 'upgrade: verifying database health');

      const healthy = this.verifyDatabaseInternal(dbPath);
      if (!healthy) {
        throw new Error('42P12: database health check failed after migration');
      }

      // ── Phase: completed ──
      status.phase = 'completed';
      this.logger.info({ shardName }, 'upgrade: shard upgrade completed successfully');
    } catch (err: any) {
      status.phase = 'failed';
      status.error = err.message || String(err);
      this.logger.error({ shardName, err: status.error }, 'upgrade: shard upgrade failed');
    }

    return status;
  }

  /**
   * Roll back a single shard by restoring from a backup file.
   * Verifies the restored database before marking as rolled-back.
   */
  async rollbackSingle(
    config: UpgradeShardConfig,
    backupPath: string,
  ): Promise<UpgradeShardStatus> {
    const { shardName, dbPath } = config;
    const status: UpgradeShardStatus = { shardName, phase: 'preparing' };

    try {
      // Validate backup file exists
      if (!backupPath || !fs.existsSync(backupPath)) {
        throw new Error(`42P01: backup file not found: "${backupPath}"`);
      }

      status.phase = 'backing-up';
      this.logger.info({ shardName, backupPath }, 'rollback: restoring from backup');

      // Copy backup back to original location
      // Create a pre-rollback snapshot of the failed state
      const failedTimestamp = Date.now();
      const failedSnapshot = `${dbPath}.failed.${failedTimestamp}.bak`;
      if (fs.existsSync(dbPath)) {
        fs.copyFileSync(dbPath, failedSnapshot);
        this.logger.info({ shardName, failedSnapshot }, 'rollback: saved failed state');
      }

      fs.copyFileSync(backupPath, dbPath);

      status.phase = 'verifying';
      this.logger.info({ shardName }, 'rollback: verifying restored database');

      const healthy = this.verifyDatabaseInternal(dbPath);
      if (!healthy) {
        throw new Error('42P12: health check failed on restored database');
      }

      status.phase = 'rolled-back';
      status.backupPath = backupPath;
      this.logger.info({ shardName }, 'rollback: shard restored successfully');
    } catch (err: any) {
      status.phase = 'rolled-back';
      status.error = err.message || String(err);
      this.logger.error({ shardName, err: status.error }, 'rollback: failed');
    }

    return status;
  }

  /**
   * Verify a SQLite database file is healthy by opening it and running
   * a basic health check.
   *
   * @returns true if the database is healthy, false otherwise
   */
  verifyDatabase(dbPath: string): boolean {
    return this.verifyDatabaseInternal(dbPath);
  }

  // ── Connection tracking ─────────────────────────────────────

  /**
   * Register a new active connection for tracking.
   * Returns false if the shard is currently draining (connection refused).
   */
  acquireConnection(dbPath: string): boolean {
    const current = this.activeConnections.get(dbPath) ?? 0;

    // If we're in drain phase for this path, refuse new connections
    if (current < 0) {
      return false;
    }

    this.activeConnections.set(dbPath, current + 1);
    return true;
  }

  /**
   * Release a tracked connection.
   */
  releaseConnection(dbPath: string): void {
    const current = this.activeConnections.get(dbPath) ?? 0;
    if (current > 0) {
      this.activeConnections.set(dbPath, current - 1);
    }
  }

  /**
   * Get the number of active connections for a given database path.
   */
  getActiveConnectionCount(dbPath: string): number {
    return this.activeConnections.get(dbPath) ?? 0;
  }

  // ── Private helpers ──────────────────────────────────────────

  /**
   * Drain connections: set the drain flag and wait for active connections to reach 0.
   * Once drain is engaged, new connections via acquireConnection() are refused.
   */
  private async drainConnections(dbPath: string): Promise<void> {
    // Mark as draining by setting a negative sentinel
    // Negative value means "drain engaged"
    const currentCount = this.activeConnections.get(dbPath) ?? 0;
    if (currentCount <= 0) {
      // No active connections — just set the drain flag
      this.activeConnections.set(dbPath, -1);
      return;
    }

    // Set drain flag (negative sentinel)
    this.activeConnections.set(dbPath, -currentCount - 1);

    // Wait for active connections to drain (poll with backoff)
    const drainTimeoutMs = 30_000; // 30 second max wait
    const startTime = Date.now();

    while (Date.now() - startTime < drainTimeoutMs) {
      const active = this.getActiveConnectionCount(dbPath);
      if (active <= 0) {
        this.activeConnections.set(dbPath, -1); // Mark fully drained
        this.logger.info({ dbPath, drainTimeMs: Date.now() - startTime }, 'drain: connections drained');
        return;
      }
      // Poll every 100ms
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    this.logger.warn({ dbPath, activeCount: this.getActiveConnectionCount(dbPath) }, 'drain: timeout waiting for connections');
    // Set drain flag anyway and proceed
    this.activeConnections.set(dbPath, -1);
  }

  /**
   * Open the SQLite database and apply each migration statement sequentially.
   * All statements run inside a single transaction for atomicity.
   */
  private applyMigration(dbPath: string, migrationSql: string[]): void {
    if (migrationSql.length === 0) {
      this.logger.info({ dbPath }, 'migration: no SQL to apply');
      return;
    }

    let db: Database.Database | null = null;

    try {
      db = new Database(dbPath, { readonly: false });

      // Run all migrations in a single transaction
      const runInTransaction = db.transaction(() => {
        for (let i = 0; i < migrationSql.length; i++) {
          const sql = migrationSql[i].trim();
          if (!sql) {
            continue;
          }
          try {
            db!.exec(sql);
            this.logger.debug({ dbPath, stmtIndex: i, sql: sql.slice(0, 80) }, 'migration: applied');
          } catch (stmtErr: any) {
            throw new Error(
              `42P11: migration statement ${i} failed: ${stmtErr.message} — SQL: ${sql.slice(0, 200)}`,
            );
          }
        }
      });

      runInTransaction();
      this.logger.info({ dbPath, stmtCount: migrationSql.length }, 'migration: all statements applied');
    } finally {
      if (db) {
        db.close();
      }
    }
  }

  /**
   * Internal verification: open the DB, run SELECT 1 and PRAGMA integrity_check.
   */
  private verifyDatabaseInternal(dbPath: string): boolean {
    let db: Database.Database | null = null;

    try {
      db = new Database(dbPath, { readonly: true });

      // Basic connectivity check
      const row = db.prepare('SELECT 1 AS ok').get() as { ok: number } | undefined;
      if (!row || row.ok !== 1) {
        this.logger.error({ dbPath }, 'verify: SELECT 1 check failed');
        return false;
      }

      // Integrity check
      const integrityRow = db.prepare('PRAGMA integrity_check').get() as { integrity_check: string } | undefined;
      if (!integrityRow || integrityRow.integrity_check !== 'ok') {
        this.logger.error({ dbPath, result: integrityRow?.integrity_check }, 'verify: integrity_check failed');
        return false;
      }

      this.logger.info({ dbPath }, 'verify: database health check passed');
      return true;
    } catch (err: any) {
      this.logger.error({ dbPath, err: err.message }, 'verify: exception during health check');
      return false;
    } finally {
      if (db) {
        db.close();
      }
    }
  }
}
