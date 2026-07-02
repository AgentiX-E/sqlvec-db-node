/**
 * AutovacuumScheduler — Automated VACUUM and FREEZE scheduler using MVCC
 * _xmin / _xmax columns for dead tuple detection.
 *
 * Design:
 * 1. Cron-based scheduling (default every 5 minutes)
 * 2. Scans all user tables that have _xmax columns
 * 3. Dead tuple = row where _xmax IS NOT NULL AND _xmax < minActiveXid
 * 4. Triggers VACUUM when dead tuple ratio > threshold (default 20%)
 * 5. Triggers FREEZE when rows exist with _xmin < freezeXid
 * 6. Cost-based throttling: sleeps after every 1000 row operations
 * 7. Concurrency: only one vacuum cycle at a time
 *
 * @module vacuum/AutovacuumScheduler
 */

import Database from 'better-sqlite3';
import { CronJob } from 'cron';
import { PinoLogger } from '../monitoring/PinoLogger';

// XID_FROZEN constant (equivalent to PG's frozen XID, value = 2)
// Frozen rows are always visible regardless of snapshot.
const XID_FROZEN = 2;
import type { MVCCExecutor } from '../query/MVCCExecutor';

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

export interface AutovacuumConfig {
  /** Enable automatic VACUUM (default: true) */
  enabled: boolean;
  /** Cron expression for check interval (default: every 5 min) */
  checkInterval: string;
  /** Dead tuple ratio threshold (default: 20%) */
  vacuumThresholdPercent: number;
  /** Max cost (row operations) before throttling (default: 1000) */
  vacuumCostLimit: number;
  /** Sleep duration after hitting cost limit in ms (default: 5) */
  vacuumCostDelay: number;
  /** Minimum XID age for FREEZE (default: 500000000 = 5e8) */
  freezeMinXid: number;
  /** Minimum table age for FREEZE check (default: 150000000 = 1.5e8) */
  freezeTableAge: number;
}

export const DEFAULT_AUTOVACUUM_CONFIG: AutovacuumConfig = {
  enabled: true,
  checkInterval: '*/5 * * * *',
  vacuumThresholdPercent: 20,
  vacuumCostLimit: 1000,
  vacuumCostDelay: 5,
  freezeMinXid: 500_000_000,
  freezeTableAge: 150_000_000,
};

export interface DeadTableInfo {
  tableName: string;
  totalCount: number;
  deadCount: number;
  deadRatio: number;
}

export interface VacuumTableResult {
  deleted: number;
  duration: number;
}

export interface FreezeTableResult {
  frozen: number;
  duration: number;
}

export interface AutovacuumCycleResult {
  vacuumed: string[];
  frozen: string[];
  deleted: number;
  duration: number;
}

// ──────────────────────────────────────────────
//  AutovacuumScheduler
// ──────────────────────────────────────────────

export class AutovacuumScheduler {
  private readonly logger = PinoLogger.forComponent('AutovacuumScheduler');
  private config: AutovacuumConfig;
  private cronJob: CronJob | null = null;
  private running: boolean = false;
  /** Guard against overlapping cycles */
  private cycleInProgress: boolean = false;
  /** Last check time per table (to avoid re-checking too often) */
  private lastCheck: Map<string, number> = new Map();
  /** Cycle statistics */
  private totalVacuumCount: number = 0;
  private totalFreezeCount: number = 0;

  constructor(
    private db: Database.Database,
    private mvccExecutor: any,
    config?: Partial<AutovacuumConfig>,
  ) {
    this.config = { ...DEFAULT_AUTOVACUUM_CONFIG, ...config };
  }

  // ── Lifecycle ─────────────────────────────────────────────────

  /**
   * Start the autovacuum scheduler.
   * Safe to call multiple times — only starts once.
   */
  start(): void {
    if (this.cronJob) {
      this.logger.warn('AutovacuumScheduler already running — ignoring duplicate start');
      return;
    }
    if (!this.config.enabled) {
      this.logger.info('AutovacuumScheduler is disabled — not starting');
      return;
    }

    this.logger.info({ checkInterval: this.config.checkInterval }, 'Starting AutovacuumScheduler');

    this.cronJob = new (CronJob as any)(
      this.config.checkInterval,
      () => { this.runCycle().catch(err => this.logger.error({ err }, 'Autovacuum cycle error')); },
      null,          // onComplete
      false,         // autoStart — we start manually below
      undefined,     // timeZone
      undefined,     // context
      false,         // runOnInit
      undefined,     // utcOffset
      undefined,     // unrefTimeout
    ) as CronJob;

    this.cronJob.start();
    this.running = true;
    this.logger.info('AutovacuumScheduler started');
  }

  /**
   * Stop the autovacuum scheduler.
   */
  stop(): void {
    if (this.cronJob) {
      this.cronJob.stop();
      this.cronJob = null;
    }
    this.running = false;
    this.logger.info('AutovacuumScheduler stopped');
  }

  /**
   * Check whether the scheduler is currently running.
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Get the current configuration.
   */
  getConfig(): Readonly<AutovacuumConfig> {
    return { ...this.config };
  }

  /**
   * Update configuration at runtime.
   */
  updateConfig(partial: Partial<AutovacuumConfig>): void {
    const wasEnabled = this.config.enabled;
    Object.assign(this.config, partial);

    if (partial.enabled !== undefined && partial.enabled !== wasEnabled) {
      if (partial.enabled) {
        this.start();
      } else {
        this.stop();
      }
      return;
    }

    // If checkInterval changed, restart
    if (partial.checkInterval !== undefined && this.cronJob) {
      this.logger.info({ checkInterval: this.config.checkInterval }, 'Restarting due to interval change');
      this.restart();
    }
  }

  /**
   * Restart the scheduler (useful after config changes).
   */
  restart(): void {
    this.stop();
    this.start();
  }

  /**
   * Dispose all resources.
   */
  dispose(): void {
    this.stop();
    this.lastCheck.clear();
    this.totalVacuumCount = 0;
    this.totalFreezeCount = 0;
  }

  // ── Public status ─────────────────────────────────────────────

  /**
   * Get scheduler status snapshot.
   */
  getStatus(): {
    running: boolean;
    config: AutovacuumConfig;
    totalVacuumCount: number;
    totalFreezeCount: number;
  } {
    return {
      running: this.running,
      config: { ...this.config },
      totalVacuumCount: this.totalVacuumCount,
      totalFreezeCount: this.totalFreezeCount,
    };
  }

  // ── Main Cycle ────────────────────────────────────────────────

  /**
   * Run one full VACUUM cycle.
   *
   * 1. Scans all tables for dead tuple ratios
   * 2. Performs VACUUM (DELETE rows where _xmax < minActiveXid)
   * 3. Performs FREEZE (UPDATE _xmin = XID_FROZEN for old rows)
   */
  async runCycle(): Promise<AutovacuumCycleResult> {
    if (this.cycleInProgress) {
      this.logger.debug('Autovacuum cycle already in progress — skipping');
      return { vacuumed: [], frozen: [], deleted: 0, duration: 0 };
    }

    this.cycleInProgress = true;
    const startMs = Date.now();
    const vacuumed: string[] = [];
    const frozenTables: string[] = [];
    let totalDeleted = 0;

    try {
      const minActiveXid = this.getMinActiveXid();
      const freezeXid = this.getFreezeXid();

      // Step 1: Check all user tables for dead tuples
      const deadTables = this.checkAllTables(minActiveXid);

      // Step 2: VACUUM tables that exceed threshold
      for (const table of deadTables) {
        if (table.deadRatio >= this.config.vacuumThresholdPercent / 100) {
          this.logger.info(
            {
              table: table.tableName,
              deadRatio: `${(table.deadRatio * 100).toFixed(1)}%`,
              deadCount: table.deadCount,
              totalCount: table.totalCount,
            },
            'Autovacuum: VACUUM triggered',
          );
          const result = this.vacuumTable(table.tableName, minActiveXid);
          totalDeleted += result.deleted;
          vacuumed.push(table.tableName);
          this.totalVacuumCount++;
          this.recordCheck(table.tableName);
        }
      }

      // Step 3: FREEZE old rows
      const userTables = this.getUserTables();
      for (const tableName of userTables) {
        const freezeResult = this.freezeTable(tableName, freezeXid);
        if (freezeResult.frozen > 0) {
          this.logger.info(
            {
              table: tableName,
              frozen: freezeResult.frozen,
              freezeXid,
            },
            'Autovacuum: FREEZE completed',
          );
          frozenTables.push(tableName);
          this.totalFreezeCount++;
        }
      }

      const duration = Date.now() - startMs;
      this.logger.info(
        { vacuumed: vacuumed.length, frozen: frozenTables.length, deleted: totalDeleted, durationMs: duration },
        'Autovacuum cycle completed',
      );

            return { vacuumed, frozen: frozenTables, deleted: totalDeleted, duration: Date.now() - startMs };
    } catch (err: any) {
      this.logger.error({ err: err.message }, 'Autovacuum cycle failed');
      return { vacuumed, frozen: frozenTables, deleted: totalDeleted, duration: Date.now() - startMs };
    } finally {
      this.cycleInProgress = false;
    }
  }

  // ── Table checks ──────────────────────────────────────────────

  /**
   * Get list of all user tables (excluding sqlite_* and __* internal tables).
   */
  private getUserTables(): string[] {
    try {
      const rows = this.db.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '__*'",
      ).all() as { name: string }[];
      return rows.map(r => r.name);
    } catch {
      return [];
    }
  }

  /**
   * Check if a table has _xmin and _xmax columns (MVCC-enabled).
   */
  private hasMvccColumns(tableName: string): boolean {
    try {
      const cols = this.db.prepare(`PRAGMA table_info("${tableName}")`).all() as { name: string }[];
      const names = cols.map(c => c.name);
      return names.includes('_xmin') && names.includes('_xmax');
    } catch {
      return false;
    }
  }

  /**
   * Check all user tables for dead tuple counts.
   *
   * A dead tuple is a row where _xmax IS NOT NULL AND _xmax < minActiveXid.
   * This means the row has been deleted by a committed transaction that
   * no active transaction can see.
   */
  private checkAllTables(minActiveXid: number): DeadTableInfo[] {
    const results: DeadTableInfo[] = [];
    const tables = this.getUserTables();

    for (const tableName of tables) {
      if (!this.hasMvccColumns(tableName)) continue;

      try {
        const row = this.db.prepare(
          `SELECT COUNT(*) AS total, SUM(CASE WHEN _xmax IS NOT NULL AND _xmax < ? THEN 1 ELSE 0 END) AS dead FROM "${tableName}"`,
        ).get(minActiveXid) as { total: number; dead: number } | undefined;

        if (!row) continue;

        const totalCount = row.total;
        const deadCount = row.dead || 0;
        const deadRatio = totalCount > 0 ? deadCount / totalCount : 0;

        results.push({ tableName, totalCount, deadCount, deadRatio });
      } catch (err: any) {
        this.logger.debug({ tableName, err: err.message }, 'Skipping table check');
      }
    }

    return results;
  }

  /**
   * VACUUM: physically delete rows whose _xmax is committed and below
   * the minimum active XID. No active transaction can see these rows,
   * so they are safe to remove.
   *
   * Applies cost-based throttling: after every `vacuumCostLimit` deletes,
   * sleeps for `vacuumCostDelay` milliseconds.
   */
  private vacuumTable(tableName: string, minActiveXid: number): VacuumTableResult {
    const startMs = Date.now();

    // Find expired rows to delete
    const rowsToDelete = this.db.prepare(
      `SELECT COUNT(*) AS cnt FROM "${tableName}" WHERE _xmax IS NOT NULL AND _xmax < ?`,
    ).get(minActiveXid) as { cnt: number } | undefined;

    const count = rowsToDelete?.cnt ?? 0;
    if (count === 0) {
      return { deleted: 0, duration: 0 };
    }

    // Delete with cost-based throttling
    const costLimit = this.config.vacuumCostLimit;
    const costDelay = this.config.vacuumCostDelay;
    let deleted = 0;

    if (count <= costLimit) {
      const result = this.db.prepare(
        `DELETE FROM "${tableName}" WHERE _xmax IS NOT NULL AND _xmax < ?`,
      ).run(minActiveXid);
      deleted = result.changes;
    } else {
      // Batch delete in costLimit chunks with sleep between batches
      const stmt = this.db.prepare(
        `DELETE FROM "${tableName}" WHERE rowid IN (
          SELECT rowid FROM "${tableName}" WHERE _xmax IS NOT NULL AND _xmax < ? LIMIT ?
        )`,
      );
      let remaining = count;
      while (remaining > 0) {
        const batchSize = Math.min(remaining, costLimit);
        const result = stmt.run(minActiveXid, batchSize);
        deleted += result.changes;
        remaining -= batchSize;
        if (remaining > 0) {
          // Sleep for costDelay ms (simulated via busy-wait with Date.now)
          // Using Atomics.wait for sub-ms precision
          const sleepUntil = Date.now() + costDelay;
          while (Date.now() < sleepUntil) {
            // busy-wait
          }
        }
      }
    }

    const duration = Date.now() - startMs;
    this.logger.debug({ tableName, deleted, durationMs: duration, minActiveXid }, 'VACUUM completed');

    return { deleted, duration };
  }

  /**
   * FREEZE: mark rows with _xmin < freezeXid as XID_FROZEN (=2).
   * Frozen rows are always visible, preventing them from becoming
   * invisible after XID wrapping.
   *
   * Only updates rows where _xmin > 0 and _xmin !== XID_FROZEN.
   * Applies cost-based throttling.
   */
  private freezeTable(tableName: string, freezeXid: number): FreezeTableResult {
    const startMs = Date.now();

    const rowsToFreeze = this.db.prepare(
      `SELECT COUNT(*) AS cnt FROM "${tableName}" WHERE _xmin < ? AND _xmin > 0 AND _xmin != ?`,
    ).get(freezeXid, XID_FROZEN) as { cnt: number } | undefined;

    const count = rowsToFreeze?.cnt ?? 0;
    if (count === 0) {
      return { frozen: 0, duration: 0 };
    }

    const costLimit = this.config.vacuumCostLimit;
    const costDelay = this.config.vacuumCostDelay;
    let frozen = 0;

    if (count <= costLimit) {
      const result = this.db.prepare(
        `UPDATE "${tableName}" SET _xmin = ? WHERE _xmin < ? AND _xmin > 0 AND _xmin != ?`,
      ).run(XID_FROZEN, freezeXid, XID_FROZEN);
      frozen = result.changes;
    } else {
      // Batch freeze in costLimit chunks
      const stmt = this.db.prepare(
        `UPDATE "${tableName}" SET _xmin = ? WHERE rowid IN (
          SELECT rowid FROM "${tableName}" WHERE _xmin < ? AND _xmin > 0 AND _xmin != ? LIMIT ?
        )`,
      );
      let remaining = count;
      while (remaining > 0) {
        const batchSize = Math.min(remaining, costLimit);
        const result = stmt.run(XID_FROZEN, freezeXid, XID_FROZEN, batchSize);
        frozen += result.changes;
        remaining -= batchSize;
        if (remaining > 0) {
          const sleepUntil = Date.now() + costDelay;
          while (Date.now() < sleepUntil) {
            // busy-wait
          }
        }
      }
    }

    const duration = Date.now() - startMs;
    this.logger.debug({ tableName, frozen, durationMs: duration, freezeXid }, 'FREEZE completed');

    return { frozen, duration };
  }

  /**
   * Get the minimum active XID from the MVCC executor.
   * If no transactions are active, uses the current XID counter.
   */
  private getMinActiveXid(): number {
    // The MVCCExecutor exposes getCurrentXid() and getActiveXidSet()
    if (this.mvccExecutor && typeof this.mvccExecutor.getCurrentXid === 'function') {
      const activeSet = this.mvccExecutor.getActiveXidSet?.();
      if (activeSet && activeSet.size > 0) {
        let min = this.mvccExecutor.getCurrentXid();
        for (const xid of activeSet) {
          if (xid < min) min = xid;
        }
        return min;
      }
      // No active txns — use current XID as safe cutoff
      // Rows with _xmax < currentXID are committed and visible
      return this.mvccExecutor.getCurrentXid();
    }
    // Fallback: return conservatively
    return XID_FROZEN + 1;
  }

  /**
   * Compute the freeze XID — rows with _xmin below this value
   * will be frozen.
   *
   * freezeXid = currentXid - freezeMinXid
   * Ensures freezeXid never goes below XID_FROZEN.
   */
  private getFreezeXid(): number {
    let currentXid: number;
    if (this.mvccExecutor && typeof this.mvccExecutor.getCurrentXid === 'function') {
      currentXid = this.mvccExecutor.getCurrentXid();
    } else {
      currentXid = this.config.freezeMinXid + XID_FROZEN + 1;
    }

    const freezeXid = currentXid - this.config.freezeMinXid;
    return Math.max(freezeXid, XID_FROZEN + 1);
  }

  /**
   * Record the time a table was last checked, to prevent re-checking
   * too frequently within the same cycle.
   */
  private recordCheck(tableName: string): void {
    this.lastCheck.set(tableName, Date.now());
  }

  // ── Testing helpers ───────────────────────────────────────────

  /**
   * Expose dead tuple info for testing.
   */
  checkTable(tableName: string, minActiveXid?: number): DeadTableInfo | null {
    const xid = minActiveXid ?? this.getMinActiveXid();
    const tables = this.checkAllTables(xid);
    return tables.find(t => t.tableName === tableName) ?? null;
  }

  /**
   * Expose getUserTables for testing.
   */
  getTables(): string[] {
    return this.getUserTables();
  }

  /**
   * Reset internal test state.
   */
  reset(): void {
    this.dispose();
  }
}
