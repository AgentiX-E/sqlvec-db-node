/**
 * AutovacuumDaemon — Background VACUUM & ANALYZE scheduler for SQLite.
 *
 * Monitors SQLite tables for dead tuple accumulation and periodically
 * executes VACUUM and ANALYZE based on configurable thresholds.
 * Designed to mirror PostgreSQL's autovacuum behavior in a SQLite context.
 *
 * Threshold formula (PG-compatible):
 *   Need vacuum:  n_dead_tup > vacuumThreshold + vacuumScaleFactor * n_live_tup
 *   Need analyze: n_mod_since_analyze > analyzeThreshold + analyzeScaleFactor * n_live_tup
 *
 * Architecture:
 *   - Timer-driven background cycle (configurable interval, default 5 min)
 *   - Queries sqlite_master + PRAGMA table_info for table metadata
 *   - Uses AutoTuner thresholds to decide which tables need vacuum
 *   - Executes PRAGMA optimize for analyze
 *   - Executes full VACUUM for heavy table space reclamation
 *   - Tracks last_vacuum, last_analyze, dead/live tuple estimates
 *   - Logs all activity via PinoLogger
 *
 * @module vacuum/AutovacuumDaemon
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import Database from 'better-sqlite3';

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

export interface AutovacuumConfig {
  /** Enable background autovacuum daemon (default: true) */
  enabled: boolean;
  /** How often to run the background cycle, in ms (default: 300000 = 5 min) */
  intervalMs: number;
  /** Minimum dead tuple ratio before VACUUM (default: 0.2 = 20%) */
  vacuumThreshold: number;
  /** Scale factor for dead tuple threshold (default: 0.01 = 1%) */
  vacuumScaleFactor: number;
  /** Minimum modification ratio before ANALYZE (default: 0.1 = 10%) */
  analyzeThreshold: number;
  /** Scale factor for analyze threshold (default: 0.05 = 5%) */
  analyzeScaleFactor: number;
}

export const DEFAULT_AUTOVACUUM_CONFIG: AutovacuumConfig = {
  enabled: true,
  intervalMs: 300_000, // 5 minutes
  vacuumThreshold: 0.2, // 20% dead tuples
  vacuumScaleFactor: 0.01, // 1%
  analyzeThreshold: 0.1, // 10%
  analyzeScaleFactor: 0.05, // 5%
};

export interface TableVacuumInfo {
  tableName: string;
  nLiveTup: number;
  nDeadTup: number;
  nModSinceAnalyze: number;
  lastVacuumTime: number;
  lastAnalyzeTime: number;
  needsVacuum: boolean;
  needsAnalyze: boolean;
}

export interface VacuumResult {
  success: boolean;
  tableName: string;
  message: string;
  reclaimedPages?: number;
  durationMs: number;
}

export interface AnalyzeResult {
  success: boolean;
  tableName: string;
  message: string;
  durationMs: number;
}

export interface AutovacuumStatus {
  running: boolean;
  config: AutovacuumConfig;
  trackedTables: number;
  tables: TableVacuumInfo[];
  lastCycleTime: number | null;
  cycleCount: number;
  totalVacuumCount: number;
  totalAnalyzeCount: number;
}

// ──────────────────────────────────────────────
//  AutovacuumDaemon
// ──────────────────────────────────────────────

export class AutovacuumDaemon {
  private config: AutovacuumConfig;
  private logger: PinoLogger;
  private timerHandle: ReturnType<typeof setInterval> | null = null;

  /** Per-table statistics keyed by schema.tableName */
  private tableStats: Map<string, TableVacuumInfo> = new Map();

  /** Track dead tuples per table (incremented by notifyMutation) */
  private deadTupleCounts: Map<string, number> = new Map();

  /** Track modifications since last analyze */
  private modSinceAnalyze: Map<string, number> = new Map();

  /** Runtime statistics */
  private lastCycleTime: number | null = null;
  private cycleCount: number = 0;
  private totalVacuumCount: number = 0;
  private totalAnalyzeCount: number = 0;

  /** Internal flag to prevent overlapping cycles */
  private cycleInProgress: boolean = false;

  /** Map of shard database connections (shardId -> Database) */
  private shardDbs: Map<number, Database.Database> = new Map();

  constructor(config?: Partial<AutovacuumConfig>) {
    this.config = { ...DEFAULT_AUTOVACUUM_CONFIG, ...config };
    this.logger = PinoLogger.forComponent('AutovacuumDaemon');
    this.logger.info({ config: this.config }, 'AutovacuumDaemon initialized');
  }

  // ──────────────────────────────────────────────
  //  Lifecycle
  // ──────────────────────────────────────────────

  /**
   * Register a shard database connection for VACUUM/ANALYZE operations.
   */
  registerShardDb(shardId: number, db: Database.Database): void {
    this.shardDbs.set(shardId, db);
    this.logger.debug({ shardId }, 'Shard registered with autovacuum daemon');
  }

  /**
   * Unregister a shard database connection.
   */
  unregisterShardDb(shardId: number): void {
    this.shardDbs.delete(shardId);
    this.logger.debug({ shardId }, 'Shard unregistered from autovacuum daemon');
  }

  /**
   * Start the autovacuum daemon background timer.
   * Safe to call multiple times (only starts once).
   */
  start(): void {
    if (this.timerHandle !== null) {
      this.logger.warn('Autovacuum daemon already running');
      return;
    }

    if (!this.config.enabled) {
      this.logger.info('Autovacuum daemon is disabled — not starting');
      return;
    }

    this.logger.info(
      { intervalMs: this.config.intervalMs },
      'Starting autovacuum daemon',
    );

    // Schedule periodic cycles
    this.timerHandle = setInterval(() => {
      this.runCycle().catch((err) => {
        this.logger.error(
          { error: err instanceof Error ? err.message : String(err) },
          'Autovacuum cycle error',
        );
      });
    }, this.config.intervalMs);

    // Make timer not keep the process alive
    if (this.timerHandle && typeof this.timerHandle === 'object' && 'unref' in this.timerHandle) {
      (this.timerHandle as ReturnType<typeof setInterval>).unref();
    }

    // Run an initial cycle after a short delay
    setTimeout(() => {
      this.runCycle().catch((err) => {
        this.logger.error(
          { error: err instanceof Error ? err.message : String(err) },
          'Autovacuum initial cycle error',
        );
      });
    }, 2000);

    this.logger.info('Autovacuum daemon started');
  }

  /**
   * Stop the autovacuum daemon timer.
   */
  stop(): void {
    if (this.timerHandle !== null) {
      clearInterval(this.timerHandle);
      this.timerHandle = null;
      this.logger.info('Autovacuum daemon stopped');
    }
  }

  /**
   * Restart the daemon (useful after config changes).
   */
  restart(): void {
    this.stop();
    this.start();
  }

  /**
   * Dispose all resources held by the daemon.
   */
  dispose(): void {
    this.stop();
    this.tableStats.clear();
    this.deadTupleCounts.clear();
    this.modSinceAnalyze.clear();
    this.shardDbs.clear();
    this.lastCycleTime = null;
    this.cycleCount = 0;
    this.totalVacuumCount = 0;
    this.totalAnalyzeCount = 0;
  }

  // ──────────────────────────────────────────────
  //  Status
  // ──────────────────────────────────────────────

  /**
   * Get the current daemon status snapshot.
   */
  getStatus(): AutovacuumStatus {
    const tables: TableVacuumInfo[] = [];

    for (const [, info] of this.tableStats) {
      tables.push({ ...info });
    }

    return {
      running: this.timerHandle !== null,
      config: { ...this.config },
      trackedTables: tables.length,
      tables,
      lastCycleTime: this.lastCycleTime,
      cycleCount: this.cycleCount,
      totalVacuumCount: this.totalVacuumCount,
      totalAnalyzeCount: this.totalAnalyzeCount,
    };
  }

  /**
   * Get current configuration (read-only snapshot).
   */
  getConfig(): Readonly<AutovacuumConfig> {
    return { ...this.config };
  }

  /**
   * Update configuration at runtime.
   */
  updateConfig(partial: Partial<AutovacuumConfig>): void {
    const oldEnabled = this.config.enabled;
    Object.assign(this.config, partial);

    this.logger.info({ config: this.config }, 'Autovacuum config updated');

    // If enabled state changed, start/stop
    if (partial.enabled !== undefined && partial.enabled !== oldEnabled) {
      if (partial.enabled) {
        this.start();
      } else {
        this.stop();
      }
      return;
    }

    // If interval changed, restart timer
    if (partial.intervalMs !== undefined && this.timerHandle) {
      this.restart();
    }
  }

  /**
   * Check if the daemon is currently running.
   */
  isRunning(): boolean {
    return this.timerHandle !== null;
  }

  // ──────────────────────────────────────────────
  //  Manual Table Operations
  // ──────────────────────────────────────────────

  /**
   * Run VACUUM on a specific table across all registered shards.
   * Returns overall result.
   */
  async vacuumTable(tableName: string): Promise<VacuumResult> {
    const startMs = Date.now();
    let totalSuccess = false;
    let reclaimedPages = 0;
    let lastMessage = '';

    for (const [shardId, db] of this.shardDbs) {
      try {
        const beforePages = this.getPageCount(db);
        db.exec('VACUUM;');
        const afterPages = this.getPageCount(db);
        const pagesReclaimed = beforePages - afterPages;
        reclaimedPages += Math.max(0, pagesReclaimed);

        this.logger.info(
          { shardId, tableName, beforePages, afterPages, pagesReclaimed },
          `VACUUM completed on table "${tableName}" for shard ${shardId}`,
        );

        totalSuccess = true;
        lastMessage = `VACUUM completed on table "${tableName}"`;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(
          { shardId, tableName, error: msg },
          `VACUUM failed on table "${tableName}" for shard ${shardId}`,
        );
        lastMessage = `VACUUM partially failed: ${msg}`;
      }
    }

    // Reset dead tuple count after vacuum
    const key = `public.${tableName}`;
    const stats = this.tableStats.get(key);
    if (stats) {
      stats.nDeadTup = 0;
      stats.lastVacuumTime = Date.now();
      stats.needsVacuum = false;
    }
    this.deadTupleCounts.set(key, 0);
    this.totalVacuumCount++;

    const durationMs = Date.now() - startMs;
    return {
      success: totalSuccess,
      tableName,
      message: lastMessage || `VACUUM completed on "${tableName}"`,
      reclaimedPages: reclaimedPages > 0 ? reclaimedPages : undefined,
      durationMs,
    };
  }

  /**
   * Run ANALYZE on a specific table across all registered shards.
   * Follows with PRAGMA optimize for SQLite statistics updates.
   */
  async analyzeTable(tableName: string): Promise<AnalyzeResult> {
    const startMs = Date.now();
    let totalSuccess = false;
    let lastMessage = '';

    for (const [, db] of this.shardDbs) {
      try {
        db.exec(`ANALYZE "${tableName}";`);
        db.exec('PRAGMA optimize;');

        this.logger.info(
          { tableName },
          `ANALYZE completed on table "${tableName}"`,
        );

        totalSuccess = true;
        lastMessage = `ANALYZE completed on table "${tableName}"`;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(
          { tableName, error: msg },
          `ANALYZE failed on table "${tableName}"`,
        );
        lastMessage = `ANALYZE partially failed: ${msg}`;
      }
    }

    // Reset modification counter after analyze
    const key = `public.${tableName}`;
    const stats = this.tableStats.get(key);
    if (stats) {
      stats.nModSinceAnalyze = 0;
      stats.lastAnalyzeTime = Date.now();
      stats.needsAnalyze = false;
    }
    this.modSinceAnalyze.set(key, 0);
    this.totalAnalyzeCount++;

    const durationMs = Date.now() - startMs;
    return {
      success: totalSuccess,
      tableName,
      message: lastMessage || `ANALYZE completed on "${tableName}"`,
      durationMs,
    };
  }

  // ──────────────────────────────────────────────
  //  Mutation Tracking
  // ──────────────────────────────────────────────

  /**
   * Notify the daemon that a mutation occurred on a table.
   * Increments dead tuple / modification counters.
   */
  notifyMutation(
    tableName: string,
    mutationType: 'INSERT' | 'UPDATE' | 'DELETE',
    schemaName: string = 'public',
  ): void {
    const key = `${schemaName}.${tableName}`;

    // Initialize if not tracked
    let stats = this.tableStats.get(key);
    if (!stats) {
      stats = {
        tableName,
        nLiveTup: 0,
        nDeadTup: 0,
        nModSinceAnalyze: 0,
        lastVacuumTime: Date.now(),
        lastAnalyzeTime: Date.now(),
        needsVacuum: false,
        needsAnalyze: false,
      };
      this.tableStats.set(key, stats);
    }

    // Update dead tuple estimates based on mutation type
    let deadTupDelta = 0;
    switch (mutationType) {
      case 'INSERT':
        stats.nLiveTup += 1;
        break;
      case 'UPDATE':
        // UPDATE creates a dead tuple (old version)
        deadTupDelta = 1;
        break;
      case 'DELETE':
        if (stats.nLiveTup > 0) {
          stats.nLiveTup -= 1;
        }
        deadTupDelta = 1;
        break;
    }

    stats.nDeadTup += deadTupDelta;
    stats.nModSinceAnalyze += 1;

    // Track in separate maps for cycle evaluation
    const currentDead = this.deadTupleCounts.get(key) || 0;
    this.deadTupleCounts.set(key, currentDead + deadTupDelta);

    const currentMod = this.modSinceAnalyze.get(key) || 0;
    this.modSinceAnalyze.set(key, currentMod + 1);
  }

  /**
   * Sync the live tuple count for a table from an actual DB row count.
   */
  syncTableLiveTup(tableName: string, nLiveTup: number, schemaName: string = 'public'): void {
    const key = `${schemaName}.${tableName}`;
    let stats = this.tableStats.get(key);
    if (!stats) {
      stats = {
        tableName,
        nLiveTup,
        nDeadTup: 0,
        nModSinceAnalyze: 0,
        lastVacuumTime: Date.now(),
        lastAnalyzeTime: Date.now(),
        needsVacuum: false,
        needsAnalyze: false,
      };
      this.tableStats.set(key, stats);
    } else {
      stats.nLiveTup = nLiveTup;
    }
  }

  // ──────────────────────────────────────────────
  //  Background Cycle
  // ──────────────────────────────────────────────

  /**
   * Main background cycle — evaluates all tables across all registered
   * shards for VACUUM and ANALYZE needs.
   */
  async runCycle(): Promise<void> {
    if (this.cycleInProgress) {
      this.logger.debug('Autovacuum cycle already in progress — skipping');
      return;
    }

    this.cycleInProgress = true;
    this.cycleCount++;
    const cycleStart = Date.now();

    try {
      if (this.shardDbs.size === 0) {
        this.logger.debug('No shard databases registered — skipping cycle');
        this.lastCycleTime = Date.now();
        return;
      }

      // Phase 1: Refresh table metadata and live tuple counts
      await this.refreshTableMetadata();

      // Phase 2: Evaluate which tables need VACUUM
      await this.evaluateVacuumNeeds();

      // Phase 3: Evaluate which tables need ANALYZE
      await this.evaluateAnalyzeNeeds();

      this.lastCycleTime = Date.now();
      const cycleDuration = Date.now() - cycleStart;
      const vacuumCount = this.totalVacuumCount;
      const analyzeCount = this.totalAnalyzeCount;

      this.logger.info(
        {
          cycleDurationMs: cycleDuration,
          totalCycles: this.cycleCount,
          vacuumCount,
          analyzeCount,
          trackedTables: this.tableStats.size,
        },
        'Autovacuum cycle completed',
      );
    } catch (err) {
      this.logger.error(
        { error: err instanceof Error ? err.message : String(err) },
        'Autovacuum cycle failed',
      );
    } finally {
      this.cycleInProgress = false;
    }
  }

  // ──────────────────────────────────────────────
  //  Private: Metadata
  // ──────────────────────────────────────────────

  /**
   * Query sqlite_master and row counts to refresh live tuple estimates.
   */
  private async refreshTableMetadata(): Promise<void> {
    for (const [, db] of this.shardDbs) {
      try {
        const tables = db.prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND substr(name, 1, 2) != '__'",
        ).all() as { name: string }[];

        for (const { name } of tables) {
          try {
            const countRow = db.prepare(
              `SELECT COUNT(*) as cnt FROM "${name}"`,
            ).get() as { cnt: number };

            this.syncTableLiveTup(name, countRow.cnt);
          } catch {
            // Skip tables that can't be counted (virtual tables, etc.)
          }
        }
      } catch {
        // Skip shards that error out
      }
    }
  }

  // ──────────────────────────────────────────────
  //  Private: Needs Evaluation
  // ──────────────────────────────────────────────

  /**
   * Evaluate which tables need VACUUM based on dead tuple thresholds.
   * Threshold formula: n_dead_tup > vacuumThreshold * n_live_tup + vacuumScaleFactor * n_live_tup
   */
  private async evaluateVacuumNeeds(): Promise<void> {
    for (const [key, stats] of this.tableStats) {
      const deadTup = this.deadTupleCounts.get(key) || stats.nDeadTup;

      // Only check tables with dead tuples
      if (deadTup <= 0) continue;

      const liveTup = stats.nLiveTup || 1; // Avoid division by zero
      const deadRatio = deadTup / (liveTup + deadTup);

      const needsVacuum = deadRatio >= this.config.vacuumThreshold
        || deadTup >= this.config.vacuumThreshold * liveTup + this.config.vacuumScaleFactor * liveTup;

      stats.needsVacuum = needsVacuum;
      stats.nDeadTup = deadTup;

      if (needsVacuum) {
        this.logger.info(
          {
            table: stats.tableName,
            nDeadTup: deadTup,
            nLiveTup: liveTup,
            deadRatio: deadRatio.toFixed(3),
            threshold: this.config.vacuumThreshold,
          },
          'Autovacuum: VACUUM triggered for table',
        );

        const result = await this.vacuumTable(stats.tableName);
        this.logger.info(
          { table: stats.tableName, success: result.success, durationMs: result.durationMs },
          result.message,
        );
      }
    }
  }

  /**
   * Evaluate which tables need ANALYZE based on modification thresholds.
   * Threshold formula: n_mod > analyzeThreshold * n_live_tup + analyzeScaleFactor * n_live_tup
   */
  private async evaluateAnalyzeNeeds(): Promise<void> {
    for (const [key, stats] of this.tableStats) {
      const mod = this.modSinceAnalyze.get(key) || stats.nModSinceAnalyze;

      if (mod <= 0) continue;

      const liveTup = stats.nLiveTup || 1;
      const needsAnalyze = mod >= this.config.analyzeThreshold * liveTup
        + this.config.analyzeScaleFactor * liveTup;

      stats.needsAnalyze = needsAnalyze;
      stats.nModSinceAnalyze = mod;

      if (needsAnalyze) {
        this.logger.info(
          {
            table: stats.tableName,
            nModSinceAnalyze: mod,
            nLiveTup: liveTup,
            threshold: this.config.analyzeThreshold,
          },
          'Autovacuum: ANALYZE triggered for table',
        );

        const result = await this.analyzeTable(stats.tableName);
        this.logger.info(
          { table: stats.tableName, success: result.success, durationMs: result.durationMs },
          result.message,
        );
      }
    }
  }

  // ──────────────────────────────────────────────
  //  Private: Helpers
  // ──────────────────────────────────────────────

  /**
   * Get the number of pages in a database (for size tracking).
   */
  private getPageCount(db: Database.Database): number {
    try {
      const row = db.prepare('PRAGMA page_count;').get() as { page_count: number } | undefined;
      return row?.page_count ?? 0;
    } catch {
      return 0;
    }
  }

  /**
   * Expose internal dead tuple counts for testing.
   */
  getDeadTupleCount(tableName: string, schemaName: string = 'public'): number {
    return this.deadTupleCounts.get(`${schemaName}.${tableName}`) || 0;
  }

  /**
   * Expose internal modification counts for testing.
   */
  getModSinceAnalyzeCount(tableName: string, schemaName: string = 'public'): number {
    return this.modSinceAnalyze.get(`${schemaName}.${tableName}`) || 0;
  }
}
