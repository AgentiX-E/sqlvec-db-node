/**
 * SlowQueryRecorder — Intercepts and persists slow queries for monitoring.
 *
 * Features:
 *   - Records queries that exceed configurable threshold (default 500ms)
 *   - Persists to slow_queries table: query_text, duration_ms, shard_id, timestamp
 *   - Exposes getSlowQueries(duration, limit) for monitoring dashboards
 *   - Integrated with the QueryRouter via record() calls
 *
 * Usage:
 *   const recorder = new SlowQueryRecorder({ dbPath: '/tmp/slow_queries.db', slowQueryThresholdMs: 200 });
 *   await recorder.init();
 *   // After executing a query:
 *   recorder.record('SELECT * FROM large_table', 1234, 0);
 *   const slow = await recorder.getSlowQueries(500, 10);
 *   await recorder.close();
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

import { PinoLogger } from './PinoLogger';
const logger = PinoLogger.forComponent('SlowQuery');

// ── Types ────────────────────────────────────────────────────────

export interface SlowQueryEntry {
  id?: number;
  queryText: string;
  durationMs: number;
  shardId: number;
  timestamp: string;
}

export interface SlowQueryRecorderConfig {
  /** Path to the SQLite database file (default: './slow_queries.db') */
  dbPath?: string;
  /** Threshold in ms; queries >= this duration are recorded (default: 500) */
  slowQueryThresholdMs?: number;
  /** Max number of stored entries before pruning (0 = unlimited, default: 10000) */
  maxEntries?: number;
  /**
   * Shared better-sqlite3 Database instance.
   * When provided, the slow_queries table is created on this database
   * instead of opening a separate file. The caller owns the lifecycle.
   * When omitted, the recorder opens its own database file at dbPath.
   */
  db?: Database.Database;
  /**
   * Sampling rate (0.0 – 1.0). When set to e.g. 0.5, only 50% of qualifying
   * slow queries are persisted. Default: 1.0 (all). Flood protection.
   */
  sampleRate?: number;
  /**
   * Max number of Top N entries kept in memory for fast access.
   * Default: 10. Set to 0 to disable in-memory Top N.
   */
  topNCount?: number;
}

// ── SlowQueryRecorder ────────────────────────────────────────────

export class SlowQueryRecorder {
  private db: Database.Database | null = null;
  /** Whether we own the db instance (own file) vs borrowing from caller. */
  private ownsDb: boolean = true;
  private config: {
    dbPath: string;
    slowQueryThresholdMs: number;
    maxEntries: number;
    sampleRate: number;
    topNCount: number;
    db?: Database.Database;
  };
  private insertStmt: Database.Statement | null = null;

  /** In-memory Top N slow queries (sorted by duration descending) */
  private topN: SlowQueryEntry[] = [];
  /** Mutex for topN updates */
  private topNMutex = false;

  constructor(config: SlowQueryRecorderConfig = {}) {
    this.config = {
      dbPath: config.dbPath ?? './slow_queries.db',
      slowQueryThresholdMs: config.slowQueryThresholdMs ?? 500,
      maxEntries: config.maxEntries ?? 10000,
      sampleRate: config.sampleRate ?? 1.0,
      topNCount: config.topNCount ?? 10,
      db: config.db,
    };
  }

  /**
   * Open the database and create the slow_queries table.
   * When a shared db instance is provided in config, uses that database
   * instead of opening a separate file.
   */
  async init(): Promise<void> {
    if (this.config.db) {
      // Shared database — use it directly (caller owns lifecycle)
      this.db = this.config.db;
      this.ownsDb = false;
    } else {
      // Open own database file
      const dbDir = dirname(this.config.dbPath);
      if (dbDir && !existsSync(dbDir)) {
        mkdirSync(dbDir, { recursive: true });
      }

      this.db = new Database(this.config.dbPath);
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('synchronous = NORMAL');
      this.ownsDb = true;
    }

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS slow_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query_text TEXT NOT NULL,
        duration_ms REAL NOT NULL,
        shard_id INTEGER NOT NULL DEFAULT -1,
        timestamp TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_slow_queries_duration ON slow_queries(duration_ms DESC);
    `);

    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_slow_queries_timestamp ON slow_queries(timestamp DESC);
    `);

    this.insertStmt = this.db.prepare(
      `INSERT INTO slow_queries (query_text, duration_ms, shard_id, timestamp)
       VALUES (?, ?, ?, ?)`
    );
  }

  /**
   * Record a query execution time.
   * Only persists if durationMs >= threshold.
   * Respects sampling rate and maintains in-memory Top N.
   */
  record(
    queryText: string,
    durationMs: number,
    shardId: number = -1
  ): void {
    if (!this.db || this.config.slowQueryThresholdMs <= 0) return;
    if (durationMs < this.config.slowQueryThresholdMs) return;

    try {
      // Sampling: skip if random roll misses sampleRate
      if (this.config.sampleRate < 1.0 && Math.random() > this.config.sampleRate) {
        return;
      }

      // Truncate very long query text
      const truncated = queryText.length > 4000 ? queryText.slice(0, 4000) + '...' : queryText;
      this.insertStmt!.run(truncated, durationMs, shardId, new Date().toISOString());

      // Update in-memory Top N
      if (this.config.topNCount > 0) {
        this.updateTopN({ queryText: truncated, durationMs, shardId, timestamp: new Date().toISOString() });
      }

      // Prune excess entries if configured
      if (this.config.maxEntries > 0) {
        this.prune();
      }
    } catch (err) {
      logger.error('[SlowQueryRecorder] Failed to record slow query:', (err as Error).message);
    }
  }

  /**
   * Get Top N slowest queries from in-memory cache (fast, no DB query).
   */
  getTopN(minDurationMs?: number, limit: number = 10): SlowQueryEntry[] {
    let entries = this.topN;
    if (minDurationMs !== undefined && minDurationMs > 0) {
      entries = entries.filter(e => e.durationMs >= minDurationMs);
    }
    return entries.slice(0, Math.min(limit, this.config.topNCount));
  }

  /**
   * Maintain sorted Top N list (insertion-sort into fixed-size array).
   */
  private updateTopN(entry: SlowQueryEntry): void {
    // Binary search insertion point
    let lo = 0, hi = this.topN.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (this.topN[mid].durationMs >= entry.durationMs) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    this.topN.splice(lo, 0, entry);
    if (this.topN.length > this.config.topNCount) {
      this.topN.length = this.config.topNCount;
    }
  }

  /**
   * Query slow queries, optionally filtered by minimum duration and limited count.
   */
  getSlowQueries(
    minDurationMs?: number,
    limit: number = 100
  ): SlowQueryEntry[] {
    if (!this.db) return [];

    const conditions: string[] = [];
    const params: unknown[] = [];

    if (minDurationMs !== undefined && minDurationMs > 0) {
      conditions.push('duration_ms >= ?');
      params.push(minDurationMs);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const sql = `SELECT id, query_text, duration_ms, shard_id, timestamp
                 FROM slow_queries ${where}
                 ORDER BY duration_ms DESC
                 LIMIT ?`;
    params.push(limit);

    const rows = this.db.prepare(sql).all(...params) as Array<{
      id: number;
      query_text: string;
      duration_ms: number;
      shard_id: number;
      timestamp: string;
    }>;

    return rows.map(r => ({
      id: r.id,
      queryText: r.query_text,
      durationMs: r.duration_ms,
      shardId: r.shard_id,
      timestamp: r.timestamp,
    }));
  }

  /**
   * Get statistics about slow queries.
   */
  getStats(): { total: number; maxDurationMs: number; avgDurationMs: number } {
    if (!this.db) return { total: 0, maxDurationMs: 0, avgDurationMs: 0 };
    const row = this.db.prepare(
      `SELECT COUNT(*) as total, COALESCE(MAX(duration_ms), 0) as maxDurationMs, COALESCE(AVG(duration_ms), 0) as avgDurationMs FROM slow_queries`
    ).get() as { total: number; maxDurationMs: number; avgDurationMs: number };
    return row;
  }

  /**
   * Update the threshold at runtime.
   */
  setThreshold(ms: number): void {
    this.config.slowQueryThresholdMs = ms;
  }

  /**
   * Get the current threshold.
   */
  getThreshold(): number {
    return this.config.slowQueryThresholdMs;
  }

  /**
   * Get the current sample rate (0.0 – 1.0).
   */
  getSampleRate(): number {
    return this.config.sampleRate;
  }

  /**
   * Set the sample rate at runtime (0.0 – 1.0).
   */
  setSampleRate(rate: number): void {
    this.config.sampleRate = Math.max(0, Math.min(1, rate));
  }

  /**
   * Close the database connection.
   * Only closes the connection when this recorder owns it (own file).
   * For shared databases, the owning component manages the lifecycle.
   */
  async close(): Promise<void> {
    if (this.db) {
      this.insertStmt = null;
      if (this.ownsDb) {
        this.db.close();
      }
      this.db = null;
    }
  }

  /**
   * Prune entries beyond maxEntries (keeps the most recent ones).
   */
  private prune(): void {
    if (!this.db) return;
    try {
      const countRow = this.db.prepare('SELECT COUNT(*) as cnt FROM slow_queries').get() as { cnt: number };
      if (countRow.cnt <= this.config.maxEntries) return;

      // Get the ID threshold for pruning
      const thresholdRow = this.db.prepare(
        'SELECT id FROM slow_queries ORDER BY id DESC LIMIT 1 OFFSET ?'
      ).get(this.config.maxEntries - 1) as { id: number } | undefined;

      if (thresholdRow) {
        this.db.prepare('DELETE FROM slow_queries WHERE id < ?').run(thresholdRow.id);
      }
    } catch {
      // Ignore pruning errors (e.g. concurrent access)
    }
  }
}
