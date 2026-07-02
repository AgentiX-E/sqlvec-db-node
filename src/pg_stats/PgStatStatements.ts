/**
 * PgStatStatements — pg_stat_statements-equivalent query statistics tracker
 *
 * Phase B #8: Monitors query execution statistics — text, timing, row counts.
 * Mirrors PostgreSQL's pg_stat_statements extension interface.
 *
 * Features:
 *   - Query normalization: literal values replaced with $N placeholders
 *   - Aggregation: same normalized query accumulates stats
 *   - queryid: crypto.hash of normalized query text for deterministic identification
 *   - Top-N queries: sortable by total_time, calls, or rows
 *   - Singleton instance for global access
 */

import * as crypto from 'crypto';

// ── Types ────────────────────────────────────────────────────────

export interface BlockIoCounters {
  reads?: number;
  writes?: number;
  readTime?: number;
  writeTime?: number;
  readBytes?: number;
  writeBytes?: number;
  sharedBlocksHit?: number;
  sharedBlocksRead?: number;
  sharedBlocksDirtied?: number;
  sharedBlocksWritten?: number;
  localBlocksHit?: number;
  localBlocksRead?: number;
  tempBlocksRead?: number;
  tempBlocksWritten?: number;
  ioTime?: number;
}

export interface QueryStatEntry {
  /** hash of normalized query text (crypto.createHash('sha256')) */
  queryid: string;
  /** normalized query text (params replaced with $N) */
  query: string;
  /** number of times this query has been executed */
  calls: number;
  /** total execution time in milliseconds */
  total_time: number;
  /** minimum execution time in milliseconds */
  min_time: number;
  /** maximum execution time in milliseconds */
  max_time: number;
  /** mean execution time in milliseconds */
  mean_time: number;
  /** total rows returned / affected */
  rows: number;
  /** simulated shared block hits (mock: 0 unless configured) */
  shared_blks_hit: number;
  /** simulated shared block reads (mock: 0 unless configured) */
  shared_blks_read: number;
  /** simulated shared block dirtied */
  shared_blks_dirtied: number;
  /** simulated shared block written */
  shared_blks_written: number;
  /** simulated local block hits */
  local_blks_hit: number;
  /** simulated local block reads */
  local_blks_read: number;
  /** simulated temp block reads */
  temp_blks_read: number;
  /** simulated temp block writes */
  temp_blks_written: number;
  /** simulated block I/O read time */
  blk_read_time: number;
  /** simulated block I/O write time */
  blk_write_time: number;
}

// ── Helpers ──────────────────────────────────────────────────────

/**
 * Normalize a SQL query by replacing literal values with $N placeholders.
 *
 * Normalization rules:
 *   1. PostgreSQL positional params ($1, $2, ...) → $N (MUST come first)
 *   2. Single-quoted string literals → '$S'
 *   3. Numeric literals (integers, floats) → $N
 *   4. NULL keyword → $N
 *
 * @example
 *   normalizeQuery("SELECT * FROM users WHERE id = 1")
 *   // → "SELECT * FROM users WHERE id = $N"
 *
 *   normalizeQuery("INSERT INTO t VALUES ('abc')")
 *   // → "INSERT INTO t VALUES ('$S')"
 */
export function normalizeQuery(sql: string): string {
  if (!sql || typeof sql !== 'string') return '';

  let normalized = sql.trim();
  if (normalized.length === 0) return '';

  // PostgreSQL positional placeholders ($1, $2, ...) → $N
  // MUST come first to avoid the `$` prefix confusing the numeric regex.
  normalized = normalized.replace(/\$\d+\b/g, '$N');

  // Single-quoted string literals (handles '' escaped quotes inside strings)
  // State-machine approach: find the opening ', then scan to the closing ',
  // treating '' as escaped quotes that don't end the string.
  normalized = normalized.replace(/'[^']*(?:''[^']*)*'/g, "'$S'");

  // Numeric literals (integers, decimals)
  normalized = normalized.replace(/\b\d+(?:\.\d+)?\b/g, '$N');

  // NULL keyword (case-insensitive)
  normalized = normalized.replace(/\bNULL\b/gi, '$N');

  return normalized;
}

/**
 * Generate a deterministic queryid by hashing the normalized SQL.
 * Uses SHA-256 (via crypto.createHash) truncated to first 16 hex chars.
 */
export function hashQuery(normalizedSql: string): string {
  return crypto.createHash('sha256').update(normalizedSql).digest('hex').slice(0, 16);
}

// ── PgStatStatements Class ───────────────────────────────────────

export class PgStatStatements {
  /** Internal map: queryid (hash) → QueryStatEntry */
  private stats = new Map<string, QueryStatEntry>();
  /** Number of unique normalized queries tracked */
  private count: number = 0;

  // ── Recording ────────────────────────────────────────────────

  /**
   * Record a SQL query execution.
   *
   * @param sql - Raw (unnormalized) SQL query string
   * @param durationMs - Execution duration in milliseconds
   * @param rowsReturned - Number of rows returned or affected
   * @param error - Optional error message (if the query failed)
   */
  recordQuery(
    sql: string,
    durationMs: number,
    rowsReturned: number,
    blockIo?: BlockIoCounters,
    error?: string,
  ): void {
    if (!sql || typeof sql !== 'string') return;

    const normalized = normalizeQuery(sql);
    if (normalized.length === 0) return;

    const queryid = hashQuery(normalized);
    const existing = this.stats.get(queryid);

    if (existing) {
      existing.calls++;
      existing.total_time += durationMs;
      existing.min_time = Math.min(existing.min_time, durationMs);
      existing.max_time = Math.max(existing.max_time, durationMs);
      existing.mean_time = existing.total_time / existing.calls;
      existing.rows += rowsReturned;
      // Accumulate block I/O counters
      if (blockIo) {
        existing.shared_blks_hit += blockIo.sharedBlocksHit ?? 0;
        existing.shared_blks_read += blockIo.sharedBlocksRead ?? 0;
        existing.shared_blks_dirtied += blockIo.sharedBlocksDirtied ?? 0;
        existing.shared_blks_written += blockIo.sharedBlocksWritten ?? 0;
        existing.local_blks_hit += blockIo.localBlocksHit ?? 0;
        existing.local_blks_read += blockIo.localBlocksRead ?? 0;
        existing.temp_blks_read += blockIo.tempBlocksRead ?? 0;
        existing.temp_blks_written += blockIo.tempBlocksWritten ?? 0;
        existing.blk_read_time += blockIo.ioTime ?? 0;
      }
    } else {
      this.stats.set(queryid, {
        queryid,
        query: normalized,
        calls: 1,
        total_time: durationMs,
        min_time: durationMs,
        max_time: durationMs,
        mean_time: durationMs,
        rows: rowsReturned,
        shared_blks_hit: blockIo?.sharedBlocksHit ?? 0,
        shared_blks_read: blockIo?.sharedBlocksRead ?? 0,
        shared_blks_dirtied: blockIo?.sharedBlocksDirtied ?? 0,
        shared_blks_written: blockIo?.sharedBlocksWritten ?? 0,
        local_blks_hit: blockIo?.localBlocksHit ?? 0,
        local_blks_read: blockIo?.localBlocksRead ?? 0,
        temp_blks_read: blockIo?.tempBlocksRead ?? 0,
        temp_blks_written: blockIo?.tempBlocksWritten ?? 0,
        blk_read_time: blockIo?.ioTime ?? 0,
        blk_write_time: 0,
      });
      this.count++;
    }
  }

  // ── Query ────────────────────────────────────────────────────

  /**
   * Get top queries sorted by the specified criteria.
   *
   * @param limit - Maximum number of entries to return (default: all)
   * @param sortBy - Sort criterion (default: 'total_time')
   */
  getTopQueries(
    limit?: number,
    sortBy: 'total_time' | 'calls' | 'rows' = 'total_time',
  ): QueryStatEntry[] {
    const entries = Array.from(this.stats.values());

    switch (sortBy) {
      case 'calls':
        entries.sort((a, b) => b.calls - a.calls);
        break;
      case 'rows':
        entries.sort((a, b) => b.rows - a.rows);
        break;
      case 'total_time':
      default:
        entries.sort((a, b) => b.total_time - a.total_time);
        break;
    }

    if (limit !== undefined && limit > 0) {
      return entries.slice(0, limit);
    }
    return entries;
  }

  /**
   * Get all tracked query statistics (alias for getTopQueries without sort).
   */
  getAll(): QueryStatEntry[] {
    return Array.from(this.stats.values());
  }

  /** Alias for getAll() (PG client compatibility) */
  getEntries(): QueryStatEntry[] {
    return this.getAll();
  }

  /**
   * Get statistics for a specific raw SQL query.
   *
   * @param sql - Raw SQL (will be normalized internally for lookup)
   */
  getStat(sql: string): QueryStatEntry | undefined {
    if (!sql) return undefined;
    const normalized = normalizeQuery(sql);
    const queryid = hashQuery(normalized);
    return this.stats.get(queryid);
  }

  // ── Maintenance ──────────────────────────────────────────────

  /**
   * Reset all tracked statistics.
   */
  reset(): void {
    this.stats.clear();
    this.count = 0;
  }

  /**
   * Number of unique normalized query shapes.
   */
  get size(): number {
    return this.count;
  }
}

// ── Singleton ────────────────────────────────────────────────────

/** Global singleton instance for pg_stat_statements access. */
export const pgStatStatements = new PgStatStatements();
