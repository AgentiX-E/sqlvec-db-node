/**
 * AutoTuner — Threshold-based auto-tuning for SQLVec
 *
 * Periodically evaluates system metrics against configurable thresholds
 * and suggests tuning actions (SHRINK_MEMORY, RESIZE_POOL, COMPACT_WAL,
 * ADJUST_CACHE, SCALE_BACKPRESSURE).
 *
 * Usage:
 *   const tuner = new AutoTuner({
 *     metrics: { maxQueryLatencyMs: 100, ... }
 *   });
 *   const actions = tuner.evaluate({
 *     queryLatencyP99: 250,
 *     cacheHitRate: 0.7,
 *     ...
 *   });
 */

export interface TuningMetrics {
  maxQueryLatencyMs: number;  // Trigger: queries over this
  minCacheHitRate: number;    // Trigger: cache hit rate below this
  maxFollowerLagMs: number;   // Trigger: replication lag over this
  maxConnectionCount: number; // Trigger: too many connections
}

export const DEFAULT_TUNING_METRICS: TuningMetrics = {
  maxQueryLatencyMs: 100,
  minCacheHitRate: 0.8,
  maxFollowerLagMs: 500,
  maxConnectionCount: 100,
};

export interface TuningActionsConfig {
  autoShrinkMemory: boolean;  // GC memory on high pressure
  autoAdjustPool: boolean;    // Resize worker pool
  autoCompactWAL: boolean;    // Trigger WAL checkpoint
}

export const DEFAULT_TUNING_ACTIONS: TuningActionsConfig = {
  autoShrinkMemory: true,
  autoAdjustPool: true,
  autoCompactWAL: true,
};

export interface TuningConfig {
  enabled: boolean;
  intervalMs: number;          // How often to evaluate (default: 60000)
  metrics: TuningMetrics;
  actions: TuningActionsConfig;
}

export const DEFAULT_TUNING_CONFIG: TuningConfig = {
  enabled: true,
  intervalMs: 60_000,
  metrics: { ...DEFAULT_TUNING_METRICS },
  actions: { ...DEFAULT_TUNING_ACTIONS },
};

export interface TuningAction {
  type: 'SHRINK_MEMORY' | 'RESIZE_POOL' | 'COMPACT_WAL' | 'ADJUST_CACHE' | 'SCALE_BACKPRESSURE';
  reason: string;
  before: Record<string, number>;
  after: Record<string, number>;
  timestamp: number;
}

export interface EvaluateInput {
  queryLatencyP99: number;
  cacheHitRate: number;
  followerLagMs: number;
  activeConnections: number;
  connectionPoolUtilization: number;
  outboxPending: number;
  memoryUsagePercent: number;
}

export class AutoTuner {
  private config: TuningConfig;
  private actionHistory: TuningAction[] = [];
  private intervalTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config?: Partial<TuningConfig>) {
    this.config = this.mergeConfig(config || {});
  }

  /**
   * Evaluate the current system metrics against thresholds.
   * Returns an array of suggested tuning actions.
   */
  evaluate(input: EvaluateInput): TuningAction[] {
    const actions: TuningAction[] = [];
    const now = Date.now();
    const { metrics } = this.config;

    // 1. High latency → suggest SHRINK_MEMORY or COMPACT_WAL
    if (input.queryLatencyP99 > metrics.maxQueryLatencyMs) {
      // Prefer COMPACT_WAL when there's significant outbox pending
      if (input.outboxPending > 0 && this.config.actions.autoCompactWAL) {
        actions.push({
          type: 'COMPACT_WAL',
          reason: `Query latency P99 ${input.queryLatencyP99}ms exceeds threshold ${metrics.maxQueryLatencyMs}ms with ${input.outboxPending} pending outbox entries`,
          before: { queryLatencyP99: input.queryLatencyP99, outboxPending: input.outboxPending },
          after: { queryLatencyP99: input.queryLatencyP99 * 0.7, outboxPending: 0 },
          timestamp: now,
        });
      } else if (this.config.actions.autoShrinkMemory) {
        actions.push({
          type: 'SHRINK_MEMORY',
          reason: `Query latency P99 ${input.queryLatencyP99}ms exceeds threshold ${metrics.maxQueryLatencyMs}ms`,
          before: { queryLatencyP99: input.queryLatencyP99, memoryUsagePercent: input.memoryUsagePercent },
          after: { queryLatencyP99: input.queryLatencyP99 * 0.7, memoryUsagePercent: input.memoryUsagePercent * 0.8 },
          timestamp: now,
        });
      }
    }

    // 2. Low cache hit rate → suggest ADJUST_CACHE
    if (input.cacheHitRate < metrics.minCacheHitRate) {
      actions.push({
        type: 'ADJUST_CACHE',
        reason: `Cache hit rate ${(input.cacheHitRate * 100).toFixed(1)}% below threshold ${(metrics.minCacheHitRate * 100).toFixed(1)}%`,
        before: { cacheHitRate: input.cacheHitRate },
        after: { cacheHitRate: Math.min(input.cacheHitRate * 1.5, 1.0) },
        timestamp: now,
      });
    }

    // 3. High follower lag → suggest COMPACT_WAL
    if (input.followerLagMs > metrics.maxFollowerLagMs) {
      actions.push({
        type: 'COMPACT_WAL',
        reason: `Follower lag ${input.followerLagMs}ms exceeds threshold ${metrics.maxFollowerLagMs}ms`,
        before: { followerLagMs: input.followerLagMs },
        after: { followerLagMs: input.followerLagMs * 0.3 },
        timestamp: now,
      });
    }

    // 4. High connection count → suggest RESIZE_POOL or SCALE_BACKPRESSURE
    const connThreshold = metrics.maxConnectionCount * 0.8;
    if (input.activeConnections > connThreshold) {
      if (this.config.actions.autoAdjustPool) {
        actions.push({
          type: 'RESIZE_POOL',
          reason: `Active connections ${input.activeConnections} exceeds 80% of max (${metrics.maxConnectionCount})`,
          before: { activeConnections: input.activeConnections, connectionPoolUtilization: input.connectionPoolUtilization },
          after: { activeConnections: input.activeConnections * 0.7, connectionPoolUtilization: input.connectionPoolUtilization * 0.7 },
          timestamp: now,
        });
      } else {
        actions.push({
          type: 'SCALE_BACKPRESSURE',
          reason: `Active connections ${input.activeConnections} exceeds 80% of max (${metrics.maxConnectionCount})`,
          before: { activeConnections: input.activeConnections },
          after: { activeConnections: metrics.maxConnectionCount * 0.5 },
          timestamp: now,
        });
      }
    }

    // 5. High memory usage → suggest SHRINK_MEMORY
    if (input.memoryUsagePercent > 0.85) {
      actions.push({
        type: 'SHRINK_MEMORY',
        reason: `Memory usage ${(input.memoryUsagePercent * 100).toFixed(1)}% exceeds 85% threshold`,
        before: { memoryUsagePercent: input.memoryUsagePercent },
        after: { memoryUsagePercent: input.memoryUsagePercent * 0.7 },
        timestamp: now,
      });
    }

    // Record actions in history
    this.actionHistory.push(...actions);

    return actions;
  }

  /**
   * Start periodic evaluation.
   */
  start(): void {
    if (this.intervalTimer) return;
    if (!this.config.enabled) return;

    this.intervalTimer = setInterval(() => {
      // Periodic evaluation is triggered externally via evaluate()
      // The interval timer is for lifecycle management
    }, this.config.intervalMs);

    this.intervalTimer.unref();
  }

  /**
   * Stop periodic evaluation.
   */
  stop(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
  }

  /**
   * Get the full action history.
   */
  getActionHistory(): TuningAction[] {
    return [...this.actionHistory];
  }

  /**
   * Get the current config (deep clone so mutation doesn't affect internal state).
   */
  getConfig(): TuningConfig {
    return {
      ...this.config,
      metrics: { ...this.config.metrics },
      actions: { ...this.config.actions },
    };
  }

  // ── G25: Adaptive tuning based on bgwriter stats ──────────────

  /**
   * Accept pg_stat_bgwriter statistics and compute adaptive tuning suggestions.
   *
   * @param stats - BgWriter statistics
   */
  evaluateBgWriter(stats: {
    checkpointsTimed: number;
    checkpointsReq: number;
    buffersCheckpoint: number;
    buffersClean: number;
    buffersBackend: number;
    dirtyRate?: number;         // Estimated dirty page ratio (0-1)
    hitRate?: number;           // Cache hit rate (0-1)
    concurrentQueries?: number; // Currently active concurrent queries
  }): TuningAction[] {
    const actions: TuningAction[] = [];
    const now = Date.now();

    // 1. Adjust checkpoint interval based on dirty page ratio
    if (stats.dirtyRate !== undefined) {
      const totalBuffers = stats.buffersCheckpoint + stats.buffersClean + stats.buffersBackend;
      const checkpointRatio = totalBuffers > 0
        ? stats.buffersCheckpoint / totalBuffers
        : 0;

      if (stats.dirtyRate > 0.5 || checkpointRatio > 0.7) {
        // High dirty page ratio — reduce checkpoint interval
        actions.push({
          type: 'COMPACT_WAL',
          reason: `High dirty page ratio ${(stats.dirtyRate * 100).toFixed(1)}% with checkpoint ratio ${(checkpointRatio * 100).toFixed(1)}% — reducing checkpoint interval`,
          before: { dirtyRate: stats.dirtyRate, checkpointRatio },
          after: { dirtyRate: stats.dirtyRate * 0.6, checkpointRatio: checkpointRatio * 0.7 },
          timestamp: now,
        });
      }
    }

    // 2. Adjust shared buffer recommendations based on cache hit rate
    if (stats.hitRate !== undefined) {
      if (stats.hitRate < 0.8) {
        // Low hit rate — recommend increasing shared buffers
        actions.push({
          type: 'ADJUST_CACHE',
          reason: `Cache hit rate ${(stats.hitRate * 100).toFixed(1)}% below 80% — increasing shared buffer recommendation`,
          before: { cacheHitRate: stats.hitRate },
          after: { cacheHitRate: Math.min(stats.hitRate * 1.3, 1.0) },
          timestamp: now,
        });
      } else if (stats.hitRate > 0.98 && stats.dirtyRate !== undefined && stats.dirtyRate < 0.2) {
        // High hit rate with low dirty rate — consider reducing buffers (over-provisioned)
        // (Less critical, log but no action needed)
      }
    }

    // 3. Adjust connection pool size based on concurrent queries
    if (stats.concurrentQueries !== undefined) {
      const optimalPool = Math.max(10, Math.ceil(stats.concurrentQueries * 1.3));

      actions.push({
        type: 'RESIZE_POOL',
        reason: `Adjusting connection pool: ${stats.concurrentQueries} concurrent queries → recommended pool size ${optimalPool}`,
        before: { concurrentQueries: stats.concurrentQueries, currentPool: stats.concurrentQueries },
        after: { concurrentQueries: stats.concurrentQueries, recommendedPool: optimalPool },
        timestamp: now,
      });
    }

    // Record actions
    this.actionHistory.push(...actions);

    return actions;
  }

  /**
   * Merge a partial config with defaults.
   */
  private mergeConfig(partial: Partial<TuningConfig>): TuningConfig {
    const metrics = { ...DEFAULT_TUNING_METRICS, ...(partial.metrics || {}) };
    const actions = { ...DEFAULT_TUNING_ACTIONS, ...(partial.actions || {}) };

    return {
      ...DEFAULT_TUNING_CONFIG,
      ...partial,
      metrics,
      actions,
    };
  }
}
