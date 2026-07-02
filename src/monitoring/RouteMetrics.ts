/**
 * RouteMetrics — Observability for OLTP/OLAP query routing decisions.
 *
 * Captures and exposes routing metrics for the UnifiedRouter, including:
 * - Query counts per engine (SQLite, DuckDB, DuckDB_federated)
 * - Latency percentiles (p50, p95, p99)
 * - Circuit breaker state tracking
 * - Fallback count
 *
 * ## Integration
 * ```
 * UnifiedRouter.execute()
 *   ├─ ... execute query ...
 *   └─ emitRouteMetrics(decision, startTime, result)
 *       └─ RouteMetrics.record(...)
 * ```
 */

import { PinoLogger } from './PinoLogger';

const logger = PinoLogger.forComponent('RouteMetrics');

export interface RouteMetricsSnapshot {
  /** Total queries processed */
  totalQueries: number;
  /** Queries routed to DuckDB */
  duckDBQueries: number;
  /** Queries routed to SQLite */
  sqliteQueries: number;
  /** Queries that fell back (DuckDB → SQLite) */
  fallbacks: number;
  /** Average latency in milliseconds */
  avgLatencyMs: number;
  /** Median latency in milliseconds */
  p50Ms: number;
  /** 95th percentile latency in milliseconds */
  p95Ms: number;
  /** 99th percentile latency in milliseconds */
  p99Ms: number;
  /** Federated queries */
  federatedQueries: number;
  /** Circuit breaker state */
  circuitBreakerState: 'closed' | 'open' | 'half-open';
}

interface LatencyBucket {
  count: number;
  latencies: number[];
}

/**
 * RouteMetrics — Records and exposes routing metrics.
 *
 * Metrics are collected in-memory and can be:
 * 1. Retrieved as a snapshot via snapshot()
 * 2. Logged to stdout/callback via setLogCallback()
 * 3. Reset via reset()
 */
export class RouteMetrics {
  private totalQueries = 0;
  private duckDBQueries = 0;
  private sqliteQueries = 0;
  private fallbacks = 0;
  private federatedQueries = 0;
  private circuitState: 'closed' | 'open' | 'half-open' = 'closed';

  /** All recorded latencies for percentile calculation */
  private latencies: number[] = [];
  /** Maximum latency samples to keep */
  private readonly maxSamples = 100_000;

  /** Periodic log callback (e.g. setInterval) */
  private logCallback?: (snapshot: RouteMetricsSnapshot) => void;
  private logInterval?: ReturnType<typeof setInterval>;

  /**
   * Record a routing event.
   *
   * @param engine   Which engine handled the query
   * @param latencyMs Query execution time in ms
   * @param wasFallback Whether this was a fallback (DuckDB → SQLite)
   */
  record(
    engine: 'sqlite_oltp' | 'duckdb_olap' | 'duckdb_federated',
    latencyMs: number,
    wasFallback: boolean = false,
  ): void {
    this.totalQueries++;

    if (engine === 'duckdb_olap') {
      this.duckDBQueries++;
    } else if (engine === 'duckdb_federated') {
      this.duckDBQueries++;
      this.federatedQueries++;
    } else {
      this.sqliteQueries++;
    }

    if (wasFallback) {
      this.fallbacks++;
    }

    // Store latency for percentile calc (throttle if needed)
    if (this.latencies.length < this.maxSamples) {
      this.latencies.push(latencyMs);
    }
  }

  /**
   * Record circuit breaker state change.
   */
  recordCircuitChange(state: 'closed' | 'open' | 'half-open'): void {
    this.circuitState = state;
    logger.info({ state }, 'Circuit breaker state changed');
  }

  /**
   * Get current metrics snapshot.
   */
  snapshot(): RouteMetricsSnapshot {
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const len = sorted.length;
    const total = this.totalQueries || 1; // avoid div by 0
    const avg = len > 0 ? sorted.reduce((a, b) => a + b, 0) / len : 0;

    return {
      totalQueries: this.totalQueries,
      duckDBQueries: this.duckDBQueries,
      sqliteQueries: this.sqliteQueries,
      fallbacks: this.fallbacks,
      avgLatencyMs: Math.round(avg * 100) / 100,
      p50Ms: len > 0 ? sorted[Math.floor(len * 0.5)] : 0,
      p95Ms: len > 0 ? sorted[Math.floor(len * 0.95)] : 0,
      p99Ms: len > 0 ? sorted[Math.floor(len * 0.99)] : 0,
      federatedQueries: this.federatedQueries,
      circuitBreakerState: this.circuitState,
    };
  }

  /**
   * Start periodic logging at a given interval.
   */
  startPeriodicLogging(intervalMs: number = 30_000): void {
    this.stopPeriodicLogging();
    this.logInterval = setInterval(() => {
      const snap = this.snapshot();
      if (this.logCallback) {
        this.logCallback(snap);
      } else {
        logger.info({
          total: snap.totalQueries,
          duckdb: snap.duckDBQueries,
          sqlite: snap.sqliteQueries,
          avg: snap.avgLatencyMs,
          p50: snap.p50Ms,
          p99: snap.p99Ms,
          circuit: snap.circuitBreakerState,
        }, 'RouteMetrics periodic snapshot');
      }
    }, intervalMs);

    // Allow timer to exit Node process
    if (this.logInterval?.unref) {
      this.logInterval.unref();
    }
  }

  /**
   * Stop periodic logging.
   */
  stopPeriodicLogging(): void {
    if (this.logInterval) {
      clearInterval(this.logInterval);
      this.logInterval = undefined;
    }
  }

  /**
   * Set a custom log callback (overrides default logger.info).
   */
  setLogCallback(cb: (snapshot: RouteMetricsSnapshot) => void): void {
    this.logCallback = cb;
  }

  /**
   * Reset all metrics.
   */
  reset(): void {
    this.totalQueries = 0;
    this.duckDBQueries = 0;
    this.sqliteQueries = 0;
    this.fallbacks = 0;
    this.federatedQueries = 0;
    this.latencies = [];
  }

  /**
   * Format snapshot as a single log line string.
   */
  toLogLine(): string {
    const s = this.snapshot();
    return [
      `q=${s.totalQueries}`,
      `duckdb=${s.duckDBQueries}`,
      `sqlite=${s.sqliteQueries}`,
      `fallback=${s.fallbacks}`,
      `avg=${s.avgLatencyMs}ms`,
      `p50=${s.p50Ms}ms`,
      `p95=${s.p95Ms}ms`,
      `p99=${s.p99Ms}ms`,
      `fed=${s.federatedQueries}`,
      `cb=${s.circuitBreakerState}`,
    ].join(' ');
  }

  /**
   * Format snapshot as Prometheus-compatible text format.
   *
   * Output format (Prometheus exposition format):
   * ```
   * # HELP sqlvec_route_queries_total Total queries processed
   * # TYPE sqlvec_route_queries_total counter
   * sqlvec_route_queries_total{engine="duckdb"} 42
   * sqlvec_route_queries_total{engine="sqlite"} 18
   * sqlvec_route_queries_total{engine="federated"} 5
   * sqlvec_route_queries_total{engine="fallback"} 2
   * # HELP sqlvec_route_latency_ms Query latency in milliseconds
   * # TYPE sqlvec_route_latency_ms gauge
   * sqlvec_route_latency_ms{quantile="avg"} 15.3
   * sqlvec_route_latency_ms{quantile="p50"} 12
   * sqlvec_route_latency_ms{quantile="p95"} 45
   * sqlvec_route_latency_ms{quantile="p99"} 120
   * # HELP sqlvec_route_circuit_breaker Circuit breaker state (1=open, 0=closed)
   * # TYPE sqlvec_route_circuit_breaker gauge
   * sqlvec_route_circuit_breaker 0
   * ```
   */
  toPrometheus(): string {
    const s = this.snapshot();
    const lines: string[] = [];

    // Headers
    lines.push('# HELP sqlvec_route_queries_total Total queries processed');
    lines.push('# TYPE sqlvec_route_queries_total counter');
    lines.push(`sqlvec_route_queries_total{engine="duckdb"} ${s.duckDBQueries}`);
    lines.push(`sqlvec_route_queries_total{engine="sqlite"} ${s.sqliteQueries}`);
    lines.push(`sqlvec_route_queries_total{engine="federated"} ${s.federatedQueries}`);
    lines.push(`sqlvec_route_queries_total{engine="fallback"} ${s.fallbacks}`);
    lines.push(`sqlvec_route_queries_total{engine="total"} ${s.totalQueries}`);

    lines.push('');
    lines.push('# HELP sqlvec_route_latency_ms Query latency in milliseconds');
    lines.push('# TYPE sqlvec_route_latency_ms gauge');
    lines.push(`sqlvec_route_latency_ms{quantile="avg"} ${s.avgLatencyMs}`);
    lines.push(`sqlvec_route_latency_ms{quantile="p50"} ${s.p50Ms}`);
    lines.push(`sqlvec_route_latency_ms{quantile="p95"} ${s.p95Ms}`);
    lines.push(`sqlvec_route_latency_ms{quantile="p99"} ${s.p99Ms}`);

    lines.push('');
    lines.push('# HELP sqlvec_route_circuit_breaker Circuit breaker state (1=open, 0=closed)');
    lines.push('# TYPE sqlvec_route_circuit_breaker gauge');
    lines.push(`sqlvec_route_circuit_breaker ${s.circuitBreakerState === 'open' ? '1' : '0'}`);
    lines.push('');

    return lines.join('\n');
  }

  /**
   * Log route metrics from within UnifiedRouter.execute().
   * Returns true if metrics were recorded.
   */
  emitRouteEvent(
    engine: 'sqlite_oltp' | 'duckdb_olap' | 'duckdb_federated',
    latencyMs: number,
    wasFallback: boolean = false,
  ): void {
    this.record(engine, latencyMs, wasFallback);

    // Log at info level periodically; this is lightweight
    logger.debug({
      engine,
      latencyMs: Math.round(latencyMs),
      total: this.totalQueries,
    }, 'Route event');
  }
}
