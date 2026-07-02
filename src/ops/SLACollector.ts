import { PinoLogger } from '../monitoring/PinoLogger';

/**
 * RH20: SLA metrics collection
 *
 * ## Background
 * Enterprise PostgreSQL deployments collect SLA metrics to measure and
 * report on database performance commitments. Standard metrics include:
 * - Uptime / availability percentage
 * - Query latency percentiles (p50, p95, p99)
 * - Error rate (failed queries / total queries)
 * - Throughput (queries per second)
 * - Connection count and pool utilization
 *
 * ## SQLite context
 * For sqlvec-db, SLA metrics should be collected from:
 * 1. **Connection pool**: Track how many connections are active vs idle,
 *    how often the pool is exhausted.
 * 2. **Query execution**: Wrap each query with timing instrumentation,
 *    record latency to a rolling-window histogram.
 * 3. **Errors**: Count SQLITE_BUSY, SQLITE_IOERR, constraint violations,
 *    and other errors.
 * 4. **Uptime**: Monitor the process uptime and database connectivity
 *    via periodic health-check queries (SELECT 1).
 *
 * ## Implementation plan (future)
 * - Use a high-resolution timer (process.hrtime.bigint) for latency.
 * - Maintain a HdrHistogram (or similar) for latency percentiles.
 * - Expose metrics via a Prometheus endpoint or a periodic log emitter.
 * - Calculate uptime as a rolling 30-day window.
 *
 * @stub Ops layer feature — metric collection infrastructure required.
 */

/** Aggregated SLA metrics snapshot */
export interface SLAMetrics {
  /** Uptime percentage over the reporting period (0–100) */
  uptime: number;
  /** Average query latency in milliseconds */
  avgLatencyMs: number;
  /** 95th percentile query latency in milliseconds */
  p95LatencyMs: number;
  /** 99th percentile query latency in milliseconds */
  p99LatencyMs: number;
  /** Fraction of queries that resulted in an error (0.0–1.0) */
  errorRate: number;
  /** Queries per second */
  qps: number;
}

export interface SLAConfig {
  /** SLO latency threshold in ms (default: 1000) */
  latencySloMs: number;
  /** SLO uptime percentage (default: 99.9) */
  uptimeSlo: number;
  /** Window size in seconds for SLA calculation (default: 300 = 5 min) */
  windowSizeSec: number;
}

interface ServiceLevelObjective {
  latencySloMs: number;
  uptimeSlo: number;
  windowSizeSec: number;
}

interface QueryRecord {
  durationMs: number;
  success: boolean;
  timestamp: number;
}

export class SLACollector {
  private readonly logger = PinoLogger.forComponent('SLACollector');
  private config: SLAConfig;
  private records: QueryRecord[] = [];
  private slo: ServiceLevelObjective;
  private windowStart: number;

  constructor(config?: Partial<SLAConfig>) {
    this.config = {
      latencySloMs: config?.latencySloMs ?? 1000,
      uptimeSlo: config?.uptimeSlo ?? 99.9,
      windowSizeSec: config?.windowSizeSec ?? 300,
    };
    this.slo = {
      latencySloMs: this.config.latencySloMs,
      uptimeSlo: this.config.uptimeSlo,
      windowSizeSec: this.config.windowSizeSec,
    };
    this.windowStart = Date.now();
  }

  /**
   * Collect and return a snapshot of current SLA metrics.
   * In production this would aggregate real-time counters and histograms.
   */
  collect(): SLAMetrics {
    /* STUB — see RH20 */
    return {
      uptime: 100,
      avgLatencyMs: 0,
      p95LatencyMs: 0,
      p99LatencyMs: 0,
      errorRate: 0,
      qps: 0,
    };
  }

  /**
   * Record a query execution for SLA tracking.
   */
  recordQuery(durationMs: number, success: boolean): void {
    this.records.push({
      durationMs,
      success,
      timestamp: Date.now(),
    });
    this.pruneOldRecords();
  }

  /**
   * Get SLA compliance data for the current window.
   */
  getSLACompliance(window?: { windowSizeSec: number }): {
    uptime: number;
    latencyP50: number;
    latencyP99: number;
    errorBudget: number;
    remaining: number;
  } {
    this.pruneOldRecords();

    const totalQueries = this.records.length;
    if (totalQueries === 0) {
      return { uptime: 100, latencyP50: 0, latencyP99: 0, errorBudget: 100, remaining: 100 };
    }

    const successfulQueries = this.records.filter(r => r.success).length;
    const uptime = (successfulQueries / totalQueries) * 100;

    const sortedLatencies = this.records
      .filter(r => r.success)
      .map(r => r.durationMs)
      .sort((a, b) => a - b);

    const latencyP50 = this.percentile(sortedLatencies, 50);
    const latencyP99 = this.percentile(sortedLatencies, 99);

    // Slow queries (>1s) count as SLO violations
    const slowQueries = this.records.filter(r => r.durationMs > this.slo.latencySloMs).length;
    const sloViolationRate = slowQueries / totalQueries;

    // Error budget = allowed violations (1 - uptimeSlo/100)
    const errorBudget = 100 - this.slo.uptimeSlo;
    const remaining = Math.max(0, errorBudget - (sloViolationRate * 100));

    return {
      uptime: Math.round(uptime * 100) / 100,
      latencyP50,
      latencyP99,
      errorBudget: Math.round(errorBudget * 100) / 100,
      remaining: Math.round(remaining * 100) / 100,
    };
  }

  /**
   * Reset the measurement window.
   */
  resetWindow(): void {
    this.records = [];
    this.windowStart = Date.now();
    this.logger.info('resetWindow: SLA window reset');
  }

  private pruneOldRecords(): void {
    const cutoff = Date.now() - (this.slo.windowSizeSec * 1000);
    const before = this.records.length;
    this.records = this.records.filter(r => r.timestamp >= cutoff);
    if (before !== this.records.length) {
      this.logger.debug({ pruned: before - this.records.length }, 'pruned old SLA records');
    }
  }

  private percentile(sorted: number[], p: number): number {
    if (sorted.length === 0) return 0;
    const index = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  }
}
