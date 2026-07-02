import { PinoLogger } from '../monitoring/PinoLogger';

/**
 * RH10: Auto-scaling
 *
 * ## Background
 * PostgreSQL-based systems can auto-scale horizontally by adding or removing
 * read replicas in response to load. Connection pooling (PgBouncer, Odyssey)
 * and cloud managed databases (RDS, Cloud SQL, AlloyDB) provide built-in
 * auto-scaling of connections and compute resources.
 *
 * ## SQLite context
 * SQLite is not a client-server database — it runs in-process. "Auto-scaling"
 * in this context means:
 * 1. **Connection pool scaling**: Increase/decrease the number of prepared
 *    connections in the pool based on concurrent query demand.
 * 2. **Read replica scaling**: For sharded SQLite deployments, dynamically
 *    add replica shard files for read-heavy shards.
 * 3. **Memory scaling**: Adjust SQLite cache size (-mmap-size, -page-cache)
 *    based on observed working set size.
 *
 * ## Implementation plan (future)
 * - Monitor connection pool utilization and query concurrency.
 * - Monitor per-connection memory usage via `PRAGMA page_count * page_size`.
 * - Trigger scale-up when any metric exceeds the configured threshold.
 * - Trigger scale-down after a cooldown period below the low watermark.
 *
 * @stub Ops layer feature — monitoring infrastructure required first.
 */
export interface AutoScalerConfig {
  /** Minimum number of read replicas / pool connections */
  minReplicas: number;
  /** Maximum number of read replicas / pool connections */
  maxReplicas: number;
  /** CPU utilization threshold (%) for scale-up trigger */
  cpuThreshold: number;
  /** Memory utilization threshold (%) for scale-up trigger */
  memoryThreshold: number;
}

interface ScaleResult {
  action: 'none' | 'up' | 'down';
  reason: string;
  targetSize: number;
}

interface AutoScalerStatus {
  currentConnections: number;
  targetConnections: number;
  min: number;
  max: number;
}

export class AutoScaler {
  private readonly logger = PinoLogger.forComponent('AutoScaler');
  private config: AutoScalerConfig;
  private currentConnections: number;
  private targetConnections: number;
  private lastScaleUpTime: number = 0;
  private readonly cooldownMs: number = 30000;

  constructor(config: AutoScalerConfig) {
    this.config = { ...config };
    this.currentConnections = config.minReplicas;
    this.targetConnections = config.minReplicas;
  }

  scaleUp(count?: number): number {
    return this.scaleUpInternal(count ?? 1);
  }

  scaleDown(count?: number): number {
    return this.scaleDownInternal(count ?? 1);
  }

  getHealth(): { replicas: number; avgCpu: number; avgMemory: number } {
    return { replicas: this.currentConnections, avgCpu: 0, avgMemory: 0 };
  }

  /**
   * Evaluate whether scaling is needed based on current load and pool utilization.
   */
  evaluateScale(currentLoad: number, poolUtilization: number): ScaleResult {
    const now = Date.now();
    const inCooldown = (now - this.lastScaleUpTime) < this.cooldownMs;

    if (inCooldown) {
      return { action: 'none', reason: 'in cooldown period after scale-up', targetSize: this.targetConnections };
    }

    // Scale up if load or utilization exceeds thresholds
    if (currentLoad > this.config.cpuThreshold || poolUtilization > this.config.memoryThreshold) {
      if (this.targetConnections >= this.config.maxReplicas) {
        return { action: 'none', reason: 'already at max replicas', targetSize: this.targetConnections };
      }
      const newTarget = Math.min(this.targetConnections + 1, this.config.maxReplicas);
      return { action: 'up', reason: `load=${currentLoad}% exceeds threshold=${this.config.cpuThreshold}%`, targetSize: newTarget };
    }

    // Scale down only if target < 70% of current (anti-flapping)
    if (this.targetConnections > this.config.minReplicas) {
      const thresholdForScaleDown = Math.floor(this.currentConnections * 0.7);
      if (this.targetConnections < thresholdForScaleDown) {
        const newTarget = Math.max(this.targetConnections - 1, this.config.minReplicas);
        return { action: 'down', reason: `load decreased, target=${this.targetConnections} < 70% of current=${this.currentConnections}`, targetSize: newTarget };
      }
    }

    return { action: 'none', reason: 'within acceptable range', targetSize: this.targetConnections };
  }

  /**
   * Get current status of the auto-scaler.
   */
  getStatus(): AutoScalerStatus {
    return {
      currentConnections: this.currentConnections,
      targetConnections: this.targetConnections,
      min: this.config.minReplicas,
      max: this.config.maxReplicas,
    };
  }

  private scaleUpInternal(count: number): number {
    const newTarget = Math.min(this.targetConnections + count, this.config.maxReplicas);
    this.targetConnections = newTarget;
    this.currentConnections = newTarget;
    this.lastScaleUpTime = Date.now();
    this.logger.info({ from: this.currentConnections - count, to: newTarget }, 'scaleUp: connections increased');
    return newTarget;
  }

  private scaleDownInternal(count: number): number {
    const newTarget = Math.max(this.targetConnections - count, this.config.minReplicas);
    this.targetConnections = newTarget;
    this.currentConnections = newTarget;
    this.logger.info({ from: this.currentConnections + count, to: newTarget }, 'scaleDown: connections decreased');
    return newTarget;
  }
}
