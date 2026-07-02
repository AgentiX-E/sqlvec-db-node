/**
 * PoolMonitor — Connection pool health tracking with Prometheus metrics and auto-scaling.
 *
 * Features:
 *   - Tracks active, idle, waiting, total connections per pool
 *   - Exposes metrics via Prometheus gauge format (compatible with prom-client)
 *   - Auto-scaling: if waiting connections exceed threshold, triggers pool growth callback
 *
 * Usage:
 *   const monitor = new PoolMonitor({ poolName: 'main', maxPoolSize: 50, scaleThreshold: 5 });
 *   monitor.update({ active: 10, idle: 5, waiting: 3, total: 18 });
 *   const metrics = monitor.getMetrics();  // Prometheus text format
 *   monitor.setScaleCallback(async (currentSize, suggestedSize) => { ... });
 *   monitor.stop();
 */

// ── Types ────────────────────────────────────────────────────────

import { PinoLogger } from './PinoLogger';
const logger = PinoLogger.forComponent('PoolMonitor');
export interface PoolState {
  /** Currently active (in-use) connections */
  active: number;
  /** Idle (available) connections */
  idle: number;
  /** Queued / waiting for a connection */
  waiting: number;
  /** Total connections in the pool */
  total: number;
  /** Optional pool name / identifier */
  poolName?: string;
}

export interface PoolMonitorConfig {
  /** Human-readable pool name used in metric labels */
  poolName: string;
  /** Maximum configured pool size (for scaling decisions) */
  maxPoolSize: number;
  /** Minimum pool size */
  minPoolSize?: number;
  /** If waiting connections exceed this, trigger auto-scale (default: 3) */
  scaleThreshold?: number;
  /** Scale increment (default: 5) */
  scaleIncrement?: number;
  /** Cooldown in ms between auto-scale actions (default: 30000) */
  scaleCooldownMs?: number;
}

export type ScaleCallback = (currentMax: number, suggestedMax: number, poolState: PoolState) => void | Promise<void>;

// ── PoolMonitor ──────────────────────────────────────────────────

export class PoolMonitor {
  private config: Required<PoolMonitorConfig>;
  private state: PoolState = { active: 0, idle: 0, waiting: 0, total: 0 };
  private scaleCallback: ScaleCallback | null = null;
  private lastScaleTime: number = 0;
  private maxPoolSize: number;
  private metricsText: string = '';

  constructor(config: PoolMonitorConfig) {
    this.config = {
      poolName: config.poolName,
      maxPoolSize: config.maxPoolSize,
      minPoolSize: config.minPoolSize ?? 1,
      scaleThreshold: config.scaleThreshold ?? 3,
      scaleIncrement: config.scaleIncrement ?? 5,
      scaleCooldownMs: config.scaleCooldownMs ?? 30_000,
    };
    this.maxPoolSize = config.maxPoolSize;
  }

  /**
   * Update the current pool state and re-evaluate auto-scaling.
   */
  update(newState: Partial<PoolState>): void {
    this.state = {
      ...this.state,
      ...newState,
    };

    // Generate metric text
    this.generateMetrics();

    // Check auto-scale
    this.evaluateScale();
  }

  /**
   * Get the current pool state snapshot.
   */
  getState(): Readonly<PoolState> {
    return { ...this.state };
  }

  /**
   * Get Prometheus-format metrics text.
   */
  getMetrics(): string {
    return this.metricsText;
  }

  /**
   * Register a callback invoked when auto-scale decides to grow the pool.
   */
  setScaleCallback(cb: ScaleCallback): void {
    this.scaleCallback = cb;
  }

  /**
   * Update the max pool size (e.g. after successful scale-up).
   */
  setMaxPoolSize(size: number): void {
    this.maxPoolSize = size;
  }

  /**
   * Get current max pool size.
   */
  getMaxPoolSize(): number {
    return this.maxPoolSize;
  }

  /**
   * Reset all metrics to zero.
   */
  reset(): void {
    this.state = { active: 0, idle: 0, waiting: 0, total: 0 };
    this.lastScaleTime = 0;
    this.generateMetrics();
  }

  /**
   * Clean up resources (no-op for now, interface compatibility).
   */
  stop(): void {
    // No timers to clear (monitor is update-driven)
  }

  // ── Private ────────────────────────────────────────────────────

  private generateMetrics(): void {
    const pool = this.config.poolName;
    this.metricsText = [
      `# HELP sqlvec_pool_active Current active connections in the pool`,
      `# TYPE sqlvec_pool_active gauge`,
      `sqlvec_pool_active{pool="${pool}"} ${this.state.active}`,
      '',
      `# HELP sqlvec_pool_idle Current idle connections in the pool`,
      `# TYPE sqlvec_pool_idle gauge`,
      `sqlvec_pool_idle{pool="${pool}"} ${this.state.idle}`,
      '',
      `# HELP sqlvec_pool_waiting Current waiting (queued) connections in the pool`,
      `# TYPE sqlvec_pool_waiting gauge`,
      `sqlvec_pool_waiting{pool="${pool}"} ${this.state.waiting}`,
      '',
      `# HELP sqlvec_pool_total Current total connections in the pool`,
      `# TYPE sqlvec_pool_total gauge`,
      `sqlvec_pool_total{pool="${pool}"} ${this.state.total}`,
      '',
      `# HELP sqlvec_pool_max Maximum pool size`,
      `# TYPE sqlvec_pool_max gauge`,
      `sqlvec_pool_max{pool="${pool}"} ${this.maxPoolSize}`,
      '',
      `# HELP sqlvec_pool_utilization_ratio Pool utilization (active / max)`,
      `# TYPE sqlvec_pool_utilization_ratio gauge`,
      `sqlvec_pool_utilization_ratio{pool="${pool}"} ${this.maxPoolSize > 0 ? (this.state.active / this.maxPoolSize).toFixed(4) : 0}`,
      '',
    ].join('\n');
  }

  private async evaluateScale(): Promise<void> {
    if (!this.scaleCallback) return;
    if (this.state.waiting <= this.config.scaleThreshold) return;

    // Cooldown check
    const now = Date.now();
    if (now - this.lastScaleTime < this.config.scaleCooldownMs) return;

    this.lastScaleTime = now;
    const suggestedSize = this.maxPoolSize + this.config.scaleIncrement;

    try {
      await this.scaleCallback(this.maxPoolSize, suggestedSize, this.getState());
    } catch (err) {
      logger.error(`[PoolMonitor] Scale callback failed for pool "${this.config.poolName}":`, (err as Error).message);
    }
  }
}
