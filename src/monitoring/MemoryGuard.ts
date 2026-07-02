/**
 * MemoryGuard — OOM protection with periodic RSS/heap monitoring.
 *
 * PROD002: OOM Protection
 *
 * Monitors process memory usage and provides:
 *   - configurable maxMemoryMB (default: 2048)
 *   - warningThreshold (default: 80%)
 *   - Periodic checks via interval timer
 *   - Callbacks for warning / critical states
 *
 * Integration in SqlVecDatabase.start() creates a 30-second interval
 * that logs warnings and can trigger graceful shutdown.
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('MemoryGuard');

const DEFAULT_MAX_MEMORY_MB = 2048;
const DEFAULT_WARNING_THRESHOLD = 0.8; // 80%

export interface MemoryCheckResult {
  /** Whether memory usage is within safe limits */
  ok: boolean;
  /** Current RSS usage in MB */
  usageMB: number;
  /** Current heap usage in MB */
  heapMB: number;
  /** Warning message when above threshold, or undefined */
  warning?: string;
}

export type MemoryWarningCallback = (result: MemoryCheckResult) => void;
export type MemoryCriticalCallback = (result: MemoryCheckResult) => void;

export class MemoryGuard {
  private maxMemoryMB: number;
  private warningThreshold: number;
  private criticalThreshold: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private _lastCheck: MemoryCheckResult | null = null;

  /** Called when memory exceeds warningThreshold */
  public onWarning: MemoryWarningCallback | null = null;
  /** Called when memory exceeds maxMemoryMB */
  public onCritical: MemoryCriticalCallback | null = null;

  // ── E8-PROD2: OOM Actions ───────────────────────
  /** Called when OOM risk triggers: reject slow connections */
  public onRejectSlowConnections: (() => void) | null = null;
  /** Called when OOM risk triggers: clear caches */
  public onClearCache: (() => void) | null = null;
  /** Called when OOM risk triggers: run VACUUM */
  public onVacuum: (() => void) | null = null;

  constructor(options?: {
    maxMemoryMB?: number;
    warningThreshold?: number;
    criticalThreshold?: number;
  }) {
    this.maxMemoryMB = options?.maxMemoryMB ?? DEFAULT_MAX_MEMORY_MB;
    this.warningThreshold = options?.warningThreshold ?? DEFAULT_WARNING_THRESHOLD;
    this.criticalThreshold = options?.criticalThreshold ?? 0.95; // 95%
  }

  /**
   * Perform a single memory check and return the result.
   */
  check(): MemoryCheckResult {
    const usage = process.memoryUsage();
    const heapMB = Math.round((usage.heapUsed / 1024 / 1024) * 100) / 100;
    const rssMB = Math.round((usage.rss / 1024 / 1024) * 100) / 100;

    if (rssMB > this.maxMemoryMB) {
      const warning = `OOM risk: ${rssMB}MB > ${this.maxMemoryMB}MB`;
      return { ok: false, usageMB: rssMB, heapMB, warning };
    }

    if (rssMB > this.maxMemoryMB * this.warningThreshold) {
      const warning = `Memory high: ${rssMB}MB / ${this.maxMemoryMB}MB`;
      return { ok: true, usageMB: rssMB, heapMB, warning };
    }

    return { ok: true, usageMB: rssMB, heapMB };
  }

  /**
   * Get the OOM risk level.
   * Returns 'none', 'warning' (above warningThreshold), or 'critical' (above criticalThreshold or maxMemoryMB).
   */
  getOomRiskLevel(): 'none' | 'warning' | 'critical' {
    const usage = process.memoryUsage();
    const rssMB = Math.round((usage.rss / 1024 / 1024) * 100) / 100;

    if (rssMB > this.maxMemoryMB) return 'critical';
    if (rssMB > this.maxMemoryMB * this.criticalThreshold) return 'critical';
    if (rssMB > this.maxMemoryMB * this.warningThreshold) return 'warning';
    return 'none';
  }

  /**
   * Start periodic monitoring at the given interval.
   * Default: 30 seconds.
   */
  start(intervalMs: number = 30_000): void {
    if (this.timer) return;

    // Run an immediate check
    this.runCheck();

    this.timer = setInterval(() => this.runCheck(), intervalMs);
    this.timer.unref(); // Don't prevent process exit

    logger.info(
      { intervalMs, maxMemoryMB: this.maxMemoryMB, warningThreshold: this.warningThreshold },
      'MemoryGuard started',
    );
  }

  /**
   * Stop periodic monitoring.
   */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    logger.info('MemoryGuard stopped');
  }

  /**
   * Get the last check result (null if never checked).
   */
  get lastCheck(): MemoryCheckResult | null {
    return this._lastCheck;
  }

  /**
   * Get the peak RSS seen since monitoring started (MB).
   */
  get peakRSS(): number {
    return this._peakRSS;
  }

  private _peakRSS = 0;

  /**
   * E8-PROD2: Trigger OOM mitigation actions.
   * Called when high memory usage is detected.
   *  1. Reject slow connections — prevent new memory-hungry operations
   *  2. Clear caches — free cached query results and buffer pool memory
   *  3. Active VACUUM — reclaim free pages from SQLite databases
   */
  triggerOomMitigation(): void {
    const risk = this.getOomRiskLevel();
    if (risk === 'none') return;

    logger.warn(
      { risk, usageMB: this._lastCheck?.usageMB },
      `[MemoryGuard] Triggering OOM mitigation (risk=${risk})`,
    );

    // 1. Reject slow connections (warning level and above)
    if (this.onRejectSlowConnections) {
      try {
        this.onRejectSlowConnections();
        logger.info('[MemoryGuard] OOM action: slow connections rejected');
      } catch (err: any) {
        logger.error(`[MemoryGuard] OOM action failed (rejectSlowConnections): ${err.message}`);
      }
    }

    // 2. Clear caches (warning level and above)
    if (this.onClearCache) {
      try {
        this.onClearCache();
        logger.info('[MemoryGuard] OOM action: caches cleared');
      } catch (err: any) {
        logger.error(`[MemoryGuard] OOM action failed (clearCache): ${err.message}`);
      }
    }

    // 3. Active VACUUM (only at critical level — VACUUM is expensive)
    if (risk === 'critical' && this.onVacuum) {
      try {
        this.onVacuum();
        logger.info('[MemoryGuard] OOM action: VACUUM triggered');
      } catch (err: any) {
        logger.error(`[MemoryGuard] OOM action failed (vacuum): ${err.message}`);
      }
    }
  }

  private runCheck(): void {
    const result = this.check();
    this._lastCheck = result;

    if (result.usageMB > this._peakRSS) {
      this._peakRSS = result.usageMB;
    }

    if (!result.ok) {
      logger.fatal(result, 'MemoryGuard: CRITICAL — OOM risk detected');
      this.triggerOomMitigation();
      this.onCritical?.(result);
    } else if (result.warning) {
      logger.warn(result, 'MemoryGuard: warning');
      this.triggerOomMitigation();
      this.onWarning?.(result);
    }
  }
}
