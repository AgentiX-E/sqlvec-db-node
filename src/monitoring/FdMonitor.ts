/**
 * FdMonitor — File descriptor monitoring for production.
 *
 * PROD006: File descriptor management
 *
 * Monitors the number of open file descriptors by reading /proc/self/fd
 * (Linux only). Falls back to -1 on non-Linux systems.
 *
 * Integrates with the database startup to periodically log fd usage
 * and warn when approaching the system limit.
 */

import * as fs from 'node:fs';
import { execSync } from 'node:child_process';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('FdMonitor');

/** Default soft limit assumed when ulimit cannot be determined. */
const DEFAULT_FD_LIMIT = 10000;
/** Warn when usage exceeds this fraction of the limit. */
const WARNING_THRESHOLD = 0.8;

export interface FdCheckResult {
  /** Whether fd count is within safe limits */
  ok: boolean;
  /** Current number of open file descriptors */
  count: number;
  /** System file descriptor limit (soft) */
  limit: number;
  /** Warning message when count > threshold */
  warning?: string;
}

export class FdMonitor {
  private fdLimit: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private _lastCheck: FdCheckResult | null = null;
  private _peakCount = 0;

  // ── E8-PROD6: Cleanup callbacks ──────────────
  /** Callback to close idle socket connections when FD usage >80%. */
  public onCleanupIdleSockets: (() => void) | null = null;
  /** Callback to clean up stale WAL files. */
  public onCleanupWalFiles: (() => void) | null = null;
  /** Callback to clean up temp files. */
  public onCleanupTempFiles: (() => void) | null = null;
  /** Callback when FD usage reaches critical level (>80%). */
  public onCriticalFdUsage: ((usage: FdCheckResult) => void) | null = null;

  constructor() {
    this.fdLimit = this.detectFdLimit();
  }

  /**
   * Get the current open file descriptor count.
   * Returns -1 if the platform does not support reading /proc/self/fd.
   */
  getOpenFdCount(): number {
    try {
      return fs.readdirSync('/proc/self/fd').length;
    } catch {
      return -1;
    }
  }

  /**
   * Perform a single fd check.
   */
  check(): FdCheckResult {
    const count = this.getOpenFdCount();

    if (count < 0) {
      return { ok: true, count: -1, limit: this.fdLimit, warning: 'FD monitoring unavailable (non-Linux)' };
    }

    if (count >= this.fdLimit) {
      return {
        ok: false,
        count,
        limit: this.fdLimit,
        warning: `FD leak risk: ${count} / ${this.fdLimit}`,
      };
    }

    if (count >= this.fdLimit * WARNING_THRESHOLD) {
      return {
        ok: true,
        count,
        limit: this.fdLimit,
        warning: `FD usage high: ${count} / ${this.fdLimit}`,
      };
    }

    return { ok: true, count, limit: this.fdLimit };
  }

  /**
   * Start periodic fd monitoring.
   * @param intervalMs Check interval in ms (default: 60000).
   */
  start(intervalMs: number = 60_000): void {
    if (this.timer) return;

    this.runCheck();
    this.timer = setInterval(() => this.runCheck(), intervalMs);
    this.timer.unref();
  }

  /**
   * Stop periodic monitoring.
   */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Get the last check result.
   */
  get lastCheck(): FdCheckResult | null {
    return this._lastCheck;
  }

  /**
   * Get the peak FD count seen since monitoring started.
   */
  get peakCount(): number {
    return this._peakCount;
  }

  // ── E8-PROD6: Active Cleanup ────────────────────────────────

  /**
   * Trigger active FD cleanup actions.
   * Called automatically when FD usage exceeds 80% threshold.
   *
   * Actions:
   *   1. Close idle socket connections
   *   2. Clean up stale WAL files
   *   3. Clean up temp files
   *   4. Notify critical callback for escalation
   */
  triggerCleanup(): void {
    const result = this._lastCheck ?? this.check();

    logger.warn(
      { count: result.count, limit: result.limit, percent: Math.round((result.count / result.limit) * 100) },
      '[FdMonitor] E8-PROD6: Triggering active FD cleanup',
    );

    // 1. Close idle socket connections
    if (this.onCleanupIdleSockets) {
      try {
        this.onCleanupIdleSockets();
        logger.info('[FdMonitor] Cleanup: idle socket connections closed');
      } catch (err: any) {
        logger.error(`[FdMonitor] Cleanup failed (idle sockets): ${err.message}`);
      }
    }

    // 2. Clean up stale WAL files
    if (this.onCleanupWalFiles) {
      try {
        this.onCleanupWalFiles();
        logger.info('[FdMonitor] Cleanup: WAL files cleaned');
      } catch (err: any) {
        logger.error(`[FdMonitor] Cleanup failed (WAL files): ${err.message}`);
      }
    }

    // 3. Clean up temp files
    if (this.onCleanupTempFiles) {
      try {
        this.onCleanupTempFiles();
        logger.info('[FdMonitor] Cleanup: temp files cleaned');
      } catch (err: any) {
        logger.error(`[FdMonitor] Cleanup failed (temp files): ${err.message}`);
      }
    }

    // 4. Critical callback escalation
    if (this.onCriticalFdUsage) {
      try {
        this.onCriticalFdUsage(result);
        logger.info('[FdMonitor] Cleanup: critical callback notified');
      } catch (err: any) {
        logger.error(`[FdMonitor] Cleanup failed (critical callback): ${err.message}`);
      }
    }
  }

  // ── Private helpers ──────────────────────────────────────────

  private runCheck(): void {
    const result = this.check();
    this._lastCheck = result;

    if (result.count > this._peakCount) {
      this._peakCount = result.count;
    }

    // E8-PROD6: Trigger active cleanup when FD usage >80%
    if (result.count >= 0 && result.limit > 0) {
      const percent = (result.count / result.limit) * 100;
      if (percent >= 80) {
        this.triggerCleanup();
      }
    }

    if (!result.ok) {
      logger.fatal(result, 'FdMonitor: CRITICAL — FD leak');
    } else if (result.warning) {
      logger.warn(result, 'FdMonitor: warning');
    }
  }

  /**
   * Detect the OS file descriptor limit (soft).
   * Tries `ulimit -n`, then falls back to DEFAULT_FD_LIMIT.
   */
  private detectFdLimit(): number {
    try {
      const output = execSync('ulimit -n', { encoding: 'utf-8', timeout: 1000 }).trim();
      const parsed = parseInt(output, 10);
      if (!isNaN(parsed) && parsed > 0) return parsed;
    } catch {
      // Fall through
    }
    return DEFAULT_FD_LIMIT;
  }
}
