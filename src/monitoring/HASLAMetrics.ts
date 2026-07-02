/**
 * HASLAMetrics — High-Availability Service Level Agreement metrics.
 *
 * Tracks downtime events and computes standard HA/SLA metrics:
 *   - Uptime percentage over any time window
 *   - Failure count (hour / day / week / month)
 *   - Mean Time Between Failures (MTBF)
 *   - Mean Time To Recover (MTTR)
 *   - Monthly, quarterly, and yearly SLA summaries
 *
 * Exposed via HealthCheckServer for operational visibility.
 *
 * @module HASLAMetrics
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('HASLAMetrics');

// ── Types ────────────────────────────────────────────────────────

export interface DowntimeEvent {
  start: Date;
  end: Date;
  nodeId: string;
  /** Duration in milliseconds */
  durationMs: number;
}

export interface SLASummary {
  /** Current month uptime % */
  monthly: number;
  /** Current quarter uptime % */
  quarterly: number;
  /** Current year uptime % */
  yearly: number;
}

// ── HASLAMetrics ─────────────────────────────────────────────────

export class HASLAMetrics {
  private downtimes: DowntimeEvent[] = [];
  private readonly logger: PinoLogger;

  constructor() {
    this.logger = PinoLogger.forComponent('HASLAMetrics');
  }

  /**
   * Record a downtime event for a node.
   * Computes and stores the duration automatically.
   */
  recordDowntime(start: Date, end: Date, nodeId: string): void {
    const durationMs = end.getTime() - start.getTime();
    if (durationMs < 0) {
      this.logger.warn({ nodeId, start, end }, 'recordDowntime: start must be before end');
      return;
    }

    const event: DowntimeEvent = {
      start: new Date(start),
      end: new Date(end),
      nodeId,
      durationMs,
    };

    this.downtimes.push(event);
    this.logger.info(
      { nodeId, durationMs, start: start.toISOString(), end: end.toISOString() },
      'Downtime recorded',
    );
  }

  /**
   * Calculate uptime percentage over a given time window.
   *
   * Returns a value between 0 and 100. If no downtime events overlap
   * the window, returns 100.
   */
  getUptimePercentage(since: Date): number {
    const now = Date.now();
    const sinceMs = since.getTime();
    const totalWindowMs = now - sinceMs;

    if (totalWindowMs <= 0) return 100;

    const totalDowntimeMs = this.downtimes
      .filter((d) => d.end.getTime() > sinceMs && d.start.getTime() < now)
      .reduce((acc, d) => {
        const overlapStart = Math.max(d.start.getTime(), sinceMs);
        const overlapEnd = Math.min(d.end.getTime(), now);
        return acc + Math.max(0, overlapEnd - overlapStart);
      }, 0);

    const uptimeRatio = (totalWindowMs - totalDowntimeMs) / totalWindowMs;
    return Math.round(uptimeRatio * 10000) / 100; // 4 decimal places
  }

  /**
   * Count the number of failure (downtime) events in a given period.
   */
  getFailureCount(period: 'hour' | 'day' | 'week' | 'month'): number {
    const now = Date.now();
    let cutoff: number;

    switch (period) {
      case 'hour':
        cutoff = now - 3600_000;
        break;
      case 'day':
        cutoff = now - 86_400_000;
        break;
      case 'week':
        cutoff = now - 604_800_000;
        break;
      case 'month':
        cutoff = now - 2_592_000_000;
        break;
    }

    return this.downtimes.filter((d) => d.start.getTime() >= cutoff).length;
  }

  /**
   * Mean Time Between Failures (MTBF) in milliseconds.
   *
   * Calculated as total uptime / number of failures.
   * Returns 0 if there are fewer than 2 events (not enough data).
   */
  getMTBF(): number {
    if (this.downtimes.length < 2) return 0;

    const sorted = [...this.downtimes].sort((a, b) => a.start.getTime() - b.start.getTime());

    // Time between consecutive failures: start of n+1 minus end of n
    let totalBetweenMs = 0;
    for (let i = 0; i < sorted.length - 1; i++) {
      const between = sorted[i + 1].start.getTime() - sorted[i].end.getTime();
      if (between > 0) {
        totalBetweenMs += between;
      }
    }

    return Math.round(totalBetweenMs / (sorted.length - 1));
  }

  /**
   * Mean Time To Recover (MTTR) in milliseconds.
   *
   * Calculated as average duration of all downtime events.
   * Returns 0 if there are no events.
   */
  getMTTR(): number {
    if (this.downtimes.length === 0) return 0;

    const total = this.downtimes.reduce((acc, d) => acc + d.durationMs, 0);
    return Math.round(total / this.downtimes.length);
  }

  /**
   * Get the SLA summary for monthly, quarterly, and yearly periods.
   *
   * Each value is an uptime percentage (0–100).
   * Periods are calculated from the beginning of the current calendar
   * month / quarter / year.
   */
  getSLASummary(): SLASummary {
    const now = new Date();

    // Start of current month
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

    // Start of current quarter
    const quarterStartMonth = Math.floor(now.getMonth() / 3) * 3;
    const quarterStart = new Date(now.getFullYear(), quarterStartMonth, 1);

    // Start of current year
    const yearStart = new Date(now.getFullYear(), 0, 1);

    return {
      monthly: this.getUptimePercentage(monthStart),
      quarterly: this.getUptimePercentage(quarterStart),
      yearly: this.getUptimePercentage(yearStart),
    };
  }

  /**
   * Reset all recorded metrics.
   * Useful for testing or when the monitoring context is re-initialised.
   */
  resetMetrics(): void {
    this.downtimes = [];
    this.logger.info('HASLAMetrics reset');
  }

  /**
   * Get all recorded downtime events (read-only snapshot).
   */
  getDowntimes(): DowntimeEvent[] {
    return [...this.downtimes];
  }
}
