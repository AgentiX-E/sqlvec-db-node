/**
 * GcObserver — observes Node.js GC events and reports duration to MetricsManager.
 *
 * Uses the V8 --expose-gc hook via performance.observer (Node.js 18+).
 * Falls back gracefully when GC monitoring is unavailable.
 *
 * Usage:
 *   const observer = new GcObserver(metricsManager);
 *   observer.start();   // begins observing
 *   observer.stop();    // clean disconnect
 */

import { performance, PerformanceObserver } from 'perf_hooks';
import type { MetricsManager } from '../core/MetricsManager';
import { PinoLogger } from './PinoLogger';

const logger = PinoLogger.forComponent('GcObserver');

export class GcObserver {
  private observer: PerformanceObserver | null = null;
  private metrics: MetricsManager;
  private enabled: boolean = false;

  constructor(metrics: MetricsManager) {
    this.metrics = metrics;
  }

  /**
   * Start observing GC events. Registers a PerformanceObserver
   * for 'gc' type entries and reports duration to MetricsManager.
   */
  start(): void {
    if (this.observer) return; // already started

    try {
      if (typeof PerformanceObserver !== 'function') {
        logger.warn('[GcObserver] PerformanceObserver not available, GC monitoring disabled');
        return;
      }

      this.observer = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        for (const entry of entries) {
          if (entry.entryType === 'gc') {
            // duration in milliseconds → convert to seconds
            const seconds = entry.duration / 1000;
            this.metrics.setGcDurationSeconds(seconds);
          }
        }
      });

      this.observer.observe({ type: 'gc', buffered: false });
      this.enabled = true;
      logger.info('[GcObserver] GC monitoring started');
    } catch (err: any) {
      // Node.js may not have the gc PerformanceObserver entry type
      logger.warn(`[GcObserver] GC monitoring not supported: ${err.message}`);
      this.enabled = false;
    }
  }

  /**
   * Stop observing GC events.
   */
  stop(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
      this.enabled = false;
      logger.info('[GcObserver] GC monitoring stopped');
    }
  }

  /**
   * Returns whether GC monitoring is active.
   */
  isEnabled(): boolean {
    return this.enabled;
  }
}
