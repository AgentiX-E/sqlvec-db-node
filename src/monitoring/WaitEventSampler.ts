import { WaitSamplingShim, WaitEventSample } from '../query/WaitSamplingShim';
import { PinoLogger } from './PinoLogger';

const logger = PinoLogger.forComponent('wait-event-sampler');

/**
 * WaitEventSampler — Automated wait event sampling with self-diagnosis.
 *
 * Wraps a WaitSamplingShim instance and provides periodic auto-sampling
 * of wait events. Stores historical sample data in memory for analysis.
 *
 * Usage:
 *   const sampler = new WaitEventSampler();
 *   sampler.startAutoSampling();          // starts sampling every 10s
 *   const data = sampler.getSampleData(); // Map<pid, WaitEventSample[]>
 *   sampler.stopAutoSampling();           // stops periodic sampling
 */
export class WaitEventSampler {
  private shim: WaitSamplingShim;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private sampleHistory: Map<number, WaitEventSample[]> = new Map();
  private defaultIntervalMs = 10000;

  /**
   * @param shim Optional WaitSamplingShim instance. Creates a new one if omitted.
   */
  constructor(shim?: WaitSamplingShim) {
    this.shim = shim ?? new WaitSamplingShim();
  }

  /**
   * Start automatic periodic sampling.
   *
   * Collects a snapshot of all tracked wait events at the given interval
   * and appends results to the in-memory sample history.
   *
   * @param intervalMs Sampling interval in milliseconds (default: 10000ms / 10s).
   *                   Must be >= 100ms to prevent runaway intervals.
   */
  startAutoSampling(intervalMs: number = this.defaultIntervalMs): void {
    if (this.intervalId !== null) {
      logger.warn('Auto-sampling is already running. Ignoring duplicate start.');
      return;
    }

    const safeInterval = Math.max(100, intervalMs);

    this.intervalId = setInterval(() => {
      try {
        const samples = this.shim.sample();
        for (const sample of samples) {
          const pid = sample.pid;
          const existing = this.sampleHistory.get(pid) || [];
          existing.push(sample);
          this.sampleHistory.set(pid, existing);
        }
      } catch (err) {
        logger.error({ err }, 'Auto-sampling iteration failed');
      }
    }, safeInterval);

    logger.info({ intervalMs: safeInterval }, 'Auto-sampling started');
  }

  /**
   * Stop automatic periodic sampling.
   *
   * Clears the interval timer. In-flight sample data remains in memory
   * and can still be retrieved via getSampleData().
   */
  stopAutoSampling(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      logger.info('Auto-sampling stopped');
    } else {
      logger.warn('Auto-sampling is not running. Nothing to stop.');
    }
  }

  /**
   * Get all historically sampled data.
   *
   * Returns a Map keyed by PID, where each value is an array of
   * WaitEventSample snapshots taken during auto-sampling.
   */
  getSampleData(): Map<number, WaitEventSample[]> {
    return new Map(this.sampleHistory);
  }

  /**
   * Clear all historical sample data from memory.
   */
  clearSampleData(): void {
    this.sampleHistory.clear();
  }

  /**
   * Get the underlying WaitSamplingShim instance.
   *
   * Provides direct access to the shim for manual record/sample/clear operations.
   */
  getShim(): WaitSamplingShim {
    return this.shim;
  }

  /**
   * Check whether auto-sampling is currently active.
   */
  isSamplingActive(): boolean {
    return this.intervalId !== null;
  }
}
