/**
 * pgWaitSampling — PostgreSQL pg_wait_sampling view compatibility.
 *
 * Samples wait events periodically, stores in a ring buffer.
 * Exposes wait event history via pg_wait_sampling view.
 *
 * Wait event types (matching PostgreSQL):
 *   - Lock       Waiting for a lock
 *   - IO         Waiting for I/O (WAL write, read)
 *   - Activity   Currently active (CPU-bound)
 *   - Extension  Extension-specific wait
 *   - Client     Waiting for client input
 *   - Timeout    Timeout wait
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-wait-sampling');

export type WaitEventType = 'Lock' | 'IO' | 'Activity' | 'Extension' | 'Client' | 'Timeout';
export type ActivityState = 'active' | 'idle' | 'idle in transaction' | 'fastpath function call' | 'disabled';

export interface WaitEventSample {
  pid: number;
  ts: number;           // epoch ms
  wait_event_type: WaitEventType | null;
  wait_event: string | null;
  state: ActivityState;
  query: string;
  query_start: number;
  wait_start: number | null;
  durationMs: number;
}

export interface WaitSamplingConfig {
  /** Maximum number of samples to retain in the ring buffer (default: 10000). */
  ringBufferSize: number;
  /** Default sampling interval in ms (default: 1000). */
  defaultIntervalMs: number;
}

const DEFAULT_CONFIG: WaitSamplingConfig = {
  ringBufferSize: 10000,
  defaultIntervalMs: 1000,
};

export class PgWaitSampling {
  private ringBuffer: WaitEventSample[] = [];
  private config: WaitSamplingConfig;
  private nextIndex = 0;
  private totalSamples = 0;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private activityMap: Map<number, Partial<WaitEventSample>> = new Map();

  constructor(config?: Partial<WaitSamplingConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ── Activity Registration ────────────────────────────────────

  /** Register or update an activity entry for a PID. */
  recordActivity(pid: number, sample: Partial<WaitEventSample>): void {
    const existing = this.activityMap.get(pid) || {};
    this.activityMap.set(pid, { ...existing, ...sample, pid });
  }

  /** Remove activity for a PID. */
  removeActivity(pid: number): void {
    this.activityMap.delete(pid);
  }

  /** Record that a PID is waiting for a lock. */
  recordLockWait(pid: number, lockName: string): void {
    this.activityMap.set(pid, {
      pid,
      wait_event_type: 'Lock' as WaitEventType,
      wait_event: lockName,
      state: 'active' as ActivityState,
      wait_start: Date.now(),
    });
  }

  /** Record that a PID is waiting for I/O. */
  recordIOWait(pid: number, ioEvent: string): void {
    this.activityMap.set(pid, {
      pid,
      wait_event_type: 'IO' as WaitEventType,
      wait_event: ioEvent,
      state: 'active' as ActivityState,
      wait_start: Date.now(),
    });
  }

  /** Clear wait state for a PID. */
  clearWait(pid: number): void {
    const existing = this.activityMap.get(pid);
    if (existing) {
      existing.wait_event_type = null;
      existing.wait_event = null;
      existing.wait_start = null;
    }
  }

  // ── Sampling ─────────────────────────────────────────────────

  /** Take a single snapshot of all activities. */
  sample(): WaitEventSample[] {
    const now = Date.now();
    const samples: WaitEventSample[] = [];

    for (const [pid, activity] of this.activityMap) {
      const startMs = activity.query_start || now;
      const sample: WaitEventSample = {
        pid,
        ts: now,
        wait_event_type: (activity.wait_event_type as WaitEventType) || null,
        wait_event: activity.wait_event ?? null,
        state: (activity.state as ActivityState) || 'active',
        query: activity.query || '',
        query_start: startMs,
        wait_start: activity.wait_start ?? null,
        durationMs: now - startMs,
      };

      this.addToRingBuffer(sample);
      samples.push(sample);
    }

    return samples;
  }

  /** Add a sample to the ring buffer. */
  private addToRingBuffer(sample: WaitEventSample): void {
    if (this.ringBuffer.length < this.config.ringBufferSize) {
      this.ringBuffer.push(sample);
    } else {
      this.ringBuffer[this.nextIndex % this.config.ringBufferSize] = sample;
    }
    this.nextIndex++;
    this.totalSamples++;
  }

  // ── Query ────────────────────────────────────────────────────

  /** Query the wait event history. */
  queryHistory(opts?: {
    pid?: number;
    waitEventType?: WaitEventType;
    minDurationMs?: number;
    limit?: number;
    sinceTs?: number;
  }): WaitEventSample[] {
    let results = this.ringBuffer;

    if (opts?.pid !== undefined) {
      results = results.filter(s => s.pid === opts.pid);
    }
    if (opts?.waitEventType) {
      results = results.filter(s => s.wait_event_type === opts.waitEventType);
    }
    if (opts?.minDurationMs !== undefined) {
      results = results.filter(s => s.durationMs >= opts.minDurationMs!);
    }
    if (opts?.sinceTs !== undefined) {
      results = results.filter(s => s.ts >= opts.sinceTs!);
    }

    results.sort((a, b) => b.ts - a.ts); // newest first

    if (opts?.limit !== undefined) {
      results = results.slice(0, opts.limit);
    }

    return results;
  }

  /** Get current wait event for a specific PID. */
  getWaitEvent(pid: number): Pick<WaitEventSample, 'wait_event_type' | 'wait_event' | 'state'> | null {
    const activity = this.activityMap.get(pid);
    if (!activity) return null;
    return {
      wait_event_type: (activity.wait_event_type as WaitEventType) || null,
      wait_event: activity.wait_event ?? null,
      state: (activity.state as ActivityState) || 'active',
    };
  }

  // ── Auto-Sampling ─────────────────────────────────────────────

  /** Start automatic periodic sampling. */
  startAutoSampling(intervalMs?: number): void {
    if (this.intervalId !== null) return;
    const interval = Math.max(100, intervalMs ?? this.config.defaultIntervalMs);
    this.intervalId = setInterval(() => {
      try {
        this.sample();
      } catch (err) {
        logger.error({ err }, 'Auto-sampling iteration failed');
      }
    }, interval);
    logger.info({ intervalMs: interval }, 'Wait sampling auto-sampling started');
  }

  /** Stop automatic periodic sampling. */
  stopAutoSampling(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
      logger.info('Wait sampling auto-sampling stopped');
    }
  }

  /** Whether auto-sampling is active. */
  isSamplingActive(): boolean {
    return this.intervalId !== null;
  }

  // ── Stats ────────────────────────────────────────────────────

  getStats(): { ringBufferSize: number; totalSamples: number; activePids: number } {
    return {
      ringBufferSize: this.config.ringBufferSize,
      totalSamples: this.totalSamples,
      activePids: this.activityMap.size,
    };
  }

  /** Clear all state. */
  clear(): void {
    this.ringBuffer = [];
    this.nextIndex = 0;
    this.totalSamples = 0;
    this.activityMap.clear();
  }
}
