import Bottleneck from 'bottleneck';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('rate-limiter');

/**
 * BottleneckRateLimiter — Token-bucket rate limiter using bottleneck.
 *
 * Provides configurable rate limiting for SQLVec operations, mimicking
 * PostgreSQL's statement_timeout / idle_in_transaction_session_timeout
 * semantics at the request-queuing level.
 *
 * Features:
 *   - Per-second throughput limit
 *   - Optional max concurrent executions
 *   - Dynamic limit adjustment at runtime
 *   - Built-in prioritisation support (via Bottleneck groups)
 *
 * Usage:
 *   const limiter = new BottleneckRateLimiter(100, 10);
 *   const result = await limiter.schedule(() => db.query('SELECT 1'));
 */

export class BottleneckRateLimiter {
  private limiter: Bottleneck;

  /**
   * @param maxPerSecond  Maximum requests per second (reservoir refresh rate)
   * @param maxConcurrent Maximum concurrent executions (default: unlimited)
   */
  constructor(maxPerSecond: number, maxConcurrent?: number) {
    const opts: Record<string, unknown> = {
      reservoir: maxPerSecond,
      reservoirRefreshAmount: maxPerSecond,
      reservoirRefreshInterval: 1000,  // every second
    };

    if (maxConcurrent !== undefined) {
      opts.maxConcurrent = maxConcurrent;
    }

    this.limiter = new Bottleneck(opts as Bottleneck.ConstructorOptions);

    this.limiter.on('error', (err: Error) => {
      logger.error({ err }, 'Bottleneck limiter error');
    });

    this.limiter.on('depleted', () => {
      logger.warn('Rate limit reservoir depleted');
    });
  }

  /**
   * Schedule a function execution under rate limiting.
   *
   * @param fn Async function to execute
   * @returns The return value of the function
   */
  async schedule<T>(fn: () => Promise<T>): Promise<T> {
    return this.limiter.schedule(fn);
  }

  /**
   * Update the per-second rate limit at runtime.
   *
   * @param maxPerSecond New maximum requests per second
   */
  updateLimit(maxPerSecond: number): void {
    this.limiter.updateSettings({
      reservoir: maxPerSecond,
      reservoirRefreshAmount: maxPerSecond,
    });
    logger.info({ maxPerSecond }, 'Rate limit updated');
  }

  /**
   * Update the max concurrent executions at runtime.
   *
   * @param maxConcurrent New max concurrent value (undefined = unlimited)
   */
  updateConcurrent(maxConcurrent?: number): void {
    this.limiter.updateSettings({
      maxConcurrent: maxConcurrent ?? null,
    } as any);
    logger.info({ maxConcurrent }, 'Max concurrent updated');
  }

  /**
   * Get current rate limiter status.
   */
  async getStatus(): Promise<{
    running: number;
    queued: number;
    done: number;
    reservoir: number;
  }> {
    const counts = await this.limiter.counts();
    return {
      running: counts.RUNNING,
      queued: counts.QUEUED,
      done: counts.DONE ?? 0,
      reservoir: await this.limiter.currentReservoir() ?? 0,
    };
  }

  /**
   * Stop the limiter and wait for all queued jobs to complete.
   */
  async stop(): Promise<void> {
    await this.limiter.stop({ dropWaitingJobs: false });
  }
}
