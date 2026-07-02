/**
 * SqlVecConnectionPool — PG 风格连接池包装器 (基于 tarn.js)
 *
 * 提供 min/max 连接池, 空闲超时, 获取超时。
 * 对标 PostgreSQL 的 PgBouncer 事务级连接池。
 *
 * Transaction stickiness (SE-013):
 *   - 当连接在事务中时（BEGIN 执行后标记），该连接不能被其他请求获取
 *   - 通过 markTransactionStart() / markTransactionEnd() 控制
 *
 * Leak detection (SE-013):
 *   - leakDetectionThreshold: 默认 30000ms
 *   - 连接占用超过 30s 未被释放则报警
 */

import { Pool, TimeoutError } from 'tarn';
import { PinoLogger } from '../monitoring/PinoLogger';

// ── Connection State ────────────────────────────────────────────

/**
 * Per-connection metadata for transaction tracking and leak detection (SE-013).
 */
interface ConnectionState {
  /** Whether this connection is currently inside a transaction. */
  inTransaction: boolean;
  /** Timestamp (epoch ms) when this connection was acquired. */
  acquiredAt: number;
  /** Whether this connection is currently checked out. */
  acquired: boolean;
}

// ── Types ───────────────────────────────────────────────────────

export interface ConnectionPoolConfig<T = any> {
  min: number;
  max: number;
  acquireTimeoutMillis?: number;
  idleTimeoutMillis?: number;
  createFn: () => Promise<T>;
  destroyFn: (conn: T) => Promise<void>;
  validateFn?: (conn: T) => boolean;
  /** Connection leak detection threshold in ms (default: 30000) (SE-013). */
  leakDetectionThreshold?: number;
}

// ── SqlVecConnectionPool ────────────────────────────────────────

export class SqlVecConnectionPool<T = any> {
  private pool: Pool<T>;
  private logger = PinoLogger.forComponent('connection-pool');

  /** Leak detection threshold in ms (SE-013). */
  private leakDetectionThreshold: number;

  /** Leak detection interval timer (SE-013). */
  private leakTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * Connection state tracking (SE-013).
   * Maps connection identity (resource reference) to its state.
   */
  private connState = new Map<string, ConnectionState>();

  /** Monotonically increasing connection counter for stable keys. */
  private nextConnId = 0;
  /** Map from resource to assigned connection ID (for WeakMap-compatible refs). */
  private resourceToId = new WeakMap<object, string>();

  constructor(config: ConnectionPoolConfig<T>) {
    this.leakDetectionThreshold = config.leakDetectionThreshold ?? 30000;

    this.pool = new Pool<T>({
      create: config.createFn,
      destroy: config.destroyFn,
      validate: config.validateFn || (() => true),
      min: config.min,
      max: config.max,
      acquireTimeoutMillis: config.acquireTimeoutMillis || 30000,
      idleTimeoutMillis: config.idleTimeoutMillis || 300000,
      reapIntervalMillis: 1000,
    });

    // Start leak detection timer (SE-013)
    this.leakTimer = setInterval(() => this.checkForLeaks(), 5000);
    this.leakTimer.unref();
  }

  /**
   * Acquire a connection from the pool.
   * Tracks the connection as acquired and records its acquisition time.
   *
   * @returns The acquired resource (T).
   */
  async acquire(): Promise<T> {
    const op = this.pool.acquire();
    const resource = await op.promise;

    const connId = this.getOrCreateConnId(resource);
    this.connState.set(connId, {
      inTransaction: false,
      acquiredAt: Date.now(),
      acquired: true,
    });

    this.logger.debug({ numUsed: this.numUsed }, 'Connection acquired');
    return resource;
  }

  /**
   * Release a connection back to the pool.
   * Clears transaction state.
   *
   * @param resource - The resource to release.
   */
  async release(resource: T): Promise<void> {
    const connId = this.getConnId(resource);
    if (connId) {
      this.connState.delete(connId);
    }
    this.pool.release(resource);
  }

  /**
   * Mark a connection as being in a transaction (SE-013).
   * The connection becomes "sticky": the caller must not release it
   * until the transaction ends via markTransactionEnd().
   *
   * @param resource - The resource to mark.
   */
  markTransactionStart(resource: T): void {
    const state = this.getState(resource);
    if (state) {
      state.inTransaction = true;
    }
  }

  /**
   * Mark a connection's transaction as ended (SE-013).
   * The connection can now be safely released back to the pool.
   *
   * @param resource - The resource to mark.
   */
  markTransactionEnd(resource: T): void {
    const state = this.getState(resource);
    if (state) {
      state.inTransaction = false;
    }
  }

  /**
   * Check if a connection is currently in a transaction (SE-013).
   *
   * @param resource - The resource to check.
   * @returns `true` if the connection is in a transaction.
   */
  isInTransaction(resource: T): boolean {
    const state = this.getState(resource);
    return state?.inTransaction ?? false;
  }

  /**
   * Request that in-transaction connections be protected (SE-013).
   * Connections in a transaction should not be released or reacquired
   * by other requests. This method ensures awareness.
   */
  protectInTransactionConnections(): void {
    const inTx = this.collectInTransactionCount();
    if (inTx > 0) {
      this.logger.debug({ inTransaction: inTx }, 'In-transaction connections protected');
    }
  }

  // ── Pool Metrics ──────────────────────────────────────────────

  /** 当前被借出的连接数 */
  get numUsed(): number { return this.pool.numUsed(); }

  /** 当前空闲连接数 */
  get numFree(): number { return this.pool.numFree(); }

  /** 等待中的获取请求数 */
  get numPending(): number { return this.pool.numPendingAcquires(); }

  /**
   * 当前事务中连接的数量 (SE-013).
   */
  get inTransactionCount(): number {
    return this.collectInTransactionCount();
  }

  // ── Lifecycle ──────────────────────────────────────────────────

  /** 销毁池, 释放所有连接 */
  async destroy(): Promise<void> {
    if (this.leakTimer) {
      clearInterval(this.leakTimer);
      this.leakTimer = null;
    }
    await this.pool.destroy();
    this.connState.clear();
    this.logger.info('Connection pool destroyed');
  }

  // ── Private ────────────────────────────────────────────────────

  /**
   * Get or create a stable connection ID for a resource.
   */
  private getOrCreateConnId(resource: T): string {
    if (typeof resource === 'object' && resource !== null) {
      const obj = resource as object;
      const existing = this.resourceToId.get(obj);
      if (existing) return existing;
      const id = `conn-${this.nextConnId++}`;
      this.resourceToId.set(obj, id);
      return id;
    }
    // For primitive resources, use a new ID each time
    return `conn-${this.nextConnId++}`;
  }

  /**
   * Get the connection ID for a resource, or undefined if not tracked.
   */
  private getConnId(resource: T): string | undefined {
    if (typeof resource === 'object' && resource !== null) {
      return this.resourceToId.get(resource as object);
    }
    return undefined;
  }

  /**
   * Get the connection state for a resource.
   */
  private getState(resource: T): ConnectionState | undefined {
    const connId = this.getConnId(resource);
    if (!connId) return undefined;
    return this.connState.get(connId);
  }

  /**
   * Collect the number of connections currently in a transaction.
   */
  private collectInTransactionCount(): number {
    let count = 0;
    for (const state of this.connState.values()) {
      if (state.inTransaction && state.acquired) {
        count++;
      }
    }
    return count;
  }

  /**
   * Periodic leak detection check (SE-013).
   * Logs a warning for any connection held longer than the threshold.
   */
  private checkForLeaks(): void {
    const threshold = this.leakDetectionThreshold;
    const now = Date.now();

    for (const [connId, state] of this.connState.entries()) {
      if (!state.acquired) continue;

      const elapsed = now - state.acquiredAt;
      if (elapsed > threshold) {
        this.logger.warn(
          {
            connId,
            elapsedMs: elapsed,
            thresholdMs: threshold,
            inTransaction: state.inTransaction,
          },
          '[LeakDetection] Connection held longer than threshold',
        );
      }
    }
  }
}
