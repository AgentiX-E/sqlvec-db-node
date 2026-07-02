/**
 * PoolModeRouter — Connection pool mode extender for `SqlVecConnectionPool`.
 *
 * Wraps an existing connection pool and provides mode-aware connection lifecycle:
 *
 * - **'session'** (default): Connection held for the full session lifetime
 *   (current behavior — no change).
 * - **'transaction'**: Connection released back to pool after COMMIT or ROLLBACK.
 * - **'statement'**: Connection released back to pool after each SQL execution.
 *
 * Compatible with both `SqlVecConnectionPool` and any pool exposing
 * `acquire()` / `release(resource)` methods.
 *
 * @module PoolModeRouter
 */

export type PoolMode = 'session' | 'transaction' | 'statement';

/**
 * Minimal connection interface expected by PoolModeRouter.
 */
export interface Connection {
  /** Unique identifier for this connection instance. */
  readonly id: string | number;
  /** Whether the connection is currently inside a transaction. */
  inTransaction?: boolean;
  /** Custom cleanup logic when releasing the connection. */
  close?: () => void;
}

/**
 * Minimal pool interface expected by PoolModeRouter.
 */
export interface PoolLike {
  acquire(): Promise<Connection>;
  release(resource: Connection): void | Promise<void>;
}

/**
 * Wraps an existing connection pool with mode-aware connection lifecycle.
 */
export class PoolModeRouter {
  private transactionBoundConn: Connection | null = null;
  private currentConn: Connection | null = null;

  /**
   * @param pool - The underlying connection pool (e.g. SqlVecConnectionPool or PoolLike).
   * @param mode - Pool mode: 'session', 'transaction', or 'statement'.
   */
  constructor(
    private pool: PoolLike,
    private _mode: PoolMode = 'session',
  ) {}

  /**
   * Get the current pool mode.
   */
  get mode(): PoolMode {
    return this._mode;
  }

  /**
   * Set the pool mode dynamically.
   */
  set mode(newMode: PoolMode) {
    this._mode = newMode;
  }

  /**
   * Acquire a connection from the pool.
   *
   * - **session** mode: Acquires once and caches the connection for the session.
   * - **transaction** mode: Acquires once per transaction block.
   * - **statement** mode: Acquires a fresh connection for each call.
   *
   * @returns A promise that resolves to a Connection instance.
   */
  async acquire(): Promise<Connection> {
    switch (this._mode) {
      case 'session':
        if (!this.currentConn) {
          this.currentConn = await this.pool.acquire();
        }
        return this.currentConn;

      case 'transaction':
        if (!this.transactionBoundConn) {
          this.transactionBoundConn = await this.pool.acquire();
          this.transactionBoundConn.inTransaction = true;
        }
        return this.transactionBoundConn;

      case 'statement':
        // Fresh connection each time
        return this.pool.acquire();

      default:
        return this.pool.acquire();
    }
  }

  /**
   * Release a connection back to the pool.
   *
   * - **session** mode: Does nothing (connection cached for session lifetime).
   * - **transaction** mode: Does nothing until `onTransactionEnd()` is called.
   * - **statement** mode: Immediately releases the connection.
   *
   * @param conn - The connection to release (or mark for release).
   */
  release(conn: Connection): void {
    switch (this._mode) {
      case 'session':
        // Don't release — held for session lifetime
        break;

      case 'transaction':
        // Don't release until transaction ends
        break;

      case 'statement':
        this.pool.release(conn);
        break;
    }
  }

  /**
   * Mark a transaction boundary (COMMIT or ROLLBACK).
   *
   * In **transaction** mode, this releases the connection back to the pool.
   * In other modes, this is a no-op.
   */
  onTransactionEnd(): void {
    if (this._mode === 'transaction' && this.transactionBoundConn) {
      const conn = this.transactionBoundConn;
      if (conn.inTransaction !== undefined) {
        conn.inTransaction = false;
      }
      this.pool.release(conn);
      this.transactionBoundConn = null;
    }
  }

  /**
   * Mark a statement completion.
   *
   * In **statement** mode, this is a no-op (release happens in `release()`).
   * In other modes, this is a no-op.
   */
  onStatementEnd(): void {
    // In statement mode, release already happened in release().
    // This method exists for compatibility and explicit signalling.
  }
}
