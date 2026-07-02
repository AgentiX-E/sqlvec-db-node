/**
 * IdleTxnTimeoutManager — Idle-in-transaction timeout enforcement
 *
 * PostgreSQL has a server parameter `idle_in_transaction_session_timeout`
 * that terminates a session that has been idle inside a transaction for
 * longer than the specified duration. The default is 0 (disabled), meaning
 * a transaction can remain idle indefinitely, consuming connection slots,
 * holding locks, and blocking vacuum.
 *
 * This manager enforces per-session idle-in-transaction timeouts:
 *   - A timer starts when a query transaction begins
 *   - If the transaction completes (COMMIT/ROLLBACK), the timer is cancelled
 *   - If the session performs activity within the transaction (e.g., another
 *     SQL execution), the timer is refreshed to prevent premature timeout
 *   - If the timer fires, the onTimeout callback is invoked (typically
 *     to ROLLBACK the transaction and close the connection)
 *
 * Usage:
 *   const txnTimeoutMgr = new IdleTxnTimeoutManager();
 *   txnTimeoutMgr.startTimer('session-1', 5 * 60 * 1000, (id) => {
 *     pgPool.query(`ROLLBACK`);
 *     socket.end();
 *   });
 *   // ... on SQL execution ...
 *   txnTimeoutMgr.refreshTimer('session-1');
 *   // ... on COMMIT/ROLLBACK ...
 *   txnTimeoutMgr.cancelTimer('session-1');
 *
 * @module IdleTxnTimeout
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_DATA_EXCEPTION,
} from '../constants/sqlstate';

const logger = PinoLogger.forComponent('IdleTxnTimeout');

// ── Constants ────────────────────────────────────────────────────────────────

/**
 * Default idle-in-transaction timeout (5 minutes).
 *
 * Production PostgreSQL deployments often set this between 5 and 60 minutes.
 * 5 minutes is a conservative default that protects against long-held locks
 * without breaking most normal transactions.
 */
export const DEFAULT_IDLE_TXN_TIMEOUT_MS = 5 * 60 * 1000;

// ── TimerEntry ───────────────────────────────────────────────────────────────

/**
 * Internal entry stored for each active idle-transaction timer.
 */
interface TimerEntry {
  /** The Node.js timer handle (Timeout). */
  timer: ReturnType<typeof setTimeout>;
  /** Optional callback invoked on timeout. */
  onTimeout?: (sessionId: string) => void;
}

// ── IdleTxnTimeoutManager ────────────────────────────────────────────────────

/**
 * Manages idle-in-transaction timeouts for sessions.
 *
 * Each session gets a timer when a new transaction begins. If the
 * transaction completes (COMMIT/ROLLBACK), the timer is cancelled.
 * If the session executes activity within the transaction, the timer
 * is refreshed. If the timer fires, the configured onTimeout callback
 * is called to roll back the transaction and close the connection.
 *
 * @example
 * ```ts
 * const mgr = new IdleTxnTimeoutManager();
 *
 * // When a transaction begins:
 * mgr.startTimer('session-1', 300000, (sessionId) => {
 *   // Roll back and close
 *   pgPool.query('ROLLBACK');
 *   socket.end();
 *   logger.warn({ sessionId }, 'Idle transaction timed out — rolled back');
 * });
 *
 * // On SQL execution within the transaction:
 * mgr.refreshTimer('session-1');
 *
 * // On COMMIT or ROLLBACK:
 * mgr.cancelTimer('session-1');
 *
 * // On server shutdown:
 * mgr.cancelAll();
 * ```
 */
export class IdleTxnTimeoutManager {
  /** Active timers keyed by session ID. */
  private timers: Map<string, TimerEntry> = new Map();

  /** Default timeout in milliseconds for new timers. */
  private defaultTimeoutMs: number;

  /**
   * Create an IdleTxnTimeoutManager.
   *
   * @param defaultTimeoutMs  - Default timeout in milliseconds
   *                            (default: 5 minutes). Used when
   *                            `startTimer` is called without an
   *                            explicit timeout.
   */
  constructor(defaultTimeoutMs: number = DEFAULT_IDLE_TXN_TIMEOUT_MS) {
    if (!Number.isFinite(defaultTimeoutMs) || defaultTimeoutMs < 1) {
      throw new DatabaseError(
        `IdleTxnTimeoutManager: invalid defaultTimeoutMs ${defaultTimeoutMs}`,
        SQLSTATE_DATA_EXCEPTION,
      );
    }
    this.defaultTimeoutMs = defaultTimeoutMs;
  }

  /**
   * Start an idle-in-transaction timeout timer for the given session.
   *
   * If a timer already exists for this sessionId, it will be silently
   * replaced (the old timer is cleared first).
   *
   * @param sessionId  - Unique session identifier
   * @param timeoutMs  - Timeout in milliseconds
   *                     (default: this.defaultTimeoutMs, i.e. 5 minutes)
   * @param onTimeout  - Callback invoked when the timer fires.
   *                     Receives the sessionId as its argument.
   *
   * @throws {Error} If `timeoutMs` is not a positive finite number
   */
  startTimer(
    sessionId: string,
    timeoutMs?: number,
    onTimeout?: (sessionId: string) => void,
  ): void {
    const effectiveTimeout = timeoutMs ?? this.defaultTimeoutMs;

    if (!Number.isFinite(effectiveTimeout) || effectiveTimeout < 1) {
      throw new DatabaseError(
        `IdleTxnTimeoutManager: invalid timeoutMs ${effectiveTimeout}`,
        SQLSTATE_DATA_EXCEPTION,
      );
    }

    // Cancel any existing timer for this session
    this.cancelTimer(sessionId);

    const timer = setTimeout(() => {
      // Remove from map before calling callback
      this.timers.delete(sessionId);
      logger.warn(
        { sessionId, timeoutMs: effectiveTimeout },
        '[IdleTxnTimeout] Idle transaction timeout — rolling back',
      );
      if (onTimeout) {
        onTimeout(sessionId);
      }
    }, effectiveTimeout);

    // Prevent the timer from keeping the process alive
    timer.unref();

    this.timers.set(sessionId, { timer, onTimeout });

    logger.debug(
      { sessionId, timeoutMs: effectiveTimeout },
      '[IdleTxnTimeout] Timer started',
    );
  }

  /**
   * Refresh the idle-in-transaction timer for a session.
   *
   * Called when the session executes new SQL within the current
   * transaction. This resets the timer to the default timeout,
   * preventing premature timeout while the transaction is actively
   * being used.
   *
   * If a custom timeout was originally provided via `startTimer`,
   * it is **not** remembered — the refresh uses the manager's
   * `defaultTimeoutMs`. If you need to preserve a per-session
   * custom timeout, call `startTimer` again instead.
   *
   * This is a no-op if no timer exists for the given sessionId
   * (no timer to refresh).
   *
   * @param sessionId  - Unique session identifier
   */
  refreshTimer(sessionId: string): void {
    const entry = this.timers.get(sessionId);
    if (!entry) {
      // No active transaction timer; nothing to refresh.
      return;
    }

    // Preserve the original callback
    const { onTimeout } = entry;

    // Clear existing timer and re-create with the default timeout.
    clearTimeout(entry.timer);

    const timer = setTimeout(() => {
      this.timers.delete(sessionId);
      logger.warn(
        { sessionId, timeoutMs: this.defaultTimeoutMs },
        '[IdleTxnTimeout] Idle transaction timeout — rolling back',
      );
      if (onTimeout) {
        onTimeout(sessionId);
      }
    }, this.defaultTimeoutMs);

    timer.unref();

    this.timers.set(sessionId, { timer, onTimeout });

    logger.debug(
      { sessionId, timeoutMs: this.defaultTimeoutMs },
      '[IdleTxnTimeout] Timer refreshed',
    );
  }

  /**
   * Cancel the idle-in-transaction timer for a session.
   *
   * Called when:
   *   - The transaction commits (COMMIT)
   *   - The transaction rolls back (ROLLBACK)
   *   - The connection is closed
   *
   * This is safe to call even if no timer exists for the session
   * (no-op for unknown session IDs).
   *
   * @param sessionId - Unique session identifier
   */
  cancelTimer(sessionId: string): void {
    const entry = this.timers.get(sessionId);
    if (entry) {
      clearTimeout(entry.timer);
      this.timers.delete(sessionId);
      logger.debug(
        { sessionId },
        '[IdleTxnTimeout] Timer cancelled',
      );
    }
  }

  /**
   * Check if a session currently has an active idle-transaction timer.
   *
   * @param sessionId - Unique session identifier
   * @returns `true` if a timer is active for this session
   */
  hasActiveTimer(sessionId: string): boolean {
    return this.timers.has(sessionId);
  }

  /**
   * Get the number of active idle-transaction timers.
   *
   * Useful for monitoring and health checks.
   */
  get activeTimerCount(): number {
    return this.timers.size;
  }

  /**
   * Cancel all active timers.
   *
   * Called during server shutdown to clean up all pending
   * idle-in-transaction timers.
   */
  cancelAll(): void {
    for (const [sessionId, entry] of this.timers) {
      clearTimeout(entry.timer);
    }
    this.timers.clear();
    logger.info('[IdleTxnTimeout] All idle-transaction timers cancelled');
  }
}
