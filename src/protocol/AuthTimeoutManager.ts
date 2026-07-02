/**
 * AuthTimeoutManager — Authentication timeout enforcement for TCP connections
 *
 * PostgreSQL's default authentication_timeout is 60 seconds. If a client
 * connects but never completes authentication, the connection stays open
 * indefinitely, consuming server resources (a DoS vector).
 *
 * This manager enforces per-session authentication timeouts:
 *   - A timer starts when a new TCP connection is established
 *   - If authentication completes, the timer is reset/cancelled
 *   - If the timer fires, the onTimeout callback is invoked (typically
 *     to close the connection and log a warning)
 *
 * Brute-force protection (SE-007):
 *   - Tracks failed authentication attempts per IP address
 *   - 5 failed attempts trigger exponential backoff: 1s → 2s → 4s → 8s
 *   - Successful auth clears the failure count for that IP
 *
 * Usage:
 *   const timeoutMgr = new AuthTimeoutManager();
 *   timeoutMgr.startTimer('session-1', 60000, (id) => socket.end());
 *   // ... on auth success ...
 *   timeoutMgr.cancelTimer('session-1');
 *
 * @module AuthTimeoutManager
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_DATA_EXCEPTION,
} from '../constants/sqlstate';

const logger = PinoLogger.forComponent('AuthTimeout');

// ── Constants ────────────────────────────────────────────────────────────────

/**
 * Default authentication timeout (60 seconds, matching PostgreSQL default).
 */
export const DEFAULT_AUTH_TIMEOUT_MS = 60_000;

/**
 * Brute-force protection constants (SE-007).
 */

/** Number of failed attempts before backoff kicks in. */
export const BRUTE_FORCE_THRESHOLD = 5;

/** Maximum backoff delay in milliseconds (capped at 8s). */
export const MAX_BACKOFF_MS = 8000;

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Internal entry stored for each active authentication timer.
 */
interface TimerEntry {
  /** The Node.js timer handle (Timeout). */
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Per-IP brute-force tracking entry (SE-007).
 */
interface BruteForceEntry {
  /** Number of consecutive failed attempts. */
  count: number;
  /** Timestamp (epoch ms) of the last failed attempt. */
  lastAttempt: number;
}

// ── AuthTimeoutManager ───────────────────────────────────────────────────────

/**
 * Manages authentication timeouts for unauthenticated TCP connections.
 *
 * Each session gets a timer when it starts the authentication handshake.
 * If authentication completes, the timer is cancelled. If the timer
 * fires, the configured onTimeout callback is called to close the
 * connection.
 *
 * Also provides IP-based brute-force tracking with exponential backoff
 * (SE-007).
 *
 * @example
 * ```ts
 * const mgr = new AuthTimeoutManager();
 *
 * // When a new connection arrives:
 * mgr.startTimer('session-1', 60000, (sessionId) => {
 *   socket.end();
 *   logger.warn({ sessionId }, 'Authentication timeout');
 * });
 *
 * // On successful authentication:
 * mgr.cancelTimer('session-1');
 *
 * // On connection close:
 * mgr.cancelTimer('session-1');
 * ```
 */
export class AuthTimeoutManager {
  /** Active timers keyed by session ID. */
  private timers: Map<string, TimerEntry> = new Map();

  /** Brute-force tracking: IP → failure count + timestamp (SE-007). */
  private bruteForceTracker: Map<string, BruteForceEntry> = new Map();

  /**
   * Start an authentication timeout timer for the given session.
   *
   * If a timer already exists for this sessionId, it will be silently
   * replaced (the old timer is cleared first).
   *
   * @param sessionId  - Unique session identifier
   * @param timeoutMs  - Timeout in milliseconds (default: 60000)
   * @param onTimeout  - Callback invoked when the timer fires.
   *                     Receives the sessionId as its argument.
   *
   * @throws {Error} If `timeoutMs` is not a positive finite number
   */
  startTimer(
    sessionId: string,
    timeoutMs: number = DEFAULT_AUTH_TIMEOUT_MS,
    onTimeout: (sessionId: string) => void,
  ): void {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
      throw new DatabaseError(
        `AuthTimeoutManager: invalid timeoutMs ${timeoutMs}`,
        SQLSTATE_DATA_EXCEPTION,
      );
    }

    // Cancel any existing timer for this session
    this.cancelTimer(sessionId);

    const timer = setTimeout(() => {
      // Remove from map before calling callback
      this.timers.delete(sessionId);
      logger.warn({ sessionId, timeoutMs }, '[AuthTimeout] Authentication timeout — closing connection');
      onTimeout(sessionId);
    }, timeoutMs);

    // Prevent the timer from keeping the process alive
    timer.unref();

    this.timers.set(sessionId, { timer });
  }

  /**
   * Reset the authentication timer for a session.
   *
   * This is called when authentication advances to a new stage
   * (e.g., received SASL response). It restarts the timer with the
   * same timeout and callback parameters.
   *
   * Note: Since `startTimer` clears any existing timer, this is
   * functionally equivalent to calling `startTimer` again. This
   * method is provided for API clarity.
   *
   * @param sessionId  - Unique session identifier
   * @param timeoutMs  - Timeout in milliseconds (default: 60000)
   * @param onTimeout  - Callback invoked when the timer fires
   */
  resetTimer(
    sessionId: string,
    timeoutMs: number = DEFAULT_AUTH_TIMEOUT_MS,
    onTimeout: (sessionId: string) => void,
  ): void {
    this.startTimer(sessionId, timeoutMs, onTimeout);
  }

  /**
   * Cancel the authentication timer for a session.
   *
   * Called when:
   *   - Authentication completes successfully
   *   - The connection is closed (cleanup)
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
    }
  }

  /**
   * Check if a session currently has an active authentication timer.
   *
   * @param sessionId - Unique session identifier
   * @returns `true` if a timer is active for this session
   */
  hasActiveTimer(sessionId: string): boolean {
    return this.timers.has(sessionId);
  }

  /**
   * Get the number of active authentication timers.
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
   * authentication timers.
   */
  cancelAll(): void {
    for (const [sessionId, entry] of this.timers) {
      clearTimeout(entry.timer);
    }
    this.timers.clear();
    logger.info('[AuthTimeout] All authentication timers cancelled');
  }

  // ── Brute-force protection (SE-007) ───────────────────────────

  /**
   * Record a failed authentication attempt for the given IP.
   * When the threshold is exceeded, callers should enforce a delay.
   *
   * @param clientIp - The client IP address.
   * @returns The required backoff delay in milliseconds (0 if no backoff needed).
   */
  recordFailedAttempt(clientIp: string): number {
    const now = Date.now();
    const entry = this.bruteForceTracker.get(clientIp) ?? { count: 0, lastAttempt: now };

    entry.count += 1;
    entry.lastAttempt = now;
    this.bruteForceTracker.set(clientIp, entry);

    logger.warn(
      { clientIp, failedAttempts: entry.count },
      '[BruteForce] Authentication failure recorded',
    );

    // Compute exponential backoff: 1s → 2s → 4s → 8s (capped at MAX_BACKOFF_MS)
    if (entry.count >= BRUTE_FORCE_THRESHOLD) {
      const backoffIndex = entry.count - BRUTE_FORCE_THRESHOLD;
      const backoffMs = Math.min(
        MAX_BACKOFF_MS,
        1000 * Math.pow(2, backoffIndex),
      );
      logger.warn(
        { clientIp, failedAttempts: entry.count, backoffMs },
        '[BruteForce] Backoff enforced',
      );
      return backoffMs;
    }

    return 0;
  }

  /**
   * Clear the brute-force failure count for a given IP.
   * Called on successful authentication.
   *
   * @param clientIp - The client IP address.
   */
  clearFailedAttempts(clientIp: string): void {
    this.bruteForceTracker.delete(clientIp);
    logger.debug({ clientIp }, '[BruteForce] Failure count cleared (successful auth)');
  }

  /**
   * Get the current brute-force tracking entry for an IP.
   * Returns null if no failures have been recorded.
   *
   * @param clientIp - The client IP address.
   */
  getBruteForceEntry(clientIp: string): BruteForceEntry | null {
    return this.bruteForceTracker.get(clientIp) ?? null;
  }

  /**
   * Check if a client IP is currently under brute-force backoff.
   *
   * @param clientIp - The client IP address to check.
   * @returns `true` if the IP has exceeded the failure threshold.
   */
  isUnderBackoff(clientIp: string): boolean {
    const entry = this.bruteForceTracker.get(clientIp);
    if (!entry) return false;
    return entry.count >= BRUTE_FORCE_THRESHOLD;
  }

  /**
   * Get the number of IPs currently being tracked for brute-force.
   */
  get trackedIpCount(): number {
    return this.bruteForceTracker.size;
  }

  /**
   * Clear all brute-force tracking data.
   */
  clearAllBruteForceData(): void {
    this.bruteForceTracker.clear();
  }
}
