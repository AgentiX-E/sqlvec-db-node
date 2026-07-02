/**
 * CircuitBreaker — Lightweight PG-style circuit breaker for Raft RPC.
 *
 * Implements a simple state machine:
 *   CLOSED  ──(failure threshold reached)──► OPEN
 *   OPEN    ──(recovery timeout elapsed)──►  HALF_OPEN
 *   HALF_OPEN ──(success)──► CLOSED
 *   HALF_OPEN ──(failure)──► OPEN
 *
 * No external dependencies. Designed for Raft peer RPC circuit breaking.
 *
 * @module CircuitBreaker
 */

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

/**
 * Lightweight PG-style circuit breaker for Raft RPC.
 */
export class CircuitBreaker {
  private _state: CircuitState = 'CLOSED';
  private _failureCount = 0;
  private _lastFailureTime = 0;
  private _halfOpenSuccessCount = 0;

  constructor(
    private readonly name: string,
    private readonly threshold: number = 5,
    private readonly recoveryTimeoutMs: number = 30000,
    private readonly halfOpenMaxRequests: number = 3,
  ) {}

  /**
   * Check if a request is allowed through the circuit breaker.
   *
   * - CLOSED: always allowed
   * - OPEN: only allowed if recovery timeout has elapsed (transitions to HALF_OPEN)
   * - HALF_OPEN: allowed if we haven't exceeded halfOpenMaxRequests since entering HALF_OPEN
   *
   * @returns `true` if the request should be allowed through.
   */
  allowRequest(): boolean {
    switch (this._state) {
      case 'CLOSED':
        return true;

      case 'OPEN':
        if (Date.now() - this._lastFailureTime >= this.recoveryTimeoutMs) {
          // Transition to half-open and allow the probe request
          this._state = 'HALF_OPEN';
          this._halfOpenSuccessCount = 0;
          return true;
        }
        return false;

      case 'HALF_OPEN':
        // Allow up to halfOpenMaxRequests probe requests
        if (this._halfOpenSuccessCount < this.halfOpenMaxRequests) {
          return true;
        }
        // If we've already used all probe slots, block until one completes
        return false;

      default:
        return true;
    }
  }

  /**
   * Record a successful call.
   *
   * - CLOSED: resets failure count to 0
   * - HALF_OPEN: increments success count; if at or above halfOpenMaxRequests, transitions to CLOSED
   */
  onSuccess(): void {
    switch (this._state) {
      case 'CLOSED':
        this._failureCount = 0;
        break;

      case 'HALF_OPEN':
        this._halfOpenSuccessCount++;
        if (this._halfOpenSuccessCount >= this.halfOpenMaxRequests) {
          // Circuit healed — transition to CLOSED
          this._state = 'CLOSED';
          this._failureCount = 0;
          this._halfOpenSuccessCount = 0;
        }
        break;

      case 'OPEN':
        // Still open, success has no meaning
        break;
    }
  }

  /**
   * Record a failed call.
   *
   * - CLOSED: increments failure count; if threshold reached, transitions to OPEN
   * - HALF_OPEN: transitions back to OPEN (probe failed)
   * - OPEN: updates last failure time
   */
  onFailure(): void {
    this._lastFailureTime = Date.now();

    switch (this._state) {
      case 'CLOSED':
        this._failureCount++;
        if (this._failureCount >= this.threshold) {
          this._state = 'OPEN';
        }
        break;

      case 'HALF_OPEN':
        // Probe failed — back to OPEN
        this._state = 'OPEN';
        this._halfOpenSuccessCount = 0;
        break;

      case 'OPEN':
        // Stay open, just update the failure timestamp
        break;
    }
  }

  /**
   * Get the current circuit breaker state.
   */
  getState(): CircuitState {
    return this._state;
  }

  /**
   * Get the current failure count.
   */
  getFailureCount(): number {
    return this._failureCount;
  }

  /**
   * Get the timestamp of the last failure (epoch ms).
   */
  getLastFailureTime(): number {
    return this._lastFailureTime;
  }

  /**
   * Get the circuit breaker name.
   */
  getName(): string {
    return this.name;
  }

  /**
   * Reset the circuit breaker to CLOSED state.
   * Clears all failure counts and resets timestamps.
   */
  reset(): void {
    this._state = 'CLOSED';
    this._failureCount = 0;
    this._lastFailureTime = 0;
    this._halfOpenSuccessCount = 0;
  }

  /**
   * Get the threshold for opening the circuit.
   */
  getThreshold(): number {
    return this.threshold;
  }

  /**
   * Get the recovery timeout in ms.
   */
  getRecoveryTimeoutMs(): number {
    return this.recoveryTimeoutMs;
  }
}
