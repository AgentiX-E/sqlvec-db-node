/**
 * CancelRequestHandler — PG CancelRequest signal handling (Gap 15).
 *
 * PostgreSQL's CancelRequest is a special protocol message sent on a
 * separate connection to cancel an ongoing query on another session.
 *
 * CancelRequest format (on the startup message channel):
 *   Length: int32 (16)
 *   Code:   int32 (80877102 — CancelRequest magic number)
 *   PID:    int32 (backend PID to cancel)
 *   Key:    int32 (secret key for authentication)
 *
 * This module handles cancel request decoding and maintains a registry
 * of active queries that can be cancelled.
 *
 * References:
 *   https://www.postgresql.org/docs/current/protocol-flow-cancel.html
 *   https://www.postgresql.org/docs/current/protocol-message-types.html
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('CancelRequestHandler');

// ── Constants ────────────────────────────────────────────────────

/** CancelRequest magic number (0x4F52434C = 80877102) */
export const CANCEL_REQUEST_CODE = 80877102;

/** SSLRequest magic number (0x534C4830 = 80877103) */
export const SSL_REQUEST_CODE = 80877103;

// ── Types ────────────────────────────────────────────────────────

export interface CancelRequest {
  pid: number;
  secretKey: number;
}

export interface ActiveQuery {
  /** Unique query ID */
  queryId: string;
  /** PID of the backend session */
  pid: number;
  /** Secret key for cancel auth */
  secretKey: number;
  /** Cancel function — called to abort the query */
  cancelFn: () => void;
  /** Query start timestamp */
  startedAt: number;
  /** SQL text (truncated for logging) */
  sql: string;
}

// ── CancelRequestHandler ─────────────────────────────────────────

export class CancelRequestHandler {
  private activeQueries: Map<string, ActiveQuery> = new Map();
  private nextPid: number = 1;

  /**
   * Generate a new PID for a backend session.
   */
  generatePid(): number {
    return this.nextPid++;
  }

  /**
   * Decode a CancelRequest from a raw buffer.
   *
   * @param buf - The startup message buffer
   * @returns Parsed CancelRequest or null if not a valid cancel request
   */
  decodeCancelRequest(buf: Buffer): CancelRequest | null {
    try {
      // CancelRequest format: int32 length, int32 code, int32 pid, int32 key
      if (buf.length < 16) return null;

      const code = buf.readInt32BE(4);
      if (code !== CANCEL_REQUEST_CODE) return null;

      const pid = buf.readInt32BE(8);
      const secretKey = buf.readInt32BE(12);

      return { pid, secretKey };
    } catch {
      return null;
    }
  }

  /**
   * Register an active query that can be cancelled.
   *
   * @param queryId - Unique query identifier
   * @param sql - The SQL being executed
   * @param cancelFn - Function to call to abort the query
   * @param secretKey - Secret key for cancel auth (default: auto-generated)
   * @returns The registered ActiveQuery
   */
  registerQuery(
    queryId: string,
    sql: string,
    cancelFn: () => void,
    secretKey?: number,
  ): ActiveQuery {
    const pid = this.generatePid();
    const query: ActiveQuery = {
      queryId,
      pid,
      secretKey: secretKey ?? Math.floor(Math.random() * 2147483647),
      cancelFn,
      startedAt: Date.now(),
      sql: sql.substring(0, 200),
    };
    this.activeQueries.set(queryId, query);
    logger.debug({ queryId, pid, sql: query.sql }, 'Query registered for cancel');
    return query;
  }

  /**
   * Unregister a completed query.
   */
  unregisterQuery(queryId: string): void {
    this.activeQueries.delete(queryId);
    logger.debug({ queryId }, 'Query unregistered from cancel');
  }

  /**
   * Attempt to cancel a query using CancelRequest credentials.
   *
   * @param request - The decoded CancelRequest
   * @returns true if a matching query was found and cancelled
   */
  attemptCancel(request: CancelRequest): boolean {
    for (const [queryId, query] of this.activeQueries) {
      if (query.pid === request.pid && query.secretKey === request.secretKey) {
        logger.info({ pid: request.pid, queryId, sql: query.sql }, 'CancelRequest: cancelling query');
        try {
          query.cancelFn();
          this.activeQueries.delete(queryId);
          return true;
        } catch (err: any) {
          logger.error({ err: err.message, queryId }, 'CancelRequest: cancel function threw');
          return false;
        }
      }
    }

    logger.warn({ pid: request.pid }, 'CancelRequest: no active query found matching pid/secretKey');
    return false;
  }

  /**
   * Get all active query IDs.
   */
  getActiveQueryIds(): string[] {
    return [...this.activeQueries.keys()];
  }

  /**
   * Get count of active queries.
   */
  getActiveQueryCount(): number {
    return this.activeQueries.size;
  }

  /**
   * Check if a CancelRequest code matches.
   */
  static isCancelRequest(buf: Buffer): boolean {
    if (buf.length < 8) return false;
    try {
      const code = buf.readInt32BE(4);
      return code === CANCEL_REQUEST_CODE;
    } catch {
      return false;
    }
  }

  /**
   * Check if an SSLRequest code matches.
   */
  static isSslRequest(buf: Buffer): boolean {
    if (buf.length < 8) return false;
    try {
      const code = buf.readInt32BE(4);
      return code === SSL_REQUEST_CODE;
    } catch {
      return false;
    }
  }
}
