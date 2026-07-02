/**
 * ConnectionManager — Centralised connection tracking and lifecycle management.
 *
 * Provides:
 *   - Register/unregister connections with session metadata
 *   - Force-terminate a connection (pg_terminate_backend equivalent)
 *   - Cancel a running query
 *   - List active queries (pg_stat_activity integration)
 *
 * Used by PgWireServer to track all active client connections and
 * implement pg_terminate_backend().
 *
 * @module monitoring/ConnectionManager
 */

import * as net from 'net';
import { PinoLogger } from '../monitoring/PinoLogger';
import type { PgSessionContext, ActiveQuery } from '../core/types';

const logger = PinoLogger.forComponent('ConnectionManager');

// ── Types ────────────────────────────────────────────────────────

export interface ConnectionEntry {
  socket: net.Socket;
  session: PgSessionContext;
  /** IP address of the client */
  clientAddress: string;
  /** Connection creation timestamp */
  connectedAt: number;
  /** Currently executing query (if any) */
  activeQuery: string | null;
  /** Query start time */
  queryStartedAt: number | null;
  /** Whether a query is currently being cancelled */
  cancelling: boolean;
}

export interface ActiveQueryInfo {
  sessionId: string;
  database: string;
  userName: string;
  query: string;
  state: 'active' | 'idle' | 'idle in transaction';
  queryStart: number;
  clientAddr: string;
  backendStart: number;
}

// ── ConnectionManager ────────────────────────────────────────────

export class ConnectionManager {
  private connections = new Map<string, ConnectionEntry>();

  /**
   * Register a new connection.
   */
  register(sessionId: string, socket: net.Socket, session: PgSessionContext): void {
    this.connections.set(sessionId, {
      socket,
      session,
      clientAddress: socket.remoteAddress || 'unknown',
      connectedAt: Date.now(),
      activeQuery: null,
      queryStartedAt: null,
      cancelling: false,
    });
    logger.debug({ sessionId, addr: socket.remoteAddress }, 'Connection registered');
  }

  /**
   * Unregister a connection (called on disconnect).
   */
  unregister(sessionId: string): void {
    this.connections.delete(sessionId);
    logger.debug({ sessionId }, 'Connection unregistered');
  }

  /**
   * Check if a connection is registered.
   */
  has(sessionId: string): boolean {
    return this.connections.has(sessionId);
  }

  /**
   * Get a connection entry by session ID.
   */
  getEntry(sessionId: string): ConnectionEntry | undefined {
    return this.connections.get(sessionId);
  }

  /**
   * Get the session context for a connection.
   */
  getSession(sessionId: string): PgSessionContext | undefined {
    return this.connections.get(sessionId)?.session;
  }

  /**
   * Update the active query for a connection.
   */
  setActiveQuery(sessionId: string, sql: string | null): void {
    const entry = this.connections.get(sessionId);
    if (entry) {
      entry.activeQuery = sql;
      entry.queryStartedAt = sql ? Date.now() : null;
      entry.cancelling = false;
    }
  }

  /**
   * Force-terminate a connection by session ID.
   * Sends a TCP RST and removes from tracking.
   *
   * @returns true if connection was found and terminated
   */
  terminate(sessionId: string): boolean {
    const entry = this.connections.get(sessionId);
    if (!entry) return false;

    try {
      // Destroy the socket (sends RST)
      entry.socket.destroy();
    } catch (_err) {
      // Socket may already be destroyed
    }

    this.connections.delete(sessionId);
    logger.warn({ sessionId }, 'Connection forcibly terminated');
    return true;
  }

  /**
   * Cancel a running query on a connection.
   * Sets a flag that the query handler can check to abort processing.
   *
   * @returns true if connection was found and cancel requested
   */
  cancelQuery(sessionId: string): boolean {
    const entry = this.connections.get(sessionId);
    if (!entry) return false;

    if (entry.activeQuery) {
      entry.cancelling = true;
      logger.warn({ sessionId, query: entry.activeQuery }, 'Query cancellation requested');
      return true;
    }
    return false;
  }

  /**
   * Check if a query should be cancelled (for use by query handlers).
   */
  isCancelling(sessionId: string): boolean {
    return this.connections.get(sessionId)?.cancelling ?? false;
  }

  /**
   * Get all active queries (pg_stat_activity style).
   */
  getActiveQueries(): ActiveQueryInfo[] {
    const queries: ActiveQueryInfo[] = [];
    for (const [sessionId, entry] of this.connections) {
      queries.push({
        sessionId,
        database: entry.session.database,
        userName: entry.session.userName,
        query: entry.activeQuery || '',
        state: entry.activeQuery
          ? 'active'
          : entry.session.transactionStatus === 'in_transaction'
            ? 'idle in transaction'
            : 'idle',
        queryStart: entry.queryStartedAt || entry.connectedAt,
        clientAddr: entry.clientAddress,
        backendStart: entry.connectedAt,
      });
    }
    return queries;
  }

  /**
   * Get the total number of registered connections.
   */
  get count(): number {
    return this.connections.size;
  }

  /**
   * Get all registered session IDs.
   */
  getSessionIds(): string[] {
    return [...this.connections.keys()];
  }

  /**
   * Unregister all connections (for shutdown).
   */
  clear(): void {
    // Destroy all sockets
    for (const [sessionId, entry] of this.connections) {
      try {
        entry.socket.destroy();
      } catch (_err) {
        // ignore
      }
    }
    this.connections.clear();
    logger.info('All connections cleared');
  }
}
