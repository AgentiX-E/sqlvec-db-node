/**
 * ConnectionPoolWrapper — Thin facade over SqlVecConnectionPool.
 *
 * PostgreSQL-style connection pool that wraps SqlVecConnectionPool
 * with PgBouncer-compatible operations, GUC-backed config, and
 * PoolModeRouter integration.
 *
 * This is the consolidated pool entry point. SqlVecConnectionPool
 * remains the implementation; this provides the public API.
 *
 * @module pool/ConnectionPoolWrapper
 */

import { SqlVecConnectionPool, type ConnectionPoolConfig } from './SqlVecConnectionPool';
import { PoolModeRouter, type PoolMode } from './PoolModeRouter';
import { PinoLogger } from '../monitoring/PinoLogger';
import { GucSystem } from '../core/GucSystem';

// ── Connection State ─────────────────────────────────────────────

interface ConnMeta {
  id: number;
  createdAt: number;
  lastUsed: number;
  inTransaction: boolean;
  preparedStmts: Map<string, boolean>; // stmt sql → cached
}

// ── Types ────────────────────────────────────────────────────────

export interface PoolWrapperConfig {
  min: number;
  max: number;
  /** superuser_reserved_connections — ensures superuser can always connect */
  superuserReserved: number;
  /** Idle connection timeout in ms (default: 300000 = 5 min) */
  idleTimeoutMs: number;
  /** Connection max lifetime in ms (default: 3600000 = 1 hour) */
  connectionLifetimeMs: number;
  /** Pool mode: session | transaction | statement */
  poolMode: PoolMode;
  /** GUC name for max_connections (for dynamic config) */
  gucMaxConnections: string;
  /** Database connection create function */
  createFn: () => Promise<any>;
  /** Database connection destroy function */
  destroyFn: (conn: any) => Promise<void>;
  /** Optional validation function */
  validateFn?: (conn: any) => boolean;
  acquireTimeoutMillis?: number;
}

const DEFAULT_WRAPPER_CONFIG: PoolWrapperConfig = {
  min: 1,
  max: 20,
  superuserReserved: 3,
  idleTimeoutMs: 300000,
  connectionLifetimeMs: 3600000,
  poolMode: 'session',
  gucMaxConnections: 'max_connections',
  createFn: async () => { throw new Error('createFn not configured'); },
  destroyFn: async () => {},
};

// ── ConnectionPoolWrapper ────────────────────────────────────────
export class ConnectionPoolWrapper {
  private impl: SqlVecConnectionPool<any>;
  private modeRouter: PoolModeRouter;
  private logger = PinoLogger.forComponent('ConnectionPoolWrapper');
  private config: PoolWrapperConfig;
  private connMeta = new WeakMap<object, ConnMeta>();
  private nextConnId = 1;
  private activeCount = 0;

  constructor(config?: Partial<PoolWrapperConfig>) {
    this.config = { ...DEFAULT_WRAPPER_CONFIG, ...config };

    const poolConfig: ConnectionPoolConfig = {
      min: this.config.min,
      max: this.config.max,
      createFn: () => this.createWrapped(),
      destroyFn: this.config.destroyFn,
      validateFn: this.config.validateFn || (() => true),
      acquireTimeoutMillis: this.config.acquireTimeoutMillis || 30000,
      leakDetectionThreshold: 60000,
    };

    this.impl = new SqlVecConnectionPool(poolConfig);
    // Wrap impl to meet PoolLike interface (PoolModeRouter uses Connection type)
    this.modeRouter = new PoolModeRouter(this.impl as any, this.config.poolMode);

    this.logger.info(
      { min: this.config.min, max: this.config.max, poolMode: this.config.poolMode },
      'ConnectionPoolWrapper initialized',
    );
  }

  private async createWrapped(): Promise<any> {
    const conn = await this.config.createFn();
    const meta: ConnMeta = {
      id: this.nextConnId++,
      createdAt: Date.now(),
      lastUsed: Date.now(),
      inTransaction: false,
      preparedStmts: new Map(),
    };
    this.connMeta.set(conn, meta);
    return conn;
  }

  /**
   * Acquire a connection.
   * Enforces max_connections via GucSystem.
   * Checks superuser_reserved_connections.
   */
  async acquire(isSuperuser: boolean = false): Promise<any> {
    const gucMax = this.readGucMaxConnections();
    const effectiveMax = gucMax - (isSuperuser ? 0 : this.config.superuserReserved);

    if (this.activeCount >= effectiveMax && !isSuperuser) {
      throw new Error(
        `Too many connections: max_connections=${gucMax}, ` +
        `superuser_reserved=${this.config.superuserReserved}, ` +
        `effective_max=${effectiveMax}, active=${this.activeCount}`,
      );
    }

    try {
      const conn = await this.modeRouter.acquire();
      this.activeCount++;
      const meta = this.connMeta.get(conn as object);
      if (meta) meta.lastUsed = Date.now();
      return conn;
    } catch (err) {
      this.logger.error({ err }, 'Failed to acquire connection from pool');
      throw err;
    }
  }

  /**
   * Release a connection.
   * Performs idle timeout / connection lifetime checks.
   */
  async release(conn: any): Promise<void> {
    const meta = this.connMeta.get(conn as object);

    // Check connection lifetime
    if (meta && (Date.now() - meta.createdAt) > this.config.connectionLifetimeMs) {
      this.logger.debug({ connId: meta.id }, 'Connection reached max lifetime, destroying');
      await this.config.destroyFn(conn);
      this.activeCount = Math.max(0, this.activeCount - 1);
      return;
    }

    // Check idle timeout (lastUsed)
    if (meta && (Date.now() - meta.lastUsed) > this.config.idleTimeoutMs) {
      this.logger.debug({ connId: meta.id }, 'Connection idle timeout, destroying');
      await this.config.destroyFn(conn);
      this.activeCount = Math.max(0, this.activeCount - 1);
      return;
    }

    try {
      this.modeRouter.release(conn as any);
      this.activeCount = Math.max(0, this.activeCount - 1);
      if (meta) meta.lastUsed = Date.now();
    } catch (err) {
      this.logger.error({ err }, 'Failed to release connection');
    }
  }

  // ── Pool Mode ──────────────────────────────────────────────────

  get poolMode(): PoolMode {
    return this.modeRouter.mode;
  }

  set poolMode(mode: PoolMode) {
    this.modeRouter.mode = mode;
  }

  // ── Transaction Tracking ──────────────────────────────────────

  markTransactionStart(conn: any): void {
    this.impl.markTransactionStart(conn);
    const meta = this.connMeta.get(conn as object);
    if (meta) meta.inTransaction = true;
  }

  markTransactionEnd(conn: any): void {
    this.impl.markTransactionEnd(conn);
    const meta = this.connMeta.get(conn as object);
    if (meta) meta.inTransaction = false;
    this.modeRouter.onTransactionEnd();
  }

  isInTransaction(conn: any): boolean {
    return this.impl.isInTransaction(conn);
  }

  // ── Prepared Statement Cache (per-connection) ─────────────────

  cachePreparedStatement(conn: any, sql: string): void {
    const meta = this.connMeta.get(conn as object);
    if (meta) {
      meta.preparedStmts.set(sql, true);
    }
  }

  hasPreparedStatement(conn: any, sql: string): boolean {
    const meta = this.connMeta.get(conn as object);
    return meta ? meta.preparedStmts.has(sql) : false;
  }

  clearPreparedStatements(conn: any): void {
    const meta = this.connMeta.get(conn as object);
    if (meta) meta.preparedStmts.clear();
  }

  getNumPreparedStatements(conn: any): number {
    const meta = this.connMeta.get(conn as object);
    return meta ? meta.preparedStmts.size : 0;
  }

  // ── Metrics ───────────────────────────────────────────────────

  get numUsed(): number { return this.impl.numUsed; }
  get numFree(): number { return this.impl.numFree; }
  get numPending(): number { return this.impl.numPending; }
  get inTransactionCount(): number { return this.impl.inTransactionCount; }
  get activeConnections(): number { return this.activeCount; }
  get idleConnections(): number { return Math.max(0, this.impl.numFree); }

  /** Total connections (active + idle) */
  get totalConnections(): number {
    return this.activeConnections + this.idleConnections;
  }

  // ── Lifecycle ─────────────────────────────────────────────────

  async destroy(): Promise<void> {
    await this.impl.destroy();
    this.activeCount = 0;
    this.logger.info('ConnectionPoolWrapper destroyed');
  }

  // ── Private ───────────────────────────────────────────────────

  private readGucMaxConnections(): number {
    try {
      return GucSystem.getInt('max_connections') ?? this.config.max;
    } catch {
      return this.config.max;
    }
  }
}

// Export underlying pool implementation for direct use when needed
export { SqlVecConnectionPool } from './SqlVecConnectionPool';
export { PoolModeRouter, type PoolMode } from './PoolModeRouter';
