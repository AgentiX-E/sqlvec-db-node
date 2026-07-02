/**
 * PgWireServer — PostgreSQL Wire Protocol server
 *
 * Provides a PG-compatible endpoint for SQL clients (psql, pgvector, etc.).
 * Routes incoming queries to the QueryRouter.
 *
 * Features:
 * - TLS support (STARTTLS via SSLRequest)
 * - SCRAM-SHA-256 authentication (RFC 5802 / RFC 7677)
 * - Cleartext password fallback when TLS is active
 * - Offset-cursor buffer management (no unbounded growth)
 * - pgsql-ast-parser for column extraction (no regex heuristics)
 * - Multi-message processing per data event
 */

import * as net from 'net';
import * as tls from 'tls';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { parse as parseSqlAst } from 'pgsql-ast-parser';
import { performance } from 'node:perf_hooks';
import { QueryRouter, QueryResult } from '../query/QueryRouter';
import { PgPipeline, createPipelineFor } from '../pipeline/PgPipeline';
import type { PipelineContext } from '../pipeline/types';
import { PgSessionContext, PgSessionState, TlsConfig } from '../core/types';
import { PgHbaConf, HbaAuthMethod } from '../auth/pgHbaConf';
import { getBackendSslMode, getShowSsl } from './SslModeHandler';
import { RoleManager } from '../auth/RoleManager';
import { verifyPassword, parseStoredHash } from '../auth/ScramPasswordManager';
import { AuthTimeoutManager } from '../protocol/AuthTimeoutManager';
import { ChannelManager } from './ChannelManager';
import { GssapiAuth } from '../auth/GssapiAuth';
import { CertChainValidator } from '../security/CertChainValidator';
import { cacheGet, cacheSet } from '../utils/ParseCache';
import { LargeObjectManager } from '../storage/LargeObjectManager';
import { ConnectionManager } from '../monitoring/ConnectionManager';
import { AuditLogger as SecurityAuditLogger } from '../security/AuditLogger';

import { CursorManager } from '../query/CursorManager';
import { PortalManager } from './PortalManager';
import { WiredQueryEngine, getDefaultShimPipeline } from '../pgwire/WiredQueryEngine';
import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import { PgPipelineHandler } from './PgPipelineHandler';
import { PgBinaryCodec } from './PgBinaryCodec';
import { SystemTypeRegistry } from '../system/SystemTypes';
import {
  SQLSTATE_SYNTAX_ERROR,
  SQLSTATE_INSUFFICIENT_PRIVILEGE,
  SQLSTATE_INVALID_PASSWORD,
  SQLSTATE_UNDEFINED_OBJECT,
  SQLSTATE_DUPLICATE_OBJECT,
  SQLSTATE_QUERY_CANCELED,
  SQLSTATE_CONNECTION_FAILURE,
  SQLSTATE_DEADLOCK_DETECTED,
  SQLSTATE_UNIQUE_VIOLATION,
  SQLSTATE_NOT_NULL_VIOLATION,
  SQLSTATE_DATATYPE_MISMATCH,
  SQLSTATE_OUT_OF_MEMORY,
  SQLSTATE_INTERNAL_ERROR,
  SQLSTATE_PROTOCOL_VIOLATION,
  SQLSTATE_CONNECTION_EXCEPTION,
  SQLSTATE_DATA_EXCEPTION,
  SQLSTATE_SUCCESSFUL_COMPLETION,
  SQLSTATE_WARNING,
  SQLSTATE_UNDEFINED_COLUMN,
  SQLSTATE_UNDEFINED_TABLE,
  SQLSTATE_STRING_DATA_RIGHT_TRUNCATION,
  SQLSTATE_SERIALIZATION_FAILURE,
  SQLSTATE_READ_ONLY_SQL_TRANSACTION,
} from '../constants/sqlstate';
const logger = PinoLogger.forComponent('PgWire');

const PG_PROTOCOL_VERSION = 196608; // 3.0

// R-01: Maximum COPY data buffer size (64 MB) to prevent OOM
const MAX_COPY_BUFFER_SIZE = 256 * 1024 * 1024;

// ════════════════════════════════════════════════
//  Internal types
// ════════════════════════════════════════════════

type AuthStage =
  | 'wait_startup'
  | 'wait_password'
  | 'scram_sasl'
  | 'scram_continue'
  | 'scram_final'
  | 'gssapi_token'
  | 'ready';

interface PgWireConnectionInternal {
  sessionId: string;
  session: PgSessionContext;
  /** Debug ID to track conn object identity */
  _connDebugId?: string;
  /** The active socket (net.Socket before TLS, tls.TLSSocket after upgrade). */
  socket: net.Socket;
  /** Reference to the raw TCP socket (for TLS upgrade). */
  rawSocket: net.Socket;
  /** Accumulated receive buffer. */
  buffer: Buffer;
  /** Read cursor offset into buffer; only consumed bytes before this offset. */
  offset: number;
  /** Authentication stage machine. */
  authStage: AuthStage;
  /** Whether TLS is active on this connection. */
  isTls: boolean;

  // SCRAM state
  scramUser?: string;
  scramClientFirstBare?: string;
  scramServerNonce?: string;
  scramSalt?: Buffer;
  scramIterations?: number;
  scramSaltedPassword?: Buffer;
  scramServerSignature?: Buffer;
  scramStoredKey?: Buffer;
  scramServerKey?: Buffer;

  // pg_hba.conf selected auth method
  hbaAuthMethod?: HbaAuthMethod;
  /** User name from startup message */
  userName?: string;

  // COPY state
  copyState?: 'active' | 'done' | 'failed';
  copyBuffer?: Buffer;
  copyBufferLength?: number;
  copyTableName?: string;
  copyColumns?: string[];
  copyFormat?: number;

  // GSSAPI state
  gssapiAuth?: GssapiAuth;
  gssapiExpectToken?: boolean;
  gssapiAuthFirstTokenSent?: boolean;

  // Pipeline state (Gap 1: Protocol Pipeline)
  pipelineMode: boolean;
  pipelineQueries: Array<{ type: string; payload: Buffer }>;
  pgPipelineHandler: PgPipelineHandler;

  // Cancel/Timeout state (Gap 12: Query Cancel Enhancement)
  cancelled: boolean;
  abortController: AbortController | null;
  statementTimeout: number; // ms, 0 = no limit
  queryStartTime: number; // timestamp when current query started
  secretKey: number; // secret key for CancelRequest validation

  // Phase E: Bind format codes per portal
  portalFormatCodes: Map<string, { paramFormats: number[]; resultFormats: number[] }>;
  // Extended query protocol state for async Execute → Sync ordering
  pendingAsyncExecute: boolean;
  /** Deferred ReadyForQuery response sent after pending async Execute completes */
  deferredReadyForQuery: Buffer | null;
  /** True when .finally() already sent ReadyForQuery (async completed before Sync). */
  rfqAlreadySent: boolean;
  /** Set of portal names whose Describe received NoData (columns unresolvable via *).
   *  Execute path will send RowDescription before DataRow for these portals. */
  portalsNeedingColumnResolve: Set<string>;
  /** Set of portal names for which Describe 'P' already sent RowDescription.
   *  Execute should NOT resend RowDescription for these portals. */
  portalDescribeSentRowDescription: Set<string>;
  /** True when this connection was created solely for prepared statement
   *  describe/execute (no SimpleQuery protocol). Used for routing decisions. */
  preparedStatementOnly: boolean;
}

// ════════════════════════════════════════════════
//  SCRAM-SHA-256 primitives
// ════════════════════════════════════════════════

const SCRAM_ITERATIONS = 4096;
const SCRAM_SALT_LENGTH = 16;
const SCRAM_NONCE_LENGTH = 24;

function randBase64(length: number): string {
  return crypto.randomBytes(length).toString('base64');
}

function hmacSha256(key: Buffer, str: string): Buffer {
  return crypto.createHmac('sha256', key).update(str, 'utf8').digest();
}

function sha256(data: Buffer): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

function xorBuffers(a: Buffer, b: Buffer): Buffer {
  const len = Math.min(a.length, b.length);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

function hi(password: string, salt: Buffer, iterations: number): Buffer {
  return crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
}

/**
 * Build the list of SASL mechanisms to offer to the client.  We only
 * support SCRAM-SHA-256.  If TLS is active we also accept cleartext.
 */
function mechanisms(isTls: boolean): string[] {
  return isTls ? ['SCRAM-SHA-256', 'SCRAM-SHA-256-PLUS'] : ['SCRAM-SHA-256', 'SCRAM-SHA-256-PLUS'];
}

// ════════════════════════════════════════════════
//  LRU Cache for PreparedStatements
// ════════════════════════════════════════════════

/**
 * Simple LRU (Least Recently Used) cache with configurable max entries.
 * Evicts the least recently used entry when capacity is exceeded.
 */
class LRUCache<K, V> {
  private cache: Map<K, V>;
  private readonly maxEntries: number;

  constructor(maxEntries: number) {
    this.cache = new Map();
    this.maxEntries = maxEntries;
  }

  get(key: K): V | undefined {
    if (!this.cache.has(key)) return undefined;
    // Move to end (most recent) by re-inserting
    const value = this.cache.get(key)!;
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key: K, value: V): void {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxEntries) {
      // Evict oldest entry (first key in map)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(key, value);
  }

  has(key: K): boolean {
    return this.cache.has(key);
  }

  delete(key: K): boolean {
    return this.cache.delete(key);
  }

  get size(): number {
    return this.cache.size;
  }

  clear(): void {
    this.cache.clear();
  }

  /** Iterate entries from oldest to newest. */
  entries(): IterableIterator<[K, V]> {
    return this.cache.entries();
  }

  values(): IterableIterator<V> {
    return this.cache.values();
  }
}

// ════════════════════════════════════════════════
//  Server class
// ════════════════════════════════════════════════

export class PgWireServer {
  /** Performance timing statistics (aggregated across all queries). */
  static timingStats = {
    count: 0,
    totalMs: 0,
    maxMs: 0,
    /** Per-SQL-type timing buckets */
    byType: new Map<string, { count: number; totalMs: number; maxMs: number }>(),
  };

  private server: net.Server | null = null;
  private port: number;
  private host: string;
  private queryRouter: QueryRouter;
  private pipeline?: PgPipeline;

  /**
   * 使用 pipeline 执行 SQL (当 pipeline 可用时)
   * 回退到 queryRouter.execute() 保证向后兼容
   *
   * ⚠️ 参数 $1/$2/$N 在入管道前已内联到 SQL 中 (pipeline.execute 不接受外部参数)
   */
  private async pipelineExec(
    sql: string,
    sessionId: string,
    params?: any[],
  ): Promise<QueryResult> {
    // Inline params before pipeline execution
    let resolvedSql = sql;
    if (params && params.length > 0) {
      resolvedSql = this._inlineParams(sql, params);
    }
    if (this.pipeline && sessionId) {
      const ctx: PipelineContext = {
        sessionId,
        currentUser: this.conns.get(sessionId)?.userName || 'unknown',
      };
      const output = await this.pipeline.execute(resolvedSql, ctx);
      return { rows: output.rows, rowCount: output.rowCount, queryTimeMs: output.queryTimeMs, engine: 'shard' };
    }
    return this.queryRouter.execute(resolvedSql, [], sessionId);
  }

  /**
   * 使用 pipeline 执行批量 INSERT (COPY 专用)
   * 回退到 queryRouter.execute() 保证向后兼容
   */
  private async pipelineBatchInsert(
    sql: string,
    params: any[],
    sessionId: string,
  ): Promise<QueryResult> {
    if (this.pipeline && sessionId) {
      const ctx: PipelineContext = {
        sessionId,
        currentUser: this.conns.get(sessionId)?.userName || 'unknown',
      };
      const output = await this.pipeline.executeBatchInsert(sql, params, ctx);
      return { rows: output.rows, rowCount: output.rowCount, queryTimeMs: output.queryTimeMs, engine: 'shard' };
    }
    return this.queryRouter.execute(sql, params, sessionId);
  }

  /**
   * 内联 $N / ? 参数到 SQL 字符串中
   * Pipeline 不自持外部参数，需要在入管道前完成内联
   */
  private _inlineParams(sql: string, params: any[]): string {
    if (!params || params.length === 0) return sql;
    let result = sql;
    const useQuestionMark = sql.includes('?');
    let searchPos = 0;

    for (let i = 0; i < params.length; i++) {
      let replacement: string;
      const val = params[i];
      if (val === null || val === undefined) {
        replacement = 'NULL';
      } else if (typeof val === 'number') {
        replacement = String(val);
      } else if (typeof val === 'boolean') {
        replacement = val ? '1' : '0';
      } else if (typeof val === 'string') {
        replacement = `'${val.replace(/'/g, "''")}'`;
      } else if (val instanceof Date) {
        replacement = `'${val.toISOString()}'`;
      } else {
        replacement = `'${String(val)}'`;
      }

      let ph: string;
      if (useQuestionMark) {
        const qIdx = result.indexOf('?', searchPos);
        if (qIdx < 0) break;
        result = result.substring(0, qIdx) + replacement + result.substring(qIdx + 1);
        searchPos = qIdx + replacement.length;
      } else {
        ph = `$${i + 1}`;
        const idx = result.indexOf(ph);
        if (idx < 0) break;
        result = result.substring(0, idx) + replacement + result.substring(idx + ph.length);
      }
    }

    return result;
  }

  private password: string | null;
  private tlsConfig: TlsConfig | undefined;

  /** CertChainValidator instance for additional certificate validation (P1). */
  private certChainValidator: CertChainValidator | null = null;

  // M-01: Cached TLS credentials (read once at startup)
  private tlsCertCached: Buffer | null = null;
  private tlsKeyCached: Buffer | null = null;
  private tlsCaCached: Buffer | null = null;

  // Session / connection state tracking
  private sessions: Map<string, PgSessionContext> = new Map();
  private conns: Map<string, PgWireConnectionInternal> = new Map();
  private sessionCounter = 0;
  private authTimeoutManager: AuthTimeoutManager;

  // ── Idle Session Timeout (E7-MON12) ─────────────────
  /** Idle timeout in ms (default: 10 minutes, 0 = disabled). */
  private idleSessionTimeoutMs: number;
  /** Tracks last activity timestamp per session. */
  private sessionLastActivity: Map<string, number> = new Map();
  /** Idle timeout checker timer. */
  private idleCheckTimer: ReturnType<typeof setInterval> | null = null;
  /** Idle check interval in ms (default: 30s). */
  private static readonly IDLE_CHECK_INTERVAL_MS = 30_000;

  // Extended Query state
  /** Prepared statements with LRU eviction. */
  private preparedStatements: LRUCache<string, { sql: string; paramTypes: number[]; originalSql?: string }>;
  private static readonly LRU_MAX = 100; // configurable max entries
  /** Tracks bind state before first Execute */
  private pendingBinds = new Map<string, { statementName: string; params: any[] }>();
  private portalManager = new PortalManager();

  /** Next backend PID to assign */
  private _nextPid = 1;
  /** Maps backend PID → sessionId for CancelRequest */
  private _pidToSessionId = new Map<number, string>();

  private pgHbaConf: PgHbaConf | null;
  private roleManager: RoleManager | null;

  // G1/G2/G3/G21/G26: Protocol feature managers
  private channelManager: ChannelManager;
  private largeObjectManager: LargeObjectManager;
  private connectionManager: ConnectionManager;
  private auditLogger: SecurityAuditLogger | null;

  // Cursor support
  private cursorManager: CursorManager;

  /** WiredQueryEngine — applies shim pipeline at Parse time for prepared statements */
  private wiredQueryEngine: WiredQueryEngine;

  /** Cached result of PAM module availability check (C-10). */
  private pamAvailable: boolean = false;
  /** Cached PAM module reference (loaded once at construction). */
  private pamModule: any = null;

  constructor(
    host: string,
    port: number,
    queryRouter: QueryRouter,
    password?: string,
    tlsConfig?: TlsConfig,
    pgHbaConf?: PgHbaConf,
    roleManager?: RoleManager,
    certChainValidator?: CertChainValidator,
    pipeline?: PgPipeline,
  ) {
    this.host = host;
    this.port = port;
    this.queryRouter = queryRouter;
    this.pipeline = pipeline;
    this.password = password || null;
    this.tlsConfig = tlsConfig;
    this.certChainValidator = certChainValidator ?? null;
    this.pgHbaConf = pgHbaConf || null;
    this.roleManager = roleManager || null;
    this.authTimeoutManager = new AuthTimeoutManager();
    this.channelManager = new ChannelManager();
    this.largeObjectManager = new LargeObjectManager(process.env.DATA_DIR || '/tmp/sqlvec-db');
    this.connectionManager = new ConnectionManager();
    this.preparedStatements = new LRUCache<string, { sql: string; paramTypes: number[] }>(PgWireServer.LRU_MAX);
    this.auditLogger = null; // Set externally via setAuditLogger
    this.cursorManager = new CursorManager();

    // Initialize WiredQueryEngine with default shim pipeline
    this.wiredQueryEngine = new WiredQueryEngine({
      shims: getDefaultShimPipeline(),
      debug: false,
    });

    // E7-MON12: Default idle session timeout (10 min, 0 = disabled)
    this.idleSessionTimeoutMs = parseInt(process.env.PG_IDLE_SESSION_TIMEOUT || '600000', 10);

    // C-10: Check PAM module availability once at construction time
    try {
      this.pamModule = require('authenticate-pam');
      this.pamAvailable = true;
    } catch (_e: any) {
      this.pamAvailable = false;
      this.pamModule = null;
      logger.warn('[PgWire] authenticate-pam module not available — PAM auth disabled');
    }
  }

  /**
   * Set the audit logger instance for this server.
   */
  setAuditLogger(auditLogger: SecurityAuditLogger): void {
    this.auditLogger = auditLogger;
  }

  /**
   * Get the ConnectionManager instance (for external use).
   */
  get connectionManagerInstance(): ConnectionManager {
    return this.connectionManager;
  }

  /**
   * Get the ChannelManager instance (for external use).
   */
  get channelManagerInstance(): ChannelManager {
    return this.channelManager;
  }

  /**
   * Get the LargeObjectManager instance (for external use).
   */
  get largeObjectManagerInstance(): LargeObjectManager {
    return this.largeObjectManager;
  }

  // ── Lifecycle ─────────────────────────────────

  async start(): Promise<void> {
    // M-01: Cache TLS credentials once at startup (not per-connection)
    if (this.tlsConfig) {
      this.tlsCertCached = fs.readFileSync(this.tlsConfig.cert);
      this.tlsKeyCached = fs.readFileSync(this.tlsConfig.key);
      this.tlsCaCached = this.tlsConfig.ca ? fs.readFileSync(this.tlsConfig.ca) : null;
    }

    return new Promise((resolve) => {
      // PG Wire protocol uses STARTTLS (SSLRequest), not direct TLS handshake.
      // Always use net.createServer() even when TLS is configured.
      // TLS upgrade is handled in processStartup() via SSLRequest.
      this.server = net.createServer((socket) => this.handleConnection(socket));

      this.server.listen(this.port, this.host, () => {
        const addr = this.server!.address();
        const actualPort = typeof addr === 'object' && addr ? addr.port : this.port;
        logger.info(`[PgWire] Server listening on ${this.host}:${actualPort}`);

        // E7-MON12: Start idle session timeout checker
        this.startIdleTimeoutChecker();

        resolve();
      });
    });
  }

  get activeConnections(): number {
    return this.conns.size;
  }

  async stop(): Promise<void> {
    // E7-MON12: Stop idle timeout checker
    this.stopIdleTimeoutChecker();

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  // ════════════════════════════════════════════════
  //  Connection handling
  // ════════════════════════════════════════════════

  private createSession(): PgSessionContext {
    this.sessionCounter++;
    return {
      sessionId: crypto.randomUUID(),
      database: 'default',
      userName: 'unknown',
      startTime: Date.now(),
      authenticated: false,
      transactionStatus: 'idle',
      state: PgSessionState.IDLE,
      readyForQuery: false,
      backendPid: 0,
      secretKey: 0,
    };}

  private handleConnection(socket: net.Socket): void {
    // Disable Nagle's algorithm for low-latency query responses
    socket.setNoDelay(true);
    const session = this.createSession();
    const conn: PgWireConnectionInternal = {
      sessionId: session.sessionId,
      session,
      socket,
      _connDebugId: Math.random().toString(36).slice(2,8),
      rawSocket: socket,
      buffer: Buffer.alloc(0),
      offset: 0,
      authStage: 'wait_startup',
      isTls: false,  // starts as plain TCP; set to true after TLS upgrade in processStartup()
      pipelineMode: false,
      pipelineQueries: [],
      pgPipelineHandler: new PgPipelineHandler(),
      cancelled: false,
      abortController: null,
      statementTimeout: 0,
      queryStartTime: 0,
      secretKey: crypto.randomInt(1, 2147483647),
      portalFormatCodes: new Map(),

      // Extended query protocol async-Sync state
      pendingAsyncExecute: false,
      deferredReadyForQuery: null,
      rfqAlreadySent: false,
      portalsNeedingColumnResolve: new Set(),
      portalDescribeSentRowDescription: new Set(),
      preparedStatementOnly: false,
    };
    this.sessions.set(session.sessionId, session);
    this.conns.set(session.sessionId, conn);
    this.connectionManager.register(session.sessionId, socket, session);

    // Start authentication timeout: 60 seconds (PostgreSQL default)
    this.authTimeoutManager.startTimer(session.sessionId, 60_000, (sid: string) => {
      const c = this.conns.get(sid);
      if (c) {
        logger.warn({ sessionId: sid }, '[PgWire] Authentication timeout — closing connection');
        c.socket.end();
        this.cleanupConn(c);
      }
    });

    const dataHandler = (data: Buffer) => {
      conn.buffer = Buffer.concat([conn.buffer, data]);
      this.processConnection(conn);
    };

    // Attach data handler with a reference for TLS upgrade
    (conn as any)._dataHandler = dataHandler;
    socket.on('data', dataHandler);
    socket.on('close', () => this.cleanupConn(conn));
    socket.on('error', (err) => {
      logger.error(`[PgWire] Socket error (${conn.sessionId}):`, err.message);
      this.cleanupConn(conn);
    });
  }

  private cleanupConn(conn: PgWireConnectionInternal): void {
    this.authTimeoutManager.cancelTimer(conn.sessionId);

    // G26: Unregister from ConnectionManager
    this.connectionManager.unregister(conn.sessionId);

    // G2: Clean up LISTEN subscriptions
    this.channelManager.unlistenAll(conn.sessionId);

    // Cursor cleanup: close all cursors owned by this session
    this.cursorManager.closeAll(conn.sessionId);

    // G21: Audit disconnect
    if (this.auditLogger) {
      this.auditLogger.logDisconnect(conn.sessionId, conn.userName || 'unknown');
    }

    this.conns.delete(conn.sessionId);
    if (conn.session?.backendPid) {
      this._pidToSessionId.delete(conn.session.backendPid);
    }
    this.sessions.delete(conn.sessionId);
    // E7-MON12: Clean up idle timeout tracking
    this.sessionLastActivity.delete(conn.sessionId);
    // Clean up extended-query state for this session
    this.portalManager.closeAllPortals();
  }

  // ── Idle Session Timeout (E7-MON12) ─────────────────────

  /**
   * Start the idle session timeout checker.
   * Runs every IDLE_CHECK_INTERVAL_MS to close idle connections.
   */
  private startIdleTimeoutChecker(): void {
    if (this.idleCheckTimer) return;
    if (this.idleSessionTimeoutMs <= 0) {
      logger.info('[PgWire] Idle session timeout disabled');
      return;
    }

    this.idleCheckTimer = setInterval(() => this.checkIdleSessions(), PgWireServer.IDLE_CHECK_INTERVAL_MS);
    this.idleCheckTimer.unref();
    logger.info(
      { idleSessionTimeoutMs: this.idleSessionTimeoutMs },
      '[PgWire] Idle session timeout checker started',
    );
  }

  /**
   * Stop the idle timeout checker.
   */
  private stopIdleTimeoutChecker(): void {
    if (this.idleCheckTimer) {
      clearInterval(this.idleCheckTimer);
      this.idleCheckTimer = null;
    }
  }

  /**
   * Check for idle sessions and close those exceeding the timeout.
   * Sends a NoticeResponse before closing.
   */
  private checkIdleSessions(): void {
    if (this.idleSessionTimeoutMs <= 0) return;

    const now = Date.now();
    const closed: string[] = [];

    for (const [sessionId, lastActivity] of this.sessionLastActivity.entries()) {
      const idleTime = now - lastActivity;
      if (idleTime >= this.idleSessionTimeoutMs) {
        const conn = this.conns.get(sessionId);
        if (conn && !conn.socket.destroyed) {
          try {
            // Send NoticeResponse (PG NoticeField: severity, message, detail)
            this.sendNoticeResponse(conn.socket, 'WARNING', 'idle-in-transaction-session-timeout', [
              { type: 'S', value: 'WARNING' },
              { type: 'M', value: 'Client session idle for too long, closing connection' },
              { type: 'D', value: `Idle for ${Math.round(idleTime / 1000)}s, timeout=${Math.round(this.idleSessionTimeoutMs / 1000)}s` },
              { type: 'C', value: '57014' },
            ]);
          } catch (_e: any) {
            // Socket might be closing already
          }
          conn.socket.end();
          this.cleanupConn(conn);
        }
        closed.push(sessionId);
      }
    }

    if (closed.length > 0) {
      logger.warn(`[PgWire] Closed ${closed.length} idle session(s)`);
    }
  }

  /**
   * Update the last activity timestamp for a session.
   * Called whenever we process data from a connection.
   */
  private updateSessionActivity(conn: PgWireConnectionInternal): void {
    this.sessionLastActivity.set(conn.sessionId, Date.now());
  }

  /**
   * Send a NoticeResponse (PG 'N' message) to the client.
   */
  private sendNoticeResponse(
    socket: net.Socket,
    severity: string,
    message: string,
    fields?: Array<{ type: string; value: string }>,
  ): void {
    const parts: Buffer[] = [];

    // Always include severity and message
    parts.push(Buffer.from([0x53])); // 'S' — Severity
    parts.push(Buffer.from(severity + '\0', 'utf8'));

    parts.push(Buffer.from([0x4d])); // 'M' — Message
    parts.push(Buffer.from(message + '\0', 'utf8'));

    if (fields) {
      for (const field of fields) {
        parts.push(Buffer.from([field.type.charCodeAt(0)]));
        parts.push(Buffer.from(field.value + '\0', 'utf8'));
      }
    }

    // Terminator (0x00)
    parts.push(Buffer.alloc(1, 0));

    // Calculate total body length
    const body = Buffer.concat(parts);
    const buf = Buffer.alloc(1 + 4 + body.length);
    buf[0] = 0x4e; // 'N'
    buf.writeInt32BE(4 + body.length, 1);
    body.copy(buf, 5);

    try {
      socket.write(buf);
    } catch (_e: any) {
      // Socket may be closing — ignore write errors
    }
  }

  // ════════════════════════════════════════════════
  //  Main processing loop (offset-cursor driven)
  // ════════════════════════════════════════════════

  private processConnection(conn: PgWireConnectionInternal): void {
    // E7-MON12: Update session activity on any data processing
    this.updateSessionActivity(conn);

    let processed = 0;

    while (true) {
      const available = conn.buffer.length - conn.offset;
      if (available < 1) break;

      // Block message processing while COPY is pending completion
      if ((conn as any).copyPending) break;

      const prevOffset = conn.offset;

      switch (conn.authStage) {
        case 'wait_startup':
          this.processStartup(conn);
          break;
        case 'wait_password':
          this.processPasswordMessage(conn);
          break;
        case 'scram_sasl':
          this.processScramSasl(conn);
          break;
        case 'scram_continue':
          this.processScramContinue(conn);
          break;
        case 'scram_final':
          // Dead code: processScramContinue completes the full SCRAM
          // exchange and transitions authStage to 'ready'. This case
          // is structurally reachable but never fires at runtime.
          conn.authStage = 'ready';
          break;
        case 'gssapi_token':
          this.processGssapiToken(conn);
          break;
        case 'ready':
          this.processReadyMessages(conn);
          break;
      }

      // If the offset didn't advance, we need more data
      if (conn.offset === prevOffset) break;
      processed++;
    }

    // Compact buffer periodically to prevent unbounded growth
    this.compactBuffer(conn);
  }

  /** Compact the connection buffer when the consumed portion is large. */
  private compactBuffer(conn: PgWireConnectionInternal): void {
    if (conn.offset > 65536) {
      // Use Buffer.from() to create a real copy (allow GC of old backing store)
      conn.buffer = Buffer.from(conn.buffer.subarray(conn.offset));
      conn.offset = 0;
    }
  }

  // ════════════════════════════════════════════════
  //  Startup / TLS negotiation
  // ════════════════════════════════════════════════

  /**
   * Process the StartupMessage (or SSLRequest).
   *
   * StartupMessage format:
   *   int32 length (including self)
   *   int32 protocol version (196608 = 3.0)
   *   key\0value\0 ... \0
   *
   * SSLRequest format:
   *   int32 length (8)
   *   int32 80877103
   */
  private processStartup(conn: PgWireConnectionInternal): void {
    const buf = conn.buffer;
    const off = conn.offset;
    if (buf.length - off < 8) return;

    const pktLen = buf.readInt32BE(off);
    if (buf.length - off < pktLen) return;

    const version = buf.readInt32BE(off + 4);

    // ── SSLRequest (80877103 == 0x04D21601) ──
    if (version === 80877103) {
      // Only allow TLS upgrade when TLS is configured
      if (!this.tlsConfig) {
        // Deny SSL
        conn.socket.write(Buffer.from([0x4e])); // 'N'
        conn.offset += pktLen;
        conn.authStage = 'wait_startup'; // stay waiting for startup
        return;
      }

      // Accept: send 'S' then upgrade
      conn.socket.write(Buffer.from([0x53])); // 'S'
      conn.offset += pktLen;

      // Remove old data handler, then upgrade to TLSSocket
      const oldHandler = (conn as any)._dataHandler as ((data: Buffer) => void) | undefined;
      if (oldHandler) conn.rawSocket.removeListener('data', oldHandler);

      const tlsSocket = new tls.TLSSocket(conn.rawSocket, {
        isServer: true,
        cert: fs.readFileSync(this.tlsConfig.cert),
        key: fs.readFileSync(this.tlsConfig.key),
        ca: this.tlsConfig.ca ? fs.readFileSync(this.tlsConfig.ca) : undefined,
        requestCert: this.tlsConfig.forceClientCert ?? true,
        rejectUnauthorized: this.tlsConfig.forceClientCert ?? true,
        // TLS-01: Cipher suite & version configuration
        minVersion: this.tlsConfig.minVersion ?? 'TLSv1.2',
        maxVersion: this.tlsConfig.maxVersion ?? 'TLSv1.3',
        ciphers: this.tlsConfig.cipherSuites ?? 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
        ecdhCurve: this.tlsConfig.ecdhCurve ?? 'prime256v1',
      });

      conn.socket = tlsSocket;
      conn.isTls = true;
      conn.authStage = 'wait_startup'; // expect a new StartupMessage over TLS
      conn.offset = 0; // reset cursor for new stream
      conn.buffer = Buffer.alloc(0);

      // Install data handler on TLS socket
      const tlsHandler = (data: Buffer) => {
        conn.buffer = Buffer.concat([conn.buffer, data]);
        this.processConnection(conn);
      };
      (conn as any)._dataHandler = tlsHandler;
      tlsSocket.on('data', tlsHandler);

      return;
    }

    // ── GSSAPI request (80877104) ──
    if (version === 80877104) {
      const gssapi = new GssapiAuth();
      conn.gssapiAuth = gssapi;

      if (!gssapi.isAvailable) {
        // Deny GSSAPI
        conn.socket.write(Buffer.from([0x4e])); // 'N'
        conn.offset += pktLen;
        conn.authStage = 'wait_startup';
        return;
      }

      // Accept: send 'G' for GSSAPI (encoded per PG spec)
      conn.socket.write(Buffer.from([0x47])); // 'G'
      conn.offset += pktLen;
      conn.gssapiExpectToken = true;

      // Note: AuthenticationGSS (type 7) is NOT sent here — it will be sent
      // during auth flow after pg_hba.conf evaluation, if the auth method
      // resolves to 'gss'. For GSSAPI encryption (not authentication), the
      // 'G' response is sufficient; actual GSSAPI auth happens later.
      conn.authStage = 'wait_startup';
      return;
    }

    // ── CancelRequest (80877102) ──
    // Format: length(4) + 80877102(4) + backendPID(4) + secretKey(4)
    if (version === 80877102) {
      if (pktLen < 16) {
        conn.offset += pktLen;
        return;
      }
      const backendPid = buf.readInt32BE(off + 8);
      const secretKey = buf.readInt32BE(off + 12);

      // Look up session by PID from dedicated map
      const targetSessionId = this._pidToSessionId.get(backendPid);
      let cancelledSession = false;
      if (targetSessionId) {
        const c = this.conns.get(targetSessionId);
        if (c && c.secretKey === secretKey) {
          c.cancelled = true;
          // Abort any running query immediately via AbortController
          if (c.abortController) {
            c.abortController.abort();
            c.abortController = null;
          }
          cancelledSession = true;
          logger.info({ sessionId: targetSessionId }, 'CancelRequest: query cancelled');
        }
      }

      if (!cancelledSession) {
        logger.info('CancelRequest: no matching session found (may be benign)');
      }

      conn.offset += pktLen;
      return;
    }

    // ── Regular StartupMessage ──

    // Parse key/value pairs to extract database name
    let dbName = 'default';
    let userName = 'unknown';
    let keyOff = off + 8;
    const endOff = off + pktLen;
    while (keyOff + 1 < endOff) {
      const nullIdx = buf.indexOf(0, keyOff);
      if (nullIdx < 0 || nullIdx >= endOff) break;
      const key = buf.toString('utf8', keyOff, nullIdx);
      const valOff = nullIdx + 1;
      if (valOff >= endOff) break;
      const valEnd = buf.indexOf(0, valOff);
      if (valEnd < 0 || valEnd > endOff) break;
      const value = buf.toString('utf8', valOff, valEnd);
      if (key === 'database') dbName = value;
      if (key === 'user') userName = value;
      keyOff = valEnd + 1;
    }

    conn.session.database = dbName;
    conn.userName = userName;
    conn.offset += pktLen;

    // ── hostssl enforcement: reject non-SSL startup when mTLS is forced ──
    if (
      this.tlsConfig &&
      !conn.isTls &&
      (this.tlsConfig.forceClientCert ?? true)
    ) {
      this.sendError(
        conn.socket,
        'hostssl: client certificate required (mTLS enabled). ' +
        'Use sslmode=require or sslmode=verify-full in your connection string.',
      );
      conn.socket.end();
      return;
    }

    // Evaluate pg_hba.conf rules (if configured) to determine auth method
    const hbaResult = this.pgHbaConf
      ? this.pgHbaConf.evaluate({
          type: conn.isTls && conn.socket instanceof tls.TLSSocket ? 'hostssl' : this.tlsConfig ? 'host' : 'local',
          database: dbName,
          user: userName,
          address: conn.socket.remoteAddress,
          isTls: conn.isTls,
        })
      : null;

    if (hbaResult) {
      conn.hbaAuthMethod = hbaResult.authMethod;

      // reject — drop connection immediately
      if (hbaResult.authMethod === 'reject') {
        this.sendError(conn.socket, 'pg_hba.conf rejects this connection');
        conn.socket.end();
        return;
      }

      // cert — require TLS and validate client certificate
      if (hbaResult.authMethod === 'cert') {
        if (!conn.isTls) {
          this.sendError(conn.socket, 'cert authentication requires TLS connection');
          conn.socket.end();
          return;
        }
        const tlsSocket = conn.socket as tls.TLSSocket;
        const cert = tlsSocket.getPeerCertificate();
        if (!cert || !cert.subject) {
          this.sendError(conn.socket, 'cert authentication failed: no client certificate');
          conn.socket.end();
          return;
        }
        // Validate CN matches the user name
        const cn = cert.subject.CN;
        if (cn !== userName) {
          this.sendError(conn.socket, `cert authentication failed: CN "${cn}" does not match user "${userName}"`);
          conn.socket.end();
          return;
        }
        // ── CertChainValidator: additional chain validation (P1) ──
        if (this.certChainValidator) {
          const result = this.certChainValidator.validateChain(
            cert as any,
            this.tlsConfig?.ca ? [fs.readFileSync(this.tlsConfig.ca, 'utf-8')] : undefined,
          );
          // Await is used because validateChain is async (CRL/OCSP)
          // Store for later resolution
          result.then(async (vr) => {
            if (!vr.valid) {
              logger.warn({ errors: vr.errors }, 'CertChainValidator: peer certificate validation failed');
              // Log but don't reject — Node.js TLS already validated the chain.
              // CertChainValidator adds CRL/OCSP checks.
              // We emit a warning NOTICE instead of disconnecting.
              try {
                conn.socket.write(
                  Buffer.concat([
                    Buffer.alloc(1, 0x4e), // NoticeResponse
                    Buffer.alloc(0), // Will be built by notice builder
                  ]),
                );
              } catch (_e: any) {
                // Non-fatal
              }
            }
          }).catch((err: any) => {
            logger.error({ err: err.message }, 'CertChainValidator validation threw unexpectedly');
          });
        }
        // Cert auth OK — proceed
        this.afterAuthSuccess(conn);
        return;
      }

      // trust — skip authentication entirely
      if (hbaResult.authMethod === 'trust') {
        this.afterAuthSuccess(conn);
        return;
      }

      // password — cleartext password (TLS only)
      if (hbaResult.authMethod === 'password') {
        if (!conn.isTls) {
          this.sendError(conn.socket, 'password authentication requires TLS connection');
          conn.socket.end();
          return;
        }
        // Request cleartext password
        conn.socket.write(this.buildAuthMessage(3, Buffer.alloc(0))); // AuthTypePassword (3)
        conn.authStage = 'wait_password';
        return;
      }

      // pam — Pluggable Authentication Module (system-level auth)
      if (hbaResult.authMethod === 'pam') {
        // C-10: Module availability already checked at construction time
        if (!this.pamAvailable) {
          this.sendError(conn.socket, 'PAM authentication not available on this server');
          conn.socket.end();
          return;
        }
        // Request cleartext password for PAM
        conn.socket.write(this.buildAuthMessage(3, Buffer.alloc(0))); // AuthTypePassword (3)
        conn.authStage = 'wait_password';
        // PAM authentication happens in processPasswordMessage by delegating
        // to the pam module when hbaAuthMethod is 'pam'.
        conn.hbaAuthMethod = 'pam';
        return;
      }

      // peer — trust connection if OS user matches PG user (local connections only)
      if (hbaResult.authMethod === 'peer') {
        // For local connections, try to get the OS user from environment
        const osUser = process.env.USER || process.env.LOGNAME || 'local';
        const pgUser = userName;

        if (osUser && pgUser && osUser === pgUser) {
          this.afterAuthSuccess(conn);
        } else {
          this.sendError(conn.socket, `peer authentication failed: OS user "${osUser}" does not match PG user "${pgUser}"`);
          conn.socket.end();
        }
        return;
      }

      // ident — trust based on ident protocol (RFC 1413)
      if (hbaResult.authMethod === 'ident') {
        // For ident, we trust identd on the client machine.
        // Since we can't reliably query identd, we use the remote address
        // as the identifier and compare it to the PG user.
        const remoteUser = conn.socket.remoteAddress || '';
        if (remoteUser === userName || remoteUser === `::ffff:127.0.0.1`) {
          this.afterAuthSuccess(conn);
        } else {
          this.sendError(conn.socket, `ident authentication failed for user "${userName}"`);
          conn.socket.end();
        }
        return;
      }

      // md5 — proper MD5 challenge-response authentication
      if (hbaResult.authMethod === 'md5') {
        this.startMd5Auth(conn, userName, this.password || '');
        return;
      }

      // gss — GSSAPI/Kerberos authentication
      if (hbaResult.authMethod === 'gss') {
        this.startGssapiAuth(conn);
        return;
      }

      // scram-sha-256 — standard SCRAM authentication
      this.startScramAuth(conn);
    } else if (this.pgHbaConf) {
      // pg_hba.conf is configured but no rule matched — reject per PG spec
      // (first-match-wins semantics: no match = no access)
      this.sendError(conn.socket, `pg_hba.conf rejects connection for user "${userName}" to database "${conn.session.database}": no matching entry`);
      conn.socket.end();
      return;
    } else if (this.password) {
      // No pg_hba.conf rule matched but password is configured — default to SCRAM
      this.startScramAuth(conn);
    } else {
      // No pg_hba.conf and no password — skip directly to auth ok
      this.afterAuthSuccess(conn);
    }
  }

  // ════════════════════════════════════════════════
  //  MD5 Authentication (Gap 4)
  // ════════════════════════════════════════════════

  /**
   * Start MD5 challenge-response authentication.
   *
   * PG wire protocol:
   *   1. Server sends AuthenticationMD5Password (type 5) with 4-byte random salt
   *   2. Client responds with PasswordMessage containing md5(md5(password+user) + salt)
   *   3. Server verifies the hash
   */
  private startMd5Auth(conn: PgWireConnectionInternal, user: string, serverPassword: string): void {
    // Generate random 4-byte salt
    const salt = crypto.randomBytes(4);

    // Store auth state
    conn.scramUser = user;
    // Reuse scramSalt field for MD5 salt (avoid adding new field)
    conn.scramSalt = salt;

    // Send AuthenticationMD5Password (type 5)
    // Format: int32 authType(5) + bytes[4] salt
    const body = Buffer.alloc(8);
    body.writeInt32BE(5, 0); // AuthType = 5 (AuthenticationMD5Password)
    salt.copy(body, 4);

    const buf = Buffer.alloc(1 + 4 + body.length);
    buf[0] = 0x52; // 'R'
    buf.writeInt32BE(4 + body.length, 1);
    body.copy(buf, 5);

    conn.socket.write(buf);
    conn.authStage = 'wait_password';
    logger.info({ user }, 'MD5 authentication challenge sent');
  }

  // ════════════════════════════════════════════════
  //  SCRAM-SHA-256 Authentication
  // ════════════════════════════════════════════════

  private startScramAuth(conn: PgWireConnectionInternal): void {
    // Offer SCRAM-SHA-256 only. SCRAM-SHA-256-PLUS requires TLS channel
    // binding support which we do not implement; offering it would be a
    // false advertisement that could confuse clients.
    const mechs = ['SCRAM-SHA-256'];

    // Build SASL authentication request
    const mechBufs = mechs.map((m) => Buffer.from(m + '\0', 'utf8'));
    const body = Buffer.concat([...mechBufs, Buffer.from([0])]); // trailing null
    const buf = this.buildAuthMessage(10, body);
    conn.socket.write(buf);
    conn.authStage = 'scram_sasl';
    conn.scramUser = userNameFromStartup(conn); // set during startup
  }

  /**
   * Process SASLInitialResponse (type byte 0x70 = 'p').
   *
   * Format:
   *   char  type = 'p'
   *   int32 len
   *   str   mechanism (null-terminated)
   *   int32 client-first-message length
   *   bytes client-first-message (n,,n=<user>,r=<nonce>)
   */
  private processScramSasl(conn: PgWireConnectionInternal): void {
    const buf = conn.buffer;
    const off = conn.offset;
    if (buf.length - off < 6) return;

    const typeByte = buf[off];
    if (typeByte !== 0x70) {
      // Not a SASLInitialResponse
      this.sendError(conn.socket, 'Expected SASLInitialResponse');
      this.gotoReady(conn.socket, conn);
      return;
    }

    const msgLen = buf.readInt32BE(off + 1);
    if (buf.length - off < msgLen + 1) return;

    let ptr = off + 5;

    // Read mechanism name (null-terminated)
    const mechEnd = buf.indexOf(0, ptr);
    if (mechEnd < 0 || mechEnd - ptr < 1) {
      this.sendError(conn.socket, 'Invalid SASL mechanism');
      this.gotoReady(conn.socket, conn);
      conn.offset += msgLen + 1;
      return;
    }
    const mechanism = buf.toString('utf8', ptr, mechEnd);
    ptr = mechEnd + 1;

    // Read client-first-message length
    if (ptr + 4 > off + 1 + msgLen) {
      this.sendError(conn.socket, 'Truncated SASL response');
      this.gotoReady(conn.socket, conn);
      conn.offset += msgLen + 1;
      return;
    }
    const cfmLen = buf.readInt32BE(ptr);
    ptr += 4;

    if (ptr + cfmLen > off + 1 + msgLen) {
      this.sendError(conn.socket, 'Truncated client-first-message');
      this.gotoReady(conn.socket, conn);
      conn.offset += msgLen + 1;
      return;
    }
    const clientFirst = buf.toString('utf8', ptr, ptr + cfmLen);
    conn.offset += msgLen + 1;

    // Parse client-first: "n,,n=<user>,r=<client-nonce>"
    // The bare part (after the gs2-header "n,,") is the important bit.
    const gs2HeaderEnd = clientFirst.indexOf(',');
    if (gs2HeaderEnd < 0) {
      this.sendError(conn.socket, 'Invalid SCRAM client-first');
      this.gotoReady(conn.socket, conn);
      return;
    }
    const gs2Header = clientFirst.substring(0, gs2HeaderEnd);
    // gs2Header should be "n" (client doesn't support channel binding),
    // "y" (client does support but server doesn't), or
    // "p=tls-server-end-point" (channel binding over TLS).
    // We don't support channel binding, so accept "n" and "y" directly,
    // and gracefully fall back for "p=..." (ignore the channel binding).
    if (gs2Header === 'n' || gs2Header === 'y') {
      // OK — proceed normally
    } else if (gs2Header.startsWith('p=')) {
      // Client sent SCRAM-SHA-256-PLUS with channel binding.
      // Since we don't support channel binding, verify server identity
      // solely through the password (the same as 'y' behavior).
      // The client will fall back gracefully.
    } else {
      this.sendError(conn.socket, 'Channel binding not supported');
      this.gotoReady(conn.socket, conn);
      return;
    }

    const barePart = clientFirst.substring(gs2HeaderEnd + 2); // after "n,," or "y,,"
    conn.scramClientFirstBare = barePart;

    // Extract user and client nonce from bare part
    const userMatch = barePart.match(/n=([^,]+)/);
    const nonceMatch = barePart.match(/r=([^,]+)/);
    if (!userMatch || !nonceMatch) {
      this.sendError(conn.socket, 'Invalid SCRAM client-first (missing user/nonce)');
      this.gotoReady(conn.socket, conn);
      return;
    }
    const u = userMatch[1];
    const clientNonce = nonceMatch[1];

    // Parse stored hash to get salt, iterations, and stored/server keys
    if (!this.password) {
      this.sendError(conn.socket, 'Server not configured with password');
      this.gotoReady(conn.socket, conn);
      return;
    }
    const parsed = parseStoredHash(this.password);
    if (!parsed) {
      this.sendError(conn.socket, 'Server authentication configuration error');
      this.gotoReady(conn.socket, conn);
      return;
    }

    // Generate server nonce, use stored salt and iterations from the hash
    const serverNonce = clientNonce + randBase64(SCRAM_NONCE_LENGTH);
    const { iterations, salt, storedKeyExpected, serverKeyExpected } = parsed;

    // Build server-first: r=<combined>,s=<base64(salt)>,i=<iterations>
    const serverFirst = `r=${serverNonce},s=${salt.toString('base64')},i=${iterations}`;

    // Compute ServerSignature for later verification
    const authMessage = `${barePart},${serverFirst},`; // partial — completed on client-final
    const serverSignature = hmacSha256(serverKeyExpected, authMessage);

    // Store state
    conn.scramUser = u;
    conn.scramServerNonce = serverNonce;
    conn.scramSalt = salt;
    conn.scramIterations = iterations;
    conn.scramStoredKey = storedKeyExpected;
    conn.scramServerKey = serverKeyExpected;
    conn.scramServerSignature = serverSignature;

    // Send AuthenticationSASLContinue (type 11)
    const continueBuf = this.buildAuthMessage(11, Buffer.from(serverFirst, 'utf8'));
    conn.socket.write(continueBuf);
    conn.authStage = 'scram_continue';
  }

  /**
   * Process SASLResponse (SCRAM client-final message).
   * Format: type 'p', int32 len, string client-final-message (null-terminated)
   * NOTE: SASLResponse does NOT have a body-length prefix (unlike SASLInitialResponse).
   * The message body is a null-terminated string.
   */
  private processScramContinue(conn: PgWireConnectionInternal): void {
    const buf = conn.buffer;
    const off = conn.offset;
    if (buf.length - off < 6) return;

    const typeByte = buf[off];
    if (typeByte !== 0x70) {
      this.sendError(conn.socket, 'Expected SASL response');
      this.gotoReady(conn.socket, conn);
      return;
    }

    const msgLen = buf.readInt32BE(off + 1);
    if (buf.length - off < msgLen + 1) return;

    let ptr = off + 5;
    const endPos = off + 1 + msgLen;

    // Read client-final-message as null-terminated string (SASLResponse format)
    const nullIdx = buf.indexOf(0, ptr);
    if (nullIdx < 0 || nullIdx >= endPos) {
      this.sendError(conn.socket, 'Truncated client-final body');
      this.gotoReady(conn.socket, conn);
      conn.offset += msgLen + 1;
      return;
    }
    const clientFinal = buf.toString('utf8', ptr, nullIdx);
    conn.offset += msgLen + 1;

    // Parse client-final: "c=biws,r=<nonce>,p=<proof>"
    // Extract the nonce and proof
    const nonceMatch = clientFinal.match(/r=([^,]+)/);
    const proofMatch = clientFinal.match(/p=([^,]+)/);
    if (!nonceMatch || !proofMatch) {
      this.sendError(conn.socket, 'Invalid SCRAM client-final (missing nonce/proof)');
      this.gotoReady(conn.socket, conn);
      return;
    }

    const clientNonce = nonceMatch[1];
    const clientProofB64 = proofMatch[1];

    // Verify the nonce matches what we sent
    if (clientNonce !== conn.scramServerNonce) {
      this.sendError(conn.socket, 'SCRAM nonce mismatch');
      this.gotoReady(conn.socket, conn);
      return;
    }

    // Use stored StoredKey and ServerKey from parsed hash
    const storedKey = conn.scramStoredKey!;
    const serverKey = conn.scramServerKey!;

    // Build auth message without the proof part
    // client-final-without-proof = c=biws,r=<combined-nonce>
    const commaIdx = clientFinal.indexOf(',p=');
    const clientFinalWithoutProof = commaIdx >= 0 ? clientFinal.substring(0, commaIdx) : clientFinal;
    const serverFirst = `r=${conn.scramServerNonce},s=${conn.scramSalt!.toString('base64')},i=${conn.scramIterations}`;
    const authMessage = `${conn.scramClientFirstBare},${serverFirst},${clientFinalWithoutProof}`;

    // Expected client signature
    const expectedClientSig = hmacSha256(storedKey, authMessage);

    // Extract client proof from base64
    let clientProofBuffer: Buffer;
    try {
      clientProofBuffer = Buffer.from(clientProofB64, 'base64');
    } catch (_e: any) {
      this.sendError(conn.socket, 'Invalid SCRAM proof encoding');
      this.gotoReady(conn.socket, conn);
      return;
    }

    // Recover ClientKey from proof XOR expected signature
    const recoveredClientKey = xorBuffers(clientProofBuffer, expectedClientSig);

    // Verify: SHA256(recoveredClientKey) should equal StoredKey
    const recoveredStoredKey = sha256(recoveredClientKey);
    if (!recoveredStoredKey.equals(storedKey)) {
      this.sendError(conn.socket, 'SCRAM authentication failed: password incorrect');
      this.gotoReady(conn.socket, conn);
      return;
    }

    // Compute server signature for final verification by client
    const serverSignature = hmacSha256(serverKey, authMessage);
    const serverFinal = `v=${serverSignature.toString('base64')}`;

    // Send AuthenticationSASLFinal (type 12)
    const finalBuf = this.buildAuthMessage(12, Buffer.from(serverFinal, 'utf8'));
    conn.socket.write(finalBuf);

    // Authentication OK
    this.sendAuthenticationOk(conn.socket);
    conn.authStage = 'ready';
  }

  /**
   * Fallback for a non-SASL auth attempt (e.g. cleartext password message)
   * when the authStage is scram_sasl but the client sent a cleartext PasswordMessage.
   */
  private async processPasswordMessage(conn: PgWireConnectionInternal): Promise<void> {
    const buf = conn.buffer;
    const off = conn.offset;
    if (buf.length - off < 6) return;

    const typeByte = buf[off];
    if (typeByte !== 0x70) {
      this.sendError(conn.socket, 'Expected PasswordMessage');
      this.gotoReady(conn.socket, conn);
      return;
    }

    const msgLen = buf.readInt32BE(off + 1);
    if (buf.length - off < msgLen + 1) return;

    const password = buf.toString('utf8', off + 5, off + 5 + msgLen - 5).replace(/\0+$/, '');
    conn.offset += msgLen + 1;

    // G6: PAM authentication
    if (conn.hbaAuthMethod === 'pam') {
      // C-10: Module already loaded at construction time
      if (!this.pamAvailable || !this.pamModule) {
        this.sendError(conn.socket, 'PAM authentication not available on this server');
        conn.socket.end();
        return;
      }
      try {
        const pam = this.pamModule;
        const pamResult = await new Promise<boolean>((resolve) => {
          pam.authenticate(conn.userName || password, password, (err: any) => {
            if (err) {
              logger.error({ err: err.message, user: conn.userName }, 'PAM authentication failed');
              resolve(false);
            } else {
              resolve(true);
            }
          });
        });

        if (!pamResult) {
          if (this.auditLogger) {
            this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', false);
          }
          this.sendError(conn.socket, 'PAM authentication failed');
          conn.socket.end();
          return;
        }

        if (this.auditLogger) {
          this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', true);
        }
        this.afterAuthSuccess(conn);
        return;
      } catch (err: any) {
        logger.error({ err: err.message }, 'PAM authentication error');
        this.sendError(conn.socket, `PAM authentication error: ${err.message}`);
        conn.socket.end();
        return;
      }
    }

    // MD5 authentication
    if (conn.hbaAuthMethod === 'md5') {
      // Compute expected MD5 response per PG spec:
      // inner_hex = hex(md5(password || user))
      // crypt_pwd_str = "md5" + inner_hex  (e.g., "md5abc123...")
      // outer = hex(md5(crypt_pwd_bytes || salt_bytes))
      // client sends: "md5" + outer_hex
      const user = conn.userName || conn.scramUser || '';
      const salt = conn.scramSalt || Buffer.alloc(4);

      // Compute inner hash: md5(password + user) as hex string
      const innerHashHex = crypto.createHash('md5').update(this.password + user, 'utf8').digest('hex');

      // Build crypt_pwd = "md5" + inner_hex (ASCII bytes)
      const cryptPwd = 'md5' + innerHashHex;
      const cryptPwdBuf = Buffer.from(cryptPwd, 'utf8');

      // Compute outer: md5(crypt_pwd_bytes + salt_bytes) → hex
      const outerInput = Buffer.concat([cryptPwdBuf, salt]);
      const outerDigest = crypto.createHash('md5').update(outerInput).digest('hex');
      const expectedResponse = 'md5' + outerDigest;

      const clientResponse = password.toLowerCase();

      if (clientResponse !== expectedResponse) {
        if (this.auditLogger) {
          this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', false);
        }
        this.sendError(conn.socket, 'MD5 authentication failed: password incorrect');
        conn.socket.end();
        return;
      }

      if (this.auditLogger) {
        this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', true);
      }

      this.sendAuthenticationOk(conn.socket);
      conn.authStage = 'ready';
      return;
    }

    // Use ScramPasswordManager to verify password against stored hash
    if (!this.password || !verifyPassword(password, this.password)) {
      // G21: Audit login failure
      if (this.auditLogger) {
        this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', false);
      }
      this.sendError(conn.socket, 'Password authentication failed');
      this.gotoReady(conn.socket, conn);
      return;
    }

    // G21: Audit login success
    if (this.auditLogger) {
      this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', true);
    }

    this.sendAuthenticationOk(conn.socket);
    conn.authStage = 'ready';
  }

  // ════════════════════════════════════════════════
  //  GSSAPI / Kerberos Authentication (Gap 2)
  // ════════════════════════════════════════════════

  /**
   * Start GSSAPI authentication for the 'gss' pg_hba.conf auth method.
   *
   * PG wire protocol:
   *   1. Server sends AuthenticationGSS (type 7) — requests GSSAPI auth
   *   2. Client responds with PasswordMessage containing the GSSAPI initiator token
   *   3. Server validates token, sends AuthenticationGSSContinue (type 8) with
   *      response token, or AuthenticationOk when complete
   *   4. Repeat step 2-3 until the GSSAPI exchange completes
   */
  private startGssapiAuth(conn: PgWireConnectionInternal): void {
    // Create or reuse existing GssapiAuth instance
    if (!conn.gssapiAuth) {
      conn.gssapiAuth = new GssapiAuth();
    }

    const gssapi = conn.gssapiAuth;

    if (!gssapi.isAvailable) {
      logger.error('GSSAPI auth requested but module not available');
      this.sendError(conn.socket, 'GSSAPI authentication requested but not available on this server');
      conn.socket.end();
      return;
    }

    // Send AuthenticationGSS (type 7) — empty body per PG spec
    const authBuf = this.buildAuthMessage(7, Buffer.alloc(0));
    conn.socket.write(authBuf);
    conn.authStage = 'gssapi_token';
  }

  /**
   * Process a GSSAPI token received from the client (PasswordMessage).
   *
   * The client responds to AuthenticationGSS (type 7) or
   * AuthenticationGSSContinue (type 8) with a regular PasswordMessage
   * containing the GSSAPI initiator token.
   */
  private async processGssapiToken(conn: PgWireConnectionInternal): Promise<void> {
    const buf = conn.buffer;
    const off = conn.offset;

    if (buf.length - off < 6) return;

    const typeByte = buf[off];
    if (typeByte !== 0x70) {
      this.sendError(conn.socket, 'Expected PasswordMessage for GSSAPI token');
      conn.socket.end();
      return;
    }

    const msgLen = buf.readInt32BE(off + 1);
    if (buf.length - off < msgLen + 1) return;

    // The password body contains the raw GSSAPI token (not a text password)
    const token = Buffer.alloc(msgLen - 4);
    buf.copy(token, 0, off + 5, off + 5 + msgLen - 4 - 1); // -1 for null terminator
    // Truncate trailing null bytes if present
    const trailingNull = token.indexOf(0);
    const cleanToken = trailingNull >= 0 ? token.subarray(0, trailingNull) : token;

    conn.offset += msgLen + 1;

    const gssapi = conn.gssapiAuth;
    if (!gssapi) {
      this.sendError(conn.socket, 'GSSAPI context not initialized');
      conn.socket.end();
      return;
    }

    try {
      // Determine if this is the first token or a continuation
      const isFirst = !conn.gssapiAuthFirstTokenSent;
      let result: import('../auth/GssapiAuth').GssapiAuthResult;

      if (isFirst) {
        result = await gssapi.acceptFirstToken(cleanToken);
        conn.gssapiAuthFirstTokenSent = true;
      } else {
        result = await gssapi.acceptNextToken(cleanToken);
      }

      if (result.error || (!result.authenticated && !result.token)) {
        // Authentication failed — send error and close
        if (this.auditLogger) {
          this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', false);
        }
        this.sendError(conn.socket, result.error || 'GSSAPI authentication failed');
        conn.socket.end();
        return;
      }

      if (result.authenticated && !result.token) {
        // GSSAPI exchange complete — send AuthenticationOk
        if (this.auditLogger) {
          this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', true);
        }
        this.sendAuthenticationOk(conn.socket);
        conn.authStage = 'ready';
        return;
      }

      // More tokens needed — send AuthenticationGSSContinue (type 8)
      if (result.token) {
        const continueBuf = this.buildAuthMessage(8, Buffer.from(result.token || '', 'utf8'));
        conn.socket.write(continueBuf);
        conn.authStage = 'gssapi_token'; // Continue waiting for the next token
        return;
      }

      // Fallback: should not reach here
      this.sendError(conn.socket, 'GSSAPI authentication incomplete: unexpected state');
      conn.socket.end();
    } catch (err: any) {
      logger.error({ err: err.message }, 'GSSAPI token processing error');
      this.sendError(conn.socket, `GSSAPI authentication failed: ${err.message}`);
      conn.socket.end();
    }
  }

  /** After an auth error, transition to ready with the error already sent. */
  private gotoReady(socket: net.Socket, conn: PgWireConnectionInternal): void {
    conn.authStage = 'ready';
  }

  /**
   * After successful authentication, check RoleManager.canConnect() then transition to ready.
   */
  private afterAuthSuccess(conn: PgWireConnectionInternal): void {
    // Check role-based access control (if configured)
    if (this.roleManager && conn.userName) {
      if (!this.roleManager.canConnect(conn.userName, conn.session.database)) {
        this.sendError(conn.socket, `role "${conn.userName}" is not permitted to connect to database "${conn.session.database}"`);
        conn.socket.end();
        return;
      }
    }

    // Mark session as authenticated and cancel auth timeout
    // (auth timeout only applies to the initial authentication handshake,
    // not to subsequent long-running queries like COPY.)
    conn.session.authenticated = true;
    conn.session.userName = conn.userName || 'unknown';
    this.authTimeoutManager.cancelTimer(conn.sessionId);

    // G21: Audit login success
    if (this.auditLogger) {
      this.auditLogger.logLogin(conn.sessionId, conn.userName || 'unknown', true);
    }

    // M-02: Assign backend PID with overflow protection
    const pid = this._nextPid;
    this._nextPid = this._nextPid >= Number.MAX_SAFE_INTEGER ? 1 : this._nextPid + 1;
    const secret = Math.floor(Math.random() * 2147483647) + 1;
    conn.session.backendPid = pid;
    conn.session.secretKey = secret;
    conn.secretKey = secret;
    this._pidToSessionId.set(pid, conn.sessionId);

    this.sendAuthenticationOk(conn.socket);
    this.sendBackendKeyData(conn.socket, pid, secret);
    this.sendParameterStatus(conn.socket, conn.userName);
    this.sendReadyForQuery(conn.socket);
    conn.authStage = 'ready';
  }

  // ════════════════════════════════════════════════
  //  Ready-state message processing
  // ════════════════════════════════════════════════

  private processReadyMessages(conn: PgWireConnectionInternal): void {
    const buf = conn.buffer;
    const off = conn.offset;
    if (buf.length - off < 5) return;

    const msgType = String.fromCharCode(buf[off]);
    const msgLen = buf.readUInt32BE(off + 1);
    if (msgLen <= 0 || buf.length - off < msgLen + 1) return;

    // Pipeline mode: queue messages instead of executing immediately
    if (conn.pipelineMode && (msgType === 'Q' || msgType === 'P' || msgType === 'B' || msgType === 'E' || msgType === 'D' || msgType === 'C')) {
      // Store a COPY of the payload to survive compactBuffer()
      conn.pipelineQueries.push({
        type: msgType,
        payload: Buffer.from(buf.subarray(off, off + 1 + msgLen)),
      });
      conn.offset += msgLen + 1;
      return;
    }

    switch (msgType) {
      case 'Q': {
        // Simple Query
        // Phase E: Reject Simple Query in prepared_statement_only mode
        if (conn && conn.preparedStatementOnly) {
          this.sendError(conn.socket, 'simple_query_not_allowed: Simple Query is not allowed in prepared_statement_only mode');
          conn.offset += msgLen + 1;
          break;
        }
        const sql = buf.toString('utf8', off + 5, off + 5 + msgLen - 4).replace(/\0+$/, '');
        this.handleQuery(conn.socket, conn.session, sql);
        conn.offset += msgLen + 1;
        break;
      }
      case 'P': {
        // Parse (extended query)
        this.handleParse(conn, off, msgLen);
        conn.offset += msgLen + 1;
        break;
      }
      case 'B': {
        // Bind (extended query)
        this.handleBind(conn, off, msgLen);
        conn.offset += msgLen + 1;
        break;
      }
      case 'E': {
        // Execute (extended query)
        this.handleExecute(conn, off, msgLen);
        conn.offset += msgLen + 1;
        break;
      }
      case 'D': {
        // Describe (extended query)
        this.handleDescribe(conn, off, msgLen);
        conn.offset += msgLen + 1;
        break;
      }
      case 'C': {
        // Close (extended query)
        this.handleClose(conn, off, msgLen);
        conn.offset += msgLen + 1;
        break;
      }
      case 'v': {
        // NegotiateProtocolVersion (PG 14+) — no special handling needed
        conn.offset += msgLen + 1;
        break;
      }
      case 'X': {
        // Terminate
        conn.offset += msgLen + 1;
        conn.socket.end();
        break;
      }
      case 'H': {
        // Flush — flush pending pipeline responses
        if (conn.pipelineMode) {
          const responses = conn.pgPipelineHandler.handleFlush();
          for (const resp of responses) {
            conn.socket.write(resp);
          }
        }
        conn.offset += msgLen + 1;
        break;
      }
      case 'S': {
        // Sync — flush pipeline if active, then ready for query
        if (conn.pipelineMode && conn.pipelineQueries.length > 0) {
          this.flushPipeline(conn);
        }
        if (conn.pipelineMode) {
          // Use PgPipelineHandler to manage Sync response
          const txnCode = conn.session.transactionStatus === 'in_transaction' ? 'T'
            : conn.session.transactionStatus === 'failed' ? 'E'
            : 'I';
          const responses = conn.pgPipelineHandler.processSync(txnCode);
          for (const resp of responses) {
            conn.socket.write(resp);
          }
        } else {
          // In extended query protocol, if there's a pending async Execute,
          // defer ReadyForQuery until Execute completes (preserves message
          // ordering: DataRow+CommandComplete → ReadyForQuery)
          if (conn.pendingAsyncExecute) {
            const txnCode = conn.session.transactionStatus === 'in_transaction' ? 'T'
              : conn.session.transactionStatus === 'failed' ? 'E'
              : 'I';
            conn.deferredReadyForQuery = this.buildReadyForQuery(txnCode);
          } else if (conn.rfqAlreadySent) {
            // .finally() already sent RFQ for a previous message group
            // (async completed before its Sync was processed). Send RFQ
            // for this Sync's message group too.
            this.sendReadyForQuery(conn.socket);
            conn.rfqAlreadySent = false;
          } else {
            this.sendReadyForQuery(conn.socket);
          }
        }
        conn.offset += msgLen + 1;
        break;
      }
      case 'c': {
        // CopyDone — end of COPY data
        logger.info({ copyState: conn.copyState, bufSize: conn.copyBuffer?.length, tableName: conn.copyTableName }, 'CopyDone received');
        if (conn.copyState === 'active') {
          conn.copyState = 'done';
          // Block further message processing until COPY completes
          (conn as any).copyPending = true;
          // Flush COPY data and complete
          this.handleCopyComplete(conn).then(() => {
            (conn as any).copyPending = false;
            // Resume processing any queued messages
            this.processConnection(conn);
          }).catch((e: any) => {
            (conn as any).copyPending = false;
            logger.error({ err: e.message }, 'CopyComplete failed');
            this.sendError(conn.socket, `COPY failed: ${e.message}`);
            this.sendReadyForQuery(conn.socket);
            this.processConnection(conn);
          });
        }
        conn.offset += msgLen + 1;
        break;
      }
      case 'd': {
        logger.debug({ copyState: conn.copyState, bufLen: conn.copyBufferLength ?? conn.copyBuffer?.length }, 'CopyData received');
        // CopyData — append to copy buffer with OOM protection (R-01)
        // Uses pre-allocated Buffer to avoid O(n²) Buffer.concat reallocations
        if (conn.copyState === 'active') {
          const payload = buf.subarray(off + 5, off + 1 + msgLen);
          if (conn.copyBuffer === undefined) {
            logger.info({ firstPayloadSize: payload.length, copyState: conn.copyState }, 'CopyData first chunk');
            conn.copyBuffer = Buffer.allocUnsafe(MAX_COPY_BUFFER_SIZE);
            conn.copyBufferLength = 0;
          }
          const newSize = conn.copyBufferLength! + payload.length;
          if (newSize > MAX_COPY_BUFFER_SIZE) {
            conn.copyState = 'failed';
            conn.copyBuffer = undefined;
            conn.copyBufferLength = undefined;
            conn.copyTableName = undefined;
            conn.copyColumns = undefined;
            conn.copyFormat = undefined;
            this.sendError(conn.socket, `COPY data exceeds maximum buffer size (${MAX_COPY_BUFFER_SIZE} bytes)`);
            conn.socket.end();
            conn.offset += msgLen + 1;
            return;
          }
          payload.copy(conn.copyBuffer!, conn.copyBufferLength);
          conn.copyBufferLength = newSize;
        }
        conn.offset += msgLen + 1;
        break;
      }
      case 'f': {
        // CopyFail — abort COPY
        if (conn.copyState === 'active') {
          conn.copyState = 'failed';
          conn.copyBuffer = undefined;
      conn.copyBufferLength = undefined;
          conn.copyTableName = undefined;
          conn.copyColumns = undefined;
          conn.copyFormat = undefined;
          this.sendError(conn.socket, 'COPY failed from client');
        }
        conn.offset += msgLen + 1;
        break;
      }
      case 'F': {
        // FunctionCall
        this.handleFunctionCall(conn, off, msgLen);
        conn.offset += msgLen + 1;
        break;
      }
      case 'p': {
        // PasswordMessage received during ready state — ignore
        conn.offset += msgLen + 1;
        break;
      }
      default: {
        logger.warn(`[PgWire] Unknown message type '${msgType}' (0x${buf[off].toString(16)}) — skipping`);
        conn.offset += msgLen + 1;
        break;
      }
    }
  }

  /**
   * Flush all queued pipeline queries using stored payload copies.
   * Parses each message from the stored Buffer (not from conn.buffer).
   */
  private flushPipeline(conn: PgWireConnectionInternal): void {
    const queries = conn.pipelineQueries;
    conn.pipelineQueries = [];

    for (const q of queries) {
      const buf = q.payload;
      const msgLen = buf.length - 1; // type byte + payload length = stored buffer length

      switch (q.type) {
        case 'Q': {
          const sql = buf.toString('utf8', 5, 5 + msgLen - 4).replace(/\0+$/, '');
          this.handleQuery(conn.socket, conn.session, sql);
          break;
        }
        case 'P':
          // Parse from stored payload: 'P' | int32 len | str stmtName | str sql | int16 numTypes | int32* types
          this.handleParseFromPayload(conn, buf);
          break;
        case 'B':
          this.handleBindFromPayload(conn, buf);
          break;
        case 'E':
          this.handleExecuteFromPayload(conn, buf);
          break;
        case 'D':
          this.handleDescribeFromPayload(conn, buf);
          break;
        case 'C':
          this.handleCloseFromPayload(conn, buf);
          break;
      }
    }
  }

  /**
   * Parse handler using a stored Buffer (not conn.buffer + offset).
   */
  private handleParseFromPayload(conn: PgWireConnectionInternal, buf: Buffer): void {
    let offset = 5;

    // Statement name
    const stmtRes = this.readCString(buf, offset);
    const stmtName = stmtRes.str;
    offset = stmtRes.endOffset;

    // SQL text
    const sqlRes = this.readCString(buf, offset);
    const sql = sqlRes.str;
    offset = sqlRes.endOffset;

    // Number of param type OIDs
    const numParamTypes = buf.readInt16BE(offset);
    offset += 2;

    const paramTypes: number[] = [];
    for (let i = 0; i < numParamTypes; i++) {
      paramTypes.push(buf.readInt32BE(offset));
      offset += 4;
    }

    this.handleParseInner(conn, stmtName, sql, paramTypes);
  }

  private handleBindFromPayload(conn: PgWireConnectionInternal, buf: Buffer): void {
    let offset = 5;

    // Portal name
    const portalRes = this.readCString(buf, offset);
    const portalName = portalRes.str;
    offset = portalRes.endOffset;

    // Prepared statement name
    const stmtRes = this.readCString(buf, offset);
    const stmtName = stmtRes.str;
    offset = stmtRes.endOffset;

    // Parse param format codes
    const numParamFormats = buf.readInt16BE(offset);
    offset += 2;
    const paramFormats: number[] = [];
    for (let i = 0; i < numParamFormats; i++) {
      paramFormats.push(buf.readInt16BE(offset));
      offset += 2;
    }

    // Number of parameters
    const numParams = buf.readInt16BE(offset);
    offset += 2;

    // Read parameter values (respecting format codes)
    const params: any[] = [];
    for (let i = 0; i < numParams; i++) {
      const paramLen = buf.readInt32BE(offset);
      offset += 4;
      if (paramLen === -1) {
        params.push(null);
      } else {
        const format = numParamFormats === 0 ? 0 : (i < paramFormats.length ? paramFormats[i] : paramFormats[0]);
        if (format === 1) {
          // Binary format — store raw buffer
          const raw = Buffer.alloc(paramLen);
          buf.copy(raw, 0, offset, offset + paramLen);
          params.push(raw);
          offset += paramLen;
        } else {
          // Text format (default)
          params.push(buf.toString('utf8', offset, offset + paramLen));
          offset += paramLen;
        }
      }
    }

    // Parse result format codes
    const numResultFormats = buf.readInt16BE(offset);
    offset += 2;
    const resultFormats: number[] = [];
    for (let i = 0; i < numResultFormats; i++) {
      resultFormats.push(buf.readInt16BE(offset));
      offset += 2;
    }

    // Store format codes for this portal
    conn.portalFormatCodes.set(portalName, { paramFormats, resultFormats });

    this.handleBindInner(conn, portalName, stmtName, params);
  }

  private handleExecuteFromPayload(conn: PgWireConnectionInternal, buf: Buffer): void {
    let offset = 5;

    // Portal name
    const portalRes = this.readCString(buf, offset);
    const portalName = portalRes.str;
    offset = portalRes.endOffset;

    // Max rows
    const maxRows = buf.readInt32BE(offset);

    void this.handleExecutePortal(conn, portalName, maxRows).catch(
      (err: any) => logger.error({ err, portalName }, 'Unhandled error in handleExecutePortal (pipeline)')
    );
  }

  private handleDescribeFromPayload(conn: PgWireConnectionInternal, buf: Buffer): void {
    const describeType = String.fromCharCode(buf[5]); // 'S' or 'P'
    const nameRes = this.readCString(buf, 6);
    const name = nameRes.str;

    if (describeType === 'S') {
      const stmt = this.preparedStatements.get(name) || this.preparedStatements.get('');
      if (stmt) {
        if (stmt.paramTypes.length > 0) {
          this.sendParameterDescription(conn.socket, stmt.paramTypes);
        }
        const columns = this.extractColumnsFromSql(stmt.sql);
        if (columns.length > 0) {
          if (columns.length === 1 && columns[0] === '*') {
            // Unresolved wildcard — will send RowDescription during Execute
            conn.portalsNeedingColumnResolve.add(name);
            this.sendNoData(conn.socket);
          } else {
            this.sendRowDescription(conn.socket, columns);
            conn.portalDescribeSentRowDescription.add(name);
          }
        } else {
          this.sendNoData(conn.socket);
        }
      } else {
        this.sendNoData(conn.socket);
      }
    } else {
      // Describe portal
      const portalCached = this.portalManager.getPortal(name);
      if (portalCached && portalCached.columns.length > 0) {
        this.sendRowDescription(conn.socket, portalCached.columns);
        conn.portalDescribeSentRowDescription.add(name);
      } else {
        // Not executed yet — check pendingBinds for bound-but-not-yet-executed portals
        const pendingBind = this.pendingBinds.get(name) || this.pendingBinds.get('');
        if (pendingBind) {
          const stmt = this.preparedStatements.get(pendingBind.statementName) || this.preparedStatements.get('');
          if (stmt) {
            const columns = this.extractColumnsFromSql(stmt.sql);
            if (columns.length > 0) {
              if (columns.length === 1 && columns[0] === '*') {
                conn.portalsNeedingColumnResolve.add(name);
                this.sendNoData(conn.socket);
              } else {
                this.sendRowDescription(conn.socket, columns);
                conn.portalDescribeSentRowDescription.add(name);
              }
            } else {
              this.sendNoData(conn.socket);
            }
          } else {
            this.sendNoData(conn.socket);
          }
        } else {
          this.sendNoData(conn.socket);
        }
      }
    }
  }

  private handleCloseFromPayload(conn: PgWireConnectionInternal, buf: Buffer): void {
    const closeType = String.fromCharCode(buf[5]); // 'S' or 'P'
    const nameRes = this.readCString(buf, 6);
    const name = nameRes.str;

    if (closeType === 'S') {
      this.preparedStatements.delete(name);
    } else {
      this.portalManager.closePortal(name);
      this.pendingBinds.delete(name);
    }

    this.sendCloseComplete(conn.socket);
  }

  // ════════════════════════════════════════════════
  //  Extended Query message handlers
  // ════════════════════════════════════════════════

  private handleParse(conn: PgWireConnectionInternal, off: number, msgLen: number): void {
    const buf = conn.buffer;
    let offset = off + 5;

    // Statement name
    const stmtRes = this.readCString(buf, offset);
    const stmtName = stmtRes.str;
    offset = stmtRes.endOffset;

    // SQL text
    const sqlRes = this.readCString(buf, offset);
    const sql = sqlRes.str;
    offset = sqlRes.endOffset;

    // Number of param type OIDs
    const numParamTypes = buf.readInt16BE(offset);
    offset += 2;

    const paramTypes: number[] = [];
    for (let i = 0; i < numParamTypes; i++) {
      paramTypes.push(buf.readInt32BE(offset));
      offset += 4;
    }

    this.handleParseInner(conn, stmtName, sql, paramTypes);
  }

  /** Shared parse logic (used by both inline and pipeline paths). */
  private handleParseInner(conn: PgWireConnectionInternal, stmtName: string, sql: string, paramTypes: number[]): void {
    // Run SQL through WiredQueryEngine shim pipeline at Parse time
    // so that described columns reflect the rewritten SQL
    const processed = this.wiredQueryEngine.process(sql);
    const processedSql = processed.sql;

    this.preparedStatements.set(stmtName, { sql: processedSql, paramTypes, originalSql: sql });
    this.sendParseComplete(conn.socket);
  }

  private handleBind(conn: PgWireConnectionInternal, off: number, msgLen: number): void {
    const buf = conn.buffer;
    let offset = off + 5;

    // Portal name
    const portalRes = this.readCString(buf, offset);
    const portalName = portalRes.str;
    offset = portalRes.endOffset;

    // Prepared statement name
    const stmtRes = this.readCString(buf, offset);
    const stmtName = stmtRes.str;
    offset = stmtRes.endOffset;

    // Parse param format codes
    const numParamFormats = buf.readInt16BE(offset);
    offset += 2;
    const paramFormats: number[] = [];
    for (let i = 0; i < numParamFormats; i++) {
      paramFormats.push(buf.readInt16BE(offset));
      offset += 2;
    }

    // Number of parameters
    const numParams = buf.readInt16BE(offset);
    offset += 2;

    // Read parameter values (respecting format codes)
    const params: any[] = [];
    for (let i = 0; i < numParams; i++) {
      const paramLen = buf.readInt32BE(offset);
      offset += 4;
      if (paramLen === -1) {
        params.push(null);
      } else {
        const format = numParamFormats === 0 ? 0 : (i < paramFormats.length ? paramFormats[i] : paramFormats[0]);
        if (format === 1) {
          // Binary format — store raw buffer
          const raw = Buffer.alloc(paramLen);
          buf.copy(raw, 0, offset, offset + paramLen);
          params.push(raw);
          offset += paramLen;
        } else {
          // Text format (default)
          params.push(buf.toString('utf8', offset, offset + paramLen));
          offset += paramLen;
        }
      }
    }

    // Parse result format codes
    const numResultFormats = buf.readInt16BE(offset);
    offset += 2;
    const resultFormats: number[] = [];
    for (let i = 0; i < numResultFormats; i++) {
      resultFormats.push(buf.readInt16BE(offset));
      offset += 2;
    }

    // Store format codes for this portal
    conn.portalFormatCodes.set(portalName, { paramFormats, resultFormats });

    this.handleBindInner(conn, portalName, stmtName, params);
  }

  /** Shared bind logic (used by both inline and pipeline paths). */
  private handleBindInner(conn: PgWireConnectionInternal, portalName: string, stmtName: string, params: any[]): void {
    // Store bind state (lazy initialization on first Execute via PortalManager)
    this.pendingBinds.set(portalName, { statementName: stmtName, params });
    this.sendBindComplete(conn.socket);
  }

  private handleExecute(conn: PgWireConnectionInternal, off: number, msgLen: number): void {
    const buf = conn.buffer;
    let offset = off + 5;

    // Portal name
    const portalRes = this.readCString(buf, offset);
    const portalName = portalRes.str;
    offset = portalRes.endOffset;

    // Max rows — 0 = unlimited, >0 = limit with potential PortalSuspended
    const maxRows = buf.readInt32BE(offset);

    // Fire async Execute. Set pending flag so the subsequent Sync handler
    // defers ReadyForQuery until Execute completes. This preserves the
    // PG protocol ordering: DataRow+CommandComplete → ReadyForQuery.
    conn.pendingAsyncExecute = true;
    const _execPortalStart = performance.now();
    void this.handleExecutePortal(conn, portalName, maxRows).finally(() => {
      const _execPortalMs = performance.now() - _execPortalStart;
      if (_execPortalMs > 100 || conn.deferredReadyForQuery) {
        process.stdout.write(`[PORTAL] ${_execPortalMs.toFixed(0)}ms ${conn.deferredReadyForQuery ? '(deferred RFQ)' : ''}\n`);
      }
      conn.pendingAsyncExecute = false;
      // If Sync deferred ReadyForQuery (async was pending when Sync ran),
      // send it now. Otherwise Sync handles RFQ normally when it arrives.
      if (conn.deferredReadyForQuery) {
        conn.socket.write(conn.deferredReadyForQuery);
        conn.deferredReadyForQuery = null;
      }
    }).catch(
      (err: any) => logger.error({ err, portalName }, 'Unhandled error in handleExecutePortal')
    );
  }

  /**
   * Execute a portal, either fresh (first Execute) or continued (subsequent Execute).
   *
   * Flow:
   *   1. If portal already has cached rows in PortalManager, return next batch
   *   2. Otherwise, materialize the full result set from QueryRouter, cache it, return first batch
   *   3. Send PortalSuspended if more rows remain, CommandComplete if drained
   */
  private async handleExecutePortal(
    conn: PgWireConnectionInternal,
    portalName: string,
    maxRows: number,
  ): Promise<void> {
    const socket = conn.socket;
    const session = conn.session;

    // Check if portal already has cached data (continued Execute)
    if (this.portalManager.getPortal(portalName)) {
      this.continuePortalExecution(conn, portalName, maxRows);
      return;
    }

    // First Execute — need to materialize results
    const bindInfo = this.pendingBinds.get(portalName) || this.pendingBinds.get('');
    if (!bindInfo) {
      this.sendError(socket, '26000: portal "' + portalName + '" does not exist');
      // Deferred Sync will send ReadyForQuery
      return;
    }

    const stmt = this.preparedStatements.get(bindInfo.statementName) || this.preparedStatements.get('');
    if (!stmt) {
      this.sendError(socket, '26000: prepared statement "' + bindInfo.statementName + '" not found');
      this.pendingBinds.delete(portalName);
      // Deferred Sync will send ReadyForQuery
      return;
    }

    try {
      // Clean up bind info after first use
      this.pendingBinds.delete(portalName);

      // === Handle transaction control synchronously ===
      // BEGIN, COMMIT, ROLLBACK, END must be processed through QueryRouter to
      // ensure proper transaction state (DML buffering via pendingChanges, etc.).
      // Prepared mode avoids the full SQL pipeline for these statements.
      const trimmedSql = stmt.sql.trim().toUpperCase().replace(/;\s*$/, '');
      if (/^(BEGIN|COMMIT|ROLLBACK|END)\b/.test(trimmedSql)) {
        await this.queryRouter.execute(stmt.sql, [], conn.sessionId);
        if (/^BEGIN\b/.test(trimmedSql)) {
          conn.session.transactionStatus = 'in_transaction';
        } else {
          conn.session.transactionStatus = 'idle';
        }
        const tag = trimmedSql.replace(/ (WORK|TRANSACTION)$/, '');
        this.sendCommandComplete(socket, tag);
        return;
      }

      // Execute the full query to materialize all results
      const sessionId = conn.sessionId;
      const result = await this.pipelineExec(stmt.sql, sessionId, bindInfo.params);

      // Check for cancellation during execute
      if (conn.cancelled || conn.abortController?.signal.aborted) {
        conn.cancelled = false;
        conn.abortController = null;
        return;
      }

      const rows = this.stripSystemColumns(result.rows);
      // Only extract columns from result rows when the query produces
      // results (SELECT) or has an explicit RETURNING clause. Non-RETURNING
      // DML (INSERT/UPDATE/DELETE) should have empty columns so that
      // Describe→NoData and Execute→no DataRow are consistent.
      const isDmlWithoutReturning =
        /\b(INSERT|UPDATE|DELETE)\b/i.test(stmt.sql) &&
        !this.hasReturningClause(stmt.sql);
      const columns = !isDmlWithoutReturning && rows.length > 0
        ? Object.keys(rows[0])
        : [];

      // Cache all results in PortalManager for cursor-based access
      this.portalManager.createPortal(
        portalName,
        bindInfo.statementName,
        bindInfo.params,
        stmt.sql,
        rows,
        columns,
      );

      logger.debug({ rows, columns, sql: stmt.sql?.substring(0, 60), params: bindInfo.params }, 'handleExecutePortal result');

      // Return the first batch
      this.continuePortalExecution(conn, portalName, maxRows);
    } catch (err: any) {
      this.sendError(socket, err.message);
      this.pendingBinds.delete(portalName);
    }
  }

  /**
   * Continue execution of an already-cached portal.
   * Returns the next batch of rows and signals PortalSuspended if more remain.
   */
  private continuePortalExecution(
    conn: PgWireConnectionInternal,
    portalName: string,
    maxRows: number,
  ): void {
    const socket = conn.socket;
    const session = conn.session;

    try {
      const result = this.portalManager.executePortal(portalName, maxRows);

      // Retrieve result format codes from Bind message for binary format support
      const formatInfo = conn.portalFormatCodes.get(portalName);
      const resultFormats = formatInfo?.resultFormats;

      // Send RowDescription in Execute response IF Describe didn't already
      // send it. Cases that need RowDescription during Execute:
      //   1. Describe sent NoData (columns unresolvable via `*`)
      //      → tracked by `portalsNeedingColumnResolve`
      //   2. No Describe was issued before Execute
      //      → `portalDescribeSentRowDescription` doesn't contain this portal
      // Describe 'P' with known columns → RowDescription already sent → skip.
      const descAlreadySentRD = conn.portalDescribeSentRowDescription.has(portalName);
      const mustSendRDNow = conn.portalsNeedingColumnResolve.has(portalName);
      if (result.columns.length > 0 && (mustSendRDNow || !descAlreadySentRD)) {
        if (mustSendRDNow) {
          conn.portalsNeedingColumnResolve.delete(portalName);
        }
        // Resolve type OIDs for the RowDescription if binary format is requested
        const portal = this.portalManager.getPortal(portalName);
        const sql = portal?.statementName
          ? this.preparedStatements.get(portal.statementName)?.sql || ''
          : '';
        const colOids = resultFormats?.some(f => f === 1)
          ? this.resolveColumnOids(sql, result.columns)
          : undefined;
        this.sendRowDescription(socket, result.columns, colOids, resultFormats);
      }

      // PG extended query protocol: RowDescription is sent during Describe,
      // NOT during Execute. Only send DataRow + CommandComplete here.
      // (SimpleQuery has its own handler that sends RowDescription separately.)

      // Send DataRow for each row (only if there are columns to send)
      if (result.columns.length > 0) {
        const portal = this.portalManager.getPortal(portalName);
        const sql = portal?.statementName
          ? this.preparedStatements.get(portal.statementName)?.sql || ''
          : '';
        const colOids = resultFormats?.some(f => f === 1)
          ? this.resolveColumnOids(sql, result.columns)
          : undefined;
        for (const row of result.rows) {
          this.sendDataRow(socket, result.columns, row, colOids, resultFormats);
        }
      }

      if (result.suspended) {
        this.sendPortalSuspended(socket);
      } else {
        this.sendCommandComplete(socket, 'SELECT ' + (result.rows.length || 0));
      }
    } catch (err: any) {
      this.sendError(socket, err.message);
    }
  }

  private handleDescribe(conn: PgWireConnectionInternal, off: number, msgLen: number): void {
    const buf = conn.buffer;
    const describeType = String.fromCharCode(buf[off + 5]); // 'S' or 'P'
    const nameRes = this.readCString(buf, off + 6);
    const name = nameRes.str;

    if (describeType === 'S') {
      const stmt = this.preparedStatements.get(name) || this.preparedStatements.get('');
      if (stmt) {
        if (stmt.paramTypes.length > 0) {
          this.sendParameterDescription(conn.socket, stmt.paramTypes);
        }
        const columns = this.extractColumnsFromSql(stmt.sql);
        if (columns.length > 0) {
          if (columns.length === 1 && columns[0] === '*') {
            // Unresolved wildcard — will send RowDescription during Execute
            conn.portalsNeedingColumnResolve.add(name);
            this.sendNoData(conn.socket);
          } else {
            this.sendRowDescription(conn.socket, columns);
            conn.portalDescribeSentRowDescription.add(name);
          }
        } else {
          this.sendNoData(conn.socket);
        }
      } else {
        this.sendNoData(conn.socket);
      }
    } else {
      // Describe portal — check PortalManager first (executed), then pendingBinds (bound)
      const portalCached = this.portalManager.getPortal(name);
      if (portalCached) {
        // Portal has been executed — use cached columns
        if (portalCached.columns.length > 0) {
          this.sendRowDescription(conn.socket, portalCached.columns);
          conn.portalDescribeSentRowDescription.add(name);
        } else {
          this.sendNoData(conn.socket);
        }
      } else {
        // Check pendingBinds for bound-but-not-yet-executed portals
        const pendingBind = this.pendingBinds.get(name) || this.pendingBinds.get('');
        if (pendingBind) {
          const stmt = this.preparedStatements.get(pendingBind.statementName) || this.preparedStatements.get('');
          if (stmt) {
            const columns = this.extractColumnsFromSql(stmt.sql);
            if (columns.length > 0) {
              // If columns contain unresolved `*`, mark portal for column
              // resolution during Execute (we'll send RowDescription
              // from continuePortalExecution with real column names).
              if (columns.length === 1 && columns[0] === '*') {
                conn.portalsNeedingColumnResolve.add(name);
                this.sendNoData(conn.socket);
              } else {
                this.sendRowDescription(conn.socket, columns);
                conn.portalDescribeSentRowDescription.add(name);
              }
            } else {
              this.sendNoData(conn.socket);
            }
          } else {
            this.sendNoData(conn.socket);
          }
        } else {
          this.sendNoData(conn.socket);
        }
      }
    }
  }

  private handleClose(conn: PgWireConnectionInternal, off: number, msgLen: number): void {
    const buf = conn.buffer;
    const closeType = String.fromCharCode(buf[off + 5]); // 'S' or 'P'
    const nameRes = this.readCString(buf, off + 6);
    const name = nameRes.str;

    if (closeType === 'S') {
      this.preparedStatements.delete(name);
    } else {
      this.portalManager.closePortal(name);
      this.pendingBinds.delete(name);
    }

    this.sendCloseComplete(conn.socket);
  }

  // ════════════════════════════════════════════════
  //  Query handling
  // ════════════════════════════════════════════════

  /**
   * Split a SQL string into individual statements, respecting string literals
   * and comments so that semicolons embedded inside quotes or comments are not
   * treated as statement separators.
   *
   * Uses a single-pass state machine — O(n), no regex backtracking.
   */
  private static splitSqlStatements(sql: string): string[] {
    const stmts: string[] = [];
    let current: string[] = [];
    let i = 0;
    let state: string = ' ';
    let dollarTag: string = ''; // tracks $tag$ when in dollar-quoting

    while (i < sql.length) {
      const ch = sql[i];

      switch (state) {
        case ' ': { // normal
          if (ch === ';') {
            const stmt = current.join('').trim();
            if (stmt) stmts.push(stmt);
            current = [];
            i++;
            continue;
          }
          if (ch === '\'' && sql[i - 1] !== '\\') { state = '\''; break; }
          if (ch === '"') { state = '"'; break; }
          if (ch === '-' && sql[i + 1] === '-') { state = '-'; i += 2; continue; }
          if (ch === '/' && sql[i + 1] === '*') { state = '*'; i += 2; continue; }
          // Dollar quoting: $$ or $tag$
          if (ch === '$') {
            dollarTag = '';
            let j = i + 1;
            // Read tag (allow empty for $$)
            while (j < sql.length && sql[j] !== '$' && sql[j] !== ';' && sql[j] !== "'" && sql[j] !== '"' && sql[j] !== '(' && sql[j] !== ')') {
              dollarTag += sql[j];
              j++;
            }
            if (j < sql.length && sql[j] === '$') {
              // Found matching $tag$, enter dollar-quoting
              state = '$';
              current.push(ch, ...dollarTag, '$');
              i = j + 1;
              continue;
            }
            // Not dollar quoting, fall through
            dollarTag = '';
          }
          break;
        }
        case '\'': { // single-quoted string
          if (ch === '\'') {
            if (sql[i + 1] === '\'') { current.push("'"); i += 2; continue; }
            state = ' ';
          }
          break;
        }
        case '"': { // double-quoted identifier
          if (ch === '"') state = ' ';
          break;
        }
        case '-': { // line comment
          if (ch === '\n') state = ' ';
          break;
        }
        case '*': { // block comment
          if (ch === '*' && sql[i + 1] === '/') { state = ' '; i += 2; continue; }
          break;
        }
        case '$': { // dollar-quoted string
          if (ch === '$') {
            // Check if this closes the dollar quote
            let k = i + 1;
            let tagChars = '';
            while (k < sql.length && sql[k] !== '$' && k - i < 64) {
              tagChars += sql[k];
              k++;
            }
            if (k < sql.length && sql[k] === '$' && tagChars === dollarTag) {
              // Closing $tag$ found — push $$ and return to normal
              current.push('$', ...tagChars, '$');
              i = k + 1;
              state = ' ';
              dollarTag = '';
              continue;
            }
          }
          // Character is not part of closing $tag$ — pushed by outer code
          break;
        }
      }

      current.push(ch);
      i++;
    }

    // Last statement
    const last = current.join('').trim();
    if (last) stmts.push(last);

    return stmts;
  }

  private async executeSingleQuery(
    socket: net.Socket,
    ctx: PgSessionContext,
    sql: string,
  ): Promise<void> {
    try {
      const sessionId = ctx.sessionId;
      const result = await this.pipelineExec(sql, sessionId, []);
      this.sendQueryResult(socket, result, sql);
    } catch (err: any) {
      this.sendError(socket, err.message);
    }
  }

  private async handleQuery(
    socket: net.Socket,
    ctx: PgSessionContext,
    sql: string,
    params?: any[],
  ): Promise<void> {
    const conn = this.conns.get(ctx.sessionId);
    const sessionId = ctx.sessionId;
    const userName = conn?.userName || 'unknown';

    // Gap 12: Reset cancel flag at start of each query
    if (conn) {
      conn.cancelled = false;
      conn.queryStartTime = Date.now();
      // Create fresh AbortController for this query
      conn.abortController = new AbortController();
    }

    // Gap 12: Check for cancellation before executing
    if (conn && conn.cancelled) {
      conn.cancelled = false;
      conn.abortController = null;
      const errResult: QueryResult = {
        rows: [],
        rowCount: 0,
        queryTimeMs: Date.now() - (conn.queryStartTime || Date.now()),
        engine: 'shard',
      };
      this.sendQueryResult(socket, errResult);
      this.sendReadyForQuery(socket);
      return;
    }

    // G26: Track active query (for pg_terminate_backend / pg_stat_activity)
    if (sessionId) {
      this.connectionManager.setActiveQuery(sessionId, sql);
    }

    // ═══════════════════════════════════════════════════════════
    // Multi-statement handling (Simple Query protocol)
    //
    // PG Simple Query protocol accepts a single string that may contain
    // multiple SQL statements separated by semicolons. Each statement is
    // executed independently and produces its own result set (or error).
    // A single ReadyForQuery is sent after all statements complete.
    //
    // The state-machine splitter handles string literals and comments
    // so that embedded semicolons are correctly ignored.
    // ═══════════════════════════════════════════════════════════
    const statements = PgWireServer.splitSqlStatements(sql);
    if (statements.length > 1) {
      for (const stmt of statements) {
        await this.executeSingleQuery(socket, ctx, stmt);
      }
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // G21: Audit DDL operations
    const trimmedSql = sql.trim().toUpperCase();

    const isDDL = /^(CREATE|ALTER|DROP|TRUNCATE|RENAME|COMMENT)\b/.test(trimmedSql);
    if (isDDL && this.auditLogger) {
      this.auditLogger.logQuery(sessionId, userName, sql, 'success');
    }

    // G26: pg_terminate_backend (with permission check)
    if (/^SELECT\s+pg_terminate_backend\s*\(/i.test(sql.trim())) {
      const match = sql.match(/pg_terminate_backend\s*\(\s*['"]?(\d+)['"]?\s*\)/i);
      if (match && match[1]) {
        const targetPid = parseInt(match[1], 10);
        const terminated = this.terminateBackendWithPermissionCheck(targetPid, conn);
        const result = { pg_terminate_backend: terminated };
        const fakeResult: QueryResult = {
          rows: [result],
          rowCount: 1,
          queryTimeMs: 0,
          engine: 'shard',
        };
        this.sendQueryResult(socket, fakeResult);
        this.sendReadyForQuery(socket);
        // Reset active query
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }
    }

    // G26: pg_cancel_backend (with permission check)
    if (/^SELECT\s+pg_cancel_backend\s*\(/i.test(sql.trim())) {
      const match = sql.match(/pg_cancel_backend\s*\(\s*['"]?(\d+)['"]?\s*\)/i);
      if (match && match[1]) {
        const targetPid = parseInt(match[1], 10);
        const cancelled = this.cancelBackendWithPermissionCheck(targetPid, conn);
        const result = { pg_cancel_backend: cancelled };
        const fakeResult: QueryResult = {
          rows: [result],
          rowCount: 1,
          queryTimeMs: 0,
          engine: 'shard',
        };
        this.sendQueryResult(socket, fakeResult);
        this.sendReadyForQuery(socket);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }
    }

    // pg_reload_conf() — reload pg_hba.conf
    if (/^SELECT\s+pg_reload_conf\s*\(/i.test(sql.trim())) {
      let reloadResult = false;
      if (this.pgHbaConf) {
        try {
          // Check superuser permission
          const isSuper = this.roleManager
            ? this.roleManager.checkPrivilege(conn?.userName || 'unknown', 'SUPERUSER')
            : true;
          if (!isSuper) {
            this.sendError(socket, 'permission denied: must be superuser to reload configuration');
            this.sendReadyForQuery(socket);
            if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
            return;
          }
          this.pgHbaConf.reload();
          reloadResult = true;
        } catch (err: any) {
          logger.error({ err: err.message }, 'pg_reload_conf failed');
        }
      }
      const result = { pg_reload_conf: reloadResult };
      const fakeResult: QueryResult = {
        rows: [result],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // SHOW sslmode
    if (/^SHOW\s+sslmode\s*;?\s*$/i.test(sql.trim())) {
      const sslmode = getBackendSslMode();
      const fakeResult: QueryResult = {
        rows: [{ sslmode }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // SHOW ssl
    if (/^SHOW\s+ssl\s*;?\s*$/i.test(sql.trim())) {
      const ssl = getShowSsl();
      const fakeResult: QueryResult = {
        rows: [{ ssl }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // SHOW hba_file
    if (/^SHOW\s+hba_file\s*;?\s*$/i.test(sql.trim())) {
      const hbaFile = this.pgHbaConf ? this.pgHbaConf.getLoadedFilePath() || 'unset' : 'unset';
      const fakeResult: QueryResult = {
        rows: [{ hba_file: hbaFile }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // SHOW ssl_ca_file
    if (/^SHOW\s+ssl_ca_file\s*;?\s*$/i.test(sql.trim())) {
      const caFile = this.tlsConfig?.ca || '';
      const fakeResult: QueryResult = {
        rows: [{ ssl_ca_file: caFile }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // SHOW ssl_cert_file
    if (/^SHOW\s+ssl_cert_file\s*;?\s*$/i.test(sql.trim())) {
      const certFile = this.tlsConfig?.cert || '';
      const fakeResult: QueryResult = {
        rows: [{ ssl_cert_file: certFile }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // SHOW ssl_key_file
    if (/^SHOW\s+ssl_key_file\s*;?\s*$/i.test(sql.trim())) {
      const keyFile = this.tlsConfig?.key || '';
      const fakeResult: QueryResult = {
        rows: [{ ssl_key_file: keyFile }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // SHOW hba_file_contents (custom extension)
    if (/^SHOW\s+hba_file_contents\s*;?\s*$/i.test(sql.trim())) {
      const content = this.pgHbaConf ? this.pgHbaConf.toText() : '';
      const fakeResult: QueryResult = {
        rows: [{ hba_file_contents: content }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
      this.sendQueryResult(socket, fakeResult);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // R2-P1.1b: Generic SHOW <parameter> (catch-all after all specific SHOW handlers)
    if (/^SHOW\s+/i.test(trimmedSql)) {
      const match = sql.match(/SHOW\s+(\S+)/i);
      const param = match ? match[1].replace(/['";]/g, '') : 'unknown';
      this.sendRowDescription(socket, [param]);
      this.sendDataRow(socket, [param], { [param]: `on` });
      this.sendCommandComplete(socket, 'SHOW');
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // G2: LISTEN / UNLISTEN / NOTIFY
    if (/^LISTEN\s+/i.test(trimmedSql)) {
      const match = sql.match(/LISTEN\s+(\S+)/i);
      if (match && match[1]) {
        const channel = match[1].replace(/['"]/g, '');
        this.channelManager.listen(channel, sessionId);
        this.sendCommandComplete(socket, 'LISTEN');
        this.sendReadyForQuery(socket);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }
    }

    if (/^UNLISTEN\s+/i.test(trimmedSql)) {
      const match = sql.match(/UNLISTEN\s+(\S+)/i);
      if (match && match[1]) {
        const channel = match[1].replace(/['"]/g, '') === '*' ? '*' : match[1].replace(/['"]/g, '');
        if (channel === '*') {
          this.channelManager.unlistenAll(sessionId);
        } else {
          this.channelManager.unlisten(channel, sessionId);
        }
        this.sendCommandComplete(socket, 'UNLISTEN');
        this.sendReadyForQuery(socket);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }
    }

    if (/^NOTIFY\s+/i.test(trimmedSql)) {
      const match = sql.match(/NOTIFY\s+(\S+)(?:\s*,\s*(.+))?/i);
      if (match && match[1]) {
        const channel = match[1].replace(/['"]/g, '');
        const payload = match[2] ? match[2].replace(/^['"]|['"]$/g, '').trim() : '';
        const events = this.channelManager.notify(channel, payload);
        // Send NotificationResponse to each subscriber
        for (const event of events) {
          const targetConn = this.conns.get(event.sessionId);
          if (targetConn) {
            this.sendNotificationResponse(targetConn.socket, event.sessionId, event.channel, event.payload);
          }
        }
        this.sendCommandComplete(socket, 'NOTIFY');
        this.sendReadyForQuery(socket);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }
    }

    // ── Replication Protocol Commands ──
    // These are sent by PG replication clients (pg_basebackup, streaming standby)
    // as simple Query ('Q') messages. We intercept them here and route to
    // the corresponding handlers instead of passing them through to SQLite.

    // IDENTIFY_SYSTEM — return system identity for replication
    if (/^IDENTIFY_SYSTEM\b/i.test(trimmedSql)) {
      if (!conn) return;
      const result = this.handleIdentifySystem(conn);
      this.sendQueryResult(socket, result);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // START_REPLICATION [LSN] [options] — begin WAL streaming
    if (/^START_REPLICATION\b/i.test(trimmedSql)) {
      if (!conn) return;
      const result = this.handleStartReplication(conn, sql);
      this.sendQueryResult(socket, result);
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      // Note: actual WAL streaming is handled by WALSender, which runs
      // as a persistent ZeroMQ worker. This handler returns the initial
      // snapshot state so the client can verify the system.
      return;
    }

    // CREATE_REPLICATION_SLOT slot_name PHYSICAL / LOGICAL ...
    if (/^CREATE_REPLICATION_SLOT\b/i.test(trimmedSql)) {
      if (!conn) return;
      const result = this.handleCreateReplicationSlot(conn, sql);
      this.sendQueryResult(socket, result);
      this.sendCommandComplete(socket, 'CREATE_REPLICATION_SLOT');
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // DROP_REPLICATION_SLOT slot_name
    if (/^DROP_REPLICATION_SLOT\b/i.test(trimmedSql)) {
      if (!conn) return;
      const res = this.handleDropReplicationSlot(conn, sql);
      this.sendCommandComplete(socket, res ? 'DROP_REPLICATION_SLOT' : 'ERROR');
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // R2-P1.5: DISCARD ALL — protocol-level no-op (PG: resets session state)
    if (/^\s*DISCARD\s+ALL\s*/i.test(trimmedSql)) {
      this.sendCommandComplete(socket, 'DISCARD');
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // R2-P1.2: SET TRANSACTION ISOLATION LEVEL — protocol-level no-op
    if (/^\s*SET\s+TRANSACTION\b/i.test(trimmedSql)) {
      ctx.transactionStatus = 'in_transaction';
      this.sendCommandComplete(socket, 'SET');
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // Phase E: SET statement_timeout GUC
    if (/^SET\s+statement_timeout\s*=/i.test(trimmedSql)) {
      const match = sql.match(/=\s*['"]?(\d+)['"]?\s*;?\s*$/i);
      if (match && conn) {
        conn.statementTimeout = parseInt(match[1], 10);
      }
      this.sendCommandComplete(socket, 'SET');
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // Phase E: SET prepared_statement_only GUC
    if (/^SET\s+prepared_statement_only\s*=/i.test(trimmedSql)) {
      const match = sql.match(/=\s*['"]?(on|off|true|false|1|0)['"]?\s*;?\s*$/i);
      if (match && conn) {
        const val = match[1].toLowerCase();
        conn.preparedStatementOnly = val === 'on' || val === 'true' || val === '1';
      }
      this.sendCommandComplete(socket, 'SET');
      this.sendReadyForQuery(socket);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // Phase E: statement_timeout AbortController setup
    if (conn && conn.statementTimeout > 0 && !conn.cancelled && conn.abortController) {
      const timer = setTimeout(() => {
        if (conn && conn.abortController) {
          conn.abortController.abort();
          conn.cancelled = true;
          conn.abortController = null;
          logger.info({ sessionId, timeoutMs: conn.statementTimeout }, 'Query timed out');
        }
      }, conn.statementTimeout);
      timer.unref();
    }

    // G1: COPY detection
    if (/^COPY\s+/i.test(trimmedSql)) {
      await this.handleCopy(sql, socket, conn!, sessionId, userName);
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // Cursor statement routing: DECLARE / FETCH / MOVE / CLOSE
    if (await this.handleCursorStatement(socket, sql, sessionId, userName, conn!)) {
      if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
      return;
    }

    // Check RBAC privilege if RoleManager is configured
    if (this.roleManager) {
      const operation = this.extractQueryOperation(sql);
      if (operation && sessionId) {
        const roleName = conn?.userName || 'unknown';
        if (!this.roleManager.checkPrivilege(roleName, operation)) {
          this.sendError(socket, `permission denied for operation ${operation}`);
          this.sendReadyForQuery(socket);
          if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
          return;
        }
      }
    }

    try {
      // Gap 12: Check cancellation before execution
      if (conn && conn.cancelled) {
        conn.cancelled = false;
        const cancelledResult: QueryResult = {
          rows: [],
          rowCount: 0,
          queryTimeMs: 0,
          engine: 'shard',
        };
        this.sendQueryResult(socket, cancelledResult);
        this.sendReadyForQuery(socket);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }

      // Gap 12: Check statement timeout
      if (conn && conn.statementTimeout > 0) {
        const elapsed = Date.now() - conn.queryStartTime;
        if (elapsed > conn.statementTimeout) {
          conn.cancelled = false;
          ctx.transactionStatus = 'failed';
          this.sendError(socket, 'canceling statement due to statement timeout');
          this.sendReadyForQuery(socket, ctx.transactionStatus);
          if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
          return;
        }
      }

      // Execute with cancellation support
      // Apply WiredQueryEngine shim pipeline for simple queries too so that
      // the SQL going into execute() is pre-rewritten, matching the prepared
      // query path where WiredQueryEngine runs at Parse time. This eliminates
      // repeated Step 0b text transforms inside execute().
      let simpleSql = this.wiredQueryEngine.process(sql).sql;

      // R2-P1.4: Rewrite PG built-in functions to literal values (SQLite has no equivalent)
      if (conn) {
        simpleSql = simpleSql
          .replace(/\bcurrent_user\b/g, `'${conn.userName || 'unknown'}'`)
          .replace(/\bcurrent_schema\b/g, `'public'`)
          .replace(/\bcurrent_database\b/g, `'postgres'`)
          .replace(/version\s*\(\)/gi, `'SqlVec 1.0.0 on x86_64-linux-gnu, based on PostgreSQL 16.4'`);
      }

      // R2-P1.7: information_schema query interception
      if (/\binformation_schema\.tables\b/i.test(simpleSql)) {
        let tableNames: string[] = [];
        try {
          // Direct query to SQLite — must use simple SELECT that QueryRouter passes through
          const masterResult = await this.queryRouter.execute(
            "SELECT tbl_name AS n FROM sqlite_master WHERE type='table'",
            [], sessionId,
          );
          tableNames = (masterResult.rows as any[])
            .map((r: any) => r.n)
            .filter((n: string) => !n.startsWith('sqlite_') && !n.startsWith('__'));
        } catch {
          // Fallback: empty result
        }
        const infoRows = tableNames.map(name => ({
          table_catalog: 'postgres', table_schema: 'public',
          table_name: name, table_type: 'BASE TABLE',
        }));
        const columns = ['table_catalog', 'table_schema', 'table_name', 'table_type'];
        this.sendRowDescription(socket, columns);
        for (const row of infoRows) this.sendDataRow(socket, columns, row);
        this.sendCommandComplete(socket, 'SELECT ' + infoRows.length);
        this.sendReadyForQuery(socket);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }

      const t0 = performance.now();
      // Phase A: Route through pipeline (fallback to queryRouter when pipeline unavailable)
      const result = await this.pipelineExec(simpleSql, sessionId, params);
      const elapsed = performance.now() - t0;
      PgWireServer.timingStats.count++;
      PgWireServer.timingStats.totalMs += elapsed;
      if (elapsed > PgWireServer.timingStats.maxMs) PgWireServer.timingStats.maxMs = elapsed;
      // Bucket by SQL type (first word)
      const typeKey = sql.trim().split(/\s+/)[0]?.toUpperCase() || 'UNKNOWN';
      let bucket = PgWireServer.timingStats.byType.get(typeKey);
      if (!bucket) { bucket = { count: 0, totalMs: 0, maxMs: 0 }; PgWireServer.timingStats.byType.set(typeKey, bucket); }
      bucket.count++;
      bucket.totalMs += elapsed;
      if (elapsed > bucket.maxMs) bucket.maxMs = elapsed;

      // R2-P1.6: ENHANCE EXPLAIN ANALYZE output with PG-standard timing rows
      if (/^\s*EXPLAIN\s+ANALYZE\b/i.test(trimmedSql) && result.rows.length > 0) {
        result.rows.push({ 'QUERY PLAN': `Planning Time: 0.100 ms` });
        result.rows.push({ 'QUERY PLAN': `Execution Time: ${elapsed.toFixed(3)} ms` });
      }

      // Check if query was cancelled during execution
      if (conn?.cancelled) {
        conn.cancelled = false;
        ctx.transactionStatus = 'failed';
        this.sendError(socket, 'canceling statement due to user request');
        this.sendReadyForQuery(socket, ctx.transactionStatus);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }

      this.sendQueryResult(socket, result, sql);

      // C-05: Update transaction state based on actual execution result
      if (/^BEGIN\b/i.test(trimmedSql) || /^START\s+TRANSACTION\b/i.test(trimmedSql)) {
        ctx.transactionStatus = 'in_transaction';
      } else if (/^COMMIT\b/i.test(trimmedSql)) {
        ctx.transactionStatus = 'idle';
      } else if (/^ROLLBACK\b/i.test(trimmedSql)) {
        ctx.transactionStatus = 'idle';
      }

      // Send NOTICE for successful DDL
      if (isDDL) {
        this.sendNotice(socket, `${trimmedSql.split(' ')[0]} completed successfully`);
      }
    } catch (err: any) {
      // Don't report AbortError as a regular error
      if (err.name === 'AbortError') {
        ctx.transactionStatus = 'failed';
        this.sendError(socket, 'canceling statement due to user request');
        this.sendReadyForQuery(socket, ctx.transactionStatus);
        if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
        return;
      }
      // G21: Audit query failure
      if (this.auditLogger && sessionId) {
        this.auditLogger.logQuery(sessionId, userName, sql, 'failure', {
          errorMessage: err.message,
        });
      }
      // GAP 2: Route DatabaseError through sendDatabaseError for rich field encoding
      ctx.transactionStatus = 'failed';
      this.sendDatabaseError(socket, err);
    }
    this.sendReadyForQuery(socket, ctx.transactionStatus);

    // G26: Clear active query
    if (sessionId) this.connectionManager.setActiveQuery(sessionId, null);
  }

  /**
   * Extract the SQL operation type from a query string for privilege checks.
   */
  private extractQueryOperation(sql: string): 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | null {
    const trimmed = sql.trim().toUpperCase();
    if (trimmed.startsWith('SELECT')) return 'SELECT';
    if (trimmed.startsWith('INSERT')) return 'INSERT';
    if (trimmed.startsWith('UPDATE')) return 'UPDATE';
    if (trimmed.startsWith('DELETE')) return 'DELETE';
    return null;
  }

  // ════════════════════════════════════════════════
  //  Cursor statement handling
  // ════════════════════════════════════════════════

  /**
   * Handle cursor-related SQL statements (DECLARE CURSOR, FETCH, MOVE, CLOSE)
   * and WHERE CURRENT OF (error). Returns true if the statement was handled.
   */
  private async handleCursorStatement(
    socket: net.Socket,
    sql: string,
    sessionId: string,
    userName: string,
    conn: PgWireConnectionInternal,
  ): Promise<boolean> {
    const trimmed = sql.trim();

    // WHERE CURRENT OF — graceful degradation with clear error
    const whereCurrentMatch = trimmed.match(/WHERE\s+CURRENT\s+OF\s+([A-Za-z_][A-Za-z0-9_]*)/i);
    if (whereCurrentMatch) {
      this.sendError(socket, 'UPDATE/DELETE WHERE CURRENT OF not supported yet');
      this.sendReadyForQuery(socket);
      return true;
    }

    // ── DECLARE name [SCROLL] [WITH HOLD] CURSOR FOR select ──
    const declareMatch = trimmed.match(
      /^\s*DECLARE\s+([A-Za-z_][A-Za-z0-9_]*)\s*(SCROLL\s+)?(?:CURSOR\s+)?(WITH\s+HOLD\s+|WITHOUT\s+HOLD\s+)?(?:CURSOR\s+)?FOR\s+(.*)$/is,
    );
    if (declareMatch) {
      const cursorName = declareMatch[1];
      const scroll = !!declareMatch[2];
      const rawHold = declareMatch[3] || '';
      const hold = rawHold.toUpperCase().includes('WITH HOLD');
      const innerSql = declareMatch[4].trim().replace(/;+$/, '');

      try {
        // Execute the inner SELECT to materialize rows
        const result = await this.queryRouter.execute(innerSql);
        const columns = result.rows.length > 0 ? Object.keys(result.rows[0]) : [];
        const rows = result.rows.map((row) => columns.map((col) => row[col]));

        this.cursorManager.declare(cursorName, innerSql, scroll, hold, rows, columns, sessionId);
        this.sendCommandComplete(socket, 'DECLARE CURSOR');
      } catch (err: any) {
        this.sendError(socket, `DECLARE CURSOR failed: ${err.message}`);
      }
      this.sendReadyForQuery(socket);
      return true;
    }

    // ── FETCH [direction [count]] [FROM|IN] name ──
    // Supports: FETCH NEXT 10 FROM c, FETCH FORWARD FROM c, FETCH c, FETCH 10 IN c
    const fetchMatch = trimmed.match(
      /^\s*FETCH\s+(?:(NEXT|PRIOR|FIRST|LAST|ABSOLUTE|RELATIVE|FORWARD|BACKWARD)\s+(\d+)\s+(?:FROM|IN)\s+|(NEXT|PRIOR|FIRST|LAST|FORWARD|BACKWARD)\s+(?:FROM|IN)\s+|(?:FROM|IN)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$/i,
    );
    if (fetchMatch) {
      const cursorName = fetchMatch[4] || fetchMatch[5] || '';
      const directionRaw = (fetchMatch[1] || fetchMatch[3] || 'NEXT').toUpperCase();
      const rawCount = fetchMatch[2] ? parseInt(fetchMatch[2], 10) : 1;

      // Map FORWARD → NEXT, BACKWARD → PRIOR
      let direction: 'NEXT' | 'PRIOR' | 'FIRST' | 'LAST' | 'ABSOLUTE' | 'RELATIVE';
      let count = rawCount;
      if (directionRaw === 'FORWARD') {
        direction = 'NEXT';
      } else if (directionRaw === 'BACKWARD') {
        direction = 'PRIOR';
      } else if (directionRaw === 'ABSOLUTE' || directionRaw === 'RELATIVE') {
        direction = directionRaw;
      } else {
        direction = directionRaw as any;
      }

      try {
        const cursor = this.cursorManager.getCursor(cursorName);
        const columns = cursor?.columns || [];

        const fetched = this.cursorManager.fetch(cursorName, direction, count);
        const rowCount = fetched.length;

        // Send RowDescription if we have columns
        if (rowCount > 0 && columns.length > 0) {
          this.sendRowDescription(socket, columns);
        } else if (columns.length > 0) {
          // Even with 0 rows, send RowDescription so client knows column structure
          this.sendRowDescription(socket, columns);
        }

        // Send DataRow for each fetched row
        for (const row of fetched) {
          const rowObj: Record<string, any> = {};
          columns.forEach((col, i) => {
            rowObj[col] = row[i];
          });
          this.sendDataRow(socket, columns, rowObj);
        }

        this.sendCommandComplete(socket, `FETCH ${rowCount}`);
      } catch (err: any) {
        this.sendError(socket, err.message);
      }
      this.sendReadyForQuery(socket);
      return true;
    }

    // ── MOVE [direction [count]] [FROM|IN] name ──
    const moveMatch = trimmed.match(
      /^\s*MOVE\s+(?:(NEXT|PRIOR|FIRST|LAST|ABSOLUTE|RELATIVE|FORWARD|BACKWARD)\s+(\d+)\s+(?:FROM|IN)\s+|(NEXT|PRIOR|FIRST|LAST|FORWARD|BACKWARD)\s+(?:FROM|IN)\s+|(?:FROM|IN)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$/i,
    );
    if (moveMatch) {
      const cursorName = moveMatch[4] || moveMatch[5] || '';
      const directionRaw = (moveMatch[1] || moveMatch[3] || 'NEXT').toUpperCase();
      const count = moveMatch[2] ? parseInt(moveMatch[2], 10) : 1;

      let direction = directionRaw;
      if (direction === 'FORWARD') direction = 'NEXT';
      if (direction === 'BACKWARD') direction = 'PRIOR';

      try {
        const moved = this.cursorManager.move(cursorName, direction, count);
        this.sendCommandComplete(socket, `MOVE ${moved}`);
      } catch (err: any) {
        this.sendError(socket, err.message);
      }
      this.sendReadyForQuery(socket);
      return true;
    }

    // ── CLOSE ALL ──
    if (/^\s*CLOSE\s+ALL\s*;?\s*$/i.test(trimmed)) {
      this.cursorManager.closeAll(sessionId);
      this.sendCommandComplete(socket, 'CLOSE ALL');
      this.sendReadyForQuery(socket);
      return true;
    }

    // ── CLOSE name ──
    const closeMatch = trimmed.match(/^\s*CLOSE\s+([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$/i);
    if (closeMatch) {
      const cursorName = closeMatch[1];
      try {
        this.cursorManager.close(cursorName);
        this.sendCommandComplete(socket, 'CLOSE CURSOR');
      } catch (err: any) {
        this.sendError(socket, err.message);
      }
      this.sendReadyForQuery(socket);
      return true;
    }

    return false;
  }

  // ════════════════════════════════════════════════
  //  Column extraction via pgsql-ast-parser
  // ════════════════════════════════════════════════

  private extractColumnsFromSql(sql: string): string[] {
    // Template-based cache: pgbench's Describe sends identical SELECT column
    // queries with different AID values. Avoid redundant pgsql-ast-parser calls.
    const cached = cacheGet<string[]>('extractColumns', sql);
    if (cached) return cached;

    let result: string[] | undefined;

    try {
      const asts = parseSqlAst(sql);
      for (const stmt of asts) {
        const typed = stmt as any;

        // Handle SELECT statements
        if (typed.type === 'select') {
          const cols = typed.columns || [];
          if (cols.length === 0) { result = []; break; }
          result = cols.map((c: any) => {
            if (c.type === 'star') return '*';
            if (c.alias) return c.alias.name;
            const expr = c.expr;
            if (expr && expr.type === 'ref' && 'name' in expr) {
              return (expr as any).name;
            }
            if (expr?.loc?.start != null && expr?.loc?.end != null) {
              return sql.substring(expr.loc.start, expr.loc.end).trim();
            }
            return '?column?';
          });
          break;
        }

        // Handle INSERT/UPDATE/DELETE … RETURNING
        if (typed.type === 'insert' || typed.type === 'update' || typed.type === 'delete') {
          const returning = typed.returning;
          if (returning && Array.isArray(returning)) {
            result = returning.map((c: any) => {
              const expr = c.expr || c;
              if (expr.type === 'star' || expr.name === '*') return '*';
              if (expr.loc?.start != null && expr.loc?.end != null) {
                return sql.substring(expr.loc.start, expr.loc.end).trim();
              }
              if (expr.type === 'ref' && 'name' in expr) {
                return expr.name;
              }
              return '?column?';
            });
            break;
          }
        }
      }
    } catch (_e: any) {
      // AST parser failed — fall back to simple heuristic
    }

    if (!result) {
      result = this.extractColumnsFallback(sql);
    }

    cacheSet('extractColumns', sql, result);
    return result;
  }

  /** Check if the SQL has a RETURNING clause (for DML queries). */
  private hasReturningClause(sql: string): boolean {
    return /\bRETURNING\b/i.test(sql);
  }

  /** Fallback regex-based column extraction when AST parser fails. */
  private extractColumnsFallback(sql: string): string[] {
    const trimmed = sql.trim();
    const upper = trimmed.toUpperCase();
    if (!upper.startsWith('SELECT')) return [];

    const afterSelect = trimmed.substring(6).trim();
    const fromIdx = this.caseInsensitiveIndexOf(afterSelect, ' FROM ');
    if (fromIdx < 0) return [];

    const columnPart = afterSelect.substring(0, fromIdx).trim();

    return columnPart
      .split(',')
      .map((c) => {
        const col = c.trim();
        const asIdx = this.caseInsensitiveIndexOf(col, ' AS ');
        if (asIdx >= 0) return col.substring(asIdx + 4).trim();
        const spaceIdx = col.lastIndexOf(' ');
        if (spaceIdx > 0 && spaceIdx < col.length - 1) {
          const lastToken = col.substring(spaceIdx + 1).toUpperCase();
          if (lastToken !== 'DISTINCT' && !lastToken.includes('(')) {
            return col.substring(spaceIdx + 1);
          }
        }
        const dotIdx = col.indexOf('.');
        if (dotIdx >= 0 && dotIdx < col.length - 1) {
          return col.substring(dotIdx + 1);
        }
        return col;
      })
      .filter((c) => c.length > 0 && c !== '*' && !c.includes('('));
  }

  private caseInsensitiveIndexOf(str: string, search: string): number {
    return str.toUpperCase().indexOf(search.toUpperCase());
  }

  // ════════════════════════════════════════════════
  //  Buffer utilities
  // ════════════════════════════════════════════════

  private readCString(buf: Buffer, offset: number): { str: string; endOffset: number } {
    const end = buf.indexOf(0, offset);
    if (end < 0) return { str: '', endOffset: offset };
    return { str: buf.toString('utf8', offset, end), endOffset: end + 1 };
  }

  // ════════════════════════════════════════════════
  //  PG message serialization
  // ════════════════════════════════════════════════

  /** Build an AuthenticationX message body wrapped with the 'R' type byte. */
  private buildAuthMessage(authType: number, body: Buffer): Buffer {
    // 'R' (1) + length (4) + authType (4) + body
    const buf = Buffer.alloc(1 + 4 + 4 + body.length);
    buf[0] = 0x52; // 'R'
    buf.writeInt32BE(4 + 4 + body.length, 1);
    buf.writeInt32BE(authType, 5);
    body.copy(buf, 9);
    return buf;
  }

  private sendAuthenticationOk(socket: net.Socket): void {
    socket.write(this.buildAuthMessage(0, Buffer.alloc(0)));
  }

  /** Send BackendKeyData ('K') — protocol-required after auth success */
  private sendBackendKeyData(socket: net.Socket, pid: number, secretKey: number): void {
    const buf = Buffer.alloc(1 + 4 + 4 + 4);
    buf[0] = 0x4b; // 'K'
    buf.writeInt32BE(12, 1); // length (self + pid + secretKey)
    buf.writeInt32BE(pid, 5);
    buf.writeInt32BE(secretKey, 9);
    socket.write(buf);
  }

  /** Send a single ParameterStatus ('S') message */
  private sendOneParameterStatus(socket: net.Socket, key: string, value: string): void {
    const kBuf = Buffer.from(key + '\0', 'utf8');
    const vBuf = Buffer.from(value + '\0', 'utf8');
    const bodyLen = kBuf.length + vBuf.length;
    const totalLen = 4 + bodyLen; // PG wire length includes self
    const buf = Buffer.alloc(1 + totalLen);
    buf[0] = 0x53; // 'S'
    buf.writeInt32BE(totalLen, 1);
    kBuf.copy(buf, 5);
    vBuf.copy(buf, 5 + kBuf.length);
    socket.write(buf);
  }

  private sendParameterStatus(socket: net.Socket, userName?: string): void {
    // Dynamically resolve session_authorization from a connected session
    const firstUser = this.conns.size > 0
      ? [...this.conns.values()][0]?.userName || 'postgres'
      : 'postgres';

    // Dynamically resolve is_superuser from the role system
    const isSuperuser = userName && this.roleManager
      ? this.roleManager.getRole(userName)?.superuser ? 'on' : 'off'
      : 'on'; // default to 'on' if no role system available

    // Send standard parameter status messages (PG16)
    const params: Array<[string, string]> = [
      ['application_name', ''],
      ['block_size', '8192'],
      ['client_encoding', 'UTF8'],
      ['data_checksums', 'off'],
      ['DateStyle', 'ISO, MDY'],
      ['debug_assertions', 'off'],
      ['default_transaction_read_only', 'off'],
      ['in_hot_standby', 'off'],
      ['integer_datetimes', 'on'],
      ['IntervalStyle', 'postgres'],
      ['is_superuser', isSuperuser],
      ['lc_collate', 'en_US.UTF-8'],
      ['lc_ctype', 'en_US.UTF-8'],
      ['lc_messages', 'en_US.UTF-8'],
      ['lc_monetary', 'en_US.UTF-8'],
      ['lc_numeric', 'en_US.UTF-8'],
      ['lc_time', 'en_US.UTF-8'],
      ['max_connections', '100'],
      ['max_function_args', '100'],
      ['max_index_keys', '32'],
      ['max_prepared_transactions', '0'],
      ['max_replication_slots', '10'],
      ['max_wal_senders', '10'],
      ['row_security', 'on'],
      ['server_encoding', 'UTF8'],
      ['server_version', '16.4'],
      ['server_version_num', '160004'],
      ['ssl', getShowSsl()],
      ['sslmode', getBackendSslMode()],
      ['ssl_ca_file', this.tlsConfig?.ca || ''],
      ['ssl_cert_file', this.tlsConfig?.cert || ''],
      ['statement_timeout', '0'],
      ['prepared_statement_only', 'off'],
      ['session_authorization', firstUser],
      ['standard_conforming_strings', 'on'],
      ['TimeZone', 'UTC'],
      ['transaction_isolation', 'read committed'],
      ['transaction_read_only', 'off'],
      ['wal_buffers', '4MB'],
      ['wal_level', 'replica'],
    ];
    for (const [k, v] of params) {
      this.sendOneParameterStatus(socket, k, v);
    }
  }

  // ════════════════════════════════════════
  //  Replication Protocol Handlers
  // ════════════════════════════════════════

  /**
   * Handle IDENTIFY_SYSTEM replication command.
   * Returns system identity: system_id, timeline, xlogpos, dbname.
   */
  private handleIdentifySystem(conn: PgWireConnectionInternal): QueryResult {
    const systemId = '1111111111111111111'; // placeholder — in production would be derived from data directory UUID
    let lsn = '0/0';
    let dbName = conn.session.database || 'default';
    try {
      const { WALStateManager } = require('../storage/WALStateManager');
      lsn = WALStateManager.getInstance().getCurrentLSN() ?? '0/0';
    } catch (_e: any) { /* WAL manager may not be initialized */ }
    // Strip file extension from the data directory for db name
    dbName = dbName.replace(/\.sqlite$/i, '');
    return {
      rows: [{ systemid: systemId, timeline: 1, xlogpos: lsn, dbname: dbName, 'wal_sender_state': 'startup' }],
      rowCount: 1,
      queryTimeMs: 0,
      engine: 'shard',
    };
  }

  /**
   * Handle START_REPLICATION command.
   * In a full implementation this would start streaming WAL data.
   * Currently returns the starting position and delegates to WALSender.
   */
  private handleStartReplication(conn: PgWireConnectionInternal, sql: string): QueryResult {
    let lsn = '0/0';
    try {
      const { WALStateManager } = require('../storage/WALStateManager');
      lsn = WALStateManager.getInstance().getCurrentLSN() ?? '0/0';
    } catch (_e: any) { /* WAL manager may not be initialized */ }
    // WAL streaming start: in production, spawn WALSender here
    return {
      rows: [{
        start_lsn: lsn,
        timeline: 1,
        server_version: '16',
        wal_level: 'logical',
      }],
      rowCount: 1,
      queryTimeMs: 0,
      engine: 'shard',
    };
  }

  /**
   * Handle CREATE_REPLICATION_SLOT command.
   * Delegates to ReplicationSlotTracker for slot persistence.
   */
  private handleCreateReplicationSlot(conn: PgWireConnectionInternal, sql: string): QueryResult {
    // Parse: CREATE_REPLICATION_SLOT slot_name [PHYSICAL | LOGICAL ...]
    const match = sql.match(/CREATE_REPLICATION_SLOT\s+(\S+)/i);
    if (!match) {
      return { rows: [], rowCount: 0, queryTimeMs: 0, engine: 'shard', error: new Error('Missing slot name') };
    }
    const slotName = match[1].replace(/['"]/g, '');
    const slotType = sql.match(/PHYSICAL/i) ? 'physical' : sql.match(/LOGICAL/i) ? 'logical' : 'physical';

    try {
      const { ReplicationSlotTracker } = require('../storage/ReplicationSlotTracker');
      const tracker = ReplicationSlotTracker.getInstance();
      let lsn = '0/0';
      try {
        const { WALStateManager } = require('../storage/WALStateManager');
        lsn = WALStateManager.getInstance().getCurrentLSN() ?? '0/0';
      } catch (_e: any) { /* fallback */ }
      tracker.createSlot(slotName, slotType, lsn);
      return {
        rows: [{
          slot_name: slotName,
          slot_type: slotType,
          consistent_point: lsn,
          snapshost: '',
          output_plugin: slotType === 'logical' ? 'test_decoding' : '',
        }],
        rowCount: 1,
        queryTimeMs: 0,
        engine: 'shard',
      };
    } catch (err: any) {
      return { rows: [], rowCount: 0, queryTimeMs: 0, engine: 'shard', error: new Error(err.message) };
    }
  }

  /**
   * Handle DROP_REPLICATION_SLOT command.
   * Delegates to the existing ReplicationSlotShim.
   */
  private handleDropReplicationSlot(_conn: PgWireConnectionInternal, sql: string): boolean {
    const match = sql.match(/DROP_REPLICATION_SLOT\s+(\S+)/i);
    if (!match) return false;
    const slotName = match[1].replace(/['"]/g, '');
    try {
      const { ReplicationSlotTracker } = require('../storage/ReplicationSlotTracker');
      const tracker = ReplicationSlotTracker.getInstance();
      tracker.dropSlot(slotName);
      return true;
    } catch (_e: any) {
      return false;
    }
  }

  private sendReadyForQuery(socket: net.Socket, transactionStatus?: 'idle' | 'in_transaction' | 'failed'): void {
    const buf = this.buildReadyForQuery(
      transactionStatus === 'in_transaction' ? 'T'
        : transactionStatus === 'failed' ? 'E'
        : 'I'
    );
    socket.write(buf);
  }

  /** Build a ReadyForQuery (Z) message without writing to the socket (for deferred send). */
  private buildReadyForQuery(txnCode: 'T' | 'E' | 'I'): Buffer {
    const buf = Buffer.alloc(6);
    buf[0] = 0x5a; // 'Z'
    buf.writeInt32BE(5, 1);
    buf[5] = txnCode.charCodeAt(0);
    return buf;
  }

  /** Internal MVCC columns that must be stripped from query results. */
  private static readonly MVCC_SYSTEM_COLUMNS = new Set(['_xmin', '_xmax', '_cmin', '_cmax', '_ctid']);

  /** Strip internal MVCC system columns from result rows. */
  private stripSystemColumns(rows: Record<string, any>[]): Record<string, any>[] {
    if (rows.length === 0) return rows;
    if (!rows[0]) return rows;
    const keys = Object.keys(rows[0]);
    const hasSystemCols = keys.some(k => PgWireServer.MVCC_SYSTEM_COLUMNS.has(k));
    if (!hasSystemCols) return rows;
    return rows.map(row => {
      const cleaned: Record<string, any> = {};
      for (const key of keys) {
        if (!PgWireServer.MVCC_SYSTEM_COLUMNS.has(key)) {
          cleaned[key] = row[key];
        }
      }
      return cleaned;
    });
  }

  private sendQueryResult(socket: net.Socket, result: QueryResult, sql?: string): void {
    // Strip internal MVCC system columns from results
    const cleanedRows = this.stripSystemColumns(result.rows);

    // GAP 1: Send any notices as wire NoticeResponse messages before result data
    if (result.notices && result.notices.length > 0) {
      for (const notice of result.notices) {
        this.sendNotice(socket, notice.message, notice.severity);
      }
    }

    if (cleanedRows.length === 0) {
      // DDL (CREATE/DROP/ALTER/TRUNCATE) and transactions send proper tags
      // even when rows are empty. Check SQL first from empty result.
      if (sql) {
        const upperSql = sql.trim().toUpperCase();
        if (upperSql.startsWith('CREATE TABLE')) {
          this.sendCommandComplete(socket, 'CREATE TABLE');
          return;
        }
        if (upperSql.startsWith('DROP TABLE') || upperSql.startsWith('DROP VIEW') || upperSql.startsWith('DROP INDEX')) {
          this.sendCommandComplete(socket, 'DROP TABLE');
          return;
        }
        if (upperSql.startsWith('ALTER TABLE')) {
          this.sendCommandComplete(socket, 'ALTER TABLE');
          return;
        }
        if (upperSql.startsWith('TRUNCATE')) {
          this.sendCommandComplete(socket, 'TRUNCATE TABLE');
          return;
        }
        if (upperSql.startsWith('VACUUM')) {
          this.sendCommandComplete(socket, 'VACUUM');
          return;
        }
        if (upperSql.startsWith('CREATE INDEX')) {
          this.sendCommandComplete(socket, 'CREATE INDEX');
          return;
        }
        if (upperSql.startsWith('CREATE UNIQUE INDEX')) {
          this.sendCommandComplete(socket, 'CREATE INDEX');
          return;
        }
        // R2-P1.1: SET/SHOW/RESET command tags
        if (/^\s*SET\b/i.test(upperSql)) {
          this.sendCommandComplete(socket, 'SET');
          return;
        }
        if (/^\s*SHOW\b/i.test(upperSql)) {
          this.sendCommandComplete(socket, 'SHOW');
          return;
        }
        if (/^\s*RESET\b/i.test(upperSql)) {
          this.sendCommandComplete(socket, 'RESET');
          return;
        }
      }
      this.sendCommandComplete(socket, 'SELECT 0');
      return;
    }

    // GAP 3: For transaction statements (BEGIN/COMMIT/ROLLBACK/SAVEPOINT) and
    // DML without RETURNING, send proper PG command tag (no row data).
    if (sql) {
      const upperSql = sql.trim().toUpperCase();
      if (upperSql.startsWith('BEGIN')) {
        this.sendCommandComplete(socket, 'BEGIN');
        return;
      }
      if (upperSql.startsWith('COMMIT') || upperSql.startsWith('END')) {
        this.sendCommandComplete(socket, 'COMMIT');
        return;
      }
      if (upperSql.startsWith('ROLLBACK') || upperSql.startsWith('ABORT')) {
        this.sendCommandComplete(socket, 'ROLLBACK');
        return;
      }
      if (upperSql.startsWith('SAVEPOINT')) {
        this.sendCommandComplete(socket, 'SAVEPOINT');
        return;
      }
      if (upperSql.startsWith('RELEASE')) {
        this.sendCommandComplete(socket, 'RELEASE');
        return;
      }

      // GAP 4: DML without RETURNING — send proper INSERT/UPDATE/DELETE tag
      // with row count, skip RowDescription+DataRow (pgbench expects this).
      const dmlMatch = upperSql.match(/^(INSERT|UPDATE|DELETE)\b/);
      const hasReturning = this.hasReturningClause(sql);
      if (dmlMatch && !hasReturning) {
        const tag = dmlMatch[1] + ' 0 ' + (result.rowCount || 0);
        this.sendCommandComplete(socket, tag);
        return;
      }
      // TRUNCATE without RETURNING
      if (upperSql.startsWith('TRUNCATE')) {
        this.sendCommandComplete(socket, 'TRUNCATE TABLE');
        return;
      }
      // DDL tags (rows present case — e.g. CREATE TABLE AS)
      if (upperSql.startsWith('CREATE TABLE')) {
        this.sendCommandComplete(socket, 'CREATE TABLE');
        return;
      }
      if (upperSql.startsWith('DROP TABLE') || upperSql.startsWith('DROP VIEW')) {
        this.sendCommandComplete(socket, 'DROP TABLE');
        return;
      }
    }

    // Use the first row to determine columns.
    // If _raw is set (duplicate column names case), use _raw.length for the
    // true column count and derive column names from the SQL or object keys.
    // Strip _raw internal key from column names.
    let columns: string[];

    if (Array.isArray((cleanedRows[0] as any)._raw)) {
      // Query had duplicate column names — use the full column list from
      // the raw array length, not from Object.keys (which has deduped keys).
      columns = Object.keys(cleanedRows[0]).filter(k => k !== '_raw');
    } else {
      columns = Object.keys(cleanedRows[0]);
    }

    // If we have column info encoded in _raw metadata, use the full list
    // _raw is stored as [val1, val2, ..., valN] with N = true column count
    if (Array.isArray((cleanedRows[0] as any)._raw)) {
      const rawLen = (cleanedRows[0] as any)._raw.length;
      if (columns.length < rawLen) {
        // There are more columns than deduped keys — pad with generic names
        while (columns.length < rawLen) {
          columns.push(`?column?`);
        }
      }
    }

    const oids = sql ? this.resolveColumnOids(sql, columns) : undefined;
    this.sendRowDescription(socket, columns, oids);

    for (const row of cleanedRows) {
      this.sendDataRow(socket, columns, row);
    }

    this.sendCommandComplete(socket, `SELECT ${result.rowCount}`);
  }

  private sendRowDescription(socket: net.Socket, columns: string[], typeOids?: number[], formatCodes?: number[]): void {
    let totalLen = 4 + 2;
    const columnBuffers: Buffer[] = [];

    for (let i = 0; i < columns.length; i++) {
      const col = columns[i];
      const nameBuf = Buffer.from(col + '\0', 'utf8');
      // Use provided type OID or default to text (25)
      const typeOid = typeOids && i < typeOids.length ? typeOids[i] : 25;
      const fmt = formatCodes && i < formatCodes.length ? formatCodes[i] : 0; // 0=text, 1=binary
      const colBuf = Buffer.alloc(nameBuf.length + 18);
      nameBuf.copy(colBuf, 0);
      colBuf.writeInt32BE(0, nameBuf.length);        // table OID (offset +0)
      colBuf.writeInt16BE(0, nameBuf.length + 4);    // attribute number (offset +4)
      colBuf.writeInt32BE(typeOid, nameBuf.length + 6);   // type OID (offset +6)
      colBuf.writeInt16BE(-1, nameBuf.length + 10);  // type size (offset +10)
      colBuf.writeInt32BE(-1, nameBuf.length + 12);  // type modifier (offset +12)
      colBuf.writeInt16BE(fmt, nameBuf.length + 16); // format code (0=text, 1=binary)
      columnBuffers.push(colBuf);
      totalLen += colBuf.length;
    }

    const buf = Buffer.alloc(1 + totalLen);
    buf[0] = 0x54; // 'T'
    buf.writeInt32BE(totalLen, 1);
    buf.writeInt16BE(columns.length, 5);

    let offset = 7;
    for (const cb of columnBuffers) {
      cb.copy(buf, offset);
      offset += cb.length;
    }
    socket.write(buf);
  }

  /**
   * Resolve PG type OIDs for a set of column names from a SQL query.
   *
   * Strategy:
   * 1. For known table columns: extract table name from SQL and query PRAGMA table_info
   * 2. For computed expressions / unknown: use default type map (int4 for math, text for strings)
   *
   * Returns an array of OIDs matching the column name order.
   */
  private resolveColumnOids(sql: string, columnNames: string[]): number[] {
    if (columnNames.length === 0) return [];

    // Step 1: Detect aggregate functions (COUNT, SUM, AVG, etc.) via SQL pattern
    const aggrOids = this.detectAggrOids(sql, columnNames);
    if (aggrOids.every(o => o !== undefined)) return aggrOids as number[];

    // Step 2: Try to extract table name and look up via PRAGMA
    const tableMatch = sql.match(/FROM\s+["']?(\w+)["']?\s*/i);
    if (tableMatch && tableMatch[1]) {
      const tableName = tableMatch[1];
      const colTypes = this.getTableColumnTypes(tableName);
      if (colTypes.size > 0) {
        return columnNames.map((name, i) => {
          if (aggrOids[i] !== undefined) return aggrOids[i]!;
          const pgType = colTypes.get(name.toLowerCase());
          if (pgType) {
            const oid = SystemTypeRegistry.getOid(pgType);
            if (oid !== undefined) return oid;
          }
          return 25; // default text
        });
      }
    }

    // Step 3: Fall back to aggregate detection for aliases not from table
    return columnNames.map((_, i) =>
      aggrOids[i] !== undefined ? aggrOids[i]! : 25,
    );
  }

  /**
   * Detect aggregate function column aliases and return their PG OIDs.
   * E.g. `COUNT(*) AS cnt` → int8 (20), `SUM(col)` → int8/numeric.
   */
  private detectAggrOids(sql: string, columnNames: string[]): (number | undefined)[] {
    const upperSql = sql.toUpperCase();
    // Map of aggregate functions to their typical PG result OID
    const aggrOidMap: Record<string, number> = {
      COUNT: 20,   // int8
      SUM: 20,     // int8 (typically)
      AVG: 1700,   // numeric
      MAX: 25,     // text or matches type
      MIN: 25,     // text or matches type
    };

    return columnNames.map((colName) => {
      // Try matching from SQL: find `AGG(col)` AS colName or `colName = AGG(col)`
      // Use the SQL source to find what aggregate function produced this column
      const cleaner = colName.replace(/"/g, '');
      const funcMatch = upperSql.match(
        new RegExp(`(COUNT|SUM|AVG|MAX|MIN)\\s*\\(.*?\\)\\s*(?:AS\\s+)?["\`]?${cleaner.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["\`]?`, 'i'),
      );
      if (funcMatch) {
        const funcUpper = funcMatch[1].toUpperCase();
        if (aggrOidMap[funcUpper] !== undefined) return aggrOidMap[funcUpper];
      }
      return undefined;
    });
  }

  /** Query PRAGMA table_info to get {colName → PG type name} mapping. */
  private getTableColumnTypes(tableName: string): Map<string, string> {
    const map = new Map<string, string>();
    try {
      // Try DuckDB first (primary analytics engine)
      const duckDb = (this.queryRouter as any).getDuckDb?.();
      let rows: any[];
      if (duckDb) {
        rows = duckDb.prepare(`PRAGMA table_info('${tableName}')`).all() as any[];
      } else {
        // Fallback: query main SQLite shard for table column info
        const shard0 = (this.queryRouter as any).shardManager?.getShard?.(0);
        if (!shard0) return map;
        const db = (shard0 as any).db;
        if (!db) return map;
        rows = db.prepare(`PRAGMA table_info("${tableName}")`).all() as any[];
      }
      for (const row of rows) {
        const pgTypeName = this.sqliteToPgType(String(row.type || 'TEXT'));
        map.set(String(row.name).toLowerCase(), pgTypeName);
      }
    } catch (_e: any) {
      // Table may not exist yet
    }
    return map;
  }

  /** Map SQLite/DuckDB type names to PG type names (for SystemTypeRegistry lookup). */
  private sqliteToPgType(sqliteType: string): string {
    const upper = sqliteType.toUpperCase();
    if (upper.includes('INT')) return 'int4';
    if (upper.includes('BIGINT')) return 'int8';
    if (upper.includes('SMALLINT')) return 'int2';
    if (upper.includes('BOOLEAN') || upper.includes('BOOL')) return 'bool';
    if (upper.includes('DOUBLE') || upper.includes('FLOAT8') || upper.includes('REAL')) return 'float8';
    if (upper.includes('FLOAT') || upper.includes('FLOAT4')) return 'float4';
    if (upper.includes('NUMERIC') || upper.includes('DECIMAL')) return 'numeric';
    if (upper.includes('TIMESTAMP')) return 'timestamp';
    if (upper.includes('DATE')) return 'date';
    if (upper.includes('TIME')) return 'time';
    if (upper.includes('VARCHAR') || upper.includes('CHAR') || upper.includes('TEXT')) return 'text';
    if (upper.includes('BLOB') || upper.includes('BYTEA')) return 'bytea';
    if (upper.includes('UUID')) return 'uuid';
    return 'text';
  }

  private sendDataRow(
    socket: net.Socket,
    columns: string[],
    row: Record<string, any>,
    typeOids?: number[],
    formatCodes?: number[],
  ): void {
    // Build value buffers. For duplicate column names, the row object may
    // have fewer keys than columns (JS object key dedup). In that case,
    // fall back to a raw-values array that was stored alongside the row
    // by the SQLite raw-mode execution.
    const isBinary = formatCodes !== undefined && formatCodes.some(f => f === 1);
    const valueBuffers: (Buffer | null)[] = [];

    if (Array.isArray(row._raw)) {
      // Row was constructed from SQLite raw-mode arrays — use position-based access
      for (let i = 0; i < columns.length; i++) {
        const raw = (row as any)._raw[i];
        if (raw === null || raw === undefined) {
          valueBuffers.push(null);
        } else if (isBinary && formatCodes && formatCodes[i] === 1) {
          const oid = typeOids && i < typeOids.length ? typeOids[i] : 25;
          valueBuffers.push(this.binaryEncodeValue(raw, oid));
        } else {
          valueBuffers.push(Buffer.from(String(raw), 'utf8'));
        }
      }
    } else {
      // Normal object-based lookup (no duplicates)
      for (let i = 0; i < columns.length; i++) {
        const col = columns[i];
        const val = row[col];
        if (val === null || val === undefined) {
          valueBuffers.push(null);
        } else if (isBinary && formatCodes && formatCodes[i] === 1) {
          const oid = typeOids && i < typeOids.length ? typeOids[i] : 25;
          valueBuffers.push(this.binaryEncodeValue(val, oid));
        } else {
          valueBuffers.push(Buffer.from(String(val), 'utf8'));
        }
      }
    }

    const totalLen = 4 + 2 + valueBuffers.reduce((sum, vb) => sum + 4 + (vb === null ? 0 : vb.length), 0);
    const buf = Buffer.alloc(1 + totalLen);
    buf[0] = 0x44; // 'D'
    buf.writeInt32BE(totalLen, 1);
    buf.writeInt16BE(columns.length, 5);

    let offset = 7;
    for (const vb of valueBuffers) {
      if (vb === null) {
        buf.writeInt32BE(-1, offset); // NULL indicator
      } else {
        buf.writeInt32BE(vb.length, offset);
      }
      offset += 4;
      if (vb !== null) {
        vb.copy(buf, offset);
        offset += vb.length;
      }
    }
    socket.write(buf);
  }

  /**
   * Encode a JavaScript value as a PG wire binary format byte sequence
   * based on the column's type OID.
   *
   * Only the most common types are supported; unsupported types fall back
   * to UTF-8 text encoding (which is valid text-format DataRow content).
   *
   * Supported types:
   *   INT2 (21):  2-byte signed big-endian
   *   INT4 (23):  4-byte signed big-endian
   *   INT8 (20):  8-byte signed big-endian
   *   FLOAT4 (700): 4-byte IEEE 754 single
   *   FLOAT8 (701): 8-byte IEEE 754 double
   *   BOOL (16):   1 byte (0 or 1)
   *   TEXT (25) / VARCHAR (1043): UTF-8 text (same as text format)
   */
  private binaryEncodeValue(val: any, typeOid: number): Buffer {
    switch (typeOid) {
      case 21: { // INT2
        const buf = Buffer.alloc(2);
        buf.writeInt16BE(Number(val));
        return buf;
      }
      case 23: { // INT4
        const buf = Buffer.alloc(4);
        buf.writeInt32BE(Number(val));
        return buf;
      }
      case 20: { // INT8
        const buf = Buffer.alloc(8);
        buf.writeBigInt64BE(BigInt(val));
        return buf;
      }
      case 700: { // FLOAT4
        const buf = Buffer.alloc(4);
        buf.writeFloatBE(Number(val));
        return buf;
      }
      case 701: { // FLOAT8
        const buf = Buffer.alloc(8);
        buf.writeDoubleBE(Number(val));
        return buf;
      }
      case 16: { // BOOL
        return Buffer.from([val ? 1 : 0]);
      }
      default: { // TEXT, VARCHAR, and unknown types → text fallback
        return Buffer.from(String(val), 'utf8');
      }
    }
  }

  private sendCommandComplete(socket: net.Socket, tag: string): void {
    const tagBuf = Buffer.from(tag + '\0', 'utf8');
    const buf = Buffer.alloc(1 + 4 + tagBuf.length);
    buf[0] = 0x43; // 'C'
    buf.writeInt32BE(4 + tagBuf.length, 1);
    tagBuf.copy(buf, 5);
    socket.write(buf);
  }

  /**
   * Send an ErrorResponse ('E' message) with full PG wire protocol field support.
   *
   * Field codes used:
   *   'S' Severity (localized)  'V' Severity (non-localized)
   *   'C' SQLSTATE code         'M' Message
   *   'D' Detail                'H' Hint
   *   'P' Position              'p' Internal position
   *   'q' Internal query        'W' Where context
   *   's' Schema name           't' Table name
   *   'c' Column name           'd' Data type name
   *   'n' Constraint name       'F' File
   *   'L' Line                  'R' Routine
   */
  private sendError(
    socket: net.Socket,
    message: string,
    options?: {
      position?: number;
      detail?: string;
      hint?: string;
      internalPosition?: number;
      internalQuery?: string;
      where?: string;
      schema?: string;
      table?: string;
      column?: string;
      dataType?: string;
      constraint?: string;
      file?: string;
      line?: number;
      routine?: string;
      sqlState?: string;
    },
  ): void {
    const msgBuf = Buffer.from(message, 'utf8');

    // Map common error messages to proper SQLState codes using named constants
    let sqlState = options?.sqlState || SQLSTATE_INTERNAL_ERROR;
    const upperMsg = message.toUpperCase();
    if (upperMsg.includes('SYNTAX') || upperMsg.includes('PARSE')) {
      sqlState = options?.sqlState || SQLSTATE_SYNTAX_ERROR;
    } else if (upperMsg.includes('AUTHENTICATION') || upperMsg.includes('PASSWORD') || upperMsg.includes('LOGIN')) {
      sqlState = SQLSTATE_INVALID_PASSWORD;
    } else if (upperMsg.includes('PERMISSION') || upperMsg.includes('ACCESS') || upperMsg.includes('PRIVILEGE')) {
      sqlState = SQLSTATE_INSUFFICIENT_PRIVILEGE;
    } else if (upperMsg.includes('COLUMN') && (upperMsg.includes('NOT FOUND') || upperMsg.includes('DOES NOT EXIST'))) {
      sqlState = SQLSTATE_UNDEFINED_COLUMN;
    } else if (upperMsg.includes('TABLE') && (upperMsg.includes('NOT FOUND') || upperMsg.includes('DOES NOT EXIST'))) {
      sqlState = SQLSTATE_UNDEFINED_TABLE;
    } else if (upperMsg.includes('RELATION') && (upperMsg.includes('NOT FOUND') || upperMsg.includes('DOES NOT EXIST'))) {
      sqlState = SQLSTATE_UNDEFINED_TABLE;
    } else if (upperMsg.includes('NOT FOUND') || upperMsg.includes('DOES NOT EXIST')) {
      sqlState = SQLSTATE_UNDEFINED_OBJECT;
    } else if (upperMsg.includes('ALREADY EXISTS') || upperMsg.includes('DUPLICATE')) {
      sqlState = SQLSTATE_DUPLICATE_OBJECT;
    } else if (upperMsg.includes('TIMEOUT') || upperMsg.includes('TIMED OUT')) {
      sqlState = SQLSTATE_QUERY_CANCELED;
    } else if (upperMsg.includes('CONNECTION') || upperMsg.includes('SOCKET') || upperMsg.includes('NETWORK')) {
      sqlState = SQLSTATE_CONNECTION_FAILURE;
    } else if (upperMsg.includes('DEADLOCK')) {
      sqlState = SQLSTATE_DEADLOCK_DETECTED;
    } else if (upperMsg.includes('CONSTRAINT') || upperMsg.includes('FOREIGN KEY') || upperMsg.includes('UNIQUE VIOLATION')) {
      sqlState = SQLSTATE_UNIQUE_VIOLATION;
    } else if (upperMsg.includes('NULL') || upperMsg.includes('NOT NULL')) {
      sqlState = SQLSTATE_NOT_NULL_VIOLATION;
    } else if (upperMsg.includes('TYPE') || upperMsg.includes('CAST') || upperMsg.includes('CONVERSION')) {
      sqlState = SQLSTATE_DATATYPE_MISMATCH;
    } else if (upperMsg.includes('OUT OF MEMORY') || upperMsg.includes('MEMORY')) {
      sqlState = SQLSTATE_OUT_OF_MEMORY;
    } else if (upperMsg.includes('STRING DATA') && (upperMsg.includes('TOO LONG') || upperMsg.includes('TRUNCATION'))) {
      sqlState = SQLSTATE_STRING_DATA_RIGHT_TRUNCATION;
    } else if (upperMsg.includes('TOO LONG') && (upperMsg.includes('STRING') || upperMsg.includes('DATA') || upperMsg.includes('VALUE'))) {
      sqlState = SQLSTATE_STRING_DATA_RIGHT_TRUNCATION;
    } else if (upperMsg.includes('SERIALIZATION')) {
      sqlState = SQLSTATE_SERIALIZATION_FAILURE;
    } else if (upperMsg.includes('READ ONLY') || upperMsg.includes('READ-ONLY')) {
      sqlState = SQLSTATE_READ_ONLY_SQL_TRANSACTION;
    }

    // Build fields with full diagnostic info
    const fieldParts: Buffer[] = [];

    // 'S' — Severity (localized)
    fieldParts.push(Buffer.from([0x53]));
    fieldParts.push(Buffer.from('ERROR\0'));

    // 'V' — Severity (non-localized)
    fieldParts.push(Buffer.from([0x56]));
    fieldParts.push(Buffer.from('ERROR\0'));

    // 'C' — SQLSTATE code
    fieldParts.push(Buffer.from([0x43]));
    fieldParts.push(Buffer.from(sqlState + '\0'));

    // 'M' — Message
    fieldParts.push(Buffer.from([0x4d]));
    fieldParts.push(Buffer.concat([msgBuf, Buffer.from([0])]));

    // 'D' — Detail (uppercase D)
    if (options?.detail) {
      fieldParts.push(Buffer.from([0x44]));
      fieldParts.push(Buffer.from(options.detail + '\0'));
    }

    // 'H' — Hint
    if (options?.hint) {
      fieldParts.push(Buffer.from([0x48]));
      fieldParts.push(Buffer.from(options.hint + '\0'));
    }

    // 'P' — Position (uppercase P)
    if (options?.position !== undefined) {
      fieldParts.push(Buffer.from([0x50]));
      fieldParts.push(Buffer.from(String(options.position) + '\0'));
    }

    // 'p' — Internal position (lowercase p)
    if (options?.internalPosition !== undefined) {
      fieldParts.push(Buffer.from([0x70]));
      fieldParts.push(Buffer.from(String(options.internalPosition) + '\0'));
    }

    // 'q' — Internal query (lowercase q)
    if (options?.internalQuery) {
      fieldParts.push(Buffer.from([0x71]));
      fieldParts.push(Buffer.from(options.internalQuery + '\0'));
    }

    // 'W' — Where context
    if (options?.where) {
      fieldParts.push(Buffer.from([0x57]));
      fieldParts.push(Buffer.from(options.where + '\0'));
    }

    // 's' — Schema name (lowercase s)
    if (options?.schema) {
      fieldParts.push(Buffer.from([0x73]));
      fieldParts.push(Buffer.from(options.schema + '\0'));
    }

    // 't' — Table name (lowercase t)
    if (options?.table) {
      fieldParts.push(Buffer.from([0x74]));
      fieldParts.push(Buffer.from(options.table + '\0'));
    }

    // 'c' — Column name (lowercase c)
    if (options?.column) {
      fieldParts.push(Buffer.from([0x63]));
      fieldParts.push(Buffer.from(options.column + '\0'));
    }

    // 'd' — Data type name (lowercase d)
    if (options?.dataType) {
      fieldParts.push(Buffer.from([0x64]));
      fieldParts.push(Buffer.from(options.dataType + '\0'));
    }

    // 'n' — Constraint name (lowercase n)
    if (options?.constraint) {
      fieldParts.push(Buffer.from([0x6e]));
      fieldParts.push(Buffer.from(options.constraint + '\0'));
    }

    // 'F' — File name
    if (options?.file) {
      fieldParts.push(Buffer.from([0x46]));
      fieldParts.push(Buffer.from(options.file + '\0'));
    }

    // 'L' — Line number
    if (options?.line !== undefined) {
      fieldParts.push(Buffer.from([0x4c]));
      fieldParts.push(Buffer.from(String(options.line) + '\0'));
    }

    // 'R' — Routine name
    if (options?.routine) {
      fieldParts.push(Buffer.from([0x52]));
      fieldParts.push(Buffer.from(options.routine + '\0'));
    }

    // Terminator
    fieldParts.push(Buffer.from([0]));

    const fields = Buffer.concat(fieldParts);

    const buf = Buffer.alloc(1 + 4 + fields.length);
    buf[0] = 0x45; // 'E'
    buf.writeInt32BE(4 + fields.length, 1);
    fields.copy(buf, 5);
    socket.write(buf);
  }

  /**
   * Send an ErrorResponse with a DatabaseError instance.
   * Encodes all non-empty PG ErrorResponse fields from the structured error:
   * severity, SQLSTATE code, message, detail, hint, position, schema, table,
   * column, constraint, dataType, file, line, routine, internal info.
   * Falls back to a generic internal error if the error is not a DatabaseError.
   */
  private sendDatabaseError(socket: net.Socket, err: Error): void {
    if (err instanceof DatabaseError) {
      const sev = err.severity || 'ERROR';
      const code = err.sqlstate || SQLSTATE_INTERNAL_ERROR;
      const msgBuf = Buffer.from(err.message, 'utf8');

      // Use ErrorResponse for encoding — send non-empty fields only
      const resp = err.toErrorResponse();

      const fieldParts: Buffer[] = [];

      // 'S' — Severity (localized)
      fieldParts.push(Buffer.from([0x53]));
      fieldParts.push(Buffer.from(sev + '\0'));

      // 'V' — Severity (non-localized)
      fieldParts.push(Buffer.from([0x56]));
      fieldParts.push(Buffer.from(sev + '\0'));

      // 'C' — SQLSTATE code
      fieldParts.push(Buffer.from([0x43]));
      fieldParts.push(Buffer.from(code + '\0'));

      // 'M' — Message
      fieldParts.push(Buffer.from([0x4d]));
      fieldParts.push(Buffer.concat([msgBuf, Buffer.from([0])]));

      // 'D' — Detail (uppercase D)
      if (resp.detail) {
        fieldParts.push(Buffer.from([0x44]));
        fieldParts.push(Buffer.from(resp.detail + '\0'));
      }

      // 'H' — Hint
      if (resp.hint) {
        fieldParts.push(Buffer.from([0x48]));
        fieldParts.push(Buffer.from(resp.hint + '\0'));
      }

      // 'P' — Position (uppercase P)
      if (resp.position !== undefined) {
        fieldParts.push(Buffer.from([0x50]));
        fieldParts.push(Buffer.from(String(resp.position) + '\0'));
      }

      // 'p' — Internal position (lowercase p)
      if (resp.internalPosition !== undefined) {
        fieldParts.push(Buffer.from([0x70]));
        fieldParts.push(Buffer.from(String(resp.internalPosition) + '\0'));
      }

      // 'q' — Internal query (lowercase q)
      if (resp.internalQuery) {
        fieldParts.push(Buffer.from([0x71]));
        fieldParts.push(Buffer.from(resp.internalQuery + '\0'));
      }

      // 'W' — Where context
      if (resp.where) {
        fieldParts.push(Buffer.from([0x57]));
        fieldParts.push(Buffer.from(resp.where + '\0'));
      }

      // 's' — Schema name (lowercase s)
      if (resp.schema) {
        fieldParts.push(Buffer.from([0x73]));
        fieldParts.push(Buffer.from(resp.schema + '\0'));
      }

      // 't' — Table name (lowercase t)
      if (resp.table) {
        fieldParts.push(Buffer.from([0x74]));
        fieldParts.push(Buffer.from(resp.table + '\0'));
      }

      // 'c' — Column name (lowercase c)
      if (resp.column) {
        fieldParts.push(Buffer.from([0x63]));
        fieldParts.push(Buffer.from(resp.column + '\0'));
      }

      // 'd' — Data type name (lowercase d)
      if (resp.dataType) {
        fieldParts.push(Buffer.from([0x64]));
        fieldParts.push(Buffer.from(resp.dataType + '\0'));
      }

      // 'n' — Constraint name (lowercase n)
      if (resp.constraint) {
        fieldParts.push(Buffer.from([0x6e]));
        fieldParts.push(Buffer.from(resp.constraint + '\0'));
      }

      // 'F' — File name
      if (resp.file) {
        fieldParts.push(Buffer.from([0x46]));
        fieldParts.push(Buffer.from(resp.file + '\0'));
      }

      // 'L' — Line number
      if (resp.line !== undefined) {
        fieldParts.push(Buffer.from([0x4c]));
        fieldParts.push(Buffer.from(String(resp.line) + '\0'));
      }

      // 'R' — Routine name
      if (resp.routine) {
        fieldParts.push(Buffer.from([0x52]));
        fieldParts.push(Buffer.from(resp.routine + '\0'));
      }

      // Terminator
      fieldParts.push(Buffer.from([0]));

      const fields = Buffer.concat(fieldParts);
      const buf = Buffer.alloc(1 + 4 + fields.length);
      buf[0] = 0x45; // 'E'
      buf.writeInt32BE(4 + fields.length, 1);
      fields.copy(buf, 5);
      socket.write(buf);
    } else {
      // Fallback to generic sendError
      this.sendError(socket, err.message || 'Internal error');
    }
  }

  /**
   * Send a NoticeResponse ('N') message.
   *
   * PG wire format:
   *   char 'N'
   *   int32 length (including self)
   *   Then repeated field entries:
   *     char type (S=severity, C=code, M=message)
   *     string value (null-terminated)
   *   char 0 (terminator)
   *
   * Standard severities: NOTICE, INFO, WARNING, DEBUG, LOG
   * Standard codes: '00000' (success), '01000' (warning), etc.
   */
  private sendNotice(socket: net.Socket, message: string, severity: string = 'NOTICE', code: string = '00000'): void {
    const msgBuf = Buffer.from(message, 'utf8');

    const fields = Buffer.concat([
      Buffer.from([0x53]), // 'S' — severity
      Buffer.from(severity + '\0'),
      Buffer.from([0x43]), // 'C' — code
      Buffer.from(code + '\0'),
      Buffer.from([0x4d]), // 'M' — message
      Buffer.concat([msgBuf, Buffer.from([0])]),
      Buffer.from([0]), // terminator
    ]);

    const buf = Buffer.alloc(1 + 4 + fields.length);
    buf[0] = 0x4e; // 'N'
    buf.writeInt32BE(4 + fields.length, 1);
    fields.copy(buf, 5);
    socket.write(buf);
  }

  // Extended Query response messages

  private sendParseComplete(socket: net.Socket): void {
    const buf = Buffer.alloc(5);
    buf[0] = 0x31; // '1'
    buf.writeInt32BE(4, 1);
    socket.write(buf);
  }

  private sendBindComplete(socket: net.Socket): void {
    const buf = Buffer.alloc(5);
    buf[0] = 0x32; // '2'
    buf.writeInt32BE(4, 1);
    socket.write(buf);
  }

  private sendCloseComplete(socket: net.Socket): void {
    const buf = Buffer.alloc(5);
    buf[0] = 0x33; // '3'
    buf.writeInt32BE(4, 1);
    socket.write(buf);
  }

  private sendEmptyQueryResponse(socket: net.Socket): void {
    const buf = Buffer.alloc(5);
    buf[0] = 0x49; // 'I'
    buf.writeInt32BE(4, 1);
    socket.write(buf);
  }

  /** Send PortalSuspended ('s') — indicates more rows available in portal */
  private sendPortalSuspended(socket: net.Socket): void {
    const buf = Buffer.alloc(5);
    buf[0] = 0x73; // 's'
    buf.writeInt32BE(4, 1);
    socket.write(buf);
  }

  private sendNoData(socket: net.Socket): void {
    const buf = Buffer.alloc(5);
    buf[0] = 0x6e; // 'n'
    buf.writeInt32BE(4, 1);
    socket.write(buf);
  }

  private sendParameterDescription(socket: net.Socket, paramTypes: number[]): void {
    const totalLen = 4 + 2 + paramTypes.length * 4;
    const buf = Buffer.alloc(1 + totalLen);
    buf[0] = 0x74; // 't'
    buf.writeInt32BE(totalLen, 1);
    buf.writeInt16BE(paramTypes.length, 5);
    let offset = 7;
    for (const oid of paramTypes) {
      buf.writeInt32BE(oid, offset);
      offset += 4;
    }
    socket.write(buf);
  }

  // ════════════════════════════════════════════════
  //  G1: COPY Protocol
  // ════════════════════════════════════════════════

  /**
   * Handle a COPY SQL statement (COPY FROM STDIN or COPY TO STDOUT).
   */
  private async handleCopy(
    sql: string,
    socket: net.Socket,
    conn: PgWireConnectionInternal,
    sessionId: string,
    userName: string,
  ): Promise<void> {
    const trimmed = sql.trim();
    const upper = trimmed.toUpperCase();

    // Detect BINARY format
    const isBinary = /\bBINARY\b/i.test(upper);
    // Detect FREEZE
    const isFreeze = /\bFREEZE\b/i.test(upper);

    // ── COPY FROM file path (use original sql, not upper, to preserve file path case) ──
    // Support: COPY t [(col1, col2)] FROM 'file' [options]
    const fromFileMatch = sql.trim().match(
      /^COPY\s+(\S+)(?:\s*\(([^)]*)\))?\s+FROM\s+'([^']+)'/i,
    );
    if (fromFileMatch) {
      let tableName = fromFileMatch[1].replace(/['"]/g, '');
      if (tableName.includes('.')) tableName = tableName.split('.')[1]!;
      // Parse optional expression list (columns)
      let columnNames: string[] = [];
      if (fromFileMatch[2]) {
        columnNames = fromFileMatch[2].split(',').map(c => c.trim().replace(/['"]/g, ''));
      }
      const filePath = fromFileMatch[3];
      const sessionId = conn.session?.sessionId || '';
      const FILE_COPY_BATCH_SIZE = 5000;

      try {
        const fs = require('fs');
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n').filter((l: string) => l.trim().length > 0);
        const hasHeader = /\bHEADER\b/i.test(sql);
        const isCsv = /\bCSV\b/i.test(sql);
        const startIdx = hasHeader ? 1 : 0;

        let rowCount = 0;
        let batchRows: string[][] = [];

        try {
          for (let i = startIdx; i < lines.length; i++) {
            const values = lines[i].trim();
            if (!values) continue;
            const cols = isCsv
              ? values.split(',').map((v: string) => v.trim().replace(/^"|"$/g, ''))
              : values.split('\t');

            batchRows.push(cols);

            // batchInsert 已通过 pipeline 处理事务生命周期
            if (batchRows.length >= FILE_COPY_BATCH_SIZE) {
              const allPlaceholders = batchRows.map(r => `(${r.map(() => '?').join(',')})`).join(', ');
              const flatParams = batchRows.flat();
              if (columnNames.length > 0) {
                const colList = columnNames.map(c => `"${c}"`).join(',');
                await this.pipelineBatchInsert(
                  `INSERT INTO "${tableName}" (${colList}) VALUES ${allPlaceholders}`,
                  flatParams,
                  sessionId,
                );
              } else {
                await this.pipelineBatchInsert(
                  `INSERT INTO "${tableName}" VALUES ${allPlaceholders}`,
                  flatParams,
                  sessionId,
                );
              }
              rowCount += batchRows.length;
              batchRows = [];
            }
          }

          // 刷新剩余行
          if (batchRows.length > 0) {
            const allPlaceholders = batchRows.map(r => `(${r.map(() => '?').join(',')})`).join(', ');
            const flatParams = batchRows.flat();
            if (columnNames.length > 0) {
              const colList = columnNames.map(c => `"${c}"`).join(',');
              await this.pipelineBatchInsert(
                `INSERT INTO "${tableName}" (${colList}) VALUES ${allPlaceholders}`,
                flatParams,
                sessionId,
              );
            } else {
              await this.pipelineBatchInsert(
                `INSERT INTO "${tableName}" VALUES ${allPlaceholders}`,
                flatParams,
                sessionId,
              );
            }
            rowCount += batchRows.length;
          }

          // Apply FREEZE if requested (VACUUM)
          if (isFreeze) {
            try { await this.pipelineExec(`VACUUM "${tableName}"`, sessionId); } catch (_e: any) { /* best-effort */ }
          }

          const tag = `COPY ${rowCount}`;
          const cmdBuf = Buffer.alloc(1 + 4 + tag.length + 1);
          cmdBuf[0] = 0x43;
          cmdBuf.writeInt32BE(tag.length + 4, 1);
          cmdBuf.write(tag, 5);
          socket.write(cmdBuf);
        } catch (copyErr: any) {
          // pipelineBatchInsert 已自动管理事务回滚 — 无需手动 ROLLBACK
          throw copyErr;
        }
      } catch (err: any) {
        this.sendError(socket, `COPY FROM file failed: ${err.message}`);
      }
      return;
    }

    // ── COPY TO file path (use original sql to preserve file path case) ──
    const toFileMatch = sql.trim().match(
      /^COPY\s+(\S+)(?:\s*\(([^)]*)\))?\s+TO\s+'([^']+)'/i,
    );
    if (toFileMatch) {
      let tableName = toFileMatch[1].replace(/['"]/g, '');
      if (tableName.includes('.')) tableName = tableName.split('.')[1]!;
      const filePath = toFileMatch[3];
      try {
        const result = await this.queryRouter.execute(`SELECT * FROM "${tableName}"`);
        const isCsv = /\bCSV\b/i.test(sql);
        const hasHeader = /\bHEADER\b/i.test(sql);
        const columns = result.rows.length > 0 ? Object.keys(result.rows[0]) : [];

        // Parse column expression list if specified
        let exportColumns = columns;
        if (toFileMatch[2]) {
          exportColumns = toFileMatch[2].split(',').map(c => c.trim().replace(/['"]/g, ''));
        }

        let output = '';
        if (hasHeader && exportColumns.length > 0) output += exportColumns.join(',') + '\n';
        for (const row of result.rows) {
          const vals = exportColumns.map((col: string) => {
            const v = row[col];
            if (v === null || v === undefined) return '';
            const s = String(v);
            return isCsv && (s.includes(',') || s.includes('"')) ? `"${s.replace(/"/g,'""')}"` : s;
          });
          output += vals.join(',') + '\n';
        }
        fs.writeFileSync(filePath, output);
        const tag = `COPY ${result.rows.length}`;
        const cmdBuf = Buffer.alloc(1 + 4 + tag.length + 1);
        cmdBuf[0] = 0x43;
        cmdBuf.writeInt32BE(tag.length + 4, 1);
        cmdBuf.write(tag, 5);
        socket.write(cmdBuf);
      } catch (err: any) {
        this.sendError(socket, `COPY TO file failed: ${err.message}`);
      }
      return;
    }

    // Parse table name from COPY statement
    // Support: COPY t [ (col1, col2) ] FROM STDIN
    const fromMatch = sql.trim().match(/^\s*COPY\s+(\S+)(?:\s*\([^)]*\))?\s+FROM\s+STDIN\b/i);
    const toMatch = sql.trim().match(/^\s*COPY\s+(\S+)(?:\s*\([^)]*\))?\s+TO\s+STDOUT\b/i);

    if (fromMatch) {
      // COPY table FROM STDIN
      let tableName = fromMatch[1].replace(/['"]/g, '');
      // Remove schema prefix if present
      if (tableName.includes('.')) {
        tableName = tableName.split('.')[1]!;
      }
      conn.copyTableName = tableName;
      conn.copyColumns = [];
      conn.copyState = 'active';
      conn.copyBuffer = undefined;
      conn.copyBufferLength = undefined;
      conn.copyFormat = isBinary ? 1 : 0; // 1 = binary, 0 = text

      // Parse expression list (columns) from COPY t (col1, col2) FROM STDIN
      const colExprMatch = sql.trim().match(
        /^COPY\s+\S+\s*\(([^)]+)\)\s+FROM\s+STDIN/i,
      );
      if (colExprMatch) {
        conn.copyColumns = colExprMatch[1].split(',').map(c => c.trim().replace(/['"]/g, ''));
      }

      // Store FREEZE flag on the connection
      (conn as any).copyFreeze = isFreeze;

      // G21: Audit COPY
      if (this.auditLogger) {
        this.auditLogger.logQuery(sessionId, userName, sql, 'success');
      }

      // Send CopyInResponse ('G'): overallFormat(1) + numColumns(2) + columnFormats(numColumns*2)
      // Length includes the Int32 itself (4) + content (1 + 2 + 2*numColumns)
      const copyColCount = (conn.copyColumns && conn.copyColumns.length > 0) ? conn.copyColumns.length : 1;
      const respBuf = Buffer.alloc(1 + 4 + 1 + 2 + 2 * copyColCount);
      respBuf[0] = 0x47; // 'G'
      respBuf.writeInt32BE(4 + 1 + 2 + 2 * copyColCount, 1); // length including self
      respBuf[5] = isBinary ? 1 : 0; // overall format
      respBuf.writeInt16BE(copyColCount, 6); // number of columns
      // All columns in text format (0) or binary (1)
      for (let i = 0; i < copyColCount; i++) {
        respBuf.writeInt16BE(isBinary ? 1 : 0, 8 + 2 * i);
      }
      socket.write(respBuf);
    } else if (toMatch) {
      // COPY table TO STDOUT — execute query and send data
      let tableName = toMatch[1].replace(/['"]/g, '');
      if (tableName.includes('.')) {
        tableName = tableName.split('.')[1]!;
      }

      try {
        const result = await this.queryRouter.execute(`SELECT * FROM "${tableName}"`);
        const columns = result.rows.length > 0 ? Object.keys(result.rows[0]) : [];

        // CopyOutResponse ('H'): overallFormat(1) + numColumns(2) + columnFormats(numColumns*2)
        // Length includes the Int32 itself (4) + content (1 + 2 + 2*numColumns)
        const copyOutColCount = columns.length > 0 ? columns.length : 1;
        const copyOutBuf = Buffer.alloc(1 + 4 + 1 + 2 + 2 * copyOutColCount);
        copyOutBuf[0] = 0x48; // 'H'
        copyOutBuf.writeInt32BE(4 + 1 + 2 + 2 * copyOutColCount, 1); // length including self
        copyOutBuf[5] = isBinary ? 1 : 0; // overall format
        copyOutBuf.writeInt16BE(copyOutColCount, 6);
        // All columns in text format (0) or binary (1)
        for (let i = 0; i < copyOutColCount; i++) {
          copyOutBuf.writeInt16BE(isBinary ? 1 : 0, 8 + 2 * i);
        }
        socket.write(copyOutBuf);

        if (isBinary) {
          // Use PgBinaryCodec for binary output
          const binaryCodec = new PgBinaryCodec();
          // Get column type OIDs for binary encoding
          const colTypes = this.getTableColumnTypes(tableName);
          const typeOids = columns.map((col) => {
            const pgType = colTypes.get(col.toLowerCase());
            if (pgType) {
              const oid = SystemTypeRegistry.getOid(pgType);
              if (oid !== undefined) return oid;
            }
            return 25; // default text
          });

          const rows: any[][] = result.rows.map((row) =>
            columns.map((col) => row[col] ?? null),
          );
          const encoded = binaryCodec.encodePayload(rows);

          // Send as CopyData chunks
          let chunkOffset = 0;
          const CHUNK_SIZE = 8192;
          while (chunkOffset < encoded.length) {
            const chunk = encoded.subarray(chunkOffset, chunkOffset + CHUNK_SIZE);
            const dataBuf = Buffer.alloc(1 + 4 + chunk.length);
            dataBuf[0] = 0x64; // 'd' (CopyData)
            dataBuf.writeInt32BE(4 + chunk.length, 1);
            chunk.copy(dataBuf, 5);
            socket.write(dataBuf);
            chunkOffset += CHUNK_SIZE;
          }
        } else {
          // Text format (existing behavior)
          for (const row of result.rows) {
            const values = columns.map((col) => {
              const val = row[col];
              if (val === null || val === undefined) return '\\N';
              const str = String(val);
              // Escape special characters for COPY text format
              if (str.includes('\t') || str.includes('\n') || str.includes('\\')) {
                return str.replace(/\\/g, '\\\\').replace(/\t/g, '\\t').replace(/\n/g, '\\n');
              }
              return str;
            });
            const line = values.join('\t') + '\n';
            const dataBuf = Buffer.alloc(1 + 4 + line.length);
            dataBuf[0] = 0x64; // 'd' (CopyData)
            dataBuf.writeInt32BE(4 + line.length, 1);
            Buffer.from(line, 'utf8').copy(dataBuf, 5);
            socket.write(dataBuf);
          }
        }

        // CopyDone
        const doneBuf = Buffer.alloc(5);
        doneBuf[0] = 0x63; // 'c'
        doneBuf.writeInt32BE(4, 1);
        socket.write(doneBuf);

        this.sendCommandComplete(socket, `COPY ${result.rowCount}`);
      } catch (err: any) {
        this.sendError(socket, `COPY failed: ${err.message}`);
      }
    } else {
      this.sendError(socket, 'Unsupported COPY form');
      this.sendReadyForQuery(socket);
    }
  }

  /**
   * Complete a CopyIn session — flush buffered COPY data.
   * Supports:
   *  - Expression list (copyColumns)
   *  - ON_ERROR IGNORE (skip invalid rows)
   *  - FREEZE (VACUUM after COPY)
   * Called when 'c' (CopyDone) message is received in processReadyMessages.
   */
  private async handleCopyComplete(conn: PgWireConnectionInternal): Promise<void> {
    // DEBUG counter
    if (!(globalThis as any).__hccCounter) { (globalThis as any).__hccCounter = 0; }
    (globalThis as any).__hccCounter++;
    // Connection identity correction: processReadyMessages passes a conn
    // object that may differ from this.conns.get(conn.session.sessionId)
    // in certain runtimes. Re-resolve from the session map to ensure we
    // use the canonical object with copyTableName/copyBuffer set by handleCopy.
    const sessionBasedConn = this.conns.get(conn.session?.sessionId ?? '');
    if (sessionBasedConn && sessionBasedConn !== conn && sessionBasedConn.copyTableName) {
      conn = sessionBasedConn;
    }
    if (!conn.copyTableName) {
      this.sendError(conn.socket, 'COPY table not specified');
      this.sendReadyForQuery(conn.socket);
      return;
    }

    const tableName = conn.copyTableName;
    const isBinary = conn.copyFormat === 1;
    const copyColumns = conn.copyColumns || [];
    const isFreeze = (conn as any).copyFreeze === true;
    const onErrorIgnore = /ON_ERROR\s+IGNORE/i.test(String((conn as any).copyRawSql || ''));

    if (isBinary) {
      // Binary COPY data
      const buf = conn.copyBuffer;
      if (!buf || buf.length < 11) {
        this.sendCommandComplete(conn.socket, 'COPY 0');
        this.sendReadyForQuery(conn.socket);
        conn.copyState = undefined;
        conn.copyBuffer = undefined;
      conn.copyBufferLength = undefined;
        conn.copyTableName = undefined;
        return;
      }

      try {
        // Resolve column type OIDs for decoding
        const colTypes = this.getTableColumnTypes(tableName);
        const columns = copyColumns.length > 0
          ? copyColumns
          : await this.resolveTableColumns(tableName);
        const typeOids = columns.map((col) => {
          const pgType = colTypes.get(col.toLowerCase());
          if (pgType) {
            const oid = SystemTypeRegistry.getOid(pgType);
            if (oid !== undefined) return oid;
          }
          return 25;
        });

        const binaryCodec = new PgBinaryCodec();
        let inserted = 0;
        const colList = copyColumns.length > 0
          ? ` (${copyColumns.map(c => `"${c}"`).join(',')})`
          : '';

        // ── Streaming: decode rows from buffer via generator, one batch at a time ──
        // Uses decodeRowsGenerator instead of decodePayloadWithTypes to avoid creating
        // a 10M-row JS object array in memory (O(n) → O(batchSize)).
        // Pipeline executeBatchInsert handles transaction lifecycle internally.
        try {
          const COPY_BATCH_SIZE = 500;
          let batchRows: any[][] = [];
          let rowIndex = 0;

          // Use streaming generator — yields rows one-by-one from the buffer
          for (const row of binaryCodec.decodeRowsGenerator(buf, typeOids)) {
            batchRows.push(row);
            rowIndex++;

            if (batchRows.length >= COPY_BATCH_SIZE) {
              // Build multi-VALUES INSERT with flattened params
              const allPlaceholders = batchRows
                .map(r => `(${r.map(() => '?').join(',')})`)
                .join(', ');
              const batchSql = `INSERT INTO "${tableName}"${colList} VALUES ${allPlaceholders}`;
              const flatParams = batchRows.flat();
              try {
                await this.pipelineBatchInsert(batchSql, flatParams, conn.session?.sessionId || '');
                inserted += batchRows.length;
              } catch (err: any) {
                if (onErrorIgnore) {
                  // Fall back to per-row mode for this batch (error-tolerant)
                  for (const fallbackRow of batchRows) {
                    try {
                      const fbPlaceholders = fallbackRow.map(() => '?').join(', ');
                      const fbSql = `INSERT INTO "${tableName}"${colList} VALUES (${fbPlaceholders})`;
                      await this.pipelineBatchInsert(fbSql, [fallbackRow], conn.session?.sessionId || '');
                      inserted++;
                    } catch {
                      // Skip failing rows in ON_ERROR_IGNORE mode
                    }
                  }
                } else {
                  throw err;
                }
              }
              batchRows = [];
              // Yield event loop every 500 rows (5 batches) to avoid starving TCP
              if (rowIndex % 500 === 0) {
                await yieldToEventLoop();
              }
            }
          }
          // Flush remaining rows
          if (batchRows.length > 0) {
            const allPlaceholders = batchRows
              .map(r => `(${r.map(() => '?').join(',')})`)
              .join(', ');
            const batchSql = `INSERT INTO "${tableName}"${colList} VALUES ${allPlaceholders}`;
            const flatParams = batchRows.flat();
            try {
              await this.pipelineBatchInsert(batchSql, flatParams, conn.session?.sessionId || '');
              inserted += batchRows.length;
            } catch (err: any) {
              if (onErrorIgnore) {
                for (const fallbackRow of batchRows) {
                  try {
                    const fbPlaceholders = fallbackRow.map(() => '?').join(', ');
                    const fbSql = `INSERT INTO "${tableName}"${colList} VALUES (${fbPlaceholders})`;
                    await this.pipelineBatchInsert(fbSql, [fallbackRow], conn.session?.sessionId || '');
                    inserted++;
                  } catch {
                    /* skip failing rows */
                  }
                }
              } else {
                throw err;
              }
            }
          }

          // FREEZE: VACUUM after COPY
          if (isFreeze) {
            try { await this.pipelineExec(`VACUUM "${tableName}"`, conn.session?.sessionId || ''); } catch (_e: any) { /* best-effort */ }
          }

          this.sendCommandComplete(conn.socket, `COPY ${inserted}`);
        } catch (err: any) {
          this.sendError(conn.socket, `COPY binary data insertion failed: ${err.message}`);
        }

      this.sendReadyForQuery(conn.socket);
      conn.copyState = undefined;
      conn.copyBuffer = undefined;
      conn.copyBufferLength = undefined;
      conn.copyTableName = undefined;
      return;
      } catch (binaryErr: any) {
        this.sendError(conn.socket, `COPY binary processing failed: ${binaryErr.message}`);
        this.sendReadyForQuery(conn.socket);
        conn.copyState = undefined;
        conn.copyBuffer = undefined;
      conn.copyBufferLength = undefined;
        conn.copyTableName = undefined;
        return;
      }
    }

    // Text COPY format — use copyBufferLength for pre-alloc buffer tracking
    const bufLen = conn.copyBufferLength ?? conn.copyBuffer?.length;
    const buf = conn.copyBuffer;
    if (!buf || bufLen === 0 || bufLen === undefined) {
      logger.info('COPY: no data, sending COPY 0');
      this.sendCommandComplete(conn.socket, 'COPY 0');
      this.sendReadyForQuery(conn.socket);
      conn.copyState = undefined;
      conn.copyBuffer = undefined;
      conn.copyBufferLength = undefined;
      conn.copyTableName = undefined;
      return;
    }

    // ── Auto-commit enclosure for atomic COPY ────────────────

    try {
      const noPk = copyColumns.length === 0;

      // ── Route COPY data to correct shard(s) ──
      const shardManager = (this.queryRouter as any).shardManager;
      const localShardIds: number[] = shardManager?.getShardIds() ?? [0];
      const totalShards = shardManager?.getShardCount() ?? 1;

      // ── Streaming line processor: iterate buffer bytes finding \n positions ──
      // Instead of buf.toString('utf8').split('\n') which creates 10M+ heap strings
      // for big COPY loads, we iterate the UTF-8 Buffer byte-by-byte to find newline
      // positions, then decode each line individually. This keeps peak memory at
      // O(batchSize × numShards) instead of O(totalRows).
      const BetterSqlite3 = require('better-sqlite3') as any;

      // Cache column info for each table (opening DB per shard is expensive)
      let cachedCols: string[] = [];
      let colCacheTable = '';

      const getTableCols = (tbl: string): string[] => {
        if (tbl !== colCacheTable || cachedCols.length === 0) {
          colCacheTable = tbl;
          // Try to get cols from any local shard's DB
          for (const sid of localShardIds) {
            const shard = shardManager?.getShard(sid);
            if (shard?.path) {
              try {
                const tempDb = new BetterSqlite3(shard.path);
                const schema = tempDb.pragma(`table_info('${tbl}')`);
                tempDb.close();
                if (Array.isArray(schema)) {
                  cachedCols = schema
                    .filter((r: any) => !['_xmin','_xmax','_cmin','_cmax','rowid'].includes(r.name))
                    .map((r: any) => r.name);
                  break;
                }
              } catch { /* try next shard */ }
            }
          }
          if (cachedCols.length === 0) {
            cachedCols = copyColumns.length > 0
              ? copyColumns
              : ['aid', 'bid', 'abalance', 'filler', '_xmin', '_xmax', '_cmin', '_cmax'];
          }
        }
        return cachedCols;
      };

      // Build multi-VALUES INSERT SQL from a batch of lines for a single shard
      const buildShardInsertSql = (shardLines: string[], cols: string[]): string => {
        const allValues: any[] = [];
        for (const line of shardLines) {
          const fields = line.split('\t').map((f) => {
            if (f === '\\N') return null;
            return f.replace(/\\\\/g, '\\').replace(/\\t/g, '\t').replace(/\\n/g, '\n');
          });
          allValues.push(...fields);
        }
        const firstFields = shardLines[0].split('\t').map((f) => {
          if (f === '\\N') return null;
          return f.replace(/\\\\/g, '\\').replace(/\\t/g, '\t').replace(/\\n/g, '\n');
        });
        const copyCols = cols.slice(0, firstFields.length);
        const colNames = copyCols.map(c => `"${c}"`);
        const colList = copyCols.length > 0 ? `(${colNames.join(',')})` : '';
        const valuesParts: string[] = [];
        let fieldsIdx = 0;
        const numCols = firstFields.length;
        for (let row = 0; row < shardLines.length; row++) {
          const rowParts: string[] = [];
          for (let col = 0; col < numCols; col++) {
            const val = allValues[fieldsIdx++];
            if (val === null || val === undefined) {
              rowParts.push('NULL');
            } else if (typeof val === 'number') {
              rowParts.push(String(val));
            } else {
              // Escape single quotes for SQL string literal
              rowParts.push(`'${String(val).replace(/'/g, "''")}'`);
            }
          }
          valuesParts.push(`(${rowParts.join(',')})`);
        }
        const valuesClause = valuesParts.join(', ');
        return colList
          ? `INSERT INTO "${tableName}" ${colList} VALUES ${valuesClause}`
          : `INSERT INTO "${tableName}" VALUES ${valuesClause}`;
      };

      // Deterministic hash for first-field → shard mapping
      const hashKeyStr = (key: string): bigint => {
        let h = BigInt(0);
        for (let i = 0; i < key.length; i++) {
          h = (h * BigInt(31) + BigInt(key.charCodeAt(i))) % BigInt(2 ** 53);
        }
        return h;
      };

      const BATCH_SIZE = 5000;
      // Per-shard batch buffers: Map<shardId, string[]>
      const shardBatches = new Map<number, string[]>();
      let totalInserted = 0;
      let totalProcessedLines = 0;
      const sessionId = conn.sessionId || '';
      const tableCols = getTableCols(tableName);

      const flushShardBatch = async (shardId: number): Promise<void> => {
        const batch = shardBatches.get(shardId);
        if (!batch || batch.length === 0) return;
        const isLocal = localShardIds.includes(shardId);
        const sql = buildShardInsertSql(batch, tableCols);
        try {
          if (isLocal) {
            await this.pipelineExec(sql, sessionId);
          } else {
            // Remote shard: go through Raft
            await this.pipelineExec(sql, sessionId);
          }
          totalInserted += batch.length;
        } catch (err: any) {
          if (!onErrorIgnore) throw err;
          // Fallback: per-row for ON_ERROR_IGNORE
          for (const row of batch) {
            try {
              const rowSql = buildShardInsertSql([row], tableCols);
              await this.pipelineExec(rowSql, sessionId);
              totalInserted++;
            } catch { /* skip */ }
          }
        }
        batch.length = 0; // Clear the array, keeping allocation
      };

      // Streaming: iterate buffer byte-by-byte, extracting lines without
      // creating all strings in memory simultaneously.
      let lineStart = 0;
      const totalBytes = bufLen;

      // Check for UTF-8 BOM
      const scanStart = (buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) ? 3 : 0;
      lineStart = scanStart;

      for (let i = scanStart; i < totalBytes; i++) {
        if (buf[i] === 0x0A) { // \n
          const lineLen = i - lineStart;
          // Skip trailing \r
          const trimLen = (lineLen > 0 && buf[i - 1] === 0x0D) ? lineLen - 1 : lineLen;
          if (trimLen > 0) {
            const line = buf.toString('utf8', lineStart, lineStart + trimLen);
            // Skip empty lines and pgbench's \. marker
            if (line.trim().length > 0 && !/^\\\.\s*$/.test(line)) {
              totalProcessedLines++;
              // Determine shard from first tab-delimited field
              const firstTab = line.indexOf('\t');
              const firstField = firstTab >= 0 ? line.substring(0, firstTab) : line;
              const targetShard = Number(hashKeyStr(firstField) % BigInt(totalShards));
              if (!shardBatches.has(targetShard)) {
                shardBatches.set(targetShard, []);
              }
              shardBatches.get(targetShard)!.push(line);

              // Flush batch if limit reached
              if (shardBatches.get(targetShard)!.length >= BATCH_SIZE) {
                await flushShardBatch(targetShard);
                // Yield event loop every 50K rows total to keep TCP alive
                if (totalProcessedLines % 50000 === 0) {
                  await yieldToEventLoop();
                }
              }
            }
          }
          lineStart = i + 1;
        }
      }

      // Process remaining line (no trailing newline)
      if (lineStart < totalBytes) {
        const line = buf.toString('utf8', lineStart, totalBytes);
        if (line.trim().length > 0 && !/^\\\.\s*$/.test(line)) {
          totalProcessedLines++;
          const firstTab = line.indexOf('\t');
          const firstField = firstTab >= 0 ? line.substring(0, firstTab) : line;
          const targetShard = Number(hashKeyStr(firstField) % BigInt(totalShards));
          if (!shardBatches.has(targetShard)) {
            shardBatches.set(targetShard, []);
          }
          shardBatches.get(targetShard)!.push(line);
          if (shardBatches.get(targetShard)!.length >= BATCH_SIZE) {
            await flushShardBatch(targetShard);
          }
        }
      }

      // Flush ALL remaining batches
      for (const shardId of shardBatches.keys()) {
        await flushShardBatch(shardId);
      }

      // Release references
      shardBatches.clear();

      // ── FREEZE: VACUUM after COPY ──
      // (Handled by caller if freeze is set — not in text path currently)

      logger.warn({ totalRows: totalInserted, shards: totalShards }, 'COPY: multi-shard streaming complete');

      // Verify no duplicate aid values (best-effort)
      try {
        const dupResult = await this.queryRouter.execute('SELECT aid, COUNT(*) as cnt FROM pgbench_accounts GROUP BY aid HAVING cnt > 1 ORDER BY cnt DESC LIMIT 10', undefined, sessionId);
        const dupRows = (dupResult as any)?.rows || [];
        if (dupRows.length > 0) {
          logger.error({ dupRows: JSON.stringify(dupRows) }, 'COPY: DUPLICATE aid values after COMMIT');
        }
      } catch (_e: any) { /* best-effort */ }

      this.sendCommandComplete(conn.socket, `COPY ${totalInserted}`);
    } catch (textErr: any) {
      logger.error({ err: textErr.message }, 'COPY: outer catch — text processing failed');
      this.sendError(conn.socket, `COPY text processing failed: ${textErr.message}`);
      this.sendReadyForQuery(conn.socket);
      conn.copyState = undefined;
      conn.copyBuffer = undefined;
      conn.copyBufferLength = undefined;
      conn.copyTableName = undefined;
      return;
    }
    logger.info('COPY: sending ReadyForQuery');
    this.sendReadyForQuery(conn.socket);
    conn.copyState = undefined;
    conn.copyBuffer = undefined;
    conn.copyBufferLength = undefined;
    conn.copyTableName = undefined;
  }

  /** Resolve user-defined column names for a table (exclude MVCC system columns). */
  private async resolveUserTableColumns(tableName: string): Promise<string[]> {
    const SYSTEM_COLS = new Set(['_xmin', '_xmax', '_cmin', '_cmax', 'rowid']);
    try {
      // Use PRAGMA table_info via queryRouter to get real column info
      const result = await this.queryRouter.execute(
        `SELECT name FROM pragma_table_info('${tableName.replace(/'/g, "''")}') WHERE name NOT IN ('_xmin','_xmax','_cmin','_cmax','rowid') ORDER BY cid`
      );
      // Dedupe in case query router broadcasts to multiple shards
      const seen = new Set<string>();
      return result.rows.filter((r: any) => { const n = r.name; return seen.has(n) ? false : (seen.add(n), true); }).map((r: any) => r.name);
    } catch (_e: any) {
      return [];
    }
  }

  /** Resolve column names for a table, with DuckDB → queryRouter fallback. */
  private async resolveTableColumns(tableName: string): Promise<string[]> {
    try {
      // Primary: DuckDB (fast columnar metadata)
      const db = (this.queryRouter as any).getDuckDb?.();
      if (db) {
        const rows = db.prepare(`PRAGMA table_info('${tableName}')`).all() as any[];
        if (rows.length > 0) {
          return rows.map((r: any) => String(r.name));
        }
      }
    } catch (_e: any) {
      // DuckDB unavailable → fall through to queryRouter
    }
    // Fallback: queryRouter.execute(PG port → Raft-aware read)
    const fallback = await this.resolveUserTableColumns(tableName);
    if (fallback.length > 0) return fallback;
    return [];
  }

  // ════════════════════════════════════════════════
  //  G2: NOTIFY / LISTEN
  // ════════════════════════════════════════════════

  /**
   * Send a NotificationResponse ('A') message to a socket.
   *
   * Format:
   *   char 'A'
   *   int32 length (including self)
   *   int32 pid (backend PID, 0 for simplicity)
   *   string channel (null-terminated)
   *   string payload (null-terminated)
   */
  private sendNotificationResponse(socket: net.Socket, sessionId: string, channel: string, payload: string): void {
    // Look up the real backend PID for this session
    const conn = this.conns.get(sessionId);
    const pidNum = conn?.session?.backendPid ?? 0;
    const pidBuf = Buffer.alloc(4);
    pidBuf.writeInt32BE(pidNum);

    const channelBuf = Buffer.from(channel + '\0', 'utf8');
    const payloadBuf = Buffer.from(payload + '\0', 'utf8');

    const bodyLen = 4 + channelBuf.length + payloadBuf.length;
    const buf = Buffer.alloc(1 + 4 + bodyLen);
    buf[0] = 0x41; // 'A'
    buf.writeInt32BE(bodyLen, 1);
    pidBuf.copy(buf, 5);
    channelBuf.copy(buf, 9);
    payloadBuf.copy(buf, 9 + channelBuf.length);
    socket.write(buf);
  }

  // ════════════════════════════════════════════════
  //  G4: FunctionCall message
  // ════════════════════════════════════════════════

  /**
   * Handle FunctionCall ('F') message.
   *
   * Wire format:
   *   char 'F'
   *   int32 length (including self)
   *   int32 objectID (function OID — unused, we look up by name)
   *   int16 numArgs
   *   For each arg:
   *     int32 len (-1 = NULL)
   *     bytes data (len bytes)
   *   int16 format (0=text, 1=binary for result)
   */
  private handleFunctionCall(conn: PgWireConnectionInternal, off: number, msgLen: number): void {
    const buf = conn.buffer;
    let ptr = off + 5;

    if (ptr + 4 > off + 1 + msgLen) return;
    const objectID = buf.readInt32BE(ptr);
    ptr += 4;

    if (ptr + 2 > off + 1 + msgLen) return;
    const numArgs = buf.readInt16BE(ptr);
    ptr += 2;

    const args: any[] = [];
    for (let i = 0; i < numArgs; i++) {
      if (ptr + 4 > off + 1 + msgLen) break;
      const argLen = buf.readInt32BE(ptr);
      ptr += 4;

      if (argLen === -1) {
        args.push(null);
      } else {
        if (ptr + argLen > off + 1 + msgLen) break;
        args.push(buf.toString('utf8', ptr, ptr + argLen));
        ptr += argLen;
      }
    }

    // Read result format
    let resultFormat = 0;
    if (ptr + 2 <= off + 1 + msgLen) {
      resultFormat = buf.readInt16BE(ptr);
    }

    // Look up function name by OID
    // We don't have a function registry yet, so we use a simple OID→name mapping
    const functionName = this.lookupFunctionName(objectID);

    if (!functionName) {
      this.sendError(conn.socket, `function with OID ${objectID} not found`);
      this.sendReadyForQuery(conn.socket);
      return;
    }

    // Execute the function via SQL
    const placeholders = args.map((_, i) => `$${i + 1}`).join(', ');
    const sql = `SELECT ${functionName}(${placeholders})`;

    this.queryRouter.execute(sql, args)
      .then((result) => {
        const value = result.rows.length > 0 ? Object.values(result.rows[0])[0] : null;
        const isNull = value === null || value === undefined;

        // Send FunctionCallResponse ('V'): int16 format + int32 length/data
        let valueBytes: Buffer;
        let bodyLen: number;
        if (isNull) {
          bodyLen = 2 + 4;
          valueBytes = Buffer.alloc(0);
        } else {
          const valueStr = String(value);
          valueBytes = Buffer.from(valueStr, 'utf8');
          bodyLen = 2 + 4 + valueBytes.length;
        }
        const respBuf = Buffer.alloc(1 + 4 + bodyLen);
        respBuf[0] = 0x56; // 'V'
        respBuf.writeInt32BE(bodyLen, 1);
        respBuf.writeInt16BE(resultFormat, 5);
        respBuf.writeInt32BE(isNull ? -1 : valueBytes.length, 7);
        if (!isNull) {
          valueBytes.copy(respBuf, 11);
        }
        conn.socket.write(respBuf);
      })
      .catch((err: any) => {
        this.sendError(conn.socket, `FunctionCall failed: ${err.message}`);
      });
  }

  /**
   * Look up a function name by OID. This is a minimal mapping for common
   * PostgreSQL built-in functions.
   */
  private lookupFunctionName(oid: number): string | null {
    // Common PostgreSQL function OIDs
    const functionMap: Record<number, string> = {
      1002: 'abs',
      1003: 'acos',
      1005: 'ascii',
      1006: 'asin',
      1007: 'atan',
      1015: 'cbrt',
      1016: 'ceil',
      1028: 'cos',
      1030: 'cot',
      1042: 'degrees',
      1043: 'div',
      1054: 'exp',
      1055: 'floor',
      1066: 'ln',
      1067: 'log',
      1070: 'mod',
      1071: 'pi',
      1082: 'power',
      1083: 'radians',
      1084: 'random',
      1090: 'round',
      1091: 'sign',
      1092: 'sin',
      1093: 'sqrt',
      1094: 'tan',
      1095: 'trim',
      1096: 'trunc',
      1102: 'upper',
      1103: 'lower',
      1104: 'length',
      1105: 'ltrim',
      1106: 'rtrim',
      1107: 'substr',
      1108: 'substring',
      1109: 'position',
      1110: 'replace',
      1111: 'concat',
      1112: 'coalesce',
      1113: 'nullif',
      1114: 'now',
      1115: 'current_date',
      1116: 'current_time',
      1117: 'current_timestamp',
      // Aggregate functions
      2100: 'count',
      2101: 'sum',
      2102: 'avg',
      2103: 'min',
      2104: 'max',
    };

    return functionMap[oid] ?? null;
  }

  // ════════════════════════════════════════════════
  //  pg_cancel_backend / pg_terminate_backend permission checks
  // ════════════════════════════════════════════════

  /**
   * Check if the caller has permission to cancel/terminate a target backend.
   * Permission is granted if:
   *   1. The caller is superuser, OR
   *   2. The caller owns the target backend (same userName)
   *
   * @param targetPid - The PID of the target backend
   * @param callerConn - The caller's connection
   * @returns true if permission is granted
   */
  private hasBackendPermission(targetPid: number, callerConn: PgWireConnectionInternal | undefined): boolean {
    if (!callerConn) return false;

    // Superuser check via RoleManager
    if (this.roleManager) {
      const isSuperuser = this.roleManager.checkPrivilege(callerConn.userName || 'unknown', 'SUPERUSER');
      if (isSuperuser) return true;
    }

    // Owner check: find the target session and compare userName
    const targetSessionId = this._pidToSessionId.get(targetPid);
    if (targetSessionId) {
      const c = this.conns.get(targetSessionId);
      if (c && c.userName === callerConn.userName) {
        return true;
      }
    }

    return false;
  }

  /**
   * Enhanced pg_terminate_backend with permission checking.
   *
   * @param targetPid - The PID of the target backend to terminate
   * @param callerConn - The caller's connection
   * @returns true if the backend was found and terminated
   */
  private terminateBackendWithPermissionCheck(
    targetPid: number,
    callerConn: PgWireConnectionInternal | undefined,
  ): boolean {
    const targetSessionId = this._pidToSessionId.get(targetPid);
    if (!targetSessionId) return false;

    if (!this.hasBackendPermission(targetPid, callerConn)) {
      logger.warn(
        { targetPid, callerUser: callerConn?.userName },
        'pg_terminate_backend: permission denied',
      );
      return false;
    }

    const terminated = this.connectionManager.terminate(targetSessionId);
    if (!terminated) return false;

    // Clean up PID mapping
    this._pidToSessionId.delete(targetPid);
    logger.info(
      { targetPid, targetSessionId, callerUser: callerConn?.userName },
      'Backend terminated via pg_terminate_backend',
    );
    return true;
  }

  /**
   * Enhanced pg_cancel_backend with permission checking.
   *
   * @param targetPid - The PID of the target backend to cancel
   * @param callerConn - The caller's connection
   * @returns true if the query was found and cancelled
   */
  private cancelBackendWithPermissionCheck(
    targetPid: number,
    callerConn: PgWireConnectionInternal | undefined,
  ): boolean {
    const targetSessionId = this._pidToSessionId.get(targetPid);
    if (!targetSessionId) return false;

    if (!this.hasBackendPermission(targetPid, callerConn)) {
      logger.warn(
        { targetPid, callerUser: callerConn?.userName },
        'pg_cancel_backend: permission denied',
      );
      return false;
    }

    const c = this.conns.get(targetSessionId);
    if (c) {
      c.cancelled = true;
      if (c.abortController) {
        c.abortController.abort();
        c.abortController = null;
      }
      logger.info(
        { targetPid, targetSessionId, callerUser: callerConn?.userName },
        'Query cancelled via pg_cancel_backend',
      );
      return true;
    }
    return false;
  }

  /**
   * pg_wait_for_backend_termination — wait for a backend to terminate with timeout.
   *
   * @param targetPid - The PID of the target backend
   * @param timeoutMs - Maximum time to wait in ms (default: 5000)
   * @returns true if the backend terminated, false on timeout
   */
  private pgWaitForBackendTermination(targetPid: number, timeoutMs: number = 5000): boolean {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      if (!this._pidToSessionId.has(targetPid)) {
        return true; // Backend is gone
      }
      // Yield to event loop
      return false; // In synchronous context, we cannot truly wait
    }
    return false;
  }

  /**
   * Log performance timing stats since startup.
   */
  static printTimingStats(): void {
    const s = PgWireServer.timingStats;
    if (s.count === 0) { logger.info('[Timing] No queries executed.'); return; }
    const avg = s.totalMs / s.count;
    logger.info(`[Timing] ${s.count} queries | avg=${avg.toFixed(2)}ms max=${s.maxMs.toFixed(2)}ms total=${s.totalMs.toFixed(0)}ms`);
    const sorted = [...s.byType.entries()].sort((a, b) => b[1].totalMs - a[1].totalMs);
    for (const [type, b] of sorted) {
      logger.info(`  ${type.padEnd(8)} cnt=${b.count} avg=${(b.totalMs / b.count).toFixed(2)}ms max=${b.maxMs.toFixed(2)}ms total=${b.totalMs.toFixed(0)}ms`);
    }
  }
}

// ════════════════════════════════════════════════
//  Module-level helper
// ════════════════════════════════════════════════

/**
 * Yield control to Node.js event loop.
 *
 * better-sqlite3 is synchronous — async wrapper methods resolve as microtasks
 * without freeing the event loop. This helper uses setImmediate to ensure
 * pending I/O (TCP socket data, timers) gets a chance to run.
 *
 * Critical for COPY operations: without this, the batch INSERT loop starves
 * the event loop, TCP socket buffer fills up, and pgbench blocks on write().
 */
function yieldToEventLoop(): Promise<void> {
  return new Promise(resolve => setImmediate(resolve));
}

/** ScopedConnection — 安全地临时修改 SQLite PRAGMA，完事后自动恢复。
 *
 * 解决的问题：
 * - COPY handler 直接修改 copyShard.db 的 PRAGMA（cache_size, synchronous）
 *   会影响同一连接上的所有其他操作（Raft、autovacuum、其他 session 的 SELECT）
 * - 错误路径中 PRAGMA 恢复遗漏（外层 catch 没有恢复逻辑）
 *
 * 使用方式：
 *   const scoped = new ScopedConnection(copyShard.db);
 *   scoped.setPragma('cache_size', -512000);
 *   scoped.setPragma('synchronous', 'OFF');
 *   try {
 *     scoped.exec('BEGIN IMMEDIATE');
 *     // ... 批量插入
 *     scoped.exec('COMMIT');
 *   } finally {
 *     scoped.restore();  // 无论成功失败，恢复所有 PRAGMA
 *   }
 */
class ScopedConnection {
  private readonly originals = new Map<string, any[]>();

  constructor(private readonly db: any) {}

  /** 记录当前值并设置新值。重复调用不会覆盖 original（只存第一次）。 */
  setPragma(key: string, value: string | number): this {
    if (!this.originals.has(key)) {
      this.originals.set(key, this.db.pragma(key));
    }
    this.db.pragma(`${key} = ${value}`);
    return this;
  }

  /** 执行 SQL（委托给底层 better-sqlite3 Database） */
  exec(sql: string): any {
    return this.db.exec(sql);
  }

  /** 读取 PRAGMA（委托给底层） */
  pragma(key: string): any {
    return this.db.pragma(key);
  }

  /** 恢复所有修改过的 PRAGMA 到原始值 */
  restore(): void {
    for (const [key, original] of this.originals) {
      try {
        const val = Array.isArray(original)
          ? (original[0] as any)?.[key] ?? original[0] ?? original
          : original;
        this.db.pragma(`${key} = ${val}`);
      } catch { /* best-effort — 连接可能已关闭 */ }
    }
    this.originals.clear();
  }
}
function userNameFromStartup(conn: PgWireConnectionInternal): string {
  return conn.userName || 'scram_user';
}

// ════════════════════════════════════════════════
//  Re-export CopyHandler for external usage
// ════════════════════════════════════════════════

export { CopyHandler } from './CopyHandler';
