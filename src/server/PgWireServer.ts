/**
 * @deprecated Phase 2 — 测试脚手架（已废弃）
 *
 * 此文件是 PG Wire 协议的 **测试专用简化实现**，仅供测试使用。
 * **生产使用请用 `src/protocol/PgWireServer.ts`**（5,472 行，支持 TLS/SCRAM-256/Cancel/offset-cursor）。
 *
 * 迁移路径：
 *   - 新测试请直接使用 `protocol.PgWireServer` + `MockQueryRouter`
 *   - 旧测试在逐步迁移中，迁移完成前此文件保留以确保不打断 CI
 *
 * 不再接收新功能，不再修复 bug（除非迁移受阻）。
 *
 * PgWireServer — PostgreSQL Wire Protocol Server for SqlVec.
 *
 * Wraps pg-server's createAdvancedServer() to speak the PG wire protocol,
 * forwarding SQL queries to a configured SqlExecutor.
 *
 * Supports:
 *  - Simple Query protocol (type 'Q')
 *  - Extended Query protocol (Parse → Bind → Execute → Sync)
 *  - No-auth (trust) authentication
 *  - Service startup/shutdown lifecycle
 *  - Error reporting via PG ErrorResponse format
 */

import net from 'net';
import { bindSocket, IAdvanceServerSession } from 'pg-server';
import { CommandCode, DbRawCommand } from 'pg-server';
import type { IResponseWriter, FieldDesc } from 'pg-server';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PgWireServer');

/** Cancel request code in PG wire protocol (0x4D4F0806 in network byte order). */
const PG_CANCEL_REQUEST_CODE = 80877102;

/** Random process ID range for BackendKeyData. */
function randomPid(): number { return Math.floor(Math.random() * 65000) + 1000; }
function randomSecret(): number { return Math.floor(Math.random() * 2147483647); }

// ── Public Result Type ──

export interface SqlExecResult {
  rows: any[];
  rowCount: number;
  error?: string | Error;
  /** PostgreSQL SQLSTATE error code (5-character alphanumeric).
   *  Maps the error to a standard PG error category for client compatibility.
   *  See https://www.postgresql.org/docs/current/errcodes-appendix.html */
  sqlState?: string;
}

/**
 * Minimal SQL executor interface for the PgWireServer.
 * Implementations can wrap DuckDB, SQLite, or the full QueryRouter.
 *
 * Each PgWire connection gets a unique session ID via onConnect/onDisconnect
 * lifecycle hooks, ensuring proper transaction isolation across connections.
 */
export interface SqlExecutor {
  execute(sql: string, params?: any[], sessionId?: string): Promise<SqlExecResult> | SqlExecResult;
  /** Called when a PG wire connection is established. Returns a session ID. */
  onConnect?(connectionId: string): string | Promise<string>;
  /** Called when a PG wire connection ends. Cleans up session state. */
  onDisconnect?(sessionId: string): void | Promise<void>;
}

// ── PG Wire Protocol Utilities (exported for testing) ─────────────────

/** Map a PG error message to a standard SQLSTATE code. */
export function sqlStateFor(err: string | Error): string {
  const msg = typeof err === 'string' ? err : err.message;
  const upper = msg.toUpperCase();

  // Class 22 — Data Exception
  if (upper.includes('DIVISION BY ZERO') || upper.includes('DIVIDE BY ZERO')) return '22012';
  if (upper.includes('NUMERIC VALUE OUT OF RANGE') || upper.includes('OUT OF RANGE')) return '22003';
  if (upper.includes('STRING RIGHT TRUNCATION')) return '22001';
  if (upper.includes('DATETIME') || upper.includes('DATE/TIME') || upper.includes('TIMESTAMP') && upper.includes('OVERFLOW')) return '22008';
  if (upper.includes('INVALID TEXT') || upper.includes('INVALID INPUT') || upper.includes('CANNOT BE CAST') || upper.includes('CAST')) return '22P02';

  // Class 23 — Integrity Constraint Violation
  if (upper.includes('UNIQUE') || (upper.includes('DUPLICATE') && !upper.includes('TABLE'))) return '23505';
  if (upper.includes('FOREIGN KEY')) return '23503';
  if (upper.includes('NOT NULL')) return '23502';
  if (upper.includes('CHECK') || upper.includes('VIOLATION')) return '23514';

  // Class 25 — Invalid Transaction State
  if (upper.includes('TRANSACTION IS ABORTED') || upper.includes('ABORTED')) return '25P02';
  if (upper.includes('NO ACTIVE TRANSACTION') || upper.includes('NOT IN A TRANSACTION')) return '25P01';

  // Class 28 — Invalid Authorization
  if (upper.includes('INVALID PASSWORD') || upper.includes('PASSWORD')) return '28P01';

  // Class 3D — Invalid Catalog
  if (upper.includes('INVALID CATALOG') || upper.includes('DATABASE') && upper.includes('NOT FOUND')) return '3D000';

  // Class 42 — Syntax / Access Rule
  if (upper.includes('SYNTAX') || upper.includes('PARSE ERROR')) return '42601';
  if (upper.includes('DUPLICATE') && (upper.includes('TABLE') || upper.includes('OBJECT'))) return '42P07';
  if (upper.includes('UNDEFINED COLUMN') || upper.includes('COLUMN') && upper.includes('NOT FOUND')) return '42703';
  if (upper.includes('UNDEFINED TABLE') || upper.includes('TABLE DOES NOT EXIST') || upper.includes('DOES NOT EXIST')) return '42P01';
  if (upper.includes('UNDEFINED FUNCTION') || upper.includes('FUNCTION') && upper.includes('NOT FOUND')) return '42883';
  if (upper.includes('UNDEFINED PARAMETER') || upper.includes('UNKNOWN PARAMETER')) return '42P02';
  if (upper.includes('TYPE MISMATCH')) return '42804';
  if (upper.includes('AMBIGUOUS') || upper.includes('AMBIGUOUS COLUMN')) return '42P08';

  // Class 42 — Permission Denied
  if (upper.includes('PERMISSION') || upper.includes('ACCESS DENIED')) return '42501';

  // Class 40 — Transaction Rollback
  if (upper.includes('DEADLOCK') || upper.includes('DEADLOCK DETECTED')) return '40P01';
  if (upper.includes('SERIALIZATION') || upper.includes('SERIALIZATION FAILURE')) return '40001';

  // Class 53 — Insufficient Resources
  if (upper.includes('DISK FULL') || upper.includes('NO SPACE')) return '53100';
  if (upper.includes('OUT OF MEMORY') || upper.includes('MEMORY')) return '53200';

  // Class 57 — Operator Intervention
  if (upper.includes('CANCEL') || upper.includes('CANCELING') || upper.includes('USER CANCEL')) return '57014';
  if (upper.includes('ADMIN SHUTDOWN') || upper.includes('SHUTDOWN')) return '57P01';

  // Class 08 — Connection Exception
  if (upper.includes('CONNECTION') || upper.includes('NETWORK')) return '08006';

  // Class 58 — System Error (IO)
  if (upper.includes('IO ERROR') || upper.includes('DISK IO') || upper.includes('I/O ERROR')) return '58030';

  // Default: Internal Error
  return 'XX000';
}

/** Escape a value for PG COPY text format. */
export function copyEscape(val: unknown): string {
  if (val == null) return '\\N';
  const s = String(val);
  return s.replace(/\\/g, '\\\\').replace(/\t/g, '\\t').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

/** Detect if SQL is a COPY TO STDOUT statement. */
export function isCopyTo(sql: string): boolean {
  return /^\s*COPY\s+/i.test(sql) && /\s+TO\s+(STDOUT|'[^']*'|"[^"]*")/i.test(sql);
}

/** Detect if SQL is a COPY FROM STDIN statement. */
export function isCopyFrom(sql: string): boolean {
  return /^\s*COPY\s+/i.test(sql) && /\s+FROM\s+STDIN/i.test(sql);
}

/** Extract table name from COPY ... FROM/TO statement. */
export function copyTableName(sql: string): string {
  const m = sql.match(/^\s*COPY\s+(?:(\w+)(?:\.\w+)?)/i);
  return m ? m[1] : '';
}

/** Parse COPY text format data and return rows (array of string arrays). */
export function parseCopyData(data: Buffer): string[][] {
  const text = data.toString('utf8');
  if (!text.trim()) return [];
  return text.split('\n')
    .filter(line => line.length > 0)
    .map(line => {
      const cols: string[] = [];
      let i = 0;
      let cur = '';
      while (i < line.length) {
        const ch = line[i];
        if (ch === '\\' && i + 1 < line.length) {
          const next = line[i + 1];
          if (next === 'n') { cur += '\n'; i += 2; continue; }
          if (next === 't') { cur += '\t'; i += 2; continue; }
          if (next === 'r') { cur += '\r'; i += 2; continue; }
          if (next === '\\') { cur += '\\'; i += 2; continue; }
          if (next === 'N') { cols.push(''); i += 2; continue; }
          cur += next; i += 2; continue;
        }
        if (ch === '\t') { cols.push(cur); cur = ''; i++; continue; }
        cur += ch; i++;
      }
      cols.push(cur);
      return cols;
    });
}

// ── PgWireServer ──

export interface PgWireServerConfig {
  host?: string;
  port?: number;
  verbose?: boolean;
  /** Log queries exceeding this duration (ms). Default 0 = disabled. */
  slowQueryThresholdMs?: number;
}

export interface PgWireServerMetrics {
  readonly totalConnections: number;
  readonly activeConnections: number;
  readonly activeQueries: number;
  readonly queryCount: number;
  readonly slowQueryCount: number;
}

export class PgWireServer {
  private server: net.Server | null = null;
  private executor: SqlExecutor;
  private config: Required<PgWireServerConfig>;
  /** Per-connection session ID tracking for transaction isolation */
  private readonly connSessions = new Map<string, string>();
  private nextConnId = 0;

  /** Cancel key infrastructure: pid → { secretKey, sessionId, abort } */
  private readonly cancelKeys = new Map<number, { secretKey: number; sessionId: string; abort: () => void }>();
  /** Pending query AbortControllers per session. */
  private readonly pendingQueries = new Map<string, AbortController>();
  /** Metrics */
  private queryCount = 0;
  private slowQueryCount = 0;

  constructor(executor: SqlExecutor, config: PgWireServerConfig = {}) {
    this.executor = executor;
    this.config = {
      host: config.host ?? '127.0.0.1',
      port: config.port ?? 9653,
      verbose: config.verbose ?? false,
      slowQueryThresholdMs: config.slowQueryThresholdMs ?? 0,
    };
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = net.createServer(socket => {
        // Peek at the first bytes to detect PG cancel requests.
        // Cancel is a 16-byte message: int32 length=16, int32 code=80877102,
        // int32 pid, int32 secretKey. Regular startup has different code.
        let cancelCheckDone = false;
        socket.once('data', (firstData: Buffer) => {
          cancelCheckDone = true;
          if (firstData.length >= 8) {
            const code = firstData.readInt32BE(4);
            if (code === PG_CANCEL_REQUEST_CODE) {
              // Cancel request — read pid + secretKey
              if (firstData.length >= 16) {
                const pid = firstData.readInt32BE(8);
                const secret = firstData.readInt32BE(12);
                this.handleCancel(pid, secret);
              }
              socket.end();
              return;
            }
          }
          // Regular connection: create session and route to pg-server
          const session = new SqlVecPgSession();
          session.onConnect(socket);
          (socket as any)._pgwConnId = session.connId;
          bindSocket(socket, session.onCommand.bind(session));
          // Push back the peeked data for pg-server to process
          socket.unshift(firstData);
        });

        // Edge case: data might never arrive on this socket
        socket.on('close', () => {
          if (!cancelCheckDone) {
            socket.destroy();
            return;
          }
          // Clean up connection state on socket close
          const connId = (socket as any)._pgwConnId as string | undefined;
          if (connId) this.destroyConnection(connId);
        });
      });

      SqlVecPgSession._executor = this.executor;
      SqlVecPgSession._verbose = this.config.verbose;
      SqlVecPgSession._serverRef = this;

      server.listen(this.config.port, this.config.host, () => {
        logger.info(
          { host: this.config.host, port: this.config.port },
          '[PgWireServer] Listening',
        );
        this.server = server;
        resolve();
      });

      server.on('error', (err: Error) => {
        logger.error({ err: err.message }, '[PgWireServer] Server error');
        reject(err);
      });
    });
  }

  /** Register a cancel key for a session (called from SqlVecPgSession.onConnect). */
  registerCancelKey(pid: number, secretKey: number, sessionId: string): void {
    this.cancelKeys.set(pid, {
      secretKey,
      sessionId,
      abort: () => {
        const ac = this.pendingQueries.get(sessionId);
        if (ac) { ac.abort(); this.pendingQueries.delete(sessionId); }
      },
    });
  }

  /** Register a pending query AbortController for cancel. */
  registerPendingQuery(sessionId: string, ac: AbortController): void {
    this.pendingQueries.set(sessionId, ac);
  }

  /** Unregister when query completes. */
  unregisterPendingQuery(sessionId: string): void {
    this.pendingQueries.delete(sessionId);
  }

  /** Return live server metrics. */
  getMetrics(): PgWireServerMetrics {
    return {
      totalConnections: this.nextConnId,
      activeConnections: this.connSessions.size,
      activeQueries: this.pendingQueries.size,
      queryCount: this.queryCount,
      slowQueryCount: this.slowQueryCount,
    };
  }

  /** Report a completed query for metrics (called from SqlVecPgSession). */
  recordQuery(durationMs: number): void {
    this.queryCount++;
    if (this.config.slowQueryThresholdMs > 0 && durationMs >= this.config.slowQueryThresholdMs) {
      this.slowQueryCount++;
      logger.warn({ durationMs, threshold: this.config.slowQueryThresholdMs }, '[PgWireServer] Slow query');
    }
  }

  /** Handle a PG wire cancel request. */
  private handleCancel(pid: number, secretKey: number): void {
    const entry = this.cancelKeys.get(pid);
    if (!entry) {
      logger.warn({ pid }, '[PgWire] Cancel request for unknown pid');
      return;
    }
    if (entry.secretKey !== secretKey) {
      logger.warn({ pid }, '[PgWire] Cancel request with invalid secret key');
      return;
    }
    logger.info({ pid, sessionId: entry.sessionId }, '[PgWire] Cancel request — aborting query');
    entry.abort();
  }

  /** Allocate a unique connection ID and session ID for a new PG wire connection. */
  createConnection(): { connId: string; sessionId: string } {
    const connId = `pgw-${++this.nextConnId}-${Date.now()}`;
    let sessionId: string;
    try {
      sessionId = this.executor.onConnect?.(connId) as string ?? `pgw-${connId}`;
    } catch {
      sessionId = `pgw-${connId}`;
    }
    this.connSessions.set(connId, sessionId);
    return { connId, sessionId };
  }

  /** Clean up session state when a connection ends. */
  destroyConnection(connId: string): void {
    const sessionId = this.connSessions.get(connId);
    if (sessionId) {
      try {
        this.executor.onDisconnect?.(sessionId);
      } catch (err: any) {
        logger.warn({ connId, sessionId, err: err.message }, '[PgWireServer] onDisconnect error');
      }
      this.connSessions.delete(connId);
    }
  }

  /** Resolve a connection ID to its session ID (or default). */
  getSessionId(connId: string): string {
    return this.connSessions.get(connId) ?? 'default';
  }

  async stop(): Promise<void> {
    // Cancel any pending queries
    for (const [sessionId, ac] of this.pendingQueries) {
      ac.abort();
    }
    this.pendingQueries.clear();
    this.cancelKeys.clear();

    return new Promise((resolve) => {
      if (!this.server) { resolve(); return; }
      this.server.close(() => {
        logger.info('[PgWireServer] Stopped');
        this.server = null;
        resolve();
      });
    });
  }
}

// ── Session class (instantiated per-connection) ──────────────────────

class SqlVecPgSession implements IAdvanceServerSession {
  static _executor: SqlExecutor | null = null;
  static _verbose = false;
  static _serverRef: PgWireServer | null = null;

  private executor!: SqlExecutor;
  private verbose = false;
  connId!: string;
  private sessionId!: string;

  // Extended query protocol state
  private prepared = new Map<string, { query: string; paramTypes: number[] }>();
  private bound = new Map<string, { statement: string; values: string[] }>();
  private sessionActive = false;
  private pgPid = 0;
  private pgSecretKey = 0;

  // Pending-execute queue: Sync must wait for async Execute to finish
  private pendingExecute: (() => Promise<void>) | null = null;
  private pendingExecuteRes: IResponseWriter | null = null;
  private deferredSync: IResponseWriter | null = null;

  // COPY FROM state: accumulate data chunks until copyDone
  private copyBuffer: Buffer[] | null = null;
  private copyTableName = '';

  onConnect(_socket: net.Socket): void {
    this.executor = SqlVecPgSession._executor!;
    this.verbose = SqlVecPgSession._verbose;
    // Allocate connection ID and session ID via server
    const server = SqlVecPgSession._serverRef;
    if (server) {
      const { connId, sessionId } = server.createConnection();
      this.connId = connId;
      this.sessionId = sessionId;
    } else {
      this.connId = `pgw-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      this.sessionId = this.connId;
    }
    this.sessionActive = true;
    this.pendingExecute = null;
    this.pendingExecuteRes = null;
    this.deferredSync = null;
    this.copyBuffer = null;
    this.copyTableName = '';
    if (this.verbose) logger.info({ connId: this.connId }, '[PgWire] New connection');
  }

  onCommand(command: DbRawCommand, res: IResponseWriter): void {
    if (!this.sessionActive) return;
    const cmd = command.command;
    try {
      switch (cmd.type) {
        case CommandCode.init:
          this.handleInit(cmd as any, res);
          break;
        case CommandCode.query:
          void this.handleQuery(cmd as any, res);
          break;
        case CommandCode.parse:
          this.handleParse(cmd as any, res);
          break;
        case CommandCode.bind:
          this.handleBind(cmd as any, res);
          break;
        case CommandCode.execute: {
          const execFn = () => this.handleExecute(cmd as any, res);
          this.pendingExecute = execFn;
          this.pendingExecuteRes = res;
          // If Sync already arrived before Execute was registered, flush now
          if (this.deferredSync) {
            void this.flushPendingExecute();
          }
          break;
        }
        case CommandCode.describe:
          this.handleDescribe(cmd as any, res);
          break;
        case CommandCode.close:
          this.handleClose(cmd as any, res);
          break;
        case CommandCode.sync:
        case CommandCode.flush:
          if (this.pendingExecute) {
            this.deferredSync = res;
            void this.flushPendingExecute();
          } else {
            res.readyForQuery();
          }
          break;
        case CommandCode.end:
          this.sessionActive = false;
          if (this.connId && SqlVecPgSession._serverRef) {
            SqlVecPgSession._serverRef.destroyConnection(this.connId);
          }
          break;
        case CommandCode.copyFromChunk:
          this.handleCopyFromChunk(cmd as any, res);
          break;
        case CommandCode.copyDone:
          void this.handleCopyDone(res);
          break;
        case CommandCode.copyFail:
          this.handleCopyFail(cmd as any, res);
          break;
        default:
          break;
      }
    } catch (err: any) {
      logger.warn({ err: err.message }, '[PgWire] Error handling command');
      const state = sqlStateFor(err);
      res.error({ message: err.message, code: state });
    }
  }

  /** Run the pending execute, then flush deferred Sync. */
  private async flushPendingExecute(): Promise<void> {
    const execFn = this.pendingExecute;
    const execRes = this.pendingExecuteRes;
    this.pendingExecute = null;
    this.pendingExecuteRes = null;
    if (execFn) await execFn();
    if (this.deferredSync) {
      const syncRes = this.deferredSync;
      this.deferredSync = null;
      syncRes.readyForQuery();
    }
  }

  // ── Auth ──

  private handleInit(
    cmd: { type: CommandCode; version: { major: number; minor: number }; options: Record<string, string> },
    res: IResponseWriter,
  ): void {
    if (this.verbose) {
      logger.info(
        { version: `${cmd.version.major}.${cmd.version.minor}`, user: cmd.options.user },
        '[PgWire] Startup',
      );
    }
    // Trust auth + cancel key registration
    this.pgPid = randomPid();
    this.pgSecretKey = randomSecret();
    const serverRef = SqlVecPgSession._serverRef;
    if (serverRef) {
      serverRef.registerCancelKey(this.pgPid, this.pgSecretKey, this.sessionId);
    }

    res.authenticationOk();
    res.parameterStatus('server_version', '16.0');
    res.parameterStatus('server_encoding', 'UTF8');
    res.parameterStatus('client_encoding', 'UTF8');
    res.parameterStatus('standard_conforming_strings', 'on');
    res.backendKeyData(this.pgPid, this.pgSecretKey);
    res.readyForQuery();
  }

  // ── Simple Query Protocol ──

  private async handleQuery(cmd: { type: CommandCode; query: string }, res: IResponseWriter): Promise<void> {
    const sql = cmd.query.trim();
    if (!sql) {
      res.emptyQuery();
      res.readyForQuery();
      return;
    }

    // COPY TO STDOUT → redirect to COPY OUT protocol
    if (isCopyTo(sql)) {
      await this.handleCopyTo(sql, res);
      return;
    }

    // COPY FROM STDIN → begin COPY IN mode
    if (isCopyFrom(sql)) {
      this.copyBuffer = [];
      this.copyTableName = copyTableName(sql);
      res.copyIn(false, []);
      return;
    }

    const result = await this.executeWithCancel(sql, [], this.sessionId);

    if (result.error) {
      const msg = typeof result.error === 'string' ? result.error : result.error.message;
      res.error(result.sqlState ? { message: msg, code: result.sqlState } : msg);
      res.readyForQuery();
      return;
    }

    const rows = result.rows ?? [];
    let columnNames: string[] = [];
    if (rows.length > 0) {
      columnNames = Object.keys(rows[0]);
    }

    if (columnNames.length > 0) {
      const fields: FieldDesc[] = columnNames.map((name, i) => ({
        name,
        tableID: 0,
        columnID: i + 1,
        dataTypeID: 25, // TEXT
        dataTypeSize: -1,
        dataTypeModifier: -1,
        mode: 'text' as const,
      }));
      res.rowDescription(fields);
    }

    for (const row of rows) {
      const values: string[] = columnNames.map((name) => {
        const val = row[name];
        return val == null ? '' : String(val);
      });
      res.dataRow(values);
    }

    const upper = sql.toUpperCase();
    if (upper.startsWith('SELECT') || upper.startsWith('WITH')) {
      res.commandComplete(`SELECT ${rows.length}`);
    } else if (upper.startsWith('INSERT')) {
      res.commandComplete(`INSERT 0 ${result.rowCount}`);
    } else if (upper.startsWith('UPDATE')) {
      res.commandComplete(`UPDATE ${result.rowCount}`);
    } else if (upper.startsWith('DELETE')) {
      res.commandComplete(`DELETE ${result.rowCount}`);
    } else {
      res.commandComplete('OK');
    }

    res.readyForQuery();
  }

  // ── Extended Query Protocol (Parse → Describe → Bind → Execute → Sync) ──

  private handleParse(
    cmd: { type: CommandCode; queryName: string; query: string; parameters: number[] },
    res: IResponseWriter,
  ): void {
    this.prepared.set(cmd.queryName || '', {
      query: cmd.query,
      paramTypes: cmd.parameters,
    });
    res.parseComplete();
  }

  private handleBind(
    cmd: { type: CommandCode; portal: string; statement: string; values: any[]; binary: boolean },
    res: IResponseWriter,
  ): void {
    const prepared = this.prepared.get(cmd.statement);
    if (!prepared) {
      res.error(`Prepared statement '${cmd.statement}' not found`);
      return;
    }
    this.bound.set(cmd.portal || '', {
      statement: cmd.statement,
      values: cmd.values.map((v: any) => (v == null ? '' : String(v))),
    });
    res.bindComplete();
  }

  /** Describe handler: must send ParameterDescription (for statement) + NoData/RowDescription */
  private handleDescribe(
    cmd: { type: CommandCode; portalType: 'P' | 'S'; name?: string },
    res: IResponseWriter,
  ): void {
    // Statement-level describe: send parameter type info so pg client can format Bind values
    if (cmd.portalType === 'S') {
      const stmt = this.prepared.get(cmd.name ?? '');
      const paramCount = stmt ? stmt.paramTypes.length : 1; // pg sends Describe even with $1
      // Count $N placeholders from the SQL to determine actual param count
      let inferredCount = 0;
      if (stmt) {
        const matches = stmt.query.match(/\$(\d+)/g);
        if (matches) {
          inferredCount = Math.max(...matches.map((m: string) => parseInt(m.substring(1), 10)));
        }
      }
      // Send parameter descriptions (using 0 = untyped/text format)  
      const count = Math.max(paramCount, inferredCount);
      if (count > 0) {
        const paramTypes = new Array(count).fill(0); // 0 = unspecified, client sends text
        res.parameterDescription(paramTypes);
      }
    }
    // No row data available at describe time
    res.noData();
  }

  /** Quote a PG value for SQL inlining. Numbers stay bare, strings get safe-quoted. */
  private static sqlValue(val: string): string {
    if (val === '' || val === 'null') return 'NULL';
    // If it parses as a number, return raw
    if (/^-?\d+(\.\d+)?$/.test(val)) return val;
    // Otherwise quote and escape
    return `'${val.replace(/'/g, "''")}'`;
  }

  private async handleExecute(
    cmd: { type: CommandCode; portal: string; rows: number },
    res: IResponseWriter,
  ): Promise<void> {
    const bound = this.bound.get(cmd.portal || '');
    if (!bound) {
      res.error(`No bound statement for portal '${cmd.portal}'`);
      return;
    }
    const prepared = this.prepared.get(bound.statement);
    if (!prepared) {
      res.error(`Prepared statement '${bound.statement}' not found`);
      return;
    }

    // Inline params into SQL (replace $1, $2, … with literal values)
    let execSql = prepared.query;
    if (bound.values.length > 0) {
      let idx = 1;
      for (const val of bound.values) {
        const literal = SqlVecPgSession.sqlValue(val);
        execSql = execSql.replace(`$${idx}`, literal);
        idx++;
      }
    }

    const result = await this.executeWithCancel(execSql, [], this.sessionId);

    if (result.error) {
      const msg = typeof result.error === 'string' ? result.error : result.error.message;
      res.error(result.sqlState ? { message: msg, code: result.sqlState } : msg);
      return;
    }

    const rows = result.rows ?? [];
    let columnNames: string[] = [];
    if (rows.length > 0) {
      columnNames = Object.keys(rows[0]);
    }

    if (columnNames.length > 0) {
      const fields: FieldDesc[] = columnNames.map((name, i) => ({
        name,
        tableID: 0,
        columnID: i + 1,
        dataTypeID: 25,
        dataTypeSize: -1,
        dataTypeModifier: -1,
        mode: 'text' as const,
      }));
      res.rowDescription(fields);
    }

    for (const row of rows) {
      const values: string[] = columnNames.map((name) => {
        const val = row[name];
        return val == null ? '' : String(val);
      });
      res.dataRow(values);
    }

    const upper = prepared.query.toUpperCase();
    if (upper.startsWith('SELECT') || upper.startsWith('WITH')) {
      res.commandComplete(`SELECT ${rows.length}`);
    } else if (upper.startsWith('INSERT')) {
      res.commandComplete(`INSERT 0 ${result.rowCount}`);
    } else if (upper.startsWith('UPDATE')) {
      res.commandComplete(`UPDATE ${result.rowCount}`);
    } else if (upper.startsWith('DELETE')) {
      res.commandComplete(`DELETE ${result.rowCount}`);
    } else {
      res.commandComplete('OK');
    }
    // Do NOT send ReadyForQuery here — Sync handler does that
  }

  private handleClose(
    cmd: { type: CommandCode; portalType: 'P' | 'S'; name?: string },
    res: IResponseWriter,
  ): void {
    if (cmd.name) {
      if (cmd.portalType === 'P') this.bound.delete(cmd.name);
      else if (cmd.portalType === 'S') this.prepared.delete(cmd.name);
    }
    res.closeComplete();
  }

  // ── COPY Protocol ──────────────────────────────────────────────────

  /** Handle COPY TO STDOUT: execute query, stream results as COPY text format. */
  private async handleCopyTo(sql: string, res: IResponseWriter): Promise<void> {
    // Rewrite COPY (...) TO STDOUT → SELECT ...
    const selectSql = sql.replace(/^\s*COPY\s*\(\s*/i, '')
      .replace(/\s*\)\s*TO\s+STDOUT.*$/i, '')
      .replace(/^\s*COPY\s+(\w+)\s+TO\s+STDOUT.*$/i, 'SELECT * FROM $1');

    const result = await this.executeWithCancel(selectSql, [], this.sessionId);

    if (result.error) {
      const msg = typeof result.error === 'string' ? result.error : result.error.message;
      res.error(result.sqlState ? { message: msg, code: result.sqlState } : msg);
      res.readyForQuery();
      return;
    }

    const rows = result.rows ?? [];
    let columnNames: string[] = [];
    if (rows.length > 0) {
      columnNames = Object.keys(rows[0]);
    }

    // Send header: column count + OIDs
    res.copyOut(false, []);

    // Send each row as COPY data row (tab-separated, newline-terminated)
    for (const row of rows) {
      const parts = columnNames.map(name => copyEscape(row[name]));
      const line = parts.join('\t') + '\n';
      res.copyData(Buffer.from(line, 'utf8'));
    }

    res.copyDone();
    res.commandComplete(`COPY ${rows.length}`);
    res.readyForQuery();
  }

  /** Handle COPY data chunk accumulation for COPY FROM STDIN. */
  private handleCopyFromChunk(
    cmd: { type: CommandCode; data: Buffer },
    _res: IResponseWriter,
  ): void {
    if (!this.copyBuffer) {
      this.copyBuffer = [];
    }
    this.copyBuffer.push(cmd.data);
  }

  /** Handle COPY FROM STDIN completion: parse data and execute INSERTs. */
  private async handleCopyDone(res: IResponseWriter): Promise<void> {
    const buffer = this.copyBuffer;
    const table = this.copyTableName;
    this.copyBuffer = null;
    this.copyTableName = '';

    if (!buffer || buffer.length === 0) {
      res.error({ message: 'No COPY data received', code: 'XX000' });
      res.readyForQuery();
      return;
    }

    // Concatenate all chunks and parse
    const fullData = Buffer.concat(buffer);
    const rows = parseCopyData(fullData);

    if (rows.length === 0) {
      res.commandComplete('COPY 0');
      res.readyForQuery();
      return;
    }

    // Determine column count from first row
    const colCount = rows[0].length;
    const colPlaceholders = new Array(colCount).fill('?').join(', ');

    // Execute as batch INSERT. For small payloads, use single INSERT.
    // For large payloads, split into chunks of 500 rows.
    const chunkSize = 500;
    let inserted = 0;
    for (let i = 0; i < rows.length; i += chunkSize) {
      const chunk = rows.slice(i, i + chunkSize);
      // Build bulk INSERT: INSERT INTO t VALUES (?,?), (?,?), ...
      const valuesClauses = chunk.map(() => `(${colPlaceholders})`).join(', ');
      const insertSql = `INSERT INTO ${table} VALUES ${valuesClauses}`;
      const flatParams = chunk.flat();

      const result = await this.executeWithCancel(insertSql, flatParams, this.sessionId);
      if (result.error) {
        const msg = typeof result.error === 'string' ? result.error : result.error.message;
        res.error(result.sqlState ? { message: msg, code: result.sqlState } : msg);
        res.readyForQuery();
        return;
      }
      inserted += chunk.length;
    }

    res.commandComplete(`COPY ${inserted}`);
    res.readyForQuery();
  }

  /** Handle COPY failure: discard accumulated data. */
  private handleCopyFail(
    cmd: { type: CommandCode; message: string },
    res: IResponseWriter,
  ): void {
    this.copyBuffer = null;
    this.copyTableName = '';
    logger.warn({ message: cmd.message }, '[PgWire] COPY FROM STDIN failed');
    res.error({ message: `COPY failed: ${cmd.message}`, code: 'XX000' });
    res.readyForQuery();
  }

  /** Execute a query with AbortController for cancel/timeout support and duration tracking. */
  private async executeWithCancel(sql: string, params: any[], sessionId: string): Promise<SqlExecResult> {
    const ac = new AbortController();
    const server = SqlVecPgSession._serverRef;
    if (server) server.registerPendingQuery(this.sessionId, ac);
    const start = Date.now();

    try {
      const result = await Promise.race([
        this.executor.execute(sql, params, sessionId),
        new Promise<never>((_, reject) => {
          ac.signal.addEventListener('abort', () => {
            reject(Object.assign(new Error('canceling statement due to user request'), { sqlState: '57014' }));
          });
        }),
      ]);
      if (server) server.recordQuery(Date.now() - start);
      return result;
    } catch (e: any) {
      if (e.sqlState === '57014') {
        if (server) server.recordQuery(Date.now() - start);
        return { rows: [], rowCount: 0, error: e.message, sqlState: '57014' };
      }
      throw e;
    } finally {
      if (server) server.unregisterPendingQuery(this.sessionId);
    }
  }
}
