/**
 * AuditLogger — Structured audit logging for SQL operations.
 *
 * Mimics the semantics of pgAudit by recording all DDL/DML queries,
 * connection events, login failures, and permission denials to
 * structured NDJSON output via PinoLogger.
 *
 * Features:
 *   - Automatic event-type classification of raw SQL (DDL / DML / READ)
 *   - Configurable audit level filtering (all / ddl / write / read / login / none)
 *   - SQL sanitisation: passwords are masked before logging
 *   - Every event carries eventId, timestamp, sessionId, userId metadata
 *
 * @module AuditLogger
 */

import * as crypto from 'node:crypto';
import Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';

// ── Types ────────────────────────────────────────────────────────────────────

/** All recognised audit event types. */
export type AuditEventType =
  | 'connection'
  | 'disconnection'
  | 'query'
  | 'ddl'
  | 'dml'
  | 'login_failure'
  | 'permission_denied'
  | 'role_created'
  | 'role_dropped'
  | 'role_altered'
  | 'ddl_executed'
  | 'sql_injection_detected'
  | 'login'
  | 'logout'
  | 'config_change';

/** Audit level filter — controls which events are actually emitted. */
export type AuditLevel = 'all' | 'ddl' | 'write' | 'read' | 'login' | 'none';

/**
 * Full audit event payload.
 *
 * Every field except `rowCount`, `errorMessage`, and `durationMs` is
 * guaranteed to be present on every event.
 */
export interface AuditEvent {
  /** Unique event identifier (UUID v4). */
  eventId: string;
  /** ISO-8601 timestamp of when the event was created. */
  timestamp: Date;
  /** Session identifier (e.g. client connection UUID). */
  sessionId: string;
  /** Authenticated user identifier. */
  userId: string;
  /** Categorisation of the event. */
  eventType: AuditEventType;
  /** Original SQL (sanitised — passwords are masked). */
  sql: string;
  /** Execution outcome. */
  result: 'success' | 'failure';
  /** Number of rows affected (query / dml events). */
  rowCount?: number;
  /** Free-text error message when `result === 'failure'`. */
  errorMessage?: string;
  /** Query execution duration in milliseconds. */
  durationMs?: number;
  /** Current audit level at the time the event was emitted. */
  auditLevel: AuditLevel;
}

/**
 * Result of a chain integrity verification.
 */
export interface IntegrityCheckResult {
  /** True when the entire hash chain is valid. */
  isValid: boolean;
  /** The 1-based index of the first row where the chain is broken. */
  firstBrokenIndex?: number;
  /** Human-readable description of the problem. */
  details?: string;
}

// ── Constants ────────────────────────────────────────────────────────────────

/** Regex that matches password literals inside single quotes. */
const PASSWORD_LITERAL_RE = /PASSWORD\s+'[^']*'/gi;

/** Default audit level when none is explicitly set. */
const DEFAULT_AUDIT_LEVEL: AuditLevel = 'all';

/** Number of audit log entries between two successive chain checkpoints. */
const CHECKPOINT_INTERVAL = 100;

/** Minimum time (in milliseconds) between two successive chain checkpoints. */
const CHECKPOINT_INTERVAL_MS = 60_000;

/** Mapping from audit level to the set of event types it allows through. */
const LEVEL_FILTER: Record<AuditLevel, ReadonlySet<AuditEventType>> = {
  all:   new Set<AuditEventType>(['connection', 'disconnection', 'query', 'ddl', 'dml', 'login_failure', 'permission_denied', 'role_created', 'role_dropped', 'role_altered', 'ddl_executed', 'sql_injection_detected', 'login', 'logout', 'config_change']),
  ddl:   new Set<AuditEventType>(['ddl', 'connection', 'disconnection']),
  write: new Set<AuditEventType>(['ddl', 'dml']),
  read:  new Set<AuditEventType>(['query']),
  login: new Set<AuditEventType>(['connection', 'disconnection', 'login_failure']),
  none:  new Set<AuditEventType>(),
};

/**
 * SQL instruction keywords that classify a statement as DDL.
 *
 * The list covers standard SQL DDL plus common extensions (CREATE OR REPLACE,
 * TRUNCATE, etc.).
 */
const DDL_KEYWORDS = new Set([
  'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'RENAME', 'COMMENT',
]);

/**
 * SQL instruction keywords that classify a statement as DML.
 */
const DML_KEYWORDS = new Set([
  'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'UPSERT', 'REPLACE',
]);

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Generate a UUID v4 event identifier synchronously.
 */
function generateEventId(): string {
  return crypto.randomUUID();
}

/**
 * Determine the audit event type from the raw SQL string.
 *
 * Classification is based on the first non-whitespace SQL keyword.
 * Sub-queries, CTEs, and parenthesized expressions are ignored.
 *
 * @param sql  The (already sanitised) SQL string.
 * @returns    The inferred event type.
 */
function classifySql(sql: string): AuditEventType {
  const trimmed = sql.trim();
  if (!trimmed) return 'query';

  // Extract the first significant keyword, skipping leading parentheses
  // and WITH (CTE) clauses.
  const firstWord = extractedFirstKeyword(trimmed);
  if (!firstWord) return 'query';

  if (DDL_KEYWORDS.has(firstWord)) return 'ddl';
  if (DML_KEYWORDS.has(firstWord)) return 'dml';
  return 'query';
}

/**
 * Extract the first SQL keyword from a statement, skipping CTEs and
 * leading parentheses.
 */
function extractedFirstKeyword(sql: string): string | null {
  // Skip leading whitespace and opening parens (e.g. sub-queries in parens).
  let idx = 0;
  while (idx < sql.length && (sql[idx] === ' ' || sql[idx] === '\t' || sql[idx] === '\n' || sql[idx] === '\r' || sql[idx] === '(')) {
    idx++;
  }
  if (idx >= sql.length) return null;

  // Read characters up to the next whitespace or parenthesis.
  const start = idx;
  while (idx < sql.length && !isWhitespaceOrParen(sql[idx])) {
    idx++;
  }
  if (idx === start) return null;

  const keyword = sql.slice(start, idx).toUpperCase();

  // If the keyword is WITH, skip past the CTE clause to find the real
  // operation keyword.
  if (keyword === 'WITH') {
    // Skip past the CTE definitions (everything up to the next top-level
    // SELECT / INSERT / UPDATE / DELETE / etc.).
    const afterCte = skipCte(sql, idx);
    if (afterCte >= sql.length) return null;
    return extractedFirstKeyword(sql.slice(afterCte));
  }

  return keyword;
}

/** Basic whitespace-or-paren check for a single character. */
function isWhitespaceOrParen(ch: string): boolean {
  return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '(' || ch === ')';
}

/**
 * Attempt to skip past a WITH clause to find the main statement keyword.
 *
 * This is a simplified heuristic that assumes a well-formed CTE.
 */
function skipCte(_sql: string, fromIdx: number): number {
  // A real parser would track paren depth; for audit purposes a simple
  // scan is sufficient.  We look for the next SELECT / INSERT / etc.
  // after a closing paren.
  let idx = fromIdx;
  let parenDepth = 0;
  while (idx < _sql.length) {
    if (_sql[idx] === '(') parenDepth++;
    else if (_sql[idx] === ')') {
      parenDepth--;
      if (parenDepth <= 0) {
        // Found the closing paren of the CTE body — return the position
        // after it so the caller can re-scan for the main keyword.
        return idx + 1;
      }
    }
    idx++;
  }
  return _sql.length;
}

// ── Audit Sink Interface ─────────────────────────────────────────────────────

/**
 * Minimal interface for an audit sink — a destination that receives every
 * fully-formed audit event after it has been emitted by AuditLogger.
 *
 * Implementations may write to files, external services, or anything else.
 */
export interface AuditSink {
  /** Forward a fully-formed audit event to this sink. */
  write(event: AuditEvent): void;

  /** Flush any buffered or queued data. */
  flush(): void;

  /** Gracefully shut down the sink (close files, clear timers, etc.). */
  close(): void;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * SQL sanitisation utility.
 *
 * Replaces all `PASSWORD '…'` literals in the input SQL string
 * with `PASSWORD '***'` so that cleartext credentials are never
 * written to audit logs.
 *
 * @param sql  The raw SQL string to sanitise.
 * @returns    The sanitised SQL string.
 */
export function sanitizeSql(sql: string): string {
  return sql.replace(PASSWORD_LITERAL_RE, "PASSWORD '***'");
}

// ── Chain hashing ────────────────────────────────────────────────────────────

/**
 * Compute the SHA-256 hash for a single audit log entry.
 *
 * Hash input: `prev_hash + event_id + timestamp + session_id + user_id +
 *             event_type + sql + result`
 *
 * @returns Hex-encoded SHA-256 digest.
 */
export function computeChainHash(
  prevHash: string,
  eventId: string,
  timestamp: string,
  sessionId: string,
  userId: string,
  eventType: string,
  sql: string,
  result: string,
): string {
  const input = prevHash + eventId + timestamp + sessionId + userId + eventType + sql + result;
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// ── AuditLogger ──────────────────────────────────────────────────────────────

export class AuditLogger {
  private readonly logger: PinoLogger;
  private auditLevel: AuditLevel;
  private readonly db: Database.Database | null;
  private readonly sinks: Set<AuditSink> = new Set();
  private _eventCounter = 0;
  private _lastCheckpointTime = 0;

  /**
   * @param logger  Optional PinoLogger instance. Creates a default one
   *                with component name `'AuditLogger'` when omitted.
   * @param db      Optional better-sqlite3 Database instance for persisting
   *                audit events to the `__audit_log` table.
   */
  constructor(logger?: PinoLogger, db?: Database.Database) {
    this.logger = logger ?? PinoLogger.forComponent('AuditLogger');
    this.auditLevel = DEFAULT_AUDIT_LEVEL;
    this.db = db ?? null;
  }

  // ── Sink Management ────────────────────────────────────────────

  /**
   * Register an {@link AuditSink} to receive every audit event.
   *
   * Sinks receive events after PinoLogger has emitted them.
   *
   * @param sink  The sink instance to add.
   */
  addSink(sink: AuditSink): void {
    this.sinks.add(sink);
  }

  /**
   * Remove a previously registered {@link AuditSink}.
   *
   * @param sink  The sink instance to remove.
   */
  removeSink(sink: AuditSink): void {
    this.sinks.delete(sink);
  }

  /**
   * Return the number of registered sinks.
   */
  getSinkCount(): number {
    return this.sinks.size;
  }

  // ── Public Methods ─────────────────────────────────────────────

  /**
   * Record an audit event.
   *
   * The `eventId` and `timestamp` fields are automatically populated.
   * Events are silently dropped when the current audit level does not
   * include the given `eventType`.
   *
   * @param event  Partial event payload (without `eventId` and `timestamp`).
   */
  log(event: Omit<AuditEvent, 'eventId' | 'timestamp' | 'auditLevel'>): void {
    const allowed = LEVEL_FILTER[this.auditLevel];
    if (!allowed.has(event.eventType)) {
      this.logger.trace({ eventType: event.eventType, auditLevel: this.auditLevel }, 'Audit event filtered by level');
      return;
    }

    const full: AuditEvent = {
      eventId: generateEventId(),
      timestamp: new Date(),
      ...event,
      auditLevel: this.auditLevel,
    };

    this.logger.info(full, 'audit');

    // ── Forward to registered sinks ──
    for (const sink of this.sinks) {
      sink.write(full);
    }

    // ── Persist to SQLite when a database instance is available ──
    if (this.db) {
      this.insertEvent(full);
    }
  }

  /**
   * Log a custom event with a specific event type (for role management,
   * config changes, injection detection, etc.).
   *
   * @param eventType  The specific event type.
   * @param sessionId  Session identifier.
   * @param userId     User identifier.
   * @param sql        Associated SQL (or description).
   * @param result     Outcome.
   * @param errorMessage  Optional error message.
   */
  logCustom(
    eventType: AuditEventType,
    sessionId: string,
    userId: string,
    sql: string,
    result: 'success' | 'failure',
    errorMessage?: string,
  ): void {
    this.log({ eventType, sessionId, userId, sql, result, errorMessage });
  }

  /**
   * Convenience method for logging SQL queries.
   *
   * Automatically classifies the SQL as `'ddl'`, `'dml'`, or `'query'`
   * and applies SQL sanitisation (password masking).
   *
   * @param sessionId  Session identifier.
   * @param userId     User identifier.
   * @param sql        Raw SQL string (will be sanitised).
   * @param result     Execution outcome (`'success'` | `'failure'`).
   * @param opts       Optional metadata (row count, duration, error message).
   */
  logQuery(
    sessionId: string,
    userId: string,
    sql: string,
    result: 'success' | 'failure',
    opts?: { rowCount?: number; durationMs?: number; errorMessage?: string },
  ): void {
    const sanitised = sanitizeSql(sql);
    const eventType = classifySql(sanitised);

    this.log({
      sessionId,
      userId,
      eventType,
      sql: sanitised,
      result,
      rowCount: opts?.rowCount,
      durationMs: opts?.durationMs,
      errorMessage: opts?.errorMessage,
    });
  }

  /**
   * Log a login (connection / login-failure) event.
   *
   * @param sessionId  Session identifier.
   * @param userId     User identifier.
   * @param success    Whether authentication succeeded.
   */
  logLogin(sessionId: string, userId: string, success: boolean): void {
    const eventType: AuditEventType = success ? 'connection' : 'login_failure';

    this.log({
      sessionId,
      userId,
      eventType,
      sql: '',
      result: success ? 'success' : 'failure',
    });
  }

  /**
   * Log a disconnection event.
   *
   * @param sessionId  Session identifier.
   * @param userId     User identifier.
   */
  logDisconnect(sessionId: string, userId: string): void {
    this.log({
      sessionId,
      userId,
      eventType: 'disconnection',
      sql: '',
      result: 'success',
    });
  }

  /**
   * Set the audit level filter.
   *
   * Subsequent calls to `log`, `logQuery`, `logLogin`, and
   * `logDisconnect` will only emit events that match the new level.
   *
   * @param level  One of `'all'`, `'ddl'`, `'write'`, `'read'`,
   *               `'login'`, or `'none'`.
   */
  setAuditLevel(level: AuditLevel): void {
    this.logger.info({ from: this.auditLevel, to: level }, 'Audit level changed');
    this.auditLevel = level;
  }

  /**
   * Return the current audit level.
   */
  getAuditLevel(): AuditLevel {
    return this.auditLevel;
  }

  // ── SQLite persistence ────────────────────────────────────────

  /**
   * Create the `__audit_log` table if it does not already exist.
   * No-op when no database instance was provided.
   */
  initTable(): void {
    if (!this.db) return;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS __audit_log (
        event_id      TEXT PRIMARY KEY,
        timestamp     TEXT NOT NULL,
        session_id    TEXT NOT NULL,
        user_id       TEXT NOT NULL,
        event_type    TEXT NOT NULL,
        sql           TEXT,
        result        TEXT NOT NULL,
        row_count     INTEGER,
        error_message TEXT,
        duration_ms   REAL,
        prev_hash     TEXT,
        hash          TEXT NOT NULL
      )
    `);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS __audit_chain_checkpoints (
        sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
        hash            TEXT NOT NULL,
        timestamp       TEXT NOT NULL,
        rowid_ref       INTEGER NOT NULL
      )
    `);
  }

  /**
   * Query the `__audit_log` table.
   *
   * @param options.limit     Maximum number of rows to return (default 100).
   * @param options.eventType Optional event type filter.
   * @returns Array of rows as plain objects.
   */
  query(options: { limit?: number; eventType?: string } = {}): Record<string, unknown>[] {
    if (!this.db) return [];
    const limit = options.limit ?? 100;
    let sql = 'SELECT * FROM __audit_log';
    const params: unknown[] = [];
    if (options.eventType) {
      sql += ' WHERE event_type = ?';
      params.push(options.eventType);
    }
    sql += ' ORDER BY rowid DESC LIMIT ?';
    params.push(limit);
    return this.db.prepare(sql).all(...params) as Record<string, unknown>[];
  }

  /**
   * Verify the integrity of the hash chain from first to last entry.
   *
   * Iterates all rows in `__audit_log` and recomputes each entry's hash.
   * Returns `true` when every link is valid; returns `false` (or throws)
   * when a chain break is detected.
   *
   * @throws If the database reports an error during iteration.
   */
  getChainIntegrity(): boolean {
    if (!this.db) return true; // no persistence → chain is vacuously intact
    const rows = this.db.prepare(
      'SELECT event_id, timestamp, session_id, user_id, event_type, sql, result, row_count, error_message, duration_ms, prev_hash, hash FROM __audit_log ORDER BY rowid ASC',
    ).all() as Array<{
      event_id: string; timestamp: string; session_id: string; user_id: string;
      event_type: string; sql: string | null; result: string;
      row_count: number | null; error_message: string | null; duration_ms: number | null;
      prev_hash: string | null; hash: string;
    }>;

    let expectedPrev = '0'.repeat(64);

    for (const row of rows) {
      const prevHash = row.prev_hash ?? '0'.repeat(64);
      if (prevHash !== expectedPrev) {
        this.logger.warn({ eventId: row.event_id, expectedPrev, actualPrev: prevHash }, 'Chain integrity violation');
        return false;
      }
      const recomputed = computeChainHash(
        prevHash,
        row.event_id,
        row.timestamp,
        row.session_id,
        row.user_id,
        row.event_type,
        row.sql ?? '',
        row.result,
      );
      if (recomputed !== row.hash) {
        this.logger.warn({ eventId: row.event_id, expected: recomputed, actual: row.hash }, 'Hash mismatch');
        return false;
      }
      expectedPrev = row.hash;
    }

    return true;
  }

  /**
   * Verify the integrity of the entire audit hash chain.
   *
   * Reads every row from `__audit_log` (in insertion order) and
   * recomputes the SHA-256 hash of each entry to validate the chain.
   * Additionally, cross-checks against any checkpoints stored in
   * `__audit_chain_checkpoints` to detect truncation attacks.
   *
   * @returns An `IntegrityCheckResult` with `isValid`, `firstBrokenIndex`
   *          (the 1-based row number where the chain breaks), and a
   *          human-readable `details` string.
   */
  verifyChain(): IntegrityCheckResult {
    if (!this.db) {
      return { isValid: true, details: 'No database — chain is vacuously intact.' };
    }

    const rows = this.db.prepare(
      'SELECT rowid, event_id, timestamp, session_id, user_id, event_type, sql, result, row_count, error_message, duration_ms, prev_hash, hash FROM __audit_log ORDER BY rowid ASC',
    ).all() as Array<{
      rowid: number;
      event_id: string; timestamp: string; session_id: string; user_id: string;
      event_type: string; sql: string | null; result: string;
      row_count: number | null; error_message: string | null; duration_ms: number | null;
      prev_hash: string | null; hash: string;
    }>;

    if (rows.length === 0) {
      return { isValid: true, details: 'No audit log entries to verify.' };
    }

    let expectedPrev = '0'.repeat(64);

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      const prevHash = row.prev_hash ?? '0'.repeat(64);

      if (prevHash !== expectedPrev) {
        return {
          isValid: false,
          firstBrokenIndex: i + 1,
          details: `Row ${i + 1} (event_id=${row.event_id}): prev_hash mismatch. Expected ${expectedPrev}, got ${prevHash}. Chain link broken.`,
        };
      }

      const recomputed = computeChainHash(
        prevHash,
        row.event_id,
        row.timestamp,
        row.session_id,
        row.user_id,
        row.event_type,
        row.sql ?? '',
        row.result,
      );

      if (recomputed !== row.hash) {
        return {
          isValid: false,
          firstBrokenIndex: i + 1,
          details: `Row ${i + 1} (event_id=${row.event_id}): hash mismatch. Re-computed ${recomputed}, stored ${row.hash}. Entry content may have been tampered.`,
        };
      }

      expectedPrev = row.hash;
    }

    // ── Cross-validate against chain checkpoints ──
    const checkpoints = this.db.prepare(
      'SELECT sequence_number, hash, rowid_ref FROM __audit_chain_checkpoints ORDER BY sequence_number ASC',
    ).all() as Array<{ sequence_number: number; hash: string; rowid_ref: number }>;

    for (const cp of checkpoints) {
      // Find the row referenced by the checkpoint
      const rowAtCp = rows.find(r => r.rowid === cp.rowid_ref);
      if (!rowAtCp) {
        return {
          isValid: false,
          details: `Checkpoint ${cp.sequence_number} references rowid ${cp.rowid_ref} which does not exist in __audit_log. Possible truncation.`,
        };
      }
      if (rowAtCp.hash !== cp.hash) {
        // Find the index for reporting
        const cpIndex = rows.indexOf(rowAtCp);
        return {
          isValid: false,
          firstBrokenIndex: cpIndex + 1,
          details: `Checkpoint ${cp.sequence_number} hash mismatch at rowid ${cp.rowid_ref} (index ${cpIndex + 1}). Log has ${rowAtCp.hash}, checkpoint stores ${cp.hash}. Possible tampering after checkpoint.`,
        };
      }
    }

    return { isValid: true, details: `All ${rows.length} log entries verified. ${checkpoints.length} chain checkpoint(s) cross-validated.` };
  }

  // ── Private helpers ───────────────────────────────────────────

  /**
   * Insert a single audit event into the `__audit_log` table with a
   * chain-validated SHA-256 hash.
   *
   * Every `CHECKPOINT_INTERVAL` events (or whenever more than
   * `CHECKPOINT_INTERVAL_MS` has elapsed since the last checkpoint)
   * the current chain-head hash is persisted to the
   * `__audit_chain_checkpoints` table so that `verifyChain()` can
   * cross-validate the log even when only the checkpoint table is
   * trusted.
   */
  private insertEvent(event: AuditEvent): void {
    const db = this.db!;

    // ── 0. Reset counters when the table is empty (fresh start) ──
    const count = (db.prepare('SELECT COUNT(*) AS cnt FROM __audit_log').get() as { cnt: number }).cnt;
    if (count === 0) {
      this._eventCounter = 0;
      this._lastCheckpointTime = 0;
    }

    // ── 1. Retrieve the previous entry's hash ──
    const lastRow = db.prepare(
      'SELECT hash, rowid FROM __audit_log ORDER BY rowid DESC LIMIT 1',
    ).get() as { hash: string; rowid: number } | undefined;

    const prevHash: string = lastRow?.hash ?? '0'.repeat(64);
    const eventTimestamp = event.timestamp instanceof Date
      ? event.timestamp.toISOString()
      : String(event.timestamp);

    const hash = computeChainHash(
      prevHash,
      event.eventId,
      eventTimestamp,
      event.sessionId,
      event.userId,
      event.eventType,
      event.sql,
      event.result,
    );

    const insertResult = db.prepare(`
      INSERT INTO __audit_log
        (event_id, timestamp, session_id, user_id, event_type, sql, result,
         row_count, error_message, duration_ms, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      event.eventId,
      eventTimestamp,
      event.sessionId,
      event.userId,
      event.eventType,
      event.sql,
      event.result,
      event.rowCount ?? null,
      event.errorMessage ?? null,
      event.durationMs ?? null,
      prevHash,
      hash,
    );

    // ── 2. Chain checkpoint ──────────────────────────────────────
    this._eventCounter++;
    const now = Date.now();
    const timeSinceLastCheckpoint = now - this._lastCheckpointTime;

    if (this._eventCounter >= CHECKPOINT_INTERVAL || timeSinceLastCheckpoint >= CHECKPOINT_INTERVAL_MS) {
      db.prepare(`
        INSERT INTO __audit_chain_checkpoints (hash, timestamp, rowid_ref)
        VALUES (?, ?, ?)
      `).run(hash, eventTimestamp, insertResult.lastInsertRowid);

      this._eventCounter = 0;
      this._lastCheckpointTime = now;
    }
  }
}
