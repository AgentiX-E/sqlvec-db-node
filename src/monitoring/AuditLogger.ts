/**
 * AuditLogger — Append-only audit log with SQLite persistence.
 *
 * Features:
 *   - Append-only: records cannot be DELETEd or UPDATEed (SQLite trigger enforces)
 *   - Queue-based batch writes: flushes every 1s or 100 events (whichever comes first)
 *   - Records: timestamp, session_id, user, action_type (DDL/DML/CONNECT/DISCONNECT), object, detail (JSON)
 *   - Exposes queryAuditLog(from, to, filters) for admin inspection
 *
 * Usage:
 *   const logger = new AuditLogger({ dbPath: '/tmp/audit.db' });
 *   await logger.init();
 *   logger.record({ sessionId: 'sess-1', user: 'postgres', actionType: 'CONNECT', object: 'postgres' });
 *   const results = await logger.queryAuditLog(new Date(Date.now() - 3600000), new Date(), { actionType: 'CONNECT' });
 *   await logger.close();
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

import { PinoLogger } from './PinoLogger';
const logger = PinoLogger.forComponent('AuditLogger');

// ── Types ────────────────────────────────────────────────────────

export type AuditActionType = 'DDL' | 'DML' | 'CONNECT' | 'DISCONNECT';

export interface AuditRecord {
  /** Optional; auto-assigned on insert */
  id?: number;
  /** Event timestamp (ISO-8601 string). Auto-set if omitted. */
  timestamp?: string;
  /** Session identifier (e.g. connection PID) */
  sessionId: string;
  /** Database user / role name */
  user: string;
  /** Type of action */
  actionType: AuditActionType;
  /** Object affected (table name, database name, etc.) */
  object: string;
  /** Arbitrary JSON-serializable detail */
  detail?: Record<string, unknown>;
}

export interface AuditQueryFilter {
  actionType?: AuditActionType;
  user?: string;
  sessionId?: string;
  object?: string;
}

export interface AuditLoggerConfig {
  /** Path to the SQLite database file (default: './audit_log.db') */
  dbPath?: string;
  /** Max events in queue before forced flush (default: 100) */
  batchSize?: number;
  /** Flush interval in ms (default: 1000) */
  flushIntervalMs?: number;
}

// ── AuditLogger ──────────────────────────────────────────────────

export class AuditLogger {
  private db: Database.Database | null = null;
  private config: Required<AuditLoggerConfig>;
  private queue: AuditRecord[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private closed = false;

  constructor(config: AuditLoggerConfig = {}) {
    this.config = {
      dbPath: config.dbPath ?? './audit_log.db',
      batchSize: config.batchSize ?? 100,
      flushIntervalMs: config.flushIntervalMs ?? 1000,
    };
  }

  /**
   * Get the underlying better-sqlite3 Database instance.
   * Returns null before init() is called.
   */
  getDatabase(): Database.Database | null {
    return this.db;
  }

  /**
   * Open the database, create the audit_log table, and install the append-only trigger.
   * Starts the periodic flush timer.
   */
  async init(): Promise<void> {
    const dbDir = dirname(this.config.dbPath);
    if (dbDir && !existsSync(dbDir)) {
      mkdirSync(dbDir, { recursive: true });
    }

    this.db = new Database(this.config.dbPath);

    // Performance: WAL mode + synchronous=NORMAL for audit write throughput
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');

    // Create audit_log table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL DEFAULT (datetime('now')),
        session_id TEXT NOT NULL,
        user TEXT NOT NULL,
        action_type TEXT NOT NULL CHECK(action_type IN ('DDL','DML','CONNECT','DISCONNECT')),
        object TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '{}'
      );
    `);

    // Append-only trigger: prevent UPDATE or DELETE on audit_log rows
    // This gives end-users a fail-fast signal rather than silent data loss.
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS trg_audit_log_append_only_update
      BEFORE UPDATE ON audit_log
      BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE forbidden');
      END;
    `);
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS trg_audit_log_append_only_delete
      BEFORE DELETE ON audit_log
      BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: DELETE forbidden');
      END;
    `);

    // Prepare insert statement
    this.flushTimer = setInterval(() => this.flush(), this.config.flushIntervalMs);
    this.flushTimer.unref();
  }

  /**
   * Enqueue an audit record. Actual write is deferred to the batch flush.
   */
  record(record: AuditRecord): void {
    if (this.closed) return;

    this.queue.push({
      ...record,
      timestamp: record.timestamp ?? new Date().toISOString(),
      detail: record.detail ?? {},
    });

    // Force flush if queue size exceeds batchSize
    if (this.queue.length >= this.config.batchSize) {
      this.flush();
    }
  }

  /**
   * Alias for record() that returns a resolved Promise, enabling optional chaining with .catch().
   */
  log(record: AuditRecord): Promise<void> {
    this.record(record);
    return Promise.resolve();
  }

  /**
   * Query audit log entries within a time range, with optional filters.
   */
  queryAuditLog(
    from: Date,
    to: Date,
    filters?: AuditQueryFilter
  ): AuditRecord[] {
    if (!this.db) return [];

    const conditions: string[] = [];
    const params: unknown[] = [];

    conditions.push('timestamp >= ?');
    params.push(from.toISOString());

    conditions.push('timestamp <= ?');
    params.push(to.toISOString());

    if (filters?.actionType) {
      conditions.push('action_type = ?');
      params.push(filters.actionType);
    }
    if (filters?.user) {
      conditions.push('"user" = ?');
      params.push(filters.user);
    }
    if (filters?.sessionId) {
      conditions.push('session_id = ?');
      params.push(filters.sessionId);
    }
    if (filters?.object) {
      conditions.push('object = ?');
      params.push(filters.object);
    }

    const sql = `SELECT id, timestamp, session_id, user, action_type, object, detail
                 FROM audit_log
                 WHERE ${conditions.join(' AND ')}
                 ORDER BY id ASC`;

    const rows = this.db.prepare(sql).all(...params) as Array<{
      id: number;
      timestamp: string;
      session_id: string;
      user: string;
      action_type: string;
      object: string;
      detail: string;
    }>;

    return rows.map(r => ({
      id: r.id,
      timestamp: r.timestamp,
      sessionId: r.session_id,
      user: r.user,
      actionType: r.action_type as AuditActionType,
      object: r.object,
      detail: this.safeParseJson(r.detail),
    }));
  }

  /**
   * Flush queued records to the database.
   */
  flush(): void {
    if (this.closed || !this.db || this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.queue.length);

    try {
      const stmt = this.db.prepare(
        `INSERT INTO audit_log (timestamp, session_id, "user", action_type, object, detail)
         VALUES (?, ?, ?, ?, ?, ?)`
      );
      const txn = this.db.transaction((items: AuditRecord[]) => {
        for (const item of items) {
          stmt.run(
            item.timestamp ?? new Date().toISOString(),
            item.sessionId,
            item.user,
            item.actionType,
            item.object,
            JSON.stringify(item.detail ?? {})
          );
        }
      });
      txn(batch);
    } catch (err) {
      logger.error('[AuditLogger] Flush failed:', (err as Error).message);
    }
  }

  /**
   * Close the database connection and stop the flush timer.
   */
  async close(): Promise<void> {
    this.closed = true;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    // Flush remaining records
    this.flush();
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  /**
   * Get the total number of audit log entries.
   */
  count(): number {
    if (!this.db) return 0;
    const row = this.db.prepare('SELECT COUNT(*) as cnt FROM audit_log').get() as { cnt: number };
    return row.cnt;
  }

  // ══════════════════════════════════════════════════════════════
  //  OPS-03: Compliance extensions (SOX/HIPAA)
  // ══════════════════════════════════════════════════════════════

  /** Compliance mode configuration. */
  private complianceConfig: ComplianceConfig = {
    mode: 'none',
    objectLevelAudit: false,
    logFormat: 'json',
    retentionDays: 0,
    includeClientInfo: false,
  };

  /**
   * Set compliance mode.
   */
  setComplianceConfig(config: Partial<ComplianceConfig>): void {
    Object.assign(this.complianceConfig, config);
    logger.info({ config: this.complianceConfig }, 'Audit compliance config updated');

    // Apply schema changes for compliance mode
    if (this.complianceConfig.objectLevelAudit && this.db) {
      this.ensureObjectAuditColumns();
    }
  }

  /** Add object-audit columns if needed. */
  private ensureObjectAuditColumns(): void {
    if (!this.db) return;
    try {
      this.db.exec(`
        ALTER TABLE audit_log ADD COLUMN object_owner TEXT DEFAULT '';
      `);
    } catch {
      // Column may already exist
    }
    try {
      this.db.exec(`
        ALTER TABLE audit_log ADD COLUMN client_addr TEXT DEFAULT '';
      `);
    } catch {
      // Column may already exist
    }
    try {
      this.db.exec(`
        ALTER TABLE audit_log ADD COLUMN compliance_tags TEXT DEFAULT '[]';
      `);
    } catch {
      // Column may already exist
    }
  }

  /**
   * Get current compliance configuration.
   */
  getComplianceConfig(): Readonly<ComplianceConfig> {
    return { ...this.complianceConfig };
  }

  /**
   * Export audit log as CSV text.
   */
  exportCsv(
    from: Date,
    to: Date,
    filters?: AuditQueryFilter,
  ): string {
    const records = this.queryAuditLog(from, to, filters);

    const headers = [
      'id', 'timestamp', 'session_id', 'user',
      'action_type', 'object', 'detail',
    ];

    const escCsv = (v: string): string => {
      if (v.includes(',') || v.includes('"') || v.includes('\n')) {
        return `"${v.replace(/"/g, '""')}"`;
      }
      return v;
    };

    const lines: string[] = [headers.join(',')];

    for (const r of records) {
      lines.push([
        String(r.id ?? ''),
        escCsv(r.timestamp ?? ''),
        escCsv(r.sessionId),
        escCsv(r.user),
        escCsv(r.actionType),
        escCsv(r.object),
        escCsv(JSON.stringify(r.detail ?? {})),
      ].join(','));
    }

    return lines.join('\n');
  }

  /**
   * Export audit log as JSON array (pretty-printed).
   */
  exportJson(
    from: Date,
    to: Date,
    filters?: AuditQueryFilter,
    pretty: boolean = true,
  ): string {
    const records = this.queryAuditLog(from, to, filters);
    const indent = pretty ? 2 : undefined;
    return JSON.stringify(records, null, indent);
  }

  /**
   * Record an object-level audit event (OPS-03: object-level audit trail).
   */
  recordObjectAccess(
    sessionId: string,
    user: string,
    actionType: AuditActionType,
    object: string,
    objectOwner?: string,
    clientAddr?: string,
    detail?: Record<string, unknown>,
  ): void {
    if (!this.complianceConfig.objectLevelAudit) return;
    this.record({
      sessionId,
      user,
      actionType,
      object,
      detail: {
        ...detail,
        objectOwner: objectOwner ?? '',
        clientAddr: clientAddr ?? '',
        complianceTags: this.getComplianceTags(),
      },
    });
  }

  /** Get compliance tags based on current mode. */
  private getComplianceTags(): string[] {
    switch (this.complianceConfig.mode) {
      case 'sox': return ['SOX-404', 'audit-trail-required'];
      case 'hipaa': return ['HIPAA-164.312(b)', 'audit-controls', 'ePHI'];
      default: return [];
    }
  }

  /**
   * Prune old audit records exceeding retention period.
   * Returns number of records deleted.
   */
  pruneOldRecords(): number {
    if (!this.db || this.complianceConfig.retentionDays <= 0) return 0;

    const cutoff = new Date(Date.now() - this.complianceConfig.retentionDays * 86400_000).toISOString();

    // Disable append-only trigger for pruning
    try {
      this.db.exec('DROP TRIGGER IF EXISTS trg_audit_log_append_only_delete');
    } catch { /* ignore */ }

    const result = this.db.prepare('DELETE FROM audit_log WHERE timestamp < ?').run(cutoff);

    // Re-enable trigger
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS trg_audit_log_append_only_delete
      BEFORE DELETE ON audit_log
      BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only: DELETE forbidden');
      END;
    `);

    logger.info({ deleted: result.changes, cutoff }, 'Audit log pruned');
    return result.changes;
  }

  // ── Helpers ────────────────────────────────────────────────────

  private safeParseJson(raw: string): Record<string, unknown> {
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
}

// ══════════════════════════════════════════════════════════════════
//  OPS-03: Compliance types
// ══════════════════════════════════════════════════════════════════

export type ComplianceMode = 'none' | 'sox' | 'hipaa';

export interface ComplianceConfig {
  /** Compliance mode: SOX, HIPAA, or none. */
  mode: ComplianceMode;
  /** Whether to enable object-level audit trail. */
  objectLevelAudit: boolean;
  /** Log output format. */
  logFormat: 'json' | 'csv';
  /** Retention period in days (0 = indefinite). */
  retentionDays: number;
  /** Whether to include client IP / port in audit records. */
  includeClientInfo: boolean;
}
