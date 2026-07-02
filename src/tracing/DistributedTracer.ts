/**
 * DistributedTracer — Lightweight distributed tracing with SQLite storage.
 *
 * Features:
 *   - Pino logger with traceId/spanId injection
 *   - Trace context propagation (headers for Raft messages)
 *   - Span hierarchy (parent-child nesting)
 *   - SQLite __trace_spans table for persistent trace storage
 *   - Auto-instrument wrappers for QueryRouter, TwoPhaseCommit, Raft
 *   - Trace export (JSON array of all spans for a trace)
 *
 * Usage:
 *   const tracer = DistributedTracer.getInstance().withDb(db);
 *   tracer.startTrace('query-execution');
 *   tracer.startSpan('parse');
 *   // ... do work ...
 *   tracer.endSpan();
 *   tracer.endTrace();
 *
 * For Raft message headers:
 *   const headers = tracer.getPropagationHeaders();
 *   // on receiver:
 *   tracer.continueTraceFromHeaders(headers);
 *
 * SQLite schema (auto-created):
 *   CREATE TABLE IF NOT EXISTS __trace_spans (
 *     id INTEGER PRIMARY KEY AUTOINCREMENT,
 *     trace_id TEXT NOT NULL,
 *     parent_span_id INTEGER,
 *     span_name TEXT NOT NULL,
 *     start_ms REAL NOT NULL,
 *     duration_ms REAL NOT NULL,
 *     metadata TEXT,
 *     created_at TEXT DEFAULT (datetime('now'))
 *   );
 */

import * as crypto from 'node:crypto';
import type Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('dist-tracer');

// ── Types ────────────────────────────────────────────────────────

export interface TraceSpan {
  id?: number;
  traceId: string;
  parentSpanId?: number;
  spanName: string;
  startMs: number;
  durationMs: number;
  metadata?: string; // JSON string
}

export interface TraceExport {
  traceId: string;
  operationName: string;
  spans: TraceSpan[];
  totalDurationMs: number;
  spanCount: number;
  createdAt: string;
}

export interface PropagationHeaders {
  'x-sqlvec-trace-id': string;
  'x-sqlvec-span-id'?: string;
}

// ── Implementation ───────────────────────────────────────────────

export class DistributedTracer {
  private static instance: DistributedTracer;

  /** Current trace ID (UUID v4). Undefined if no active trace. */
  private currentTraceId?: string;

  /** Current span stack (LIFO). Each entry is [name, startHrtime, dbSpanId] */
  private spanStack: { name: string; startTime: [number, number]; dbSpanId?: number }[] = [];

  /** Optional SQLite database for persisting spans. */
  private db?: Database.Database;

  private constructor() {}

  static getInstance(): DistributedTracer {
    if (!DistributedTracer.instance) {
      DistributedTracer.instance = new DistributedTracer();
    }
    return DistributedTracer.instance;
  }

  /**
   * Bind a SQLite database to the tracer for persistent span storage.
   * Auto-creates the __trace_spans table.
   */
  withDb(database: Database.Database): this {
    this.db = database;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS __trace_spans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id TEXT NOT NULL,
        parent_span_id INTEGER,
        span_name TEXT NOT NULL,
        start_ms REAL NOT NULL,
        duration_ms REAL NOT NULL,
        metadata TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )
    `);
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_trace_spans_trace_id
      ON __trace_spans(trace_id)
    `);
    logger.info('DistributedTracer bound to SQLite database');
    return this;
  }

  /** Get the bound SQLite database, if any. */
  getDb(): Database.Database | undefined {
    return this.db;
  }

  // ── Trace Lifecycle ───────────────────────────────────────────

  /**
   * Start a new trace.
   *
   * @param operationName Human-readable name for the root operation
   * @param explicitTraceId Optional trace ID (for propagation from upstream)
   * @returns The trace ID
   */
  startTrace(operationName: string, explicitTraceId?: string): string {
    this.currentTraceId = explicitTraceId || crypto.randomUUID();
    this.spanStack = [];

    const now = Date.now();
    this.spanStack.push({
      name: operationName,
      startTime: process.hrtime(),
    });

    logger.debug({ traceId: this.currentTraceId, operation: operationName }, 'Trace started');
    return this.currentTraceId;
  }

  /**
   * End the current trace, persist spans to SQLite, and log timing.
   */
  endTrace(): void {
    if (!this.currentTraceId || this.spanStack.length === 0) {
      logger.warn('endTrace called without active trace');
      return;
    }

    const rootSpan = this.spanStack[0];
    const elapsed = process.hrtime(rootSpan.startTime);
    const durationMs = elapsed[0] * 1_000 + elapsed[1] / 1_000_000;

    // End the root span's duration
    this.persistSpanToDb(rootSpan.name, durationMs, undefined);

    logger.debug({
      traceId: this.currentTraceId,
      operation: rootSpan.name,
      durationMs: Math.round(durationMs * 100) / 100,
      spanCount: this.spanStack.length,
    }, 'Trace ended');

    this.currentTraceId = undefined;
    this.spanStack = [];
  }

  /**
   * Start a new child span within the current trace.
   *
   * @param name Span name
   * @param metadata Optional JSON-serializable metadata
   */
  startSpan(name: string, metadata?: Record<string, unknown>): void {
    if (!this.currentTraceId) {
      logger.debug('startSpan called without active trace, starting implicit trace');
      this.startTrace(name);
      return;
    }

    this.spanStack.push({
      name,
      startTime: process.hrtime(),
    });

    logger.debug({ traceId: this.currentTraceId, span: name }, 'Span started');
  }

  /**
   * End the current leaf span and persist to SQLite.
   */
  endSpan(metadata?: Record<string, unknown>): void {
    if (this.spanStack.length <= 1) {
      logger.warn('endSpan called but only root span remains — use endTrace instead');
      return;
    }

    const span = this.spanStack.pop();
    if (!span) return;

    const elapsed = process.hrtime(span.startTime);
    const durationMs = elapsed[0] * 1_000 + elapsed[1] / 1_000_000;

    this.persistSpanToDb(span.name, durationMs, metadata);

    logger.debug({
      traceId: this.currentTraceId,
      span: span.name,
      durationMs: Math.round(durationMs * 100) / 100,
    }, 'Span ended');
  }

  // ── SQLite Persistence ───────────────────────────────────────

  private persistSpanToDb(
    spanName: string,
    durationMs: number,
    metadata?: Record<string, unknown>,
  ): void {
    if (!this.db || !this.currentTraceId) return;

    const parentId = this.spanStack.length > 1
      ? this.spanStack[this.spanStack.length - 1]?.dbSpanId
      : undefined;

    const stmt = this.db.prepare(`
      INSERT INTO __trace_spans (trace_id, parent_span_id, span_name, start_ms, duration_ms, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      this.currentTraceId,
      parentId ?? null,
      spanName,
      Date.now() - durationMs,
      durationMs,
      metadata ? JSON.stringify(metadata) : null,
    );

    // Store the db-assigned id on the current top-of-stack if this is the root
    if (this.spanStack.length === 1) {
      this.spanStack[0].dbSpanId = Number(result.lastInsertRowid);
    }
  }

  // ── Context Propagation ──────────────────────────────────────

  /**
   * Get propagation headers for Raft messages.
   */
  getPropagationHeaders(): PropagationHeaders {
    if (!this.currentTraceId) {
      return {} as PropagationHeaders;
    }
    return {
      'x-sqlvec-trace-id': this.currentTraceId,
    };
  }

  /**
   * Continue a trace from headers received in a Raft / RPC message.
   */
  continueTraceFromHeaders(headers: Record<string, string>): void {
    const traceId = headers['x-sqlvec-trace-id'];
    if (traceId) {
      this.startTrace('continued-trace', traceId);
      logger.debug({ traceId }, 'Trace continued from headers');
    }
  }

  /**
   * Get the current trace ID.
   */
  getTraceId(): string | undefined {
    return this.currentTraceId;
  }

  // ── Export ───────────────────────────────────────────────────

  /**
   * Export all spans for a given trace ID as a structured object.
   */
  exportTrace(traceId: string): TraceExport | null {
    if (!this.db) {
      logger.warn('Cannot export trace: no SQLite database bound');
      return null;
    }

    const rows = this.db.prepare(`
      SELECT id, trace_id, parent_span_id, span_name, start_ms, duration_ms, metadata, created_at
      FROM __trace_spans
      WHERE trace_id = ?
      ORDER BY id ASC
    `).all(traceId) as Array<{
      id: number;
      trace_id: string;
      parent_span_id: number | null;
      span_name: string;
      start_ms: number;
      duration_ms: number;
      metadata: string | null;
      created_at: string;
    }>;

    if (rows.length === 0) return null;

    const spans: TraceSpan[] = rows.map(r => ({
      id: r.id,
      traceId: r.trace_id,
      parentSpanId: r.parent_span_id ?? undefined,
      spanName: r.span_name,
      startMs: r.start_ms,
      durationMs: r.duration_ms,
      metadata: r.metadata ?? undefined,
    }));

    const totalDurationMs = Math.max(...spans.map(s => s.startMs + s.durationMs)) -
      Math.min(...spans.map(s => s.startMs));

    return {
      traceId,
      operationName: rows[0].span_name,
      spans,
      totalDurationMs,
      spanCount: spans.length,
      createdAt: rows[rows.length - 1].created_at,
    };
  }

  /**
   * List all trace IDs in the database.
   */
  listTraceIds(): string[] {
    if (!this.db) return [];
    const rows = this.db.prepare(`
      SELECT trace_id FROM __trace_spans
      GROUP BY trace_id ORDER BY MIN(start_ms) DESC
    `).all() as Array<{ trace_id: string }>;
    return rows.map(r => r.trace_id);
  }

  /**
   * Query spans with optional filtering.
   */
  querySpans(opts?: {
    traceId?: string;
    spanName?: string;
    minDurationMs?: number;
    maxDurationMs?: number;
    limit?: number;
  }): TraceSpan[] {
    if (!this.db) return [];

    let sql = `SELECT id, trace_id, parent_span_id, span_name, start_ms, duration_ms, metadata, created_at FROM __trace_spans WHERE 1=1`;
    const params: unknown[] = [];

    if (opts?.traceId) {
      sql += ` AND trace_id = ?`;
      params.push(opts.traceId);
    }
    if (opts?.spanName) {
      sql += ` AND span_name = ?`;
      params.push(opts.spanName);
    }
    if (opts?.minDurationMs !== undefined) {
      sql += ` AND duration_ms >= ?`;
      params.push(opts.minDurationMs);
    }
    if (opts?.maxDurationMs !== undefined) {
      sql += ` AND duration_ms <= ?`;
      params.push(opts.maxDurationMs);
    }
    sql += ` ORDER BY id ASC`;
    if (opts?.limit !== undefined) {
      sql += ` LIMIT ?`;
      params.push(opts.limit);
    }

    const rows = this.db.prepare(sql).all(...params) as Array<{
      id: number;
      trace_id: string;
      parent_span_id: number | null;
      span_name: string;
      start_ms: number;
      duration_ms: number;
      metadata: string | null;
      created_at: string;
    }>;

    return rows.map(r => ({
      id: r.id,
      traceId: r.trace_id,
      parentSpanId: r.parent_span_id ?? undefined,
      spanName: r.span_name,
      startMs: r.start_ms,
      durationMs: r.duration_ms,
      metadata: r.metadata ?? undefined,
    }));
  }

  /**
   * Clear all trace data from the database.
   */
  clearTraces(): void {
    if (!this.db) return;
    this.db.exec('DELETE FROM __trace_spans');
    logger.info('All trace spans cleared');
  }

  // ── Auto-instrument Wrappers ─────────────────────────────────

  /**
   * Wrap a QueryRouter method with tracing.
   * Returns a wrapper function that creates a trace around the operation.
   */
  wrapQueryRouter<T>(operationName: string, fn: () => Promise<T>): Promise<T> {
    this.startTrace(`query-router:${operationName}`);
    try {
      const result = fn();
      if (result instanceof Promise) {
        return result.then(r => {
          this.endTrace();
          return r;
        }).catch(err => {
          this.endSpan({ error: (err as Error).message });
          this.endTrace();
          throw err;
        });
      }
      this.endTrace();
      return Promise.resolve(result);
    } catch (err) {
      this.endSpan({ error: (err as Error).message });
      this.endTrace();
      throw err;
    }
  }

  /**
   * Wrap a TwoPhaseCommit operation with tracing.
   */
  wrapTwoPhaseCommit<T>(operationName: string, fn: () => Promise<T>): Promise<T> {
    this.startTrace(`2pc:${operationName}`);
    this.startSpan('prepare');
    try {
      const result = fn();
      if (result instanceof Promise) {
        return result.then(r => {
          this.endSpan({ phase: 'commit' });
          this.endTrace();
          return r;
        }).catch(err => {
          this.endSpan({ phase: 'abort', error: (err as Error).message });
          this.endTrace();
          throw err;
        });
      }
      this.endSpan({ phase: 'commit' });
      this.endTrace();
      return Promise.resolve(result);
    } catch (err) {
      this.endSpan({ phase: 'abort', error: (err as Error).message });
      this.endTrace();
      throw err;
    }
  }

  /**
   * Wrap a Raft operation with tracing.
   */
  wrapRaft<T>(operationName: string, fn: () => Promise<T>): Promise<T> {
    this.startTrace(`raft:${operationName}`);
    try {
      const result = fn();
      if (result instanceof Promise) {
        return result.then(r => {
          this.endTrace();
          return r;
        }).catch(err => {
          this.endSpan({ error: (err as Error).message });
          this.endTrace();
          throw err;
        });
      }
      this.endTrace();
      return Promise.resolve(result);
    } catch (err) {
      this.endSpan({ error: (err as Error).message });
      this.endTrace();
      throw err;
    }
  }
}
