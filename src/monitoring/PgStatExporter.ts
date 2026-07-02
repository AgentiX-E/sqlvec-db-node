/**
 * PgStatExporter — handles SELECT * FROM pg_stat_activity queries.
 *
 * Translates the ActiveQueryRegistry into the schema expected by PostgreSQL's
 * pg_stat_activity system view. This allows tools (psql, pgAdmin, etc.) that
 * query pg_stat_activity to see SQLVec's active query state.
 */

import { ActiveQueryRegistry, type ActiveQuery } from './ActiveQueryRegistry';
import { WaitEventSampler } from './WaitEventSampler';

export interface PgStatActivityRow {
  datid: string;
  datname: string;
  pid: number;
  usesysid: string;
  usename: string;
  application_name: string;
  client_addr: string;
  client_port: number;
  backend_start: number;
  xact_start: number | null;
  query_start: number;
  state_change: number;
  wait_event_type: string | null;
  wait_event: string | null;
  state: string;
  backend_xid: string | null;
  backend_xmin: string | null;
  query_id: string;
  query: string;
  backend_type: string;
}

export class PgStatExporter {
  private registry: ActiveQueryRegistry;
  private sampler: WaitEventSampler | null;
  private static pidCounter = 0;

  constructor(registry: ActiveQueryRegistry, sampler?: WaitEventSampler) {
    this.registry = registry;
    this.sampler = sampler ?? null;
  }

  /**
   * Return rows matching the pg_stat_activity schema.
   * Called when a user executes `SELECT * FROM pg_stat_activity`.
   * Optionally filtered by database name.
   */
  getStatActivity(database?: string): PgStatActivityRow[] {
    const activeQueries = database
      ? this.registry.list().filter(q => q.database === database)
      : this.registry.list();
    return activeQueries.map(q => this.toRow(q));
  }

  /**
   * Count of active queries (excluding idle).
   */
  getActiveCount(): number {
    return this.registry.listActive().length;
  }

  /**
   * Count of idle-in-transaction queries (potential lock holders).
   */
  getIdleInTransactionCount(): number {
    return this.registry.list().filter(q => q.state === 'idle in transaction').length;
  }

  /**
   * Detect if a given SQL statement is a pg_stat_activity query.
   */
  static isStatActivityQuery(sql: string): boolean {
    const normalized = sql.replace(/\s+/g, ' ').trim().toLowerCase();
    // Match: SELECT * FROM pg_stat_activity
    // Also: SELECT ... FROM pg_catalog.pg_stat_activity
    return (
      normalized.includes('from pg_stat_activity') ||
      normalized.includes('from pg_catalog.pg_stat_activity')
    );
  }

  /**
   * Handle a pg_stat_activity query and return formatted results.
   * Returns null if the SQL is not a pg_stat_activity query.
   */
  handleQuery(sql: string, params?: any[]): PgStatActivityRow[] | null {
    if (!PgStatExporter.isStatActivityQuery(sql)) {
      return null;
    }

    // Support optional database filter: WHERE datname = ?
    const dbMatch = sql.match(/datname\s*=\s*'([^']+)'/i);
    const database = dbMatch ? dbMatch[1] : undefined;

    // Also support parameterized WHERE datname = $1
    if (!database && params && params.length > 0) {
      // If the SQL has a `datname = $1` pattern, use the first parameter as db name
      const hasDbParam = /datname\s*=\s*\$1/i.test(sql);
      if (hasDbParam && typeof params[0] === 'string') {
        return this.getStatActivity(params[0]);
      }
    }

    return this.getStatActivity(database);
  }

  private toRow(q: ActiveQuery): PgStatActivityRow {
    PgStatExporter.pidCounter++;
    const pid = q.pid ?? (10000 + (PgStatExporter.pidCounter % 90000));

    // Look up wait event from the sampler if configured
    let waitEventType: string | null = null;
    let waitEvent: string | null = null;
    if (this.sampler) {
      const waitInfo = this.sampler.getShim().getWaitEvent(pid);
      if (waitInfo) {
        waitEventType = waitInfo.wait_event_type;
        waitEvent = waitInfo.wait_event;
      }
    }

    return {
      datid: '0',
      datname: q.database,
      pid,
      usesysid: q.userId,
      usename: q.userId,
      application_name: 'sqlvec',
      client_addr: q.clientAddr,
      client_port: 5432,
      backend_start: q.queryStart - 5000, // approximate: 5s before query
      xact_start: q.state === 'idle in transaction' ? q.queryStart : null,
      query_start: q.queryStart,
      state_change: q.queryStart,
      wait_event_type: waitEventType,
      wait_event: waitEvent,
      state: q.state,
      backend_xid: null,
      backend_xmin: null,
      query_id: q.queryId,
      query: q.sql,
      backend_type: 'client backend',
    };
  }
}
