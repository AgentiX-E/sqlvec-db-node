/**
 * ActiveQueryRegistry — pg_stat_activity equivalent for SQLVec.
 *
 * Tracks currently executing queries per session, mirroring PostgreSQL's
 * pg_stat_activity view. Each connection registers a query on start and
 * unregisters on completion.
 */

export interface ActiveQuery {
  queryId: string;
  sql: string;
  userId: string;
  database: string;
  state: 'active' | 'idle' | 'idle in transaction';
  queryStart: number;      // epoch ms
  clientAddr: string;
  /** Real or synthetic PID for this backend. Used to correlate with WaitEventSampler data. */
  pid?: number;
}

export class ActiveQueryRegistry {
  private queries: Map<string, ActiveQuery> = new Map();

  /**
   * Register a new active query.
   */
  register(q: ActiveQuery): void {
    this.queries.set(q.queryId, q);
  }

  /**
   * Unregister a completed / cancelled query.
   */
  unregister(queryId: string): void {
    this.queries.delete(queryId);
  }

  /**
   * Return a snapshot of all active queries.
   */
  list(): ActiveQuery[] {
    return Array.from(this.queries.values());
  }

  /**
   * Return the number of currently active queries.
   */
  count(): number {
    return this.queries.size;
  }

  /**
   * Return only queries in 'active' state.
   */
  listActive(): ActiveQuery[] {
    return this.list().filter(q => q.state === 'active');
  }

  /**
   * Return only queries that have been running longer than `thresholdMs`.
   */
  listLongRunning(thresholdMs: number): ActiveQuery[] {
    const now = Date.now();
    return this.list().filter(q => (now - q.queryStart) > thresholdMs);
  }

  /**
   * Clear all registered queries (e.g. on connection reset).
   */
  clear(): void {
    this.queries.clear();
  }
}
