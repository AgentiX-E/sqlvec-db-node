import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_DUPLICATE_OBJECT,
  SQLSTATE_UNDEFINED_OBJECT,
} from '../constants/sqlstate';

/**
 * TX17: Parallel query isolation
 *
 * ## Background
 * PostgreSQL can parallelize a single query (e.g., a sequential scan or an
 * aggregation) across multiple worker processes while maintaining snapshot
 * isolation — all workers see the same MVCC snapshot, so results are
 * consistent as if the query ran single-threaded.
 *
 * ## SQLite limitation
 * SQLite is single-threaded per connection. A single `SELECT` statement
 * cannot be parallelized across threads. This is a fundamental architectural
 * difference: SQLite trades parallel query execution for simplicity and
 * embeddability.
 *
 * ## Potential approaches (future)
 * For workloads that need parallelism, one could:
 * 1. **Multi-connection fan-out**: Split a query into chunks (e.g., by
 *    date range or shard key), execute on separate connections in parallel,
 *    then merge results via a coordinator.
 * 2. **Shared snapshot**: Use BEGIN DEFERRED on all connections before
 *    the first read to get a consistent point-in-time across connections.
 * 3. **Barrier synchronization**: Wait for all parallel workers to finish
 *    before returning merged results.
 *
 * ## Current stance
 * SQLite's single-threaded execution means parallel query isolation is
 * inherently not applicable for single-connection usage. Multi-connection
 * parallelism is deferred to the CrossShardReadConsistency module.
 *
 * @stub No-op — SQLite serial execution makes this trivially consistent.
 */

export type IsolationLevel = 'read_uncommitted' | 'read_committed' | 'repeatable_read' | 'serializable';

interface ActiveQuery {
  id: string;
  level: IsolationLevel;
}

export class ParallelQueryIsolation {
  private readonly logger = PinoLogger.forComponent('ParallelQueryIsolation');
  private activeQueries: Map<string, ActiveQuery> = new Map();

  constructor() {}

  executeParallel(sql: string, params?: any[]): any[] {
    /* STUB — see TX17 */
    return [];
  }

  /**
   * Check whether the given SQL can proceed at the specified isolation level.
   * Returns an advisory lock key and whether execution is allowed.
   */
  enforceLevel(sql: string, level: IsolationLevel): { advisoryLock: string; canProceed: boolean } {
    // Check for conflicts with existing queries at stricter levels
    for (const q of this.activeQueries.values()) {
      if (q.level === 'serializable' && level !== 'serializable') {
        return { advisoryLock: '', canProceed: false };
      }
      if (level === 'read_uncommitted' && q.level === 'repeatable_read') {
        return { advisoryLock: '', canProceed: false };
      }
    }

    const advisoryLock = 'lock-' + Buffer.from(sql).toString('base64').slice(0, 32);
    return { advisoryLock, canProceed: true };
  }

  /**
   * Register a query for isolation tracking.
   */
  registerQuery(queryId: string, level: IsolationLevel): void {
    if (this.activeQueries.has(queryId)) {
      throw new DatabaseError(
        '42P17: query "' + queryId + '" is already registered',
        SQLSTATE_DUPLICATE_OBJECT,
      );
    }
    this.activeQueries.set(queryId, { id: queryId, level });
    this.logger.debug({ queryId, level }, 'registerQuery: query registered');
  }

  /**
   * Unregister a completed or cancelled query.
   */
  unregisterQuery(queryId: string): void {
    if (!this.activeQueries.has(queryId)) {
      throw new DatabaseError(
        '42P18: query "' + queryId + '" is not registered',
        SQLSTATE_UNDEFINED_OBJECT,
      );
    }
    this.activeQueries.delete(queryId);
    this.logger.debug({ queryId }, 'unregisterQuery: query unregistered');
  }

  /**
   * Get all active queries, optionally filtered by isolation level.
   */
  getActiveQueries(level?: IsolationLevel): { id: string; level: IsolationLevel }[] {
    const queries = Array.from(this.activeQueries.values());
    if (level) {
      return queries.filter(q => q.level === level);
    }
    return queries;
  }
}
