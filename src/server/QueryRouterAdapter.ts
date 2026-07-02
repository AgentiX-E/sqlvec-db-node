/**
 * @deprecated Phase 2 — 与 src/server/PgWireServer.ts 一起废弃
 *
 * 生产使用请直接通过 `protocol.PgWireServer` 的 `queryRouter` 参数传递 `QueryRouter` 实例。
 * 此适配器是为了让测试脚手架 `PgWireServer` 能接受 `SqlExecutor` 接口而存在的桥接层。
 *
 * 不再接收新功能。迁移完成后将与此文件一起移除。
 *
 * QueryRouterAdapter — adapts QueryRouter to PgWireServer's SqlExecutor interface.
 *
 * Enables PostgreSQL Wire Protocol clients to execute SQL through the full
 * QueryRouter pipeline (routing, federation, CDC integration, etc.), not just
 * the DuckDB analytics backend.
 *
 * ## Session Lifecycle
 *
 * Each PG wire connection gets a unique session ID. The adapter:
 * 1. onConnect(): Allocates session ID from connection ID
 * 2. onDisconnect(): ROLLBACKs any pending transaction
 * 3. execute(): Passes sessionId through to QueryRouter for transaction isolation
 *
 * This ensures two concurrent PG clients can each BEGIN/INSERT/COMMIT without
 * cross-contamination.
 */

import { QueryRouter } from '../query/QueryRouter';
import { SqlExecutor, SqlExecResult } from './PgWireServer';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('QueryRouterAdapter');

export class QueryRouterAdapter implements SqlExecutor {
  constructor(
    private readonly queryRouter: QueryRouter,
  ) {}

  /**
   * Allocate a session ID for a new PG wire connection.
   * The session ID is derived from the connection ID to ensure uniqueness.
   */
  onConnect(connectionId: string): string {
    return `pgw-${connectionId}`;
  }

  /**
   * Clean up session state when a PG wire connection ends.
   * ROLLBACKs any in-flight transaction to prevent orphaned locks.
   */
  async onDisconnect(sessionId: string): Promise<void> {
    try {
      await this.queryRouter.execute('ROLLBACK', [], sessionId);
    } catch {
      // Best-effort cleanup — connection is already closing
    }
  }

  async execute(sql: string, params?: any[], sessionId?: string): Promise<SqlExecResult> {
    try {
      const sid = sessionId ?? 'default';
      const result = await this.queryRouter.execute(sql, params, sid);
      return {
        rows: result.rows ?? [],
        rowCount: result.rowCount ?? result.rows?.length ?? 0,
        error: result.error,
      };
    } catch (err: any) {
      logger.error({ err: err.message, sql: sql.substring(0, 100) }, '[QueryRouterAdapter] Query failed');
      return {
        rows: [],
        rowCount: 0,
        error: err.message ?? String(err),
      };
    }
  }
}
