import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_DUPLICATE_OBJECT,
  SQLSTATE_UNDEFINED_OBJECT,
  SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
  SQLSTATE_DATA_EXCEPTION,
  SQLSTATE_INTERNAL_ERROR,
} from '../constants/sqlstate';
import type Database from 'better-sqlite3';

export type ExtendedQueryState = 'idle' | 'parsed' | 'bound' | 'executed' | 'closed';

export interface ExtendedQueryContext {
  statementName: string;
  portalName: string;
  sql: string;
  parameterTypes: string[];
  parameterValues: string[];
  state: ExtendedQueryState;
}

/**
 * TX08: Extended Query protocol state machine
 *
 * ## Background
 * PostgreSQL supports a multi-step prepared statement protocol:
 *   Parse → Bind → Describe → Execute → Close
 * This gives clients fine-grained control over parameter binding, result
 * metadata inspection, and plan caching.
 *
 * ## SQLite equivalence
 * better-sqlite3 provides `prepare(sql)` which parses and caches a statement,
 * then `run()`, `get()`, `all()` to execute with bound parameters. This is
 * simpler — parse and bind are combined, and there is no portal concept.
 *
 * ## Implementation plan (future)
 * 1. **Parse**: Parse SQL with better-sqlite3, infer parameter types from
 *    schema reflection, cache the PreparedStatement object keyed by name.
 * 2. **Bind**: Type-check incoming parameter values against inferred types,
 *    store bound values on the portal context.
 * 3. **Execute**: Run the cached PreparedStatement with bound values,
 *    return rows or row-count as appropriate.
 * 4. **Describe**: Return column metadata (names, types, nullable) for a
 *    parsed statement via PRAGMA table_info or ResultSet metadata.
 * 5. **Close**: Finalize/destroy the PreparedStatement and evict from cache.
 *
 * @stub Full implementation needed — currently provides type scaffolding only.
 */
export class ExtendedQueryProtocol {
  private readonly logger = PinoLogger.forComponent('ExtendedQueryProtocol');
  private statements: Map<string, ExtendedQueryContext> = new Map();

  constructor(private db?: Database.Database) {}

  parse(statementName: string, sql: string, paramTypes?: string[]): void {
    const existing = this.statements.get(statementName);
    if (existing && existing.state !== 'parsed' && existing.state !== 'closed') {
      throw new DatabaseError(
        '42P01: statement already exists in state ' + existing.state,
        SQLSTATE_DUPLICATE_OBJECT,
      );
    }
    this.statements.set(statementName, {
      statementName,
      portalName: '',
      sql,
      parameterTypes: paramTypes ?? [],
      parameterValues: [],
      state: 'parsed',
    });
    this.logger.debug({ statementName, sql }, 'parse: SQL statement parsed');
  }

  bind(
    statementName: string,
    portalName: string,
    paramValues: string[],
  ): void {
    const stmt = this.statements.get(statementName);
    if (!stmt) {
      throw new DatabaseError(
        '42P02: statement "' + statementName + '" does not exist',
        SQLSTATE_UNDEFINED_OBJECT,
      );
    }
    if (stmt.state !== 'parsed') {
      throw new DatabaseError(
        '42P03: cannot bind statement in state ' + stmt.state,
        SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
      );
    }
    if (stmt.parameterTypes.length > 0 && paramValues.length !== stmt.parameterTypes.length) {
      throw new DatabaseError(
        '42P04: expected ' + stmt.parameterTypes.length + ' parameters, got ' + paramValues.length,
        SQLSTATE_DATA_EXCEPTION,
      );
    }
    stmt.portalName = portalName;
    stmt.parameterValues = [...paramValues];
    stmt.state = 'bound';
    this.logger.debug({ statementName, portalName, paramCount: paramValues.length }, 'bind: parameters bound');
  }

  execute(portalName: string): { rows: Record<string, unknown>[]; rowCount: number; columns: Record<string, unknown>[] } {
    // Find a statement whose portal matches
    for (const stmt of this.statements.values()) {
      if (stmt.portalName === portalName) {
        if (stmt.state !== 'bound') {
          throw new DatabaseError(
            '42P05: cannot execute statement in state ' + stmt.state,
            SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
          );
        }
        stmt.state = 'executed';
        return this.doExecute(stmt);
      }
    }

    // If portal not found, try matching by statement name (portal may be empty)
    const stmt = this.statements.get(portalName);
    if (stmt) {
      if (stmt.state !== 'bound') {
        throw new DatabaseError(
          '42P05: cannot execute statement in state ' + stmt.state,
          SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
        );
      }
      stmt.state = 'executed';
      return this.doExecute(stmt);
    }

    throw new DatabaseError(
      '42P06: portal "' + portalName + '" does not exist',
      SQLSTATE_UNDEFINED_OBJECT,
    );
  }

  private doExecute(stmt: ExtendedQueryContext): { rows: Record<string, unknown>[]; rowCount: number; columns: Record<string, unknown>[] } {
    if (!this.db) {
      this.logger.warn('execute: no database instance available, returning stub result');
      return { rows: [], rowCount: 0, columns: [] };
    }
    try {
      const prepared = this.db.prepare(stmt.sql);
      const params = stmt.parameterValues.map(v => {
        // Try converting numeric strings to numbers
        const num = Number(v);
        return isNaN(num) ? v : num;
      });
      const isSelect = /^\s*SELECT/i.test(stmt.sql);
      if (isSelect) {
        const rows = prepared.all(...params) as Record<string, unknown>[];
        const columns = prepared.columns().map(c => ({ name: c.name, type: c.type }));
        return { rows, rowCount: rows.length, columns };
      } else {
        const info = prepared.run(...params);
        return { rows: [{ changes: info.changes, lastInsertRowid: info.lastInsertRowid }], rowCount: info.changes, columns: [] };
      }
    } catch (err: any) {
      this.logger.error({ err, sql: stmt.sql }, 'execute failed');
      throw new DatabaseError(err.message, SQLSTATE_INTERNAL_ERROR);
    }
  }

  describe(statementName: string): { paramTypes: string[]; sql: string } {
    const stmt = this.statements.get(statementName);
    if (!stmt) {
      throw new DatabaseError(
        '42P02: statement "' + statementName + '" does not exist',
        SQLSTATE_UNDEFINED_OBJECT,
      );
    }
    if (stmt.state === 'idle' || stmt.state === 'closed') {
      throw new DatabaseError(
        '42P07: cannot describe statement in state ' + stmt.state,
        SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
      );
    }
    return { paramTypes: [...stmt.parameterTypes], sql: stmt.sql };
  }

  close(statementName: string): void {
    const stmt = this.statements.get(statementName);
    if (!stmt) {
      throw new DatabaseError(
        '42P02: statement "' + statementName + '" does not exist',
        SQLSTATE_UNDEFINED_OBJECT,
      );
    }
    if (stmt.state === 'closed') {
      throw new DatabaseError(
        '42P08: statement "' + statementName + '" is already closed',
        SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
      );
    }
    stmt.state = 'closed';
    this.statements.delete(statementName);
    this.logger.debug({ statementName }, 'close: statement closed and evicted');
  }
}
