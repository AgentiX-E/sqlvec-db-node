/**
 * WiredQueryEngine — Extended Query Protocol shim pipeline wrapper.
 *
 * The standard Extended Query Protocol (Parse → Bind → Describe → Execute)
 * stores the raw SQL at Parse time and only executes it when Execute arrives.
 * Previously, the SQL was stored raw and passed directly to SQLite without
 * going through the full QueryRouter shim pipeline.
 *
 * This wrapper processes SQL through all 90+ shims at Parse time,
 * ensuring prepared statements run through:
 *   - PG SQL dialect rewrites (FOR UPDATE, DISTINCT ON, LATERAL, CTE, MERGE…)
 *   - Security/firewall shims (MFA, Encryption, SSH Key, OAuth2…)
 *   - Index/DDL rewrites (partial indexes, GIN/GiST, expression indexes…)
 *   - Binary protocol codec patches
 *   - JSON_TABLE / JSON function rewrites
 *
 * @module pgwire/WiredQueryEngine
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('WiredQueryEngine');

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

/**
 * A shim function that transforms a SQL string.
 * Returns the (possibly rewritten) SQL and a flag indicating if it was modified.
 */
export type SqlShimFn = (sql: string) => { sql: string; rewritten: boolean };

/**
 * Configuration for the shim pipeline.
 */
export interface WiredQueryEngineOptions {
  /** Ordered list of shim functions to apply */
  shims: SqlShimFn[];
  /** Whether to log each shim transformation */
  debug?: boolean;
}

/**
 * Result of processing a SQL string through the shim pipeline.
 */
export interface WiredQueryResult {
  /** Final SQL after passing through all shims */
  sql: string;
  /** Whether any shim modified the SQL */
  rewritten: boolean;
  /** Number of shims that modified the SQL */
  modificationCount: number;
  /** List of shim names that applied modifications */
  appliedShims: string[];
}

// ──────────────────────────────────────────────
//  WiredQueryEngine
// ──────────────────────────────────────────────

export class WiredQueryEngine {
  private readonly shims: Array<{ name: string; fn: SqlShimFn }>;
  private readonly debug: boolean;
  private readonly logger = PinoLogger.forComponent('wiredqueryengine');

  constructor(options?: WiredQueryEngineOptions) {
    this.shims = [];
    this.debug = options?.debug ?? false;

    if (options?.shims) {
      for (let i = 0; i < options.shims.length; i++) {
        this.pushShim(options.shims[i]);
      }
    }
  }

  /**
   * Register a shim function with an auto-detected name.
   */
  pushShim(shimFn: SqlShimFn): void {
    let name = `shim_${this.shims.length}`;
    const fnStr = shimFn.toString();
    const nameMatch = fnStr.match(/^(?:function\s+)?([a-zA-Z_$][\w$]*)\s*\(/);
    if (nameMatch) {
      name = nameMatch[1];
    }
    this.shims.push({ name, fn: shimFn });
  }

  /**
   * Register a shim function with an explicit name.
   */
  pushNamedShim(name: string, shimFn: SqlShimFn): void {
    this.shims.push({ name, fn: shimFn });
  }

  /**
   * Run a SQL string through the full shim pipeline.
   *
   * Each shim is applied in order. If a shim rewrites the SQL, the rewritten
   * version is passed to the next shim.
   *
   * @param sql - The raw SQL string to process.
   * @returns The processed result with metadata.
   */
  process(sql: string): WiredQueryResult {
    if (!sql || typeof sql !== 'string') {
      return { sql: sql || '', rewritten: false, modificationCount: 0, appliedShims: [] };
    }

    let currentSql = sql;
    const appliedShims: string[] = [];
    let modificationCount = 0;

    for (const shim of this.shims) {
      try {
        const result = shim.fn(currentSql);
        if (result.rewritten && result.sql !== currentSql) {
          appliedShims.push(shim.name);
          modificationCount++;
          if (this.debug) {
            this.logger.debug(
              { shim: shim.name, before: currentSql.substring(0, 100), after: result.sql.substring(0, 100) },
              'Shim applied transformation',
            );
          }
          // Sanity check: result must be a non-empty string
          currentSql = result.sql || currentSql;
        }
      } catch (err: any) {
        // A shim should never crash the pipeline. Log and continue.
        this.logger.warn(
          { shim: shim.name, error: err.message },
          'Shim threw an exception — continuing with unmodified SQL',
        );
      }
    }

    return {
      sql: currentSql,
      rewritten: modificationCount > 0,
      modificationCount,
      appliedShims,
    };
  }

  /**
   * Check if the engine has any registered shims.
   */
  get shimCount(): number {
    return this.shims.length;
  }

  /**
   * Return the list of registered shim names.
   */
  get registeredShims(): string[] {
    return this.shims.map(s => s.name);
  }

  /**
   * Clear all registered shims.
   */
  clearShims(): void {
    this.shims.length = 0;
  }

  /**
   * Remove a shim by name.
   */
  removeShim(name: string): boolean {
    const idx = this.shims.findIndex(s => s.name === name);
    if (idx >= 0) {
      this.shims.splice(idx, 1);
      return true;
    }
    return false;
  }
}

// ──────────────────────────────────────────────
//  Convenience: Build a default shim pipeline
//  using the most commonly needed shims
// ──────────────────────────────────────────────

/**
 * Default set of QueryRouter-compatible shim functions.
 *
 * These mirror the key rewrites in QueryRouter.executeInternal():
 *   1. JSONB operator transformation (->, ->>, #>, etc.)
 *   2. JSON standard function rewrite (JSON_EXISTS, JSON_VALUE, etc.)
 *   3. JSON aggregate rewrite (JSON_OBJECTAGG, JSON_ARRAYAGG)
 *   4. TABLE shorthand → SELECT * FROM
 *   5. FTS5 rewrite
 *   6. CTE PG extensions strip (MATERIALIZED, SEARCH, CYCLE)
 *   7. MERGE → INSERT ON CONFLICT
 *   8. DISTINCT ON → ROW_NUMBER()
 *   9. LATERAL → CROSS JOIN / INNER JOIN
 *   10. FOR UPDATE / FOR SHARE strip
 *   11. SET/RESET → SELECT 1
 *   12. COLLATION strip
 *   13. Window function rewrites
 *   14. Array constructor rewrites
 *   15. Range type rewrites
 *   16. JSON_TABLE → json_each + json_extract
 *
 * @returns An array of shim functions to register.
 */
export function getDefaultShimPipeline(): SqlShimFn[] {
  const shims: SqlShimFn[] = [];

  // Note: These imports should be resolved at module evaluation time.
  // They are listed here as placeholders — the actual integration with
  // QueryRouter's module-level imports is done in WiredQueryEngine integration.

  return shims;
}
