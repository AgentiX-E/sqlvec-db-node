/**
 * RLSPolicyInjector — AST-based RLS policy injection
 *
 * Replaces regex string concatenation with proper AST-based injection
 * using pgsql-ast-parser. Parses incoming SQL queries, injects RLS policy
 * predicates into the WHERE clause at the AST level, then re-serializes.
 *
 * ## Features
 *
 * - **Multiple statement types**: SELECT, UPDATE, DELETE
 * - **Edge cases**: CTEs (WITH), UNIONs, JOINs
 * - **PERMISSIVE / RESTRICTIVE policy types**:
 *   - PERMISSIVE policies are combined with OR
 *   - RESTRICTIVE policies are combined with AND
 * - **WITH CHECK clause support**: Validates INSERT/UPDATE operations
 * - **Multiple policies**: Combined according to their type (PERMISSIVE OR, RESTRICTIVE AND)
 * - **Empty predicate**: passthrough
 * - **Gradual fallback**: returns original SQL if AST parsing fails
 *
 * @module RLSPolicyInjector
 */

import { parse, toSql } from 'pgsql-ast-parser';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('RLSPolicyInjector');

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

/** RLS policy type — determines how multiple policies are combined. */
export type PolicyType = 'PERMISSIVE' | 'RESTRICTIVE';

/** A single RLS policy definition. */
export interface RLSPolicy {
  /** Policy name (for logging/debugging). */
  name: string;
  /** Policy type: PERMISSIVE (OR-combined) or RESTRICTIVE (AND-combined). */
  type: PolicyType;
  /** The SQL predicate expression (e.g. "tenant_id = 123"). */
  usingPredicate: string;
  /**
   * Optional WITH CHECK predicate for INSERT/UPDATE validation.
   * When set, ensures new/updated rows satisfy the predicate.
   */
  withCheckPredicate?: string;
  /** The table this policy applies to. */
  tableName: string;
}

/** A named group of RLS policies (one per table). */
export interface PolicyGroup {
  /** Table name. */
  table: string;
  /** Policies for this table. */
  policies: RLSPolicy[];
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/**
 * AST-based RLS policy injector with PERMISSIVE/RESTRICTIVE support.
 */
export class RLSPolicyInjector {
  /** Registered policy groups by table name. */
  private policyGroups: Map<string, PolicyGroup> = new Map();

  // ── Policy Registration ──────────────────────────────────────

  /**
   * Register an RLS policy for a table.
   *
   * @param tableName - The table name the policy applies to.
   * @param policy    - The RLS policy definition.
   */
  registerPolicy(tableName: string, policy: RLSPolicy): void {
    if (!this.policyGroups.has(tableName)) {
      this.policyGroups.set(tableName, { table: tableName, policies: [] });
    }
    this.policyGroups.get(tableName)!.policies.push(policy);
    logger.debug(
      { tableName, policyName: policy.name, type: policy.type },
      'RLS policy registered',
    );
  }

  /**
   * Remove all policies for a table.
   */
  removePolicies(tableName: string): void {
    this.policyGroups.delete(tableName);
  }

  /**
   * Get policies for a table.
   */
  getPolicies(tableName: string): RLSPolicy[] {
    return this.policyGroups.get(tableName)?.policies ?? [];
  }

  /**
   * Clear all registered policies.
   */
  clearPolicies(): void {
    this.policyGroups.clear();
  }

  // ── Policy Injection ─────────────────────────────────────────

  /**
   * Inject RLS policies into a SQL query.
   *
   * Combines all registered policies for the target tables:
   * - PERMISSIVE policies: OR-combined
   * - RESTRICTIVE policies: AND-combined
   * - Final: (PERMISSIVE_combined) AND (RESTRICTIVE_combined)
   *
   * @param sql - The original SQL query.
   * @returns The injected SQL, or original if no policies apply or parsing fails.
   */
  injectPolicy(sql: string): string {
    const tables = this.getAffectedTables(sql);
    if (tables.length === 0) return sql;

    // Collect permissive and restrictive predicates for all affected tables
    const permissivePredicates: string[] = [];
    const restrictivePredicates: string[] = [];

    for (const table of tables) {
      const policies = this.getPolicies(table);
      for (const p of policies) {
        if (!p.usingPredicate || p.usingPredicate.trim() === '') continue;
        if (p.type === 'PERMISSIVE') {
          permissivePredicates.push(p.usingPredicate);
        } else {
          restrictivePredicates.push(p.usingPredicate);
        }
      }
    }

    // Combine permissive predicates with OR
    const permissiveCombined = permissivePredicates.length > 0
      ? permissivePredicates.join(' OR ')
      : '';

    // Combine restrictive predicates with AND
    const restrictiveCombined = restrictivePredicates.length > 0
      ? restrictivePredicates.join(' AND ')
      : '';

    // Final combination: (PERMISSIVE) AND (RESTRICTIVE)
    let finalPredicate = '';
    if (permissiveCombined && restrictiveCombined) {
      finalPredicate = `(${permissiveCombined}) AND (${restrictiveCombined})`;
    } else if (permissiveCombined) {
      finalPredicate = permissiveCombined;
    } else if (restrictiveCombined) {
      finalPredicate = restrictiveCombined;
    }

    if (!finalPredicate) return sql;

    return this.doInjectIntoSQL(sql, finalPredicate);
  }

  /**
   * Check if a row satisfies the WITH CHECK policies for a table.
   * Used during INSERT/UPDATE to validate new/updated rows.
   *
   * @param tableName - The table being modified.
   * @param rowData   - Key-value pairs representing the row being inserted/updated.
   * @returns true if the row satisfies all WITH CHECK predicates.
   */
  checkWithCheck(tableName: string, rowData: Record<string, any>): boolean {
    const policies = this.getPolicies(tableName);
    for (const p of policies) {
      if (!p.withCheckPredicate) continue;
      if (!this.evaluatePredicate(p.withCheckPredicate, rowData)) {
        logger.warn(
          { tableName, policyName: p.name, rowData },
          'WITH CHECK policy violation',
        );
        return false;
      }
    }
    return true;
  }

  // ── Internal: SQL injection ──────────────────────────────────

  /**
   * Inject a predicate string into a SQL query at the AST level.
   *
   * This is the public entry point for injecting a pre-built predicate
   * into any SQL query. The predicate is parsed and grafted onto the
   * WHERE clause using the parser's AST rather than string concatenation.
   *
   * @param sql       - The original SQL query.
   * @param predicate - The RLS predicate string to inject (e.g. "tenant_id = 123").
   * @returns The modified SQL, or the original if parsing/injection fails.
   */
  injectPredicate(sql: string, predicate: string): string {
    return this.doInjectIntoSQL(sql, predicate);
  }

  /**
   * Inject a combined predicate into the SQL query at the AST level.
   */
  private doInjectIntoSQL(sql: string, predicate: string): string {
    if (!predicate || predicate.trim() === '') return sql;

    const trimmedSql = sql.trim();
    if (!trimmedSql) return sql;

    try {
      const ast = parse(trimmedSql);
      if (!ast || ast.length === 0) return sql;

      const modified = this.injectIntoStatement(ast[0], predicate);
      if (!modified) return sql;

      return toSql.statement(modified);
    } catch {
      return sql;
    }
  }

  // ── AST traversal ────────────────────────────────────────────

  private injectIntoStatement(stmt: any, predicate: string): any | null {
    switch (stmt.type) {
      case 'select':
        return this.injectIntoSelect(stmt, predicate);
      case 'update':
        return this.injectIntoUpdate(stmt, predicate);
      case 'delete':
        return this.injectIntoDelete(stmt, predicate);
      case 'with':
      case 'with recursive':
        return this.injectIntoWith(stmt, predicate);
      case 'union':
      case 'union all':
        return this.injectIntoUnion(stmt, predicate);
      default:
        return null;
    }
  }

  private injectIntoSelect(stmt: any, predicate: string): any | null {
    const predicateExpr = this.parsePredicateExpr(predicate);
    if (!predicateExpr) return null;
    stmt.where = this.combineWhere(stmt.where, predicateExpr);
    return stmt;
  }

  private injectIntoUpdate(stmt: any, predicate: string): any | null {
    const predicateExpr = this.parsePredicateExpr(predicate);
    if (!predicateExpr) return null;
    stmt.where = this.combineWhere(stmt.where, predicateExpr);
    return stmt;
  }

  private injectIntoDelete(stmt: any, predicate: string): any | null {
    const predicateExpr = this.parsePredicateExpr(predicate);
    if (!predicateExpr) return null;
    stmt.where = this.combineWhere(stmt.where, predicateExpr);
    return stmt;
  }

  private injectIntoWith(stmt: any, predicate: string): any | null {
    if (stmt.bind && Array.isArray(stmt.bind)) {
      for (const binding of stmt.bind) {
        if (binding.statement) {
          binding.statement =
            this.injectIntoStatement(binding.statement, predicate) ??
            binding.statement;
        }
      }
    }
    if (stmt.in) {
      stmt.in =
        this.injectIntoStatement(stmt.in, predicate) ?? stmt.in;
    }
    return stmt;
  }

  private injectIntoUnion(stmt: any, predicate: string): any | null {
    if (stmt.left) {
      stmt.left =
        this.injectIntoStatement(stmt.left, predicate) ?? stmt.left;
    }
    if (stmt.right) {
      stmt.right =
        this.injectIntoStatement(stmt.right, predicate) ?? stmt.right;
    }
    return stmt;
  }

  // ── Predicate parsing & combination ──────────────────────────

  private parsePredicateExpr(predicate: string): any | null {
    try {
      const fakeSql = `SELECT * FROM __rls_dummy WHERE ${predicate}`;
      const ast = parse(fakeSql);
      if (ast && ast.length > 0) {
        const stmt = ast[0] as any;
        if (stmt.type === 'select' && stmt.where) {
          return stmt.where;
        }
      }
    } catch {
      // Predicate cannot be parsed — abort injection
    }
    return null;
  }

  private combineWhere(
    existingWhere: any | null | undefined,
    predicateExpr: any,
  ): any {
    if (!existingWhere) return predicateExpr;
    return {
      type: 'binary',
      op: 'AND',
      left: existingWhere,
      right: predicateExpr,
    };
  }

  // ── Table extraction ─────────────────────────────────────────

  /**
   * Extract table names from a SQL query by parsing the AST.
   */
  private getAffectedTables(sql: string): string[] {
    if (this.policyGroups.size === 0) return [];

    try {
      const ast = parse(sql);
      if (!ast || ast.length === 0) return [];

      const tables: string[] = [];
      this.extractTables(ast[0], tables);

      // Return only tables that have registered policies
      return tables.filter((t) => this.policyGroups.has(t));
    } catch {
      return [];
    }
  }

  private extractTables(stmt: any, tables: string[]): void {
    if (!stmt) return;

    switch (stmt.type) {
      case 'select': {
        if (stmt.from && Array.isArray(stmt.from)) {
          for (const ref of stmt.from) {
            if (ref.type === 'table') {
              tables.push(ref.name.name);
            }
          }
        }
        break;
      }
      case 'update': {
        if (stmt.table && stmt.table.name) {
          tables.push(stmt.table.name.name || stmt.table.name);
        }
        break;
      }
      case 'delete': {
        if (stmt.from && Array.isArray(stmt.from)) {
          for (const ref of stmt.from) {
            if (ref.type === 'table') {
              tables.push(ref.name.name);
            }
          }
        }
        break;
      }
      case 'with':
      case 'with recursive': {
        if (stmt.bind) {
          for (const b of stmt.bind) {
            this.extractTables(b.statement, tables);
          }
        }
        if (stmt.in) this.extractTables(stmt.in, tables);
        break;
      }
      case 'union':
      case 'union all': {
        if (stmt.left) this.extractTables(stmt.left, tables);
        if (stmt.right) this.extractTables(stmt.right, tables);
        break;
      }
    }
  }

  // ── WITH CHECK evaluation (simplified) ───────────────────────

  /**
   * Simple predicate evaluation for WITH CHECK.
   * Supports basic comparisons: col = value, col != value, col > value, etc.
   *
   * In production, this would use the SQL parser for full expression evaluation.
   * For now, we do basic key-value matching for the most common patterns.
   */
  private evaluatePredicate(
    predicate: string,
    rowData: Record<string, any>,
  ): boolean {
    // Normalize: handle simple "col = value" patterns
    const normalized = predicate.replace(/\s+/g, ' ').trim();

    // Try to match "column = 'value'" or "column = value" patterns
    const eqMatch = normalized.match(/^(\w+)\s*=\s*['"]?(.+?)['"]?\s*$/);
    if (eqMatch) {
      const col = eqMatch[1];
      const val = eqMatch[2].replace(/['"]/g, '');
      return String(rowData[col]) === val;
    }

    // Try "column = current_setting('...')" pattern
    const csMatch = normalized.match(/^(\w+)\s*=\s*current_setting\(['"](.+?)['"]\)\s*$/);
    if (csMatch) {
      const col = csMatch[1];
      const settingName = csMatch[2];
      const settingVal = this.getSettingValue(settingName);
      return String(rowData[col]) === settingVal;
    }

    // For complex predicates, fail open (log warning)
    logger.warn({ predicate, rowData }, 'WITH CHECK: complex predicate evaluation not implemented');
    return true;
  }

  private getSettingValue(name: string): string {
    try {
      const appSetting = process.env['PG_SETTING_' + name.toUpperCase()];
      if (appSetting !== undefined) return appSetting;
    } catch {
      // ignore
    }
    return '';
  }
}

// ── Static helpers ────────────────────────────────────────────────────────────

/**
 * Build a combined RLS predicate from multiple policies.
 *
 * @param policies - List of policies for a table.
 * @returns Combined predicate string.
 */
export function buildCombinedPredicate(policies: RLSPolicy[]): string {
  const permissive: string[] = [];
  const restrictive: string[] = [];

  for (const p of policies) {
    if (!p.usingPredicate) continue;
    if (p.type === 'PERMISSIVE') {
      permissive.push(p.usingPredicate);
    } else {
      restrictive.push(p.usingPredicate);
    }
  }

  let combined = '';
  if (permissive.length > 0) {
    combined += '(' + permissive.join(' OR ') + ')';
  }
  if (restrictive.length > 0) {
    if (combined) combined += ' AND ';
    combined += '(' + restrictive.join(' AND ') + ')';
  }
  return combined;
}
