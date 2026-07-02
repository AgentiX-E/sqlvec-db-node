/**
 * RowLevelSecurity — Per-row security policy enforcement.
 *
 * Injects policy predicates into SQL WHERE clauses to enforce
 * row-level access control. Supports:
 *   - PERMISSIVE (OR-combined) and RESTRICTIVE (AND-combined) policies
 *   - Multi-tenant table filtering
 *   - Policy management (CREATE/DROP/ALTER ROW LEVEL SECURITY POLICY)
 *   - Automatic WHERE-clause injection at SQL parse/exec boundary
 *
 * Architecture:
 *   Policies are stored in a SQLite table (row_security_policies) and
 *   applied by the PolicyInjector when a query targets a table with
 *   active RLS policies. The injector adds AND/OR clauses to the
 *   query's WHERE condition before execution.
 *
 * @module security/RowLevelSecurity
 */

import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';

import { PinoLogger } from '../monitoring/PinoLogger';
import { RLSPolicyInjector } from './RLSPolicyInjector';

const logger = PinoLogger.forComponent('RowLevelSecurity');

// ── Types ────────────────────────────────────────────────────────

export type PolicyType = 'PERMISSIVE' | 'RESTRICTIVE';
export type PolicyCommand = 'ALL' | 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';

export interface RlsPolicy {
  id?: number;
  /** Policy name (unique per table). */
  name: string;
  /** Table name this policy applies to. */
  tableName: string;
  /** PERMISSIVE (OR) or RESTRICTIVE (AND). */
  type: PolicyType;
  /** Command type this policy applies to. */
  command: PolicyCommand;
  /** SQL predicate expression (e.g., "tenant_id = current_setting('app.tenant_id')"). */
  using: string;
  /** Optional check expression for INSERT/UPDATE. */
  check?: string;
  /** Whether the policy is enabled. */
  enabled: boolean;
}

export interface RlsState {
  /** Whether RLS is enabled on the table. */
  enabled: boolean;
  /** Whether table owner bypasses RLS (default: true). */
  bypassOwner: boolean;
  /** Whether the current force mode is active (force_rls). */
  force: boolean;
}

// ── RowLevelSecurity Manager ─────────────────────────────────────

export class RowLevelSecurity {
  private db: Database.Database;
  private initialized = false;
  private injector = new RLSPolicyInjector();

  /** Per-table RLS state. */
  private tableStates: Map<string, RlsState> = new Map();

  /**
   * @param dbPath - Path to the SQLite database for policy storage.
   */
  constructor(dbPath?: string) {
    const resolvedPath = dbPath || path.join(process.env.DATA_DIR || '/tmp/sqlvec-db', 'rls_policies.db');
    const dir = path.dirname(resolvedPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    this.db = new Database(resolvedPath);
    this.db.pragma('journal_mode = WAL');
  }

  /**
   * Initialize schema.
   */
  init(): void {
    if (this.initialized) return;

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS row_security_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        table_name TEXT NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('PERMISSIVE', 'RESTRICTIVE')),
        command TEXT NOT NULL CHECK(command IN ('ALL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE')),
        using_expr TEXT NOT NULL DEFAULT '',
        check_expr TEXT DEFAULT NULL,
        enabled INTEGER NOT NULL DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS row_security_state (
        table_name TEXT PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 0,
        bypass_owner INTEGER NOT NULL DEFAULT 1,
        force_rls INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_rls_policy_table ON row_security_policies(table_name);
    `);

    this.initialized = true;
    logger.info('RowLevelSecurity initialized');
  }

  // ── Policy Management ──────────────────────────────────────────

  /**
   * Enable or disable RLS on a table.
   */
  setTableRls(tableName: string, enabled: boolean): void {
    this.ensureInitialized();
    this.db.prepare(`
      INSERT INTO row_security_state (table_name, enabled, bypass_owner, force_rls)
      VALUES (?, ?, 1, 0)
      ON CONFLICT(table_name) DO UPDATE SET enabled = ?
    `).run(tableName, enabled ? 1 : 0, enabled ? 1 : 0);
    this.tableStates.set(tableName, {
      enabled,
      bypassOwner: true,
      force: false,
    });
    logger.info({ tableName, enabled }, 'Table RLS state set');
  }

  /**
   * Create an RLS policy on a table.
   */
  createPolicy(policy: RlsPolicy): void {
    this.ensureInitialized();
    this.db.prepare(`
      INSERT INTO row_security_policies (name, table_name, type, command, using_expr, check_expr, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      policy.name,
      policy.tableName,
      policy.type,
      policy.command,
      policy.using,
      policy.check || null,
      policy.enabled ? 1 : 0,
    );
    logger.info({ policy: policy.name, table: policy.tableName }, 'RLS policy created');
  }

  /**
   * Drop an RLS policy.
   */
  dropPolicy(policyName: string, tableName: string): void {
    this.ensureInitialized();
    this.db.prepare('DELETE FROM row_security_policies WHERE name = ? AND table_name = ?')
      .run(policyName, tableName);
    logger.info({ policy: policyName, table: tableName }, 'RLS policy dropped');
  }

  /**
   * Get all policies for a table.
   */
  getPolicies(tableName: string, command?: PolicyCommand): RlsPolicy[] {
    this.ensureInitialized();
    let sql = 'SELECT * FROM row_security_policies WHERE table_name = ?';
    const params: unknown[] = [tableName];

    if (command) {
      sql += ' AND (command = ? OR command = \'ALL\')';
      params.push(command);
    }

    const rows = this.db.prepare(sql).all(...params) as Array<{
      id: number;
      name: string;
      table_name: string;
      type: string;
      command: string;
      using_expr: string;
      check_expr: string | null;
      enabled: number;
    }>;

    return rows.map(r => ({
      id: r.id,
      name: r.name,
      tableName: r.table_name,
      type: r.type as PolicyType,
      command: r.command as PolicyCommand,
      using: r.using_expr,
      check: r.check_expr || undefined,
      enabled: r.enabled === 1,
    }));
  }

  /**
   * Check if RLS is enabled for a table.
   */
  isRlsEnabled(tableName: string): boolean {
    this.ensureInitialized();
    const cached = this.tableStates.get(tableName);
    if (cached !== undefined) return cached.enabled;

    const row = this.db.prepare('SELECT enabled FROM row_security_state WHERE table_name = ?')
      .get(tableName) as { enabled: number } | undefined;
    return row ? row.enabled === 1 : false;
  }

  // ── SQL Injection (RLS Predicate Injection) ────────────────────

  /**
   * Inject RLS predicates into a SQL query.
   *
   * For SELECT/UPDATE/DELETE, injects the USING expression for all
   * active policies. PERMISSIVE policies are OR'd together, then
   * AND'd with RESTRICTIVE policies.
   *
   * @param sql      - Original SQL query
   * @param tableName - Target table name
   * @param command  - Command type
   * @returns Modified SQL with RLS predicates injected, or original SQL if no RLS applies.
   */
  injectPolicy(sql: string, tableName: string, command: PolicyCommand = 'ALL'): string {
    if (!this.isRlsEnabled(tableName)) return sql;

    const policies = this.getPolicies(tableName, command)
      .filter(p => p.enabled && p.using.length > 0);

    if (policies.length === 0) return sql;

    const permissive: string[] = [];
    const restrictive: string[] = [];

    for (const p of policies) {
      if (p.type === 'PERMISSIVE') {
        permissive.push(p.using);
      } else {
        restrictive.push(p.using);
      }
    }

    // Build the RLS predicate
    let rlsPredicate: string;

    if (permissive.length > 0 && restrictive.length > 0) {
      rlsPredicate = `(${permissive.join(' OR ')}) AND (${restrictive.join(' AND ')})`;
    } else if (permissive.length > 0) {
      rlsPredicate = `(${permissive.join(' OR ')})`;
    } else {
      rlsPredicate = `(${restrictive.join(' AND ')})`;
    }

    // Don't inject if the predicate is empty
    if (!rlsPredicate || rlsPredicate === '()') return sql;

    // AST-based injection via RLSPolicyInjector
    return this.injector.injectPredicate(sql, rlsPredicate);
  }

  /**
   * Get all table RLS states.
   */
  getAllTableStates(): Record<string, RlsState> {
    this.ensureInitialized();
    const rows = this.db.prepare('SELECT * FROM row_security_state').all() as Array<{
      table_name: string;
      enabled: number;
      bypass_owner: number;
      force_rls: number;
    }>;

    const result: Record<string, RlsState> = {};
    for (const r of rows) {
      result[r.table_name] = {
        enabled: r.enabled === 1,
        bypassOwner: r.bypass_owner === 1,
        force: r.force_rls === 1,
      };
    }
    return result;
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.db.close();
  }

  // ── Internal ───────────────────────────────────────────────────

  private ensureInitialized(): void {
    if (!this.initialized) {
      this.init();
    }
  }
}
