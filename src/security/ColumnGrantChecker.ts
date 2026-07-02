/**
 * ColumnGrantChecker — Column-level privilege enforcement for SQLite.
 *
 * PostgreSQL supports column-level grants:
 *   GRANT SELECT(col1, col2) ON t TO user;
 *   GRANT INSERT(col1) ON t TO user;
 *
 * SQLite only supports table-level grants. This class stores column-level
 * grant metadata in a SQLite `__column_grants` table and provides methods
 * to grant, check, and revoke column-level privileges.
 *
 * @module ColumnGrantChecker
 */

import Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('ColumnGrantChecker');

const COLUMN_GRANTS_TABLE = '__column_grants';

// ── Types ────────────────────────────────────────────────────────

export interface ColumnGrantRow {
  grantee: string;
  table_name: string;
  privilege: string;
  columns: string; // JSON array of column names
}

// ── ColumnGrantChecker Class ─────────────────────────────────────

export class ColumnGrantChecker {
  private db: Database.Database | null = null;
  private ready: boolean = false;

  /**
   * @param dbProvider - A function that returns a better-sqlite3 Database instance.
   *                     The provider is called lazily (on first grant operation).
   *                     Pass `null` to create a fully in-memory, no-op checker
   *                     (all checks pass, all grants are ignored).
   */
  constructor(dbProvider?: () => Database.Database) {
    if (dbProvider) {
      try {
        this.db = dbProvider();
        this.initTable();
        this.ready = true;
        logger.debug('ColumnGrantChecker initialized with SQLite backing');
      } catch (err) {
        logger.warn({ err }, 'Failed to initialize ColumnGrantChecker SQLite backing — running in no-op mode');
        this.ready = false;
        this.db = null;
      }
    } else {
      // No provider = no-op mode
      this.ready = false;
      this.db = null;
    }
  }

  // ── Private helpers ────────────────────────────────────────────

  private initTable(): void {
    if (!this.db) return;
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ${COLUMN_GRANTS_TABLE} (
        grantee   TEXT NOT NULL,
        table_name TEXT NOT NULL,
        privilege TEXT NOT NULL,
        columns   TEXT NOT NULL DEFAULT '[]',
        PRIMARY KEY (grantee, table_name, privilege)
      )
    `);
  }

  // ── Public API ─────────────────────────────────────────────────

  /**
   * Record a column-level privilege grant.
   *
   * Example:
   *   grantColumnPrivilege('user1', 'orders', 'INSERT', ['order_id', 'amount'])
   *
   * The `columns` array may contain '*' to denote "ALL columns".
   *
   * @param grantee  - The user/role receiving the grant.
   * @param tableName - The target table name.
   * @param privilege - The privilege (e.g. 'SELECT', 'INSERT', 'UPDATE', 'ALL').
   * @param columns  - The list of column names the grant applies to.
   */
  grantColumnPrivilege(
    grantee: string,
    tableName: string,
    privilege: string,
    columns: string[],
  ): void {
    if (!this.ready || !this.db) {
      logger.debug('grantColumnPrivilege skipped — no-op mode');
      return;
    }

    const granteeKey = grantee.toLowerCase();
    const tableKey = tableName.toLowerCase();
    const privKey = privilege.toUpperCase();

    const jsonColumns = JSON.stringify(
      columns.map((c) => (c === '*' ? '*' : c.toLowerCase())),
    );

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO ${COLUMN_GRANTS_TABLE}
        (grantee, table_name, privilege, columns)
      VALUES (?, ?, ?, ?)
    `);

    stmt.run(granteeKey, tableKey, privKey, jsonColumns);
    logger.debug(
      'Granted %s(%s) ON %s TO %s',
      privKey,
      columns.join(', '),
      tableKey,
      granteeKey,
    );
  }

  /**
   * Check whether a user has the specified column-level privilege.
   *
   * Logic:
   *   1. If the checker is not backed by a database (no-op mode), ALLOW.
   *   2. If the user has a specific grant for this privilege+table with
   *      matching column (or wildcard), ALLOW.
   *   3. If the user has a grant for 'ALL' privilege on this table with
   *      matching column (or wildcard), ALLOW (ALL covers all privileges).
   *   4. If this user has ANY column-level grant on this table (any privilege),
   *      they are in "restricted" mode → DENY (column not in allowed set).
   *   5. If no grants exist at all for this table+privilege combo (any user),
   *      ALLOW (open by default — no one set up column restrictions).
   *   6. Otherwise, DENY.
   *
   * @param user      - The user to check.
   * @param tableName - The target table name.
   * @param privilege - The requested privilege.
   * @param column    - The column being accessed.
   * @returns `true` if access is allowed, `false` if denied.
   */
  checkColumnPrivilege(
    user: string,
    tableName: string,
    privilege: string,
    column: string,
  ): boolean {
    if (!this.ready || !this.db) {
      return true; // no-op mode → allow
    }

    const userKey = user.toLowerCase();
    const tableKey = tableName.toLowerCase();
    const privKey = privilege.toUpperCase();
    const columnKey = column.toLowerCase();

    // Priority 1: Check for exact user grant on this privilege+table
    const exactStmt = this.db.prepare(`
      SELECT columns FROM ${COLUMN_GRANTS_TABLE}
      WHERE grantee = ? AND table_name = ? AND privilege = ?
    `);
    const exactRow = exactStmt.get(userKey, tableKey, privKey) as
      | ColumnGrantRow
      | undefined;

    if (exactRow) {
      const allowedColumns: string[] = JSON.parse(exactRow.columns);
      if (allowedColumns.includes('*') || allowedColumns.includes(columnKey)) {
        return true;
      }
      // User has this privilege but not on this column → DENY
      return false;
    }

    // Priority 2: If the user has a grant for 'ALL' on this table,
    // treat 'ALL' as covering all privileges (SELECT, INSERT, UPDATE, etc.)
    const allStmt = this.db.prepare(`
      SELECT columns FROM ${COLUMN_GRANTS_TABLE}
      WHERE grantee = ? AND table_name = ? AND privilege = 'ALL'
    `);
    const allRow = allStmt.get(userKey, tableKey) as
      | ColumnGrantRow
      | undefined;

    if (allRow) {
      const allowedColumns: string[] = JSON.parse(allRow.columns);
      if (allowedColumns.includes('*') || allowedColumns.includes(columnKey)) {
        return true;
      }
      // User has ALL but not on this column → DENY
      return false;
    }

    // Priority 3: Does this user have ANY column-level grant on this table?
    // If so, they are in "restricted" mode for all privileges.
    const userHasGrant = this.db.prepare(`
      SELECT 1 FROM ${COLUMN_GRANTS_TABLE}
      WHERE grantee = ? AND table_name = ?
      LIMIT 1
    `).get(userKey, tableKey);

    if (userHasGrant) {
      return false; // User has column grants on this table but not the requested one
    }

    // Priority 4: Are there ANY grants for this table+privilege combo?
    // If at least one grant exists but the user doesn't have one → DENY.
    const anyGrant = this.db.prepare(`
      SELECT 1 FROM ${COLUMN_GRANTS_TABLE}
      WHERE table_name = ? AND privilege = ?
      LIMIT 1
    `).get(tableKey, privKey);

    if (anyGrant) {
      logger.debug(
        'Column privilege DENIED: user=%s table=%s privilege=%s column=%s',
        userKey,
        tableKey,
        privKey,
        columnKey,
      );
      return false;
    }

    // No grants exist for this table+privilege at all → open access
    return true;
  }

  /**
   * Revoke a column-level privilege grant.
   *
   * If `columns` is provided, only those columns are removed from the grant.
   * If `columns` is omitted or empty, the entire grant is removed.
   *
   * @param grantee   - The user/role whose grant to revoke.
   * @param tableName - The target table name.
   * @param privilege - The privilege to revoke.
   * @param columns   - Optional subset of columns to revoke.
   */
  revokeColumnPrivilege(
    grantee: string,
    tableName: string,
    privilege: string,
    columns?: string[],
  ): void {
    if (!this.ready || !this.db) return;

    const granteeKey = grantee.toLowerCase();
    const tableKey = tableName.toLowerCase();
    const privKey = privilege.toUpperCase();

    if (columns && columns.length > 0) {
      // Partial revoke — remove specific columns from the existing grant
      const row = this.db
        .prepare(
          `SELECT columns FROM ${COLUMN_GRANTS_TABLE}
           WHERE grantee = ? AND table_name = ? AND privilege = ?`,
        )
        .get(granteeKey, tableKey, privKey) as ColumnGrantRow | undefined;

      if (row) {
        const existingColumns: string[] = JSON.parse(row.columns);
        const revokeSet = new Set(columns.map((c) => c.toLowerCase()));
        const remaining = existingColumns.filter((c) => !revokeSet.has(c));

        if (remaining.length > 0) {
          this.db
            .prepare(
              `UPDATE ${COLUMN_GRANTS_TABLE} SET columns = ?
               WHERE grantee = ? AND table_name = ? AND privilege = ?`,
            )
            .run(
              JSON.stringify(remaining),
              granteeKey,
              tableKey,
              privKey,
            );
        } else {
          // No columns left — remove the entire grant
          this.db
            .prepare(
              `DELETE FROM ${COLUMN_GRANTS_TABLE}
               WHERE grantee = ? AND table_name = ? AND privilege = ?`,
            )
            .run(granteeKey, tableKey, privKey);
        }
      }
    } else {
      // Full revoke — remove all grants for this user/table/privilege
      this.db
        .prepare(
          `DELETE FROM ${COLUMN_GRANTS_TABLE}
           WHERE grantee = ? AND table_name = ? AND privilege = ?`,
        )
        .run(granteeKey, tableKey, privKey);
    }

    logger.debug(
      'Revoked %s ON %s.%s FROM %s',
      columns ? `${privKey}(${columns.join(', ')})` : privKey,
      tableKey,
      tableKey,
      granteeKey,
    );
  }

  /**
   * Check if the checker is backed by a real SQLite database.
   */
  isReady(): boolean {
    return this.ready;
  }

  /**
   * Close the underlying database connection.
   */
  close(): void {
    if (this.db) {
      try {
        this.db.close();
      } catch {
        // Already closed
      }
      this.db = null;
      this.ready = false;
    }
  }
}
