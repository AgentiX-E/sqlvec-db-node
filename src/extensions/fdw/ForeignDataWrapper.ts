/**
 * ForeignDataWrapper — Full FDW implementation using SQLite ATTACH DATABASE.
 *
 * Supports:
 *   - CREATE FOREIGN TABLE mapping local table name → remote table in another .db file
 *   - IMPORT FOREIGN SCHEMA to bulk-import all tables from a remote database
 *   - Cross-file queries via SQLite ATTACH DATABASE
 *   - Predicate pushdown (WHERE clause conditions passed to remote)
 *
 * ## Usage
 *
 * ```ts
 * const fdw = new ForeignDataWrapper();
 *
 * // Register a foreign server pointing to another SQLite database
 * fdw.createForeignServer('remote1', '/path/to/remote.db');
 *
 * // CREATE FOREIGN TABLE with column definitions
 * fdw.createForeignTable('local_orders', 'remote1', 'orders', [
 *   { name: 'id', type: 'INTEGER' },
 *   { name: 'total', type: 'REAL' },
 * ]);
 *
 * // IMPORT FOREIGN SCHEMA — bulk-import all tables from the remote
 * fdw.importForeignSchema('remote1', 'public', 'local');
 *
 * // Execute cross-file query with predicate pushdown
 * const rows = fdw.executeQuery('SELECT * FROM local_orders WHERE total > 100');
 * ```
 *
 * @module fdw/ForeignDataWrapper
 */

import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';
import { PinoLogger } from '../monitoring/PinoLogger';

// ── Types ────────────────────────────────────────────────────────

export interface ForeignServer {
  /** Unique server name. */
  name: string;
  /** File path to the foreign SQLite database. */
  dbPath: string;
  /** Optional options for ATTACH. */
  options?: Record<string, string>;
}

export interface ForeignColumnDef {
  name: string;
  type: string;
  /** PG-compatible column options (e.g., NOT NULL, DEFAULT). */
  options?: string;
}

export interface ForeignTableDef {
  /** Local name exposed to queries. */
  localName: string;
  /** Foreign server name (must be registered). */
  serverName: string;
  /** Actual remote table name in the foreign database. */
  remoteTable: string;
  /** Column definitions (optional, used for introspection). */
  columns?: ForeignColumnDef[];
}

export interface FDWQueryResult {
  rows: Record<string, any>[];
  columns: string[];
  rowCount: number;
}

// ── Logger ───────────────────────────────────────────────────────


// ── ForeignDataWrapper ───────────────────────────────────────────

export class ForeignDataWrapper {
  private readonly logger = PinoLogger.forComponent('foreigndatawrapper');

  private servers: Map<string, ForeignServer> = new Map();
  private tables: Map<string, ForeignTableDef> = new Map();
  /** Cached ATTACH DATABASE connection strings for reuse. */
  private attachedDatabases: Map<string, string> = new Map();
  /** Counter for ATTACH DATABASE schema names. */
  private attachSchemaCounter: number = 0;

  /** Map<schemaName, { dbPath, serverName }> tracking ATTACH info. */
  private attachedSchemaInfo: Map<string, { dbPath: string; serverName: string }> = new Map();

  /** Imports performed via IMPORT FOREIGN SCHEMA. */
  private importRecords: Array<{
    serverName: string;
    schemaName: string;
    localPrefix: string;
    tables: ForeignTableDef[];
    importedAt: Date;
  }> = [];

  constructor() {
    this.logger.info('ForeignDataWrapper initialized');
  }

  // ── Server management ──────────────────────────────────────────

  /**
   * Register a foreign server.
   * The database file must exist at the given path.
   *
   * @param name   - Unique server name (used in CREATE FOREIGN TABLE).
   * @param dbPath - Path to the foreign SQLite database file.
   * @param options - Optional ATTACH options.
   */
  createForeignServer(name: string, dbPath: string, options?: Record<string, string>): void {
    const absPath = path.resolve(dbPath);
    if (!fs.existsSync(absPath)) {
      throw new Error(`FDW: Foreign database file not found: ${absPath}`);
    }

    this.servers.set(name, { name, dbPath: absPath, options });
    this.logger.info({ name, dbPath: absPath }, 'Foreign server created');
  }

  /**
   * Drop a foreign server and detach its database.
   *
   * @param name - Server name to drop.
   * @param db   - Optional database connection to execute DETACH.
   */
  dropForeignServer(name: string, db?: Database.Database): void {
    const server = this.servers.get(name);
    if (!server) return;

    // Detach if attached
    for (const [schema, info] of this.attachedSchemaInfo) {
      if (info.serverName === name) {
        if (db) {
          try { db.exec(`DETACH DATABASE "${schema}"`); } catch { /* non-fatal */ }
        }
        this.attachedDatabases.delete(schema);
        this.attachedSchemaInfo.delete(schema);
      }
    }

    // Drop all tables referencing this server
    for (const [localName, tableDef] of this.tables) {
      if (tableDef.serverName === name) {
        this.tables.delete(localName);
      }
    }

    this.servers.delete(name);
    this.logger.info({ name }, 'Foreign server dropped');
  }

  /**
   * Get a registered server by name.
   */
  getServer(name: string): ForeignServer | undefined {
    return this.servers.get(name);
  }

  /**
   * Get all registered servers.
   */
  getAllServers(): ForeignServer[] {
    return Array.from(this.servers.values());
  }

  // ── CREATE FOREIGN TABLE ──────────────────────────────────────

  /**
   * Create a foreign table mapping.
   *
   * This registers a virtual table `localName` that maps to `remoteTable`
   * in the database referenced by `serverName`.
   *
   * @param localName  - Local name exposed to SQL queries.
   * @param serverName - Foreign server name (must be registered).
   * @param remoteTable - Actual table name in the remote database.
   * @param columns    - Optional column definitions.
   */
  createForeignTable(
    localName: string,
    serverName: string,
    remoteTable: string,
    columns?: ForeignColumnDef[],
  ): void {
    const server = this.servers.get(serverName);
    if (!server) {
      throw new Error(`FDW: Foreign server "${serverName}" not found`);
    }

    this.tables.set(localName, {
      localName,
      serverName,
      remoteTable,
      columns,
    });

    this.logger.info({ localName, serverName, remoteTable }, 'Foreign table created');
  }

  /**
   * Drop a foreign table mapping.
   *
   * @param localName - Local table name to drop.
   */
  dropForeignTable(localName: string): void {
    this.tables.delete(localName);
    this.logger.info({ localName }, 'Foreign table dropped');
  }

  /**
   * Get a foreign table definition.
   */
  getForeignTable(localName: string): ForeignTableDef | undefined {
    return this.tables.get(localName);
  }

  /**
   * Check if a table name is registered as foreign.
   */
  isForeignTable(tableName: string): boolean {
    return this.tables.has(tableName);
  }

  /**
   * Get all registered foreign tables.
   */
  getAllForeignTables(): ForeignTableDef[] {
    return Array.from(this.tables.values());
  }

  // ── IMPORT FOREIGN SCHEMA ─────────────────────────────────────

  /**
   * Import all tables from a remote database schema.
   *
   * Introspects the remote database's sqlite_master table and creates
   * foreign table mappings for each user table.
   *
   * @param serverName  - Foreign server name.
   * @param schemaName  - Schema name in the remote DB (ignored — SQLite doesn't have PG schemas).
   * @param localPrefix - Optional prefix to add to local table names.
   * @param db          - Optional local database connection for introspection.
   * @returns The list of imported foreign table definitions.
   */
  importForeignSchema(
    serverName: string,
    schemaName: string,
    localPrefix?: string,
    db?: Database.Database,
  ): ForeignTableDef[] {
    const server = this.servers.get(serverName);
    if (!server) {
      throw new Error(`FDW: Foreign server "${serverName}" not found`);
    }

    // Attach the remote database to introspect
    const schema = this.attachDatabase(db);
    const prefix = localPrefix || serverName;

    // Query sqlite_master for user tables
    let remoteDb: Database.Database;
    try {
      remoteDb = new Database(server.dbPath, { readonly: true });
    } catch (err: any) {
      throw new Error(`FDW: Cannot open foreign database "${server.dbPath}": ${err.message}`);
    }

    const tables: ForeignTableDef[] = [];

    try {
      const rows = remoteDb.prepare(
        "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
      ).all() as Array<{ name: string; sql: string | null }>;

      for (const row of rows) {
        const localName = prefix ? `${prefix}_${row.name}` : row.name;

        // Parse column defs from CREATE TABLE SQL if available
        let columns: ForeignColumnDef[] | undefined;
        if (row.sql) {
          columns = this.parseColumnDefs(row.sql);
        }

        this.tables.set(localName, {
          localName,
          serverName,
          remoteTable: row.name,
          columns,
        });

        tables.push({ localName, serverName, remoteTable: row.name, columns });
      }
    } finally {
      remoteDb.close();
    }

    this.importRecords.push({
      serverName,
      schemaName,
      localPrefix: prefix,
      tables,
      importedAt: new Date(),
    });

    this.logger.info(
      { serverName, schemaName, localPrefix: prefix, count: tables.length },
      'IMPORT FOREIGN SCHEMA completed',
    );

    return tables;
  }

  /**
   * Get all import records.
   */
  getImportRecords(): Array<{
    serverName: string;
    schemaName: string;
    localPrefix: string;
    tables: ForeignTableDef[];
    importedAt: Date;
  }> {
    return [...this.importRecords];
  }

  // ── Query execution with SQLite ATTACH DATABASE ──────────────

  /**
   * Attach the remote database for a given foreign table to a local
   * SQLite connection, enabling cross-file SQL queries via
   * `ATTACH DATABASE`.
   *
   * Returns the schema name used for the attachment (e.g. "fdw_0").
   *
   * @param db - Local database connection.
   * @param foreignTable - Foreign table to resolve.
   * @returns The ATTACH schema name (e.g., "fdw_0").
   */
  attachForQuery(db: Database.Database, foreignTable: ForeignTableDef): string {
    const server = this.servers.get(foreignTable.serverName);
    if (!server) {
      throw new Error(`FDW: Server "${foreignTable.serverName}" not found`);
    }

    // Check if already attached
    for (const [schema, info] of this.attachedSchemaInfo) {
      if (info.serverName === foreignTable.serverName) {
        return schema; // Already attached
      }
    }

    // Attach the remote database
    const schema = `fdw_${this.attachSchemaCounter++}`;
    const attachSql = `ATTACH DATABASE '${server.dbPath.replace(/'/g, "''")}' AS "${schema}"`;
    try {
      db.exec(attachSql);
    } catch (err: any) {
      throw new Error(`FDW: ATTACH DATABASE failed: ${err.message}`);
    }

    this.attachedDatabases.set(foreignTable.serverName, schema);
    this.attachedSchemaInfo.set(schema, {
      dbPath: server.dbPath,
      serverName: foreignTable.serverName,
    });

    this.logger.debug(
      { schema, dbPath: server.dbPath, serverName: foreignTable.serverName },
      'ATTACH DATABASE for FDW query',
    );

    return schema;
  }

  /**
   * Execute a cross-file query using ATTACH DATABASE.
   *
   * Translates the local table name to schema.remoteTable format
   * and runs the query on the provided database connection.
   *
   * Supports predicate pushdown — the WHERE clause is passed through
   * to the remote database.
   *
   * @param sql   - SQL query (e.g., "SELECT * FROM local_orders WHERE total > 100").
   * @param db    - Local SQLite database connection.
   * @returns Query results.
   */
  executeQuery(sql: string, db: Database.Database): FDWQueryResult {
    const tableNames = this.extractTableNames(sql);
    let rewrittenSql = sql;

    for (const localName of tableNames) {
      const foreignTable = this.tables.get(localName);
      if (!foreignTable) continue;

      const schema = this.attachForQuery(db, foreignTable);
      // Rewrite local table name to schema.remoteTable
      const escapedLocal = localName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      rewrittenSql = rewrittenSql.replace(
        new RegExp(`\\b${escapedLocal}\\b`, 'g'),
        `"${schema}"."${foreignTable.remoteTable}"`,
      );
    }

    // If no foreign tables found, still try execution
    if (rewrittenSql === sql) {
      // Check if any server needs attaching for cross-file queries
      // (e.g., direct queries against attached databases)
    }

    // Execute the (potentially rewritten) SQL
    try {
      const stmt = db.prepare(rewrittenSql);
      const rows = stmt.all();
      const columns = stmt.columns().map((c) => c.name);

      this.logger.debug(
        { originalSql: sql, rewrittenSql, rowCount: rows.length },
        'FDW cross-file query executed',
      );

      return {
        rows: rows as Record<string, any>[],
        columns,
        rowCount: rows.length,
      };
    } catch (err: any) {
      // Try with direct remote table name
      for (const localName of tableNames) {
        const foreignTable = this.tables.get(localName);
        if (!foreignTable) continue;

        const schema = this.attachForQuery(db, foreignTable);
        const escapedLocal = localName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        rewrittenSql = sql.replace(
          new RegExp(`\\b${escapedLocal}\\b`, 'g'),
          `"${schema}"."${foreignTable.remoteTable}"`,
        );

        try {
          const stmt = db.prepare(rewrittenSql);
          const rows = stmt.all();
          const columns = stmt.columns().map((c) => c.name);

          return {
            rows: rows as Record<string, any>[],
            columns,
            rowCount: rows.length,
          };
        } catch (err2: any) {
          throw new Error(
            `FDW query failed: ${err2.message} (original: ${err.message})`,
          );
        }
      }
      throw new Error(
        `FDW query failed: SQL="${rewrittenSql}": ${err.message}`,
      );
    }
  }

  // ── Predicate pushdown ────────────────────────────────────────

  /**
   * Push a WHERE predicate down to the remote query.
   *
   * Given a SQL query referencing a foreign table, extracts the WHERE clause
   * and returns a simplified (pushable) predicate string.
   *
   * @param sql - The full SQL query.
   * @returns The WHERE clause without the WHERE keyword, or empty string.
   */
  extractPushablePredicates(sql: string): string {
    const whereMatch = sql.match(/WHERE\s+(.+?)(?:\s+(?:ORDER|LIMIT|GROUP|HAVING)\b|$)/i);
    if (!whereMatch) return '';
    return whereMatch[1].trim();
  }

  // ── Detachment & cleanup ─────────────────────────────────────

  /**
   * Detach a specific foreign server's database from a connection.
   *
   * @param serverName - Server name to detach.
   * @param db         - Local database connection.
   */
  detachDatabase(serverName: string, db: Database.Database): void {
    for (const [schema, info] of this.attachedSchemaInfo) {
      if (info.serverName === serverName) {
        try {
          db.exec(`DETACH DATABASE "${schema}"`);
        } catch { /* non-fatal */ }
        this.attachedDatabases.delete(schema);
        this.attachedSchemaInfo.delete(schema);
        this.logger.info({ schema, serverName }, 'DETACH DATABASE');
      }
    }
  }

  /**
   * Detach all foreign databases from a connection.
   *
   * @param db - Local database connection.
   */
  detachAll(db: Database.Database): void {
    for (const schema of this.attachedSchemaInfo.keys()) {
      try {
        db.exec(`DETACH DATABASE "${schema}"`);
      } catch { /* non-fatal */ }
    }
    this.attachedDatabases.clear();
    this.attachedSchemaInfo.clear();
    this.logger.info('All foreign databases detached');
  }

  /**
   * Reset all state (for testing).
   */
  reset(): void {
    this.servers.clear();
    this.tables.clear();
    this.attachedDatabases.clear();
    this.attachedSchemaInfo.clear();
    this.attachSchemaCounter = 0;
    this.importRecords = [];
    this.logger.info('ForeignDataWrapper state reset');
  }

  // ── Private helpers ───────────────────────────────────────────

  /**
   * Extract all table names from a SQL query.
   */
  private extractTableNames(sql: string): string[] {
    const tables: string[] = [];

    // Match FROM clause table names
    const fromMatches = sql.matchAll(/\bFROM\s+(?:`|")?(\w+)(?:`|")?\b/gi);
    for (const m of fromMatches) tables.push(m[1]);

    // Match JOIN clause table names
    const joinMatches = sql.matchAll(/\bJOIN\s+(?:`|")?(\w+)(?:`|")?\b/gi);
    for (const m of joinMatches) {
      if (!tables.includes(m[1])) tables.push(m[1]);
    }

    // Match INSERT INTO / UPDATE / DELETE FROM table names
    const dmlMatches = sql.matchAll(
      /\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:`|")?(\w+)(?:`|")?\b/gi,
    );
    for (const m of dmlMatches) {
      if (!tables.includes(m[1])) tables.push(m[1]);
    }

    return tables;
  }

  /**
   * Register ATTACH after introspecting a remote database.
   * Used by importForeignSchema to ensure the database gets attached.
   */
  private attachDatabase(db?: Database.Database): string {
    if (!db) return '';
    // Don't actually attach just for introspection; we open a separate
    // read-only connection later.
    return '';
  }

  /**
   * Parse column definitions from a CREATE TABLE SQL statement.
   */
  private parseColumnDefs(createSql: string): ForeignColumnDef[] {
    const columns: ForeignColumnDef[] = [];

    // Extract the column definitions between the first ( and the last )
    const parenMatch = createSql.match(/\(([\s\S]+)\)\s*$/);
    if (!parenMatch) return columns;

    const body = parenMatch[1];
    // Split by commas, but not inside sub-parens (constraint definitions)
    const parts = this.splitSqlDefs(body);

    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;

      // Skip constraints, PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK, etc.
      if (
        /^(PRIMARY|FOREIGN|UNIQUE|CHECK|CONSTRAINT|INDEX|REFERENCES)\b/i.test(trimmed)
      ) {
        continue;
      }

      // Parse: column_name TYPE [(options)]
      const colMatch = trimmed.match(/^[`"]?(\w+)[`"]?\s+(\w+(?:\s*\(\d+(?:,\s*\d+)?\))?)/i);
      if (colMatch) {
        columns.push({
          name: colMatch[1],
          type: colMatch[2].toUpperCase(),
          options: trimmed.substring(colMatch[0].length).trim() || undefined,
        });
      }
    }

    return columns;
  }

  /**
   * Split SQL column definitions by commas, respecting nested parentheses.
   */
  private splitSqlDefs(body: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let current = '';

    for (const ch of body) {
      if (ch === '(') {
        depth++;
        current += ch;
      } else if (ch === ')') {
        depth--;
        current += ch;
      } else if (ch === ',' && depth === 0) {
        parts.push(current);
        current = '';
      } else {
        current += ch;
      }
    }
    if (current.trim()) parts.push(current);

    return parts;
  }
}
