/**
 * LogicalBackup — pg_dump-equivalent logical backup for SQLVec (SQL/CSV/JSON export)
 *
 * Provides SQL dump, CSV export, JSON Lines export, and import capabilities
 * for better-sqlite3 databases.  Designed as a logical complement to the
 * file-level SafeBackupManager.
 *
 * @example
 * ```ts
 * const lb = new LogicalBackup(db);
 *
 * // SQL dump
 * const sql = lb.exportSQL();
 * const filtered = lb.exportSQL('users', 'age > 25');
 *
 * // CSV export
 * const csv = lb.exportCSV('users', { header: true, delimiter: ',' });
 *
 * // JSON Lines export
 * const json = lb.exportJSON('users', { pretty: true });
 *
 * // Import
 * const stats = lb.importSQL(dumpString);
 * const result = lb.importCSV('users', csvData, { header: true });
 * ```
 */

import * as path from 'path';
import Database from 'better-sqlite3';
import Piscina from 'piscina';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('LogicalBackup');

// ── Types ────────────────────────────────────────────────────────────────────

export interface ExportSQLOptions {
  /** Emit DROP TABLE IF EXISTS before each CREATE TABLE (default: false) */
  clean?: boolean;
  /** Only output DDL (CREATE TABLE), no INSERT statements (default: false) */
  schemaOnly?: boolean;
  /** Only output INSERT statements, no DDL (default: false) */
  dataOnly?: boolean;
}

export interface ImportSQLOptions {
  /** Number of parallel workers for restore. 0 or undefined = sequential (default: undefined) */
  parallel?: number;
}

export interface CSVOptions {
  /** Include header row (default: true) */
  header?: boolean;
  /** Column delimiter (default: ',') */
  delimiter?: string;
  /** Quote character (default: '"') */
  quoteChar?: string;
  /** Optional WHERE clause (without the WHERE keyword) */
  where?: string;
}

export interface JSONOptions {
  /** Pretty-print each JSON object (default: false) */
  pretty?: boolean;
  /** Optional WHERE clause (without the WHERE keyword) */
  where?: string;
}

export interface ImportSQLResult {
  /** Number of SQL statements executed */
  statements: number;
  /** Total rows affected (INSERTs, UPDATEs, DELETEs, etc.) */
  rows: number;
  /** Duration in milliseconds */
  durationMs: number;
}

export interface ImportCSVResult {
  /** Number of rows successfully inserted */
  rows: number;
  /** Number of rows that failed */
  errors: number;
}

// ── Resolved defaults ────────────────────────────────────────────────────────

const DEFAULT_CSV_OPTIONS: Required<CSVOptions> = {
  header: true,
  delimiter: ',',
  quoteChar: '"',
  where: '',
};

const DEFAULT_JSON_OPTIONS: Required<JSONOptions> = {
  pretty: false,
  where: '',
};

// ── LogicalBackup ────────────────────────────────────────────────────────────

export class LogicalBackup {
  private db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  exportDDL — DDL-only export
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Export only CREATE TABLE statements (no INSERT data).
   *
   * @param opts  Options: clean (add DROP TABLE IF EXISTS before CREATE)
   * @returns SQL DDL script as a string
   */
  exportDDL(opts?: { clean?: boolean }): string {
    const tableNames = this.resolveTables();
    const parts: string[] = [];

    parts.push(`-- LogicalBackup generated at ${new Date().toISOString()}`);
    parts.push('-- Format: SQL (DDL only)');
    parts.push('');

    for (const tbl of tableNames) {
      if (opts?.clean) {
        parts.push(`DROP TABLE IF EXISTS "${tbl}";`);
        parts.push('');
      }

      const createSql = this.getCreateTableSql(tbl);
      parts.push(createSql);
      parts.push('');
    }

    return parts.join('\n');
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  exportData — Data-only export
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Export only INSERT statements (no CREATE TABLE).
   *
   * @param table  Optional table name (export all tables if omitted)
   * @param where  Optional WHERE clause filter (without the WHERE keyword)
   * @param opts   Options: clean (add DELETE FROM before INSERTs per table)
   * @returns SQL data script as a string
   */
  exportData(table?: string, where?: string, opts?: { clean?: boolean }): string {
    const tableNames = this.resolveTables(table);
    const parts: string[] = [];

    parts.push(`-- LogicalBackup generated at ${new Date().toISOString()}`);
    parts.push('-- Format: SQL (data only)');
    parts.push('');

    for (const tbl of tableNames) {
      if (opts?.clean) {
        parts.push(`DELETE FROM "${tbl}";`);
        parts.push('');
      }

      // INSERT rows — WHERE filter only applies when exporting a specific table
      const effectiveWhere = table ? where : undefined;
      const columns = this.getColumnNames(tbl);
      const colList = columns.map((c) => `"${c}"`).join(', ');
      const rows = this.selectRows(tbl, columns, effectiveWhere);

      if (rows.length === 0) {
        parts.push(`-- Table "${tbl}" is empty`);
        parts.push('');
        continue;
      }

      for (const row of rows) {
        const values = columns.map((c) => this.sqlLiteral(row[c]));
        parts.push(
          `INSERT INTO "${tbl}" (${colList}) VALUES (${values.join(', ')});`,
        );
      }
      parts.push('');
    }

    return parts.join('\n');
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  exportSQL — SQL dump
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Export the database (or a single table) as a SQL script containing
   * CREATE TABLE and INSERT INTO statements.
   *
   * @param table  Optional table name (export all tables if omitted)
   * @param where  Optional WHERE clause filter (without the WHERE keyword)
   * @param opts   Export options (clean, schemaOnly, dataOnly)
   * @returns SQL script as a string
   */
  exportSQL(table?: string, where?: string, opts?: ExportSQLOptions): string {
    const options: Required<ExportSQLOptions> = {
      clean: opts?.clean ?? false,
      schemaOnly: opts?.schemaOnly ?? false,
      dataOnly: opts?.dataOnly ?? false,
    };

    const tableNames = this.resolveTables(table);
    const parts: string[] = [];

    parts.push(`-- LogicalBackup generated at ${new Date().toISOString()}`);
    parts.push('-- Format: SQL');
    parts.push('');

    for (const tbl of tableNames) {
      // DROP TABLE IF EXISTS (when clean, always — before DDL and/or data)
      if (options.clean) {
        parts.push(`DROP TABLE IF EXISTS "${tbl}";`);
        parts.push('');
      }

      // CREATE TABLE (unless data-only)
      if (!options.dataOnly) {
        const createSql = this.getCreateTableSql(tbl);
        parts.push(createSql);
        parts.push('');
      }

      // INSERT rows (unless schema-only)
      if (!options.schemaOnly) {
        const effectiveWhere = table ? where : undefined;
        const columns = this.getColumnNames(tbl);
        const colList = columns.map((c) => `"${c}"`).join(', ');
        const rows = this.selectRows(tbl, columns, effectiveWhere);

        if (rows.length === 0) {
          parts.push(`-- Table "${tbl}" is empty`);
          parts.push('');
          continue;
        }

        for (const row of rows) {
          const values = columns.map((c) => this.sqlLiteral(row[c]));
          parts.push(
            `INSERT INTO "${tbl}" (${colList}) VALUES (${values.join(', ')});`,
          );
        }
        parts.push('');
      }
    }

    return parts.join('\n');
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  exportCSV — CSV export
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Export a table as a CSV string.
   *
   * @param table  Table name to export
   * @param opts   CSV options (header, delimiter, quoteChar, where)
   * @returns CSV string
   */
  exportCSV(table: string, opts?: CSVOptions): string {
    const options: Required<CSVOptions> = { ...DEFAULT_CSV_OPTIONS, ...opts };

    // Validate table exists
    this.assertTableExists(table);
    const columns = this.getColumnNames(table);
    const rows = this.selectRows(table, columns, options.where);

    const result: string[] = [];

    // Header row
    if (options.header) {
      result.push(
        columns
          .map((c) => this.csvEscape(c, options.delimiter, options.quoteChar))
          .join(options.delimiter),
      );
    }

    // Data rows
    for (const row of rows) {
      result.push(
        columns
          .map((c) => {
            const val = row[c];
            if (val === null || val === undefined) return '';
            return this.csvEscape(String(val), options.delimiter, options.quoteChar);
          })
          .join(options.delimiter),
      );
    }

    return result.join('\n');
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  exportJSON — JSON Lines export
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Export a table as JSON Lines (one JSON object per row).
   *
   * @param table  Table name to export
   * @param opts   JSON options (pretty, where)
   * @returns JSON string
   */
  exportJSON(table: string, opts?: JSONOptions): string {
    const options: Required<JSONOptions> = { ...DEFAULT_JSON_OPTIONS, ...opts };

    // Validate table exists
    this.assertTableExists(table);
    const columns = this.getColumnNames(table);
    const rows = this.selectRows(table, columns, options.where);

    const lines: string[] = [];

    for (const row of rows) {
      const obj: Record<string, unknown> = {};
      for (const col of columns) {
        const val = row[col];
        // Convert Buffer to hex string for JSON
        if (Buffer.isBuffer(val)) {
          obj[col] = val.toString('hex');
        } else {
          obj[col] = val;
        }
      }

      if (options.pretty) {
        lines.push(JSON.stringify(obj, null, 2));
      } else {
        lines.push(JSON.stringify(obj));
      }
    }

    // If pretty, separate objects with a newline
    if (options.pretty) {
      return lines.join('\n');
    }
    return lines.join('\n');
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  importSQL — SQL import
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Execute a batch of SQL statements.
   *
   * Splits statements by `;\n` (semicolon followed by newline) and executes
   * each one sequentially, tracking total rows affected and duration.
   *
   * When `opts.parallel > 0`, uses Piscina worker pool to restore tables
   * in parallel.  Each worker opens its own database connection and processes
   * a disjoint set of tables, keeping INSERTs to the same table sequential.
   *
   * @param sql   SQL script string
   * @param opts  Import options (parallel)
   * @returns Statistics: statements executed, rows affected, duration in ms
   */
  async importSQL(sql: string, opts?: ImportSQLOptions): Promise<ImportSQLResult> {
    const statements = this.splitStatements(sql);

    if (opts?.parallel && opts.parallel > 1) {
      return this.importSQLParallel(statements, opts.parallel);
    }

    const start = Date.now();
    let totalRows = 0;
    let executed = 0;

    for (const stmt of statements) {
      try {
        const info = this.db.prepare(stmt).run();
        totalRows += info.changes;
        executed++;
      } catch (err: any) {
        logger.warn({ statement: stmt.slice(0, 80) }, `[importSQL] Skipping statement: ${err.message}`);
        // Still count as executed (attempted)
        executed++;
      }
    }

    const durationMs = Date.now() - start;

    logger.info(
      { statements: executed, rows: totalRows, durationMs },
      '[importSQL] Import completed',
    );

    return { statements: executed, rows: totalRows, durationMs };
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  importCSV — CSV import
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Import data from a CSV string into a table.
   *
   * Parses the CSV (first row is treated as header by default), then
   * inserts rows in batches of 100 for performance.
   *
   * @param table   Target table name
   * @param csv     CSV data string
   * @param opts    CSV options (header, delimiter, quoteChar)
   * @returns Import statistics: rows inserted, errors encountered
   */
  importCSV(table: string, csv: string, opts?: CSVOptions): ImportCSVResult {
    const options: Required<CSVOptions> = { ...DEFAULT_CSV_OPTIONS, ...opts };

    // Parse all rows
    const lines = this.parseCSV(csv, options.delimiter, options.quoteChar);

    if (lines.length === 0 || (lines.length === 1 && lines[0].length === 1 && lines[0][0] === '')) {
      return { rows: 0, errors: 0 };
    }

    // Determine columns
    let columns: string[];
    let dataLines: string[][];

    if (options.header) {
      columns = lines[0];
      dataLines = lines.slice(1);
    } else {
      // No header — use existing table columns
      columns = this.getColumnNames(table);
      dataLines = lines;
    }

    if (columns.length === 0) {
      throw new Error('CSV import failed: no columns available');
    }

    // Normalise row lengths
    for (let i = 0; i < dataLines.length; i++) {
      const row = dataLines[i];
      while (row.length < columns.length) row.push('');
      dataLines[i] = row.slice(0, columns.length);
    }

    // Prepare INSERT statement
    const placeholders = columns.map(() => '?').join(', ');
    const colList = columns.map((c) => `"${c}"`).join(', ');
    const insert = this.db.prepare(
      `INSERT INTO "${table}" (${colList}) VALUES (${placeholders})`,
    );

    // Batch insert in a transaction
    const BATCH_SIZE = 100;
    let inserted = 0;
    let errors = 0;

    const insertBatch = this.db.transaction((batch: string[][]) => {
      for (const row of batch) {
        try {
          const params = row.map((v) => (v === '' && this.shouldTreatEmptyAsNull(v, row, columns) ? null : v));
          insert.run(...params);
          inserted++;
        } catch {
          errors++;
        }
      }
    });

    for (let i = 0; i < dataLines.length; i += BATCH_SIZE) {
      const batch = dataLines.slice(i, i + BATCH_SIZE);
      insertBatch(batch);
    }

    logger.info(
      { table, rows: inserted, errors },
      '[importCSV] Import completed',
    );

    return { rows: inserted, errors };
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  Private helpers: table discovery
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Resolve the list of table names to export.
   * If a specific table is given, validates it exists.
   */
  private resolveTables(table?: string): string[] {
    if (table) {
      const exists = this.db
        .prepare(
          `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`,
        )
        .get(table);
      if (!exists) {
        throw new Error(`Table "${table}" does not exist`);
      }
      return [table];
    }

    const rows = this.db
      .prepare(
        `SELECT name FROM sqlite_master
         WHERE type='table'
           AND name NOT LIKE 'sqlite_%'
           AND substr(name, 1, 4) != 'vec_'
         ORDER BY name`,
      )
      .all() as Array<{ name: string }>;

    return rows.map((r) => r.name);
  }

  /**
   * Get the CREATE TABLE SQL for a given table.
   */
  private getCreateTableSql(table: string): string {
    const row = this.db
      .prepare(
        `SELECT sql FROM sqlite_master WHERE type='table' AND name = ?`,
      )
      .get(table) as { sql: string } | undefined;

    if (!row || !row.sql) {
      throw new Error(`Cannot find CREATE TABLE for "${table}"`);
    }

    const sql = row.sql.trim();
    return sql.endsWith(';') ? sql : sql + ';';
  }

  /**
   * Assert that a table exists in the database.
   * @throws {Error} If the table does not exist
   */
  private assertTableExists(table: string): void {
    const exists = this.db
      .prepare(
        `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`,
      )
      .get(table);
    if (!exists) {
      throw new Error(`Table "${table}" does not exist`);
    }
  }

  /**
   * Get column names for a table (from PRAGMA table_info).
   */
  private getColumnNames(table: string): string[] {
    const cols = this.db
      .prepare(`SELECT name FROM pragma_table_info(?) ORDER BY cid`)
      .all(table) as Array<{ name: string }>;

    return cols.map((c) => c.name);
  }

  /**
   * Select rows from a table, optionally filtered by a WHERE clause.
   */
  private selectRows(
    table: string,
    columns: string[],
    where?: string,
  ): Array<Record<string, unknown>> {
    const quotedCols = columns.map((c) => `"${c}"`).join(', ');
    let sql = `SELECT ${quotedCols} FROM "${table}"`;

    if (where && where.trim().length > 0) {
      sql += ` WHERE ${where}`;
    }

    return this.db.prepare(sql).all() as Array<Record<string, unknown>>;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  Private helpers: SQL literal formatting
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Convert a JavaScript value to a SQL literal string.
   */
  private sqlLiteral(val: unknown): string {
    if (val === null || val === undefined) return 'NULL';
    if (typeof val === 'number') return String(val);
    if (typeof val === 'boolean') return val ? '1' : '0';
    if (Buffer.isBuffer(val)) return `X'${val.toString('hex')}'`;
    if (typeof val === 'bigint') return String(val);
    // String: escape single quotes by doubling them
    const str = String(val).replace(/'/g, "''");
    return `'${str}'`;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  Private helpers: CSV formatting
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Escape a value for CSV output.
   *
   * Wraps in quotes if the value contains the delimiter, quote char, or newlines.
   * Embedded quote characters are doubled.
   */
  private csvEscape(val: string, delimiter: string, quoteChar: string): string {
    const needsQuoting =
      val.includes(delimiter) ||
      val.includes(quoteChar) ||
      val.includes('\n') ||
      val.includes('\r');

    if (!needsQuoting) return val;

    const escaped = val.replace(new RegExp(quoteChar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), quoteChar + quoteChar);
    return `${quoteChar}${escaped}${quoteChar}`;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  Private helpers: CSV parsing
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Parse a CSV string into rows of field arrays.
   * Handles quoted fields with embedded quotes (doubled) and delimiters.
   */
  private parseCSV(
    csv: string,
    delimiter: string,
    quoteChar: string,
  ): string[][] {
    const rows: string[][] = [];
    const chars = csv.split('');
    const len = chars.length;
    const escQuote = quoteChar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    let i = 0;
    let currentRow: string[] = [];
    let currentField = '';
    let inQuotes = false;

    while (i < len) {
      const ch = chars[i];

      if (inQuotes) {
        if (ch === quoteChar) {
          // Check for doubled quote (escaped)
          if (i + 1 < len && chars[i + 1] === quoteChar) {
            currentField += quoteChar;
            i += 2;
            continue;
          }
          // End of quoted field
          inQuotes = false;
          i++;
          continue;
        }
        currentField += ch;
        i++;
        continue;
      }

      // Not in quotes
      if (ch === delimiter) {
        currentRow.push(currentField);
        currentField = '';
        i++;
        continue;
      }

      if (ch === '\n') {
        // End of row
        currentRow.push(currentField);
        // Flush trailing empty fields only if the last char was the delimiter
        if (currentField === '') {
          // Keep as-is
        }
        rows.push(currentRow);
        currentRow = [];
        currentField = '';
        i++;
        continue;
      }

      if (ch === '\r') {
        // CR — skip, LF will handle the row break
        i++;
        continue;
      }

      if (ch === quoteChar) {
        inQuotes = true;
        i++;
        continue;
      }

      currentField += ch;
      i++;
    }

    // Flush last field/row
    currentRow.push(currentField);
    if (currentRow.length > 0 || currentField !== '') {
      rows.push(currentRow);
    }

    return rows;
  }

  /**
   * Determine if an empty field value should be treated as NULL.
   * In CSV, empty fields cannot be distinguished from NULL — we treat them
   * as NULL for maximum fidelity (especially for roundtrip export→import).
   */
  private shouldTreatEmptyAsNull(
    _val: string,
    _row: string[],
    _columns: string[],
  ): boolean {
    return true;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  Private helpers: parallel restore
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Restore a set of SQL statements in parallel using a Piscina worker pool.
   *
   * Groups statements by table name so INSERTs to the same table are always
   * sequential within a single worker.  Each worker opens its own connection
   * to the database.
   */
  private async importSQLParallel(
    statements: string[],
    numWorkers: number,
  ): Promise<ImportSQLResult> {
    const dbPath = this.getDatabasePath();
    const start = Date.now();

    // Group statements by table
    const tableGroups = new Map<string, string[]>();
    const globalStmts: string[] = [];

    for (const stmt of statements) {
      const table = this.extractTableNameFromStatement(stmt);
      if (table) {
        if (!tableGroups.has(table)) {
          tableGroups.set(table, []);
        }
        tableGroups.get(table)!.push(stmt);
      } else {
        globalStmts.push(stmt);
      }
    }

    // Convert to array entries for round-robin distribution
    const entries: Array<{ table: string; statements: string[] }> = [];
    const groupEntries = Array.from(tableGroups.entries());
    for (let ei = 0; ei < groupEntries.length; ei++) {
      const [table, stmts] = groupEntries[ei];
      entries.push({ table, statements: stmts });
    }

    // If no table groups and only global statements, run sequentially
    if (entries.length === 0) {
      const seqResult = this.importSQLSequential(statements);
      const seqDurationMs = Date.now() - start;
      return { statements: seqResult.statements, rows: seqResult.rows, durationMs: seqDurationMs };
    }

    // Distribute table groups across workers round-robin
    const workerBatches: Array<Array<{ table: string; statements: string[] }>> =
      Array.from({ length: numWorkers }, () => []);

    for (let i = 0; i < entries.length; i++) {
      workerBatches[i % numWorkers].push(entries[i]);
    }

    // Create Piscina pool
    const pool = new Piscina({
      filename: path.resolve(__dirname, 'LogicalBackupWorker.js'),
    });

    let totalRows = 0;
    let totalStatements = 0;

    try {
      const promises = workerBatches.map((batch) => {
        if (batch.length === 0) return Promise.resolve({ rows: 0, statements: 0 });
        return pool.run({ dbPath, tableGroups: batch });
      });

      const results = await Promise.all(promises);
      for (const r of results) {
        totalRows += r.rows;
        totalStatements += r.statements;
      }
    } finally {
      await pool.destroy();
    }

    // Execute global statements (DDL without table reference) sequentially
    if (globalStmts.length > 0) {
      const globalResult = this.importSQLSequential(globalStmts);
      totalRows += globalResult.rows;
      totalStatements += globalResult.statements;
    }

    const durationMs = Date.now() - start;

    logger.info(
      { statements: totalStatements, rows: totalRows, durationMs, parallel: numWorkers },
      '[importSQL] Parallel import completed',
    );

    return { statements: totalStatements, rows: totalRows, durationMs };
  }

  /**
   * Execute SQL statements sequentially (sync helper for parallel path).
   */
  private importSQLSequential(
    statements: string[],
  ): { rows: number; statements: number } {
    let totalRows = 0;
    let executed = 0;

    for (const stmt of statements) {
      try {
        const info = this.db.prepare(stmt).run();
        totalRows += info.changes;
        executed++;
      } catch (err: any) {
        logger.warn({ statement: stmt.slice(0, 80) }, `[importSQL] Skipping statement: ${err.message}`);
        executed++;
      }
    }

    return { rows: totalRows, statements: executed };
  }

  /**
   * Get the file path of the connected database.
   * @throws If the database is in-memory (no file path)
   */
  private getDatabasePath(): string {
    // better-sqlite3 exposes the database path via the `name` property
    const name = (this.db as any).name;
    if (!name || name === ':memory:') {
      throw new Error(
        'Parallel restore is not supported for in-memory databases. ' +
        'Use a file-based database or set parallel to 0.',
      );
    }
    return name;
  }

  /**
   * Extract the table name from a SQL statement (CREATE TABLE, INSERT INTO, DROP TABLE).
   * Returns null if no table name can be identified.
   */
  private extractTableNameFromStatement(stmt: string): string | null {
    // Match CREATE TABLE, INSERT INTO, DROP TABLE (with optional IF EXISTS / IF NOT EXISTS)
    const match = stmt.trim().match(
      /(?:CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?|INSERT\s+INTO|DROP\s+TABLE(?:\s+IF\s+EXISTS)?)\s+(?:["`]?)(\w+)(?:["`]?)/i,
    );
    return match ? match[1] : null;
  }

  // ──────────────────────────────────────────────────────────────────────────
  //  Private helpers: SQL statement splitting
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Split a SQL script into individual statements.
   *
   * Handles string literals (single-quoted) to avoid splitting on
   * semicolons that appear inside values.
   */
  private splitStatements(sql: string): string[] {
    const statements: string[] = [];
    const len = sql.length;
    let current = '';
    let inString = false;

    for (let i = 0; i < len; i++) {
      const ch = sql[i];

      if (inString) {
        current += ch;
        if (ch === "'") {
          // Check for doubled quote (escaped)
          if (i + 1 < len && sql[i + 1] === "'") {
            current += "'";
            i++;
          } else {
            inString = false;
          }
        }
        continue;
      }

      if (ch === "'") {
        inString = true;
        current += ch;
        continue;
      }

      if (ch === ';') {
        // Check if followed by newline or end-of-string
        statements.push((current + ';').trim());
        current = '';
        i++;
        continue;
      }

      current += ch;
    }

    // Flush remaining
    const remaining = current.trim();
    if (remaining) {
      statements.push(remaining);
    }

    // Filter out empty/whitespace-only statements
    return statements.filter((s) => s.length > 0);
  }
}
