/**
 * CopyProtocol — PgWire COPY sub-protocol implementation
 *
 * Manages the COPY state machine for CopyIn (COPY FROM STDIN) and
 * CopyOut (COPY TO STDOUT) flows. Handles query parsing, data
 * accumulation, and integration with the database layer.
 *
 * Wire message types used:
 *   CopyInResponse  ('G' = 0x47)
 *   CopyOutResponse ('H' = 0x48)
 *   CopyData        ('d' = 0x64)
 *   CopyDone        ('c' = 0x63)
 *   CopyFail        ('f' = 0x66)
 *
 * CopyIn flow:
 *   Server → Client: CopyInResponse ('G')
 *   Client → Server: CopyData ('d') × N
 *   Client → Server: CopyDone ('c')
 *   Server → Client: CommandComplete
 *
 * CopyOut flow:
 *   Server → Client: CopyOutResponse ('H')
 *   Server → Client: CopyData ('d') × N
 *   Server → Client: CopyDone ('c')
 *   Server → Client: CommandComplete
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { CopyHandler, CopyFormat as HandlerCopyFormat } from './CopyHandler';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
  SQLSTATE_SYNTAX_ERROR,
} from '../constants/sqlstate';

const logger = PinoLogger.forComponent('CopyProtocol');

// ── Copy Format Enum ──────────────────────────────

export enum CopyFormat {
  TEXT = 0,
  BINARY = 1,
  CSV = 2,
}

// ── Wire Message Type Constants ──────────────────

export const COPY_WIRE_TYPES = {
  CopyData: 0x64,  // 'd'
  CopyDone: 0x63,  // 'c'
  CopyFail: 0x66,  // 'f'
  CopyInResponse: 0x47,  // 'G'
  CopyOutResponse: 0x48, // 'H'
} as const;

// ── Copy Direction ───────────────────────────────

export enum CopyDirection {
  IN = 'in',
  OUT = 'out',
  IDLE = 'idle',
}

// ── Parsed COPY Query ────────────────────────────

export interface ParsedCopyQuery {
  /** The COPY direction */
  direction: 'in' | 'out';
  /** Target table name (with possible schema prefix stripped) */
  tableName: string;
  /** Optional column list (empty = all columns) */
  columns: string[];
  /** Format specifier */
  format: CopyFormat;
  /** Original query string */
  sql: string;
}

// ── Copy Result ──────────────────────────────────

export interface CopyResult {
  /** Number of rows processed */
  rowCount: number;
  /** Duration in milliseconds */
  durationMs: number;
}

// ── Internal CopyState ───────────────────────────

interface CopyInState {
  direction: CopyDirection.IN;
  tableName: string;
  columns: string[];
  format: CopyFormat;
  dataBuffer: Buffer;
}

interface CopyOutState {
  direction: CopyDirection.OUT;
  tableName: string;
  columns: string[];
  format: CopyFormat;
  /** All rows fetched from DB, pre-formatted as strings */
  rows: string[];
  /** Current index into rows array */
  index: number;
}

type CopyState = CopyInState | CopyOutState | { direction: CopyDirection.IDLE };

// ── Query Executor interface ─────────────────────

/**
 * Minimal query executor abstraction.
 * In production this wraps QueryRouter; in tests a mock can be used.
 */
export interface QueryExecutor {
  execute(sql: string, params?: any[]): Promise<{ rows: any[]; rowCount: number }>;
}

// ── CopyProtocol class ───────────────────────────

export class CopyProtocol {
  private executor: QueryExecutor;
  private state: CopyState = { direction: CopyDirection.IDLE };
  private _copyHandler: CopyHandler | null = null;

  constructor(executor: QueryExecutor) {
    this.executor = executor;
  }

  // ── Public State ──────────────────────────────

  /** Whether a COPY operation is currently active. */
  get isActive(): boolean {
    return this.state.direction !== CopyDirection.IDLE;
  }

  /** The current copy direction. */
  get direction(): CopyDirection {
    return this.state.direction;
  }

  /** The current copy format. */
  get format(): CopyFormat {
    if (this.state.direction === CopyDirection.IDLE) return CopyFormat.TEXT;
    return this.state.format;
  }

  /** The table name from the COPY statement. */
  get tableName(): string {
    if (this.state.direction === CopyDirection.IDLE) return '';
    return this.state.tableName;
  }

  /** The columns (may be empty = all columns). */
  get columns(): string[] {
    if (this.state.direction === CopyDirection.IDLE) return [];
    return this.state.columns;
  }

  // ── Query Parsing ─────────────────────────────

  /**
   * Parse a COPY SQL statement and extract metadata.
   *
   * Supported forms:
   *   COPY table_name [(col1, col2, ...)] FROM STDIN [WITH (FORMAT csv|text|binary)]
   *   COPY table_name [(col1, col2, ...)] TO STDOUT [WITH (FORMAT csv|text|binary)]
   *   COPY (SELECT ...) TO STDOUT [WITH (FORMAT csv|text|binary)]
   */
  static parseQuery(sql: string): ParsedCopyQuery | null {
    const trimmed = sql.trim().replace(/\s+/g, ' ');
    const upper = trimmed.toUpperCase();

    if (!upper.startsWith('COPY ')) return null;

    // Detect direction
    const isFrom = /FROM\s+STDIN\b/i.test(trimmed);
    const isTo = /TO\s+STDOUT\b/i.test(trimmed);

    if (!isFrom && !isTo) return null;
    const direction: 'in' | 'out' = isFrom ? 'in' : 'out';

    // Extract table name: COPY <table_name> [(...)] FROM/TO ...
    let tableName = '';
    let columns: string[] = [];
    let format: CopyFormat = CopyFormat.TEXT;

    const afterCopy = trimmed.replace(/^COPY\s+/i, '');

    // Check if this is a subquery form: COPY (SELECT ...) TO STDOUT
    if (afterCopy.startsWith('(')) {
      // Subquery form — extract table name from the subquery
      // For simplicity, use a placeholder
      tableName = 'subquery';
    } else {
      // Simple form: COPY tablename [(columns)] FROM/TO ...
      const match = afterCopy.match(/^"?(\w+)"?(?:\s*\(([^)]*)\))?\s+(FROM|TO)\s+(STDIN|STDOUT)/i);
      if (match) {
        tableName = match[1]!.replace(/['"]/g, '');

        // Parse column list if present
        if (match[2]) {
          columns = match[2]!.split(',').map((c) => c.trim().replace(/['"]/g, ''));
        }

        // Parse WITH options to detect format
        const withMatch = trimmed.match(/WITH\s*\(([^)]+)\)/i);
        if (withMatch) {
          const opts = withMatch[1]!.toLowerCase();
          if (/\bformat\s*=\s*binary\b/.test(opts) || /\bformat\s+binary\b/.test(opts)) {
            format = CopyFormat.BINARY;
          } else if (/\bformat\s*=\s*csv\b/.test(opts) || /\bformat\s+csv\b/.test(opts)) {
            format = CopyFormat.CSV;
          }
        }

        // Detect CSV format from WITH CSV keyword
        if (/\b(?:WITH\s+)?CSV\b/i.test(trimmed)) {
          format = CopyFormat.CSV;
        }
      }
    }

    if (!tableName) return null;

    return { direction, tableName, columns, format, sql: trimmed };
  }

  // ── CopyIn (Client → Server) ─────────────────

  /**
   * Initialize a CopyIn session (COPY table FROM STDIN).
   *
   * Parses the query, validates the target table, sends CopyInResponse via
   * the callback, and transitions to CopyIn state.
   *
   * @param query    The COPY FROM STDIN SQL statement
   * @param format   Copy format (TEXT, BINARY, CSV)
   * @param sendFn   Optional callback to send wire messages (CopyInResponse)
   */
  async handleCopyIn(query: string, format: CopyFormat): Promise<void> {
    if (this.isActive) {
      throw new DatabaseError(`Copy already active in direction ${this.state.direction}`, SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const parsed = CopyProtocol.parseQuery(query);
    if (!parsed || parsed.direction !== 'in') {
      throw new DatabaseError(`Invalid COPY FROM STDIN statement: ${query}`, SQLSTATE_SYNTAX_ERROR);
    }

    const tableName = parsed.tableName;
    const columns = parsed.columns;
    const resolvedFormat = format;

    logger.info({ tableName, columns, format: resolvedFormat }, 'Starting CopyIn');

    this.state = {
      direction: CopyDirection.IN,
      tableName,
      columns,
      format: resolvedFormat,
      dataBuffer: Buffer.alloc(0),
    };

    logger.debug({ tableName, columns, format: resolvedFormat }, 'CopyIn initialized');
  }

  /**
   * Handle an incoming CopyData message ('d').
   * Accumulates row data into the internal buffer.
   *
   * @param data  Raw payload from CopyData wire message (not including type/length)
   */
  handleCopyData(data: Buffer): void {
    if (this.state.direction !== CopyDirection.IN) {
      logger.warn('Received CopyData but not in CopyIn state — ignoring');
      return;
    }

    const inState = this.state as CopyInState;
    inState.dataBuffer = Buffer.concat([inState.dataBuffer, data]);
    logger.trace({ bytesReceived: data.length, totalBytes: inState.dataBuffer.length }, 'CopyData received');
  }

  /**
   * Handle CopyDone ('c') — finalize the CopyIn session.
   * Parses accumulated data and inserts rows into the database.
   *
   * @returns  Result with row count and duration
   */
  async handleCopyDone(): Promise<CopyResult> {
    if (this.state.direction !== CopyDirection.IN) {
      throw new DatabaseError('Not in CopyIn state', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const inState = this.state as CopyInState;
    const startTime = Date.now();

    try {
      const dataStr = inState.dataBuffer.toString('utf-8');
      const rows = this.parseCopyData(dataStr, inState.format);
      const rowCount = rows.length;

      if (rowCount === 0) {
        logger.info({ tableName: inState.tableName }, 'CopyDone with zero rows');
        const durationMs = Date.now() - startTime;
        return { rowCount: 0, durationMs };
      }

      // Insert rows using CopyHandler
      const result = await this.executeInserts(inState.tableName, inState.columns, rows, inState.format);
      const durationMs = Date.now() - startTime;
      logger.info({ tableName: inState.tableName, rowCount: result, durationMs }, 'CopyIn completed');
      return { rowCount: result, durationMs };
    } finally {
      this.reset();
    }
  }

  /**
   * Handle CopyFail ('f') — abort the CopyIn session.
   * Buffered data is discarded.
   *
   * @param errorMsg  Error message from client
   */
  handleCopyFail(errorMsg: string): void {
    if (this.state.direction !== CopyDirection.IN) {
      logger.warn('Received CopyFail but not in CopyIn state — ignoring');
      return;
    }

    logger.warn({ errorMsg, tableName: this.state.tableName }, 'CopyIn failed by client');
    this.reset();
  }

  // ── CopyOut (Server → Client) ────────────────

  /**
   * Initialize a CopyOut session (COPY table TO STDOUT).
   *
   * Parses the query, fetches data from the database, formats rows as
   * COPY data lines, and transitions to CopyOut state. Data is retrieved
   * via iterateCopyData() for streaming to the client.
   *
   * @param query    The COPY TO STDOUT SQL statement
   * @param format   Copy format (TEXT, BINARY, CSV)
   */
  async handleCopyOut(query: string, format: CopyFormat): Promise<void> {
    if (this.isActive) {
      throw new DatabaseError(`Copy already active in direction ${this.state.direction}`, SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const parsed = CopyProtocol.parseQuery(query);
    if (!parsed || parsed.direction !== 'out') {
      throw new DatabaseError(`Invalid COPY TO STDOUT statement: ${query}`, SQLSTATE_SYNTAX_ERROR);
    }

    const tableName = parsed.tableName;
    const columns = parsed.columns;
    const resolvedFormat = format;

    logger.info({ tableName, columns, format: resolvedFormat }, 'Starting CopyOut');

    // Resolve columns if empty
    let resolvedColumns = columns;
    if (resolvedColumns.length === 0 && tableName !== 'subquery') {
      resolvedColumns = await this.resolveTableColumns(tableName);
    }
    // For subquery form, we fetch columns from the result set
    if (resolvedColumns.length === 0 && tableName === 'subquery') {
      resolvedColumns = ['*'];
    }

    // Fetch rows from database
    const selectSql = resolvedColumns.length === 0 || (resolvedColumns.length === 1 && resolvedColumns[0] === '*')
      ? `SELECT * FROM "${tableName}"`
      : `SELECT ${resolvedColumns.map((c) => `"${c}"`).join(', ')} FROM "${tableName}"`;

    const result = await this.executor.execute(selectSql);

    const rows = result.rows;
    const activeColumns = rows.length > 0 ? Object.keys(rows[0]) : resolvedColumns;

    // Pre-format rows into COPY data lines
    const formattedLines: string[] = [];
    for (const row of rows) {
      const line = this.formatRow(row, activeColumns, resolvedFormat);
      formattedLines.push(line);
    }

    this.state = {
      direction: CopyDirection.OUT,
      tableName,
      columns: activeColumns,
      format: resolvedFormat,
      rows: formattedLines,
      index: 0,
    };

    logger.debug({ tableName, columns: activeColumns, rowCount: formattedLines.length, format: resolvedFormat }, 'CopyOut initialized');
  }

  /**
   * Iterate over CopyOut data. Returns the next chunk of formatted data
   * as a COPY data string (rows separated by newlines, suitable for
   * sending as CopyData wire messages).
   *
   * @param maxRows  Maximum number of rows per chunk (default: 100)
   * @returns        A string of COPY data rows, or empty string if done
   */
  iterateCopyData(maxRows: number = 100): string {
    if (this.state.direction !== CopyDirection.OUT) {
      throw new DatabaseError('Not in CopyOut mode', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const outState = this.state as CopyOutState;
    if (outState.index >= outState.rows.length) return '';

    const end = Math.min(outState.index + maxRows, outState.rows.length);
    const lines = outState.rows.slice(outState.index, end);
    outState.index = end;

    // Join rows with newlines, add trailing newline for COPY wire format
    return lines.join('\n') + '\n';
  }

  /**
   * Finalize a CopyOut session.
   * Returns the total number of rows sent.
   */
  async handleCopyOutComplete(): Promise<CopyResult> {
    if (this.state.direction !== CopyDirection.OUT) {
      throw new DatabaseError('Not in CopyOut mode', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const outState = this.state as CopyOutState;
    const rowCount = outState.index; // rows actually iterated
    const durationMs = 0; // caller tracks duration

    this.reset();
    return { rowCount, durationMs };
  }

  // ── State Management ─────────────────────────

  /**
   * Reset the copy state to idle.
   */
  reset(): void {
    this.state = { direction: CopyDirection.IDLE };
    this._copyHandler = null;
  }

  // ── CSV Support ──────────────────────────────

  /**
   * Parse a CSV line into fields, handling quoted fields.
   *
   * @param line  A single CSV line
   * @returns     Array of field values
   */
  static parseCsvLine(line: string): string[] {
    const fields: string[] = [];
    let current = '';
    let inQuotes = false;
    let i = 0;

    while (i < line.length) {
      const ch = line[i];
      const next = i + 1 < line.length ? line[i + 1] : '';

      if (inQuotes) {
        if (ch === '"' && next === '"') {
          // Escaped quote
          current += '"';
          i += 2;
        } else if (ch === '"') {
          inQuotes = false;
          i++;
        } else {
          current += ch;
          i++;
        }
      } else if (ch === '"') {
        inQuotes = true;
        i++;
      } else if (ch === ',') {
        fields.push(current);
        current = '';
        i++;
      } else {
        current += ch;
        i++;
      }
    }

    fields.push(current);
    return fields;
  }

  /**
   * Parse a CSV row into fields, handling quoted fields and newlines
   * within quoted values.
   */
  static parseCsvRow(lines: string[], startIndex: number): { fields: string[]; endIndex: number } | null {
    if (startIndex >= lines.length) return null;
    const allText = lines.slice(startIndex).join('\n');
    const fields = CopyProtocol.parseCsvLine(allText);

    // Count quotes to detect if we have unclosed quotes (multi-line fields)
    const quoteCount = (allText.match(/"/g) || []).length;
    if (quoteCount % 2 !== 0) {
      // Unclosed quotes — need more lines (but we process what we have)
      return { fields, endIndex: lines.length };
    }

    return { fields, endIndex: startIndex + 1 };
  }

  // ── Private Helpers ──────────────────────────

  /**
   * Parse accumulated COPY data into an array of row values.
   */
  private parseCopyData(data: string, format: CopyFormat): string[][] {
    if (data.length === 0) return [];

    if (format === CopyFormat.CSV) {
      return this.parseCsvData(data);
    }

    // TEXT format: lines separated by '\n', fields by '\t'
    const lines = data.split('\n').filter((l) => l.trim().length > 0);
    return lines.map((line) => {
      const fields: string[] = [];
      let current = '';
      let inQuotes = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (inQuotes) {
          if (ch === '"' && i + 1 < line.length && line[i + 1] === '"') {
            current += '"';
            i++;
          } else if (ch === '"') {
            inQuotes = false;
          } else {
            current += ch;
          }
        } else if (ch === '"') {
          inQuotes = true;
        } else if (ch === '\t') {
          fields.push(current);
          current = '';
        } else {
          current += ch;
        }
      }
      fields.push(current);
      return fields;
    });
  }

  /**
   * Parse CSV data into rows.
   * Handles quoted fields (including multi-line quoted fields by detecting
   * unclosed quotes and merging subsequent lines).
   */
  private parseCsvData(data: string): string[][] {
    const rawLines = data.split('\n');
    const rows: string[][] = [];
    let pending: string[] | null = null;

    for (const line of rawLines) {
      const trimmed = line.trim();
      if (trimmed.length === 0 && pending === null) continue;

      if (pending !== null) {
        // Append to pending multi-line field
        pending.push(trimmed);
        const merged = pending.join('\n');
        // Check if quotes are now balanced
        const quoteCount = (merged.match(/"/g) || []).length;
        if (quoteCount % 2 === 0) {
          rows.push(CopyProtocol.parseCsvLine(merged));
          pending = null;
        }
      } else {
        // Try to parse as a complete line
        const quoteCount = (trimmed.match(/"/g) || []).length;
        if (quoteCount % 2 === 0) {
          // Balanced quotes — simple single-line row
          rows.push(CopyProtocol.parseCsvLine(trimmed));
        } else {
          // Unclosed quote — start multi-line accumulation
          pending = [trimmed];
        }
      }
    }

    // If we have an unclosed multi-line field at end, parse what we have
    if (pending !== null) {
      rows.push(CopyProtocol.parseCsvLine(pending.join('\n')));
    }

    return rows;
  }

  /**
   * Format a single row for COPY output.
   */
  private formatRow(row: Record<string, any>, columns: string[], format: CopyFormat): string {
    const values = columns.map((col) => {
      const val = row[col];
      if (val === null || val === undefined) return '\\N';

      const str = String(val);

      if (format === CopyFormat.CSV) {
        // CSV: quote if contains comma, quote, or newline
        if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      }

      // TEXT: tab-separated, escape special chars
      if (str.includes('\t') || str.includes('\n') || str.includes('\\')) {
        return str.replace(/\\/g, '\\\\').replace(/\t/g, '\\t').replace(/\n/g, '\\n');
      }
      return str;
    });

    const delimiter = format === CopyFormat.CSV ? ',' : '\t';
    return values.join(delimiter);
  }

  /**
   * Execute INSERT statements for parsed COPY rows.
   */
  private async executeInserts(
    tableName: string,
    columns: string[],
    rows: string[][],
    format: CopyFormat,
  ): Promise<number> {
    // Build the INSERT SQL
    let resolvedColumns = columns;
    if (resolvedColumns.length === 0) {
      resolvedColumns = await this.resolveTableColumns(tableName);
    }

    const colList = resolvedColumns.map((c) => `"${c}"`).join(', ');
    const placeholders = resolvedColumns.map(() => '?').join(', ');
    const insertSql = `INSERT INTO "${tableName}" (${colList}) VALUES (${placeholders})`;

    let inserted = 0;
    for (const row of rows) {
      const values = row.map((f, i) => {
        if (f === '\\N' || f === '') return null;

        // Try numeric conversion for values that look like numbers
        if (/^-?\d+$/.test(f)) return parseInt(f, 10);
        if (/^-?\d+\.?\d*(?:[eE][+-]?\d+)?$/.test(f) && f.includes('.')) return parseFloat(f);

        return f;
      });

      // Pad or truncate to match column count
      while (values.length < resolvedColumns.length) values.push(null);
      const finalValues = values.slice(0, resolvedColumns.length);

      await this.executor.execute(insertSql, finalValues);
      inserted++;
    }

    return inserted;
  }

  /**
   * Resolve table columns from database metadata.
   */
  private async resolveTableColumns(tableName: string): Promise<string[]> {
    try {
      const infoResult = await this.executor.execute(`PRAGMA table_info("${tableName}")`);
      return infoResult.rows.map((r: any) => r.name);
    } catch {
      // Fallback: try to infer from a SELECT *
      try {
        const sampleResult = await this.executor.execute(`SELECT * FROM "${tableName}" LIMIT 0`);
        if (sampleResult.rows.length > 0) {
          return Object.keys(sampleResult.rows[0]);
        }
      } catch {
        // ignore
      }
      return [];
    }
  }

  // ── Column List Parsing ─────────────────────

  /**
   * Parse a column list string from a COPY statement.
   *
   * @param colStr  Column list string like "col1, col2, col3"
   * @returns       Array of column names
   */
  static parseColumnList(colStr: string): string[] {
    if (!colStr || colStr.trim().length === 0) return [];
    return colStr
      .split(',')
      .map((c) => c.trim().replace(/['"]/g, ''))
      .filter((c) => c.length > 0);
  }
}
