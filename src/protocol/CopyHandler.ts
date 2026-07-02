/**
 * CopyHandler — PG Wire COPY protocol handling (CopyIn / CopyOut)
 *
 * Implements the PostgreSQL COPY sub-protocol for transferring data between
 * a client and the server.  Two modes:
 *
 * - CopyIn:   Client sends data → server (COPY table FROM STDIN)
 * - CopyOut:  Server sends data → client (COPY table TO STDOUT)
 *
 * This is a pure-data handler: it encodes/decodes COPY data messages
 * and manages the state machine.  The actual socket I/O is owned by
 * PgWireServer.
 *
 * COPY protocol (from PG wire spec):
 *
 * CopyIn flow:
 *   Server: CopyInResponse ('G')
 *   Client: CopyData ('d')  ×N
 *   Client: CopyDone ('c')
 *   Server: CommandComplete | ErrorResponse
 *
 * CopyOut flow:
 *   Client: CopyOutResponse ('H')
 *   Server: CopyData ('d')  ×N
 *   Server: CopyDone ('c')
 *   Client: CommandComplete
 *
 * CopyData message format (on wire):
 *   char    type = 'd'    (0x64)
 *   int32   length        (including self)
 *   byte[]  payload
 */

/**
 * COPY BINARY (PG binary format) support.
 *
 * PostgreSQL COPY BINARY format structure:
 *   Header: 11 bytes [PGCOPY\n\377\r\n\0]
 *   Flags:  int32 (bit 0 = OIDs included, bits 16-31 = extra header)
 *   HeaderExt: int32 length + bytes (if flags.bit 16 set)
 *   Per-tuple:
 *     int16 field_count
 *     For each field:
 *       int32 length (-1 = NULL) + bytes
 *   Trailer: int16 -1 (field count = -1 signals end)
 *
 * See: https://www.postgresql.org/docs/current/sql-copy.html#id-1.9.3.8.9
 */

import Database from 'better-sqlite3';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE,
} from '../constants/sqlstate';

// ── Types ──────────────────────────────────────────

export enum CopyDirection {
  /** Client → Server (COPY FROM STDIN) */
  IN = 'in',
  /** Server → Client (COPY TO STDOUT) */
  OUT = 'out',
}

export enum CopyFormat {
  TEXT = 0,
  BINARY = 1,
  CSV = 2,
}

export interface CopyInResponse {
  direction: CopyDirection.IN;
  format: CopyFormat;
  columns: string[];
}

export interface CopyOutResponse {
  direction: CopyDirection.OUT;
  format: CopyFormat;
  columns: string[];
  /** Total rows to copy */
  totalRows: number;
}

export type CopyState =
  | CopyInResponse
  | CopyOutResponse
  | { direction: 'idle' };

// ── CopyHandler ────────────────────────────────────

export class CopyHandler {
  private db: Database.Database;

  // CopyIn state
  private buffer: string[] = [];
  private delimiter: string;
  private nullString: string;
  private quoteChar: string;
  private escapeChar: string;
  private csvHeader: boolean;
  private forceNotNull: Set<string>;
  private onError: 'abort' | 'ignore';
  private columns: string[] = [];
  private tableName: string = '';
  private _copyState: CopyState = { direction: 'idle' };
  private _copyFormat: CopyFormat = CopyFormat.TEXT;

  /** Buffer for binary CopyIn data (PG binary format rows). */
  private binaryBuffer: Buffer[] = [];
  /** Current binary parsing state */
  private binaryOffset: number = 0;
  /** Accumulated binary data from CopyData messages */
  private binaryAccumulator: Buffer = Buffer.alloc(0);
  /** Whether header row has been consumed (for CSV HEADER) */
  private csvHeaderConsumed: boolean = false;
  /** Error rows for ON_ERROR 'ignore' mode */
  private ignoredErrorCount: number = 0;
  /** COPY FREEZE flag — if true, VACUUM FREEZE applied after COPY */
  private freeze: boolean = false;

  // Stats
  private rowsReceived = 0;
  private rowsSent = 0;

  constructor(
    db: Database.Database,
    delimiter: string = '\t',
    nullString: string = '\\N',
    quoteChar: string = '"',
    escapeChar: string = '\\',
    csvHeader: boolean = false,
    forceNotNullColumns: string[] = [],
    onError: 'abort' | 'ignore' = 'abort',
    freeze: boolean = false,
  ) {
    this.db = db;
    this.delimiter = delimiter;
    this.nullString = nullString;
    this.quoteChar = quoteChar;
    this.escapeChar = escapeChar;
    this.csvHeader = csvHeader;
    this.forceNotNull = new Set(forceNotNullColumns);
    this.onError = onError;
    this.freeze = freeze;
    this.csvHeaderConsumed = false;
    this.ignoredErrorCount = 0;
  }

  // ──────────────────────────────────────────────
  //  State
  // ──────────────────────────────────────────────

  get copyState(): CopyState {
    return this._copyState;
  }

  get stats(): { rowsReceived: number; rowsSent: number; ignoredErrors?: number } {
    const s: any = { rowsReceived: this.rowsReceived, rowsSent: this.rowsSent };
    if (this.ignoredErrorCount > 0) s.ignoredErrors = this.ignoredErrorCount;
    return s;
  }

  // ──────────────────────────────────────────────
  //  CopyIn (Client → Server)
  // ──────────────────────────────────────────────

  /**
   * Begin a COPY FROM STDIN session.
   *
   * @param tableName  Target table
   * @param columns    Column list (empty = all)
   * @param format     Copy format (text or binary)
   * @returns          CopyInResponse with column metadata
   */
  beginCopyIn(
    tableName: string,
    columns: string[] = [],
    format: CopyFormat = CopyFormat.TEXT,
  ): CopyInResponse {
    this.tableName = tableName;

    // Resolve columns if empty (use all columns)
    if (columns.length === 0) {
      const info = this.db
        .prepare(`PRAGMA table_info("${tableName}")`)
        .all() as Array<{ name: string }>;
      columns = info.map((c) => c.name);
    }

    this.columns = columns;
    this.buffer = [];
    this.rowsReceived = 0;

    this._copyState = {
      direction: CopyDirection.IN,
      format,
      columns: [...columns],
    };

    return this._copyState as CopyInResponse;
  }

  /**
   * Submit a chunk of COPY data (one or more rows in text or binary format).
   *
   * In text format, rows are separated by '\n' and fields by the delimiter.
   * In binary format, data is PG binary COPY format (accumulated until endCopyIn).
   *
   * @param data  Raw COPY data (string for text, Buffer for binary)
   */
  copyInData(data: string | Buffer): void {
    if (this._copyState.direction !== CopyDirection.IN) {
      throw new DatabaseError('Not in CopyIn mode', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const format = this._copyState.format;

    if (format === CopyFormat.BINARY) {
      // Accumulate binary data — parse on endCopyIn
      if (Buffer.isBuffer(data)) {
        this.binaryAccumulator = Buffer.concat([this.binaryAccumulator, data]);
      } else {
        // String data in binary mode — try to convert
        this.binaryAccumulator = Buffer.concat([
          this.binaryAccumulator,
          Buffer.from(data, 'utf-8'),
        ]);
      }
      return;
    }

    // Text / CSV format: split into lines (each line is a row)
    const textData = typeof data === 'string' ? data : data.toString('utf-8');
    const lines = textData.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.length === 0) continue;

      // CSV HEADER: skip the first line of data
      if (this.csvHeader && !this.csvHeaderConsumed) {
        this.csvHeaderConsumed = true;
        continue;
      }

      // Parse fields
      const fields = this.parseTextRow(trimmed);

      // Apply FORCE_NOT_NULL: for specified columns, empty string → empty string, not NULL
      const coercedFields = fields.map((f, i) => {
        const colName = i < this.columns.length ? this.columns[i] : '';
        if (f === '' && this.forceNotNull.has(colName)) {
          return ''; // empty string, not converted to null
        }
        return f;
      });

      // Pad or truncate fields to match expected column count
      while (coercedFields.length < this.columns.length) coercedFields.push(''); // pad
      this.buffer.push(
        coercedFields.slice(0, this.columns.length).join('\t'), // store tab-separated
      );
    }
  }

  /**
   * Flush buffered rows to the database in a single transaction.
   * Returns the number of rows inserted.
   */
  flushRows(): number {
    if (this._copyState.direction !== CopyDirection.IN) {
      throw new DatabaseError('Not in CopyIn mode', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    if (this.buffer.length === 0) return 0;

    const rows = [...this.buffer];
    this.buffer = [];

    const insertSql = this.buildInsertSql();
    const insertStmt = this.db.prepare(insertSql);

    const insertBatch = this.db.transaction((batch: string[]) => {
      for (const row of batch) {
        const fields = row.split('\t');
        const values = fields.map((f) => this.coerceCopyValue(f));
        try {
          insertStmt.run(...values);
        } catch (err: any) {
          if (this.onError === 'ignore') {
            this.ignoredErrorCount++;
            // Log the error but continue
            continue;
          }
          throw err;
        }
      }
    });

    insertBatch(rows);
    this.rowsReceived += rows.length;
    return rows.length;
  }

  /**
   * End a CopyIn session, flushing remaining rows (both text and binary).
   *
   * For binary CopyIn, the accumulated binary data is parsed into rows
   * and inserted using the PG binary format parser.
   *
   * If FREEZE was requested, VACUUM FREEZE is applied to the table after
   * all rows are inserted.
   *
   * @returns  Total rows received during this CopyIn
   */
  endCopyIn(): number {
    if (this._copyState.direction !== CopyDirection.IN) {
      throw new DatabaseError('Not in CopyIn mode', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const format = this._copyState.format;

    if (format === CopyFormat.BINARY && this.binaryAccumulator.length > 0) {
      // Parse binary data into rows and insert them
      const parsedRows = CopyHandler.parseBinaryCopy(this.binaryAccumulator);
      const insertStmt = this.db.prepare(this.buildInsertSql());

      const insertBatch = this.db.transaction((rows: Array<Array<Buffer | null>>) => {
        for (const row of rows) {
          const values = row.map((val, i) => {
            if (val === null) return null;
            // Convert binary value based on expected column type
            return this.binaryValueToSql(val, this.columns[i]);
          });
          // Pad/truncate to match column count
          while (values.length < this.columns.length) values.push(null);
          try {
            insertStmt.run(...values.slice(0, this.columns.length));
          } catch (err: any) {
            if (this.onError === 'ignore') {
              this.ignoredErrorCount++;
              continue;
            }
            throw err;
          }
        }
      });

      insertBatch(parsedRows);
      this.rowsReceived += parsedRows.length;
      this.binaryAccumulator = Buffer.alloc(0);
    }

    // Flush any remaining text buffered rows
    this.flushRows();

    // Apply FREEZE if requested (VACUUM FREEZE on the table)
    if (this.freeze && this.tableName) {
      try {
        this.db.exec(`VACUUM`);
        // For SQLite, VACUUM enforces write-ahead-log state; log the FREEZE
      } catch (err: any) {
        // FREEZE is best-effort, don't fail the COPY
      }
    }

    const total = this.rowsReceived;
    this._copyState = { direction: 'idle' };
    return total;
  }

  /**
   * Cancel a CopyIn session (reset without applying buffered rows).
   */
  cancelCopyIn(): void {
    this.buffer = [];
    this.binaryAccumulator = Buffer.alloc(0);
    this.binaryBuffer = [];
    this.rowsReceived = 0;
    this._copyState = { direction: 'idle' };
  }

  // ──────────────────────────────────────────────
  //  CopyOut (Server → Client)
  // ──────────────────────────────────────────────

  /**
   * Begin a COPY TO STDOUT session.
   * All rows are immediately fetched from the database.
   *
   * @param tableName  Source table
   * @param sql        Optional custom SQL (otherwise SELECT * FROM tableName)
   * @param params     Optional query parameters
   * @param format      Copy format (text or binary)
   * @returns          CopyOutResponse
   */
  beginCopyOut(
    tableName: string,
    sql?: string,
    params?: any[],
    format: CopyFormat = CopyFormat.TEXT,
  ): CopyOutResponse {
    this.tableName = tableName;

    // Resolve columns
    const info = this.db
      .prepare(`PRAGMA table_info("${tableName}")`)
      .all() as Array<{ name: string }>;
    this.columns = info.map((c) => c.name);

    // Fetch rows
    const querySql = sql || `SELECT * FROM "${tableName}"`;
    const rows = this.db
      .prepare(querySql)
      .all(...(params || [])) as Array<Record<string, any>>;

    this._copyState = {
      direction: CopyDirection.OUT,
      format,
      columns: [...this.columns],
      totalRows: rows.length,
    };

    // Store fetched rows for getNextCopyData
    (this as any)._outRows = rows;
    (this as any)._outIndex = 0;
    this.rowsSent = 0;

    return this._copyState as CopyOutResponse;
  }

  /**
   * Get the next chunk of COPY data for CopyOut.
   *
   * In text format, returns tab-separated text rows ending with newline.
   * In binary format, returns buffer data (with header on first chunk, trailer on last).
   *
   * @param maxRows  Maximum number of rows per chunk (default: 100)
   * @returns        COPY data string (text) or empty string if done
   */
  getNextCopyData(maxRows: number = 100): string | Buffer {
    if (this._copyState.direction !== CopyDirection.OUT) {
      throw new DatabaseError('Not in CopyOut mode', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const rows: Array<Record<string, any>> = (this as any)._outRows || [];
    let index: number = (this as any)._outIndex || 0;

    if (index >= rows.length) return '';

    const format = this._copyState.format;

    if (format === CopyFormat.BINARY) {
      return this.getNextBinaryCopyData(maxRows, rows, index);
    }

    // Text format
    const end = Math.min(index + maxRows, rows.length);
    const lines: string[] = [];

    for (let i = index; i < end; i++) {
      const row = rows[i];
      const fields = this.columns.map((col) => {
        const val = row[col];
        return this.formatCopyValue(val);
      });
      lines.push(fields.join('\t'));
    }

    (this as any)._outIndex = end;
    this.rowsSent += end - index;

    return lines.join('\n') + '\n';
  }

  /**
   * Get the next chunk of COPY data in binary format.
   * Adds binary header on the first chunk and trailer on the last.
   */
  private getNextBinaryCopyData(
    maxRows: number,
    rows: Array<Record<string, any>>,
    index: number,
  ): Buffer {
    const end = Math.min(index + maxRows, rows.length);
    const parts: Buffer[] = [];

    // Add PG binary header on first chunk
    if (index === 0) {
      parts.push(CopyHandler.buildBinaryHeader());
    }

    for (let i = index; i < end; i++) {
      const row = rows[i];
      const values = this.columns.map((col) => row[col]);
      parts.push(CopyHandler.encodeBinaryRow(this.columns, values));
    }

    // Add PG binary trailer on last chunk
    if (end >= rows.length) {
      parts.push(CopyHandler.buildBinaryTrailer());
    }

    (this as any)._outIndex = end;
    this.rowsSent += end - index;

    return Buffer.concat(parts);
  }

  /**
   * End a CopyOut session.
   *
   * @returns  Total rows sent
   */
  endCopyOut(): number {
    if (this._copyState.direction !== CopyDirection.OUT) {
      throw new DatabaseError('Not in CopyOut mode', SQLSTATE_OBJECT_NOT_IN_PREREQUISITE_STATE);
    }

    const total = this.rowsSent;
    this._copyState = { direction: 'idle' };
    (this as any)._outRows = [];
    (this as any)._outIndex = 0;
    return total;
  }

  // ──────────────────────────────────────────────
  //  Wire protocol message builders
  // ──────────────────────────────────────────────

  /**
   * Build a CopyInResponse wire message ('G').
   * Format byte 0 = text overall, 1 = binary overall.
   * Column format bytes: 0 = text per column, 1 = binary per column.
   */
  buildCopyInResponse(): Buffer {
    const props = this._copyState as CopyInResponse;
    const formatByte = Buffer.from([props.format]);
    const numCols = props.columns.length;
    const colBufs = props.columns.map(() => {
      const buf = Buffer.alloc(2);
      // Per-column format: binary (1) if overall format is binary, else text (0)
      buf.writeInt16BE(props.format === CopyFormat.BINARY ? 1 : 0);
      return buf;
    });

    // 'G' + int32 totalLen + format + numCols + column formats
    const headerLen = 1 + 4 + 1 + 2 + colBufs.length * 2;
    const totalLen = headerLen;
    const buf = Buffer.alloc(totalLen);
    buf[0] = 0x47; // 'G'
    buf.writeInt32BE(totalLen - 1, 1); // length excluding type byte
    buf[5] = formatByte[0];
    buf.writeInt16BE(numCols, 6);

    let off = 8;
    for (const cb of colBufs) {
      cb.copy(buf, off);
      off += cb.length;
    }

    return buf;
  }

  /**
   * Build a CopyOutResponse wire message ('H').
   * Format byte 0 = text overall, 1 = binary overall.
   * Column format bytes: 0 = text per column, 1 = binary per column.
   */
  buildCopyOutResponse(): Buffer {
    const props = this._copyState as CopyOutResponse;
    const formatByte = Buffer.from([props.format]);
    const numCols = props.columns.length;
    const colBufs = props.columns.map(() => {
      const buf = Buffer.alloc(2);
      // Per-column format: binary (1) if overall format is binary, else text (0)
      buf.writeInt16BE(props.format === CopyFormat.BINARY ? 1 : 0);
      return buf;
    });

    const headerLen = 1 + 4 + 1 + 2 + colBufs.length * 2;
    const totalLen = headerLen;
    const buf = Buffer.alloc(totalLen);
    buf[0] = 0x48; // 'H'
    buf.writeInt32BE(totalLen - 1, 1);
    buf[5] = formatByte[0];
    buf.writeInt16BE(numCols, 6);

    let off = 8;
    for (const cb of colBufs) {
      cb.copy(buf, off);
      off += cb.length;
    }

    return buf;
  }

  /**
   * Build a CopyData wire message ('d') from raw string data.
   */
  static buildCopyData(data: string): Buffer {
    const payload = Buffer.from(data, 'utf-8');
    const buf = Buffer.alloc(1 + 4 + payload.length);
    buf[0] = 0x64; // 'd'
    buf.writeInt32BE(4 + payload.length, 1);
    payload.copy(buf, 5);
    return buf;
  }

  /**
   * Build a CopyDone wire message ('c').
   */
  static buildCopyDone(): Buffer {
    const buf = Buffer.alloc(5);
    buf[0] = 0x63; // 'c'
    buf.writeInt32BE(4, 1);
    return buf;
  }

  /**
   * Build a CopyFail wire message ('f').
   */
  static buildCopyFail(errorMessage: string): Buffer {
    const msgBuf = Buffer.from(errorMessage + '\0', 'utf-8');
    const buf = Buffer.alloc(1 + 4 + msgBuf.length);
    buf[0] = 0x66; // 'f'
    buf.writeInt32BE(4 + msgBuf.length, 1);
    msgBuf.copy(buf, 5);
    return buf;
  }

  /**
   * Parse a CopyData message payload from a raw wire message.
   * Assumes the message has already been decoded from the wire.
   */
  static parseCopyData(payload: Buffer): string {
    return payload.toString('utf-8');
  }

  // ──────────────────────────────────────────────
  //  Private helpers
  // ──────────────────────────────────────────────

  /**
   * Build an INSERT SQL statement for the current table/columns.
   */
  private buildInsertSql(): string {
    const placeholders = this.columns.map(() => '?').join(', ');
    const colList = this.columns.map((c) => `"${c}"`).join(', ');
    return `INSERT INTO "${this.tableName}" (${colList}) VALUES (${placeholders})`;
  }

  /**
   * Convert a binary-encoded value from PG COPY BINARY format to a SQL value.
   * Since binary COPY data carries raw bytes without type metadata, we check
   * the column type via PRAGMA table_info to determine the expected type.
   */
  private binaryValueToSql(val: Buffer, _column: string): any {
    // Use the column name to determine type if available
    // For SQLite, we always try to convert to appropriate numeric type
    const asText = val.toString('utf-8');

    // If the value is all printable text and not just a number, return as text
    // Check if most bytes are printable ASCII
    let printableCount = 0;
    for (let i = 0; i < val.length; i++) {
      const b = val[i];
      if (b >= 0x20 && b <= 0x7e) printableCount++;
    }

    // If most bytes are printable ASCII, treat as text
    if (printableCount >= val.length * 0.8 && printableCount > 0) {
      return asText;
    }

    // Otherwise try numeric decoding based on length
    if (val.length === 8) {
      try { return Number(val.readBigInt64BE(0)); } catch { return asText; }
    } else if (val.length === 4) {
      try { return val.readInt32BE(0); } catch { return asText; }
    } else if (val.length === 2) {
      try { return val.readInt16BE(0); } catch { return asText; }
    } else if (val.length === 1) {
      try { return val.readInt8(0); } catch { return asText; }
    }

    return asText;
  }

  /**
   * Parse a text-format COPY row into fields.
   */
  private parseTextRow(line: string): string[] {
    const fields: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      const next = i + 1 < line.length ? line[i + 1] : '';

      if (inQuotes) {
        if (ch === this.quoteChar && next === this.quoteChar) {
          current += this.quoteChar;
          i++;
        } else if (ch === this.quoteChar) {
          inQuotes = false;
        } else {
          current += ch;
        }
      } else if (ch === this.quoteChar) {
        inQuotes = true;
      } else if (ch === this.delimiter) {
        fields.push(current);
        current = '';
      } else {
        current += ch;
      }
    }

    fields.push(current);
    return fields;
  }

  /**
   * Coerce a text-format COPY value for INSERT.
   */
  private coerceCopyValue(value: string): any {
    if (value === this.nullString || value === '') return null;

    // Try integer
    if (/^-?\d+$/.test(value)) return parseInt(value, 10);
    // Try float
    if (/^-?\d+\.?\d*(?:[eE][+-]?\d+)?$/.test(value)) return parseFloat(value);
    // Boolean-like
    if (/^(true|t|yes)$/i.test(value)) return 1;
    if (/^(false|f|no)$/i.test(value)) return 0;

    return value;
  }

  /**
   * Format a value for COPY text output.
   */
  private formatCopyValue(val: any): string {
    if (val === null || val === undefined) return this.nullString;

    const str = String(val);

    // Escape special characters
    if (
      str.includes(this.delimiter) ||
      str.includes(this.quoteChar) ||
      str.includes('\n') ||
      str.includes('\r')
    ) {
      const escaped = str.replace(
        new RegExp(this.quoteChar, 'g'),
        this.quoteChar + this.quoteChar,
      );
      return `${this.quoteChar}${escaped}${this.quoteChar}`;
    }

    return str;
  }

  // ══════════════════════════════════════════════════════════════
  //  COPY BINARY (Gap 6)
  // ══════════════════════════════════════════════════════════════

  /** PG COPY binary signature */
  static readonly PGCOPY_BINARY_SIGNATURE = Buffer.from([0x50, 0x47, 0x43, 0x4f, 0x50, 0x59, 0x0a, 0xff, 0x0d, 0x0a, 0x00]);

  /**
   * Encode a single value as PG binary format.
   *
   * Handles common PG types:
   *   - null → int32 -1
   *   - number → int64 network byte order
   *   - string/boolean → UTF-8 text
   *   - Buffer → raw bytes
   *
   * @param val - The value to encode
   * @returns Buffer with int32 length prefix + bytes, or int32 -1 for NULL
   */
  static encodeBinaryValue(val: any): Buffer {
    if (val === null || val === undefined) {
      const buf = Buffer.alloc(4);
      buf.writeInt32BE(-1, 0);
      return buf;
    }

    let payload: Buffer;

    if (typeof val === 'number') {
      if (Number.isInteger(val)) {
        // int8/int4 encoding
        payload = Buffer.alloc(8);
        payload.writeBigInt64BE(BigInt(val), 0);
      } else {
        // float8
        payload = Buffer.alloc(8);
        payload.writeDoubleBE(val, 0);
      }
    } else if (typeof val === 'boolean') {
      payload = Buffer.from(val ? 't' : 'f', 'utf-8');
    } else if (Buffer.isBuffer(val)) {
      payload = val;
    } else if (typeof val === 'bigint') {
      payload = Buffer.alloc(8);
      payload.writeBigInt64BE(val, 0);
    } else {
      // string or other → UTF-8 text
      payload = Buffer.from(String(val), 'utf-8');
    }

    const result = Buffer.alloc(4 + payload.length);
    result.writeInt32BE(payload.length, 0);
    payload.copy(result, 4);
    return result;
  }

  /**
   * Decode a PG binary value from a Buffer.
   *
   * Reads int32 length prefix, then the value bytes.
   * Returns null for length = -1 (SQL NULL).
   *
   * @param buf - The full buffer containing the binary value
   * @param offset - Starting offset
   * @returns Object with decoded value and new offset
   */
  static decodeBinaryValue(
    buf: Buffer,
    offset: number,
  ): { value: any; newOffset: number } {
    const len = buf.readInt32BE(offset);
    offset += 4;

    if (len === -1) {
      return { value: null, newOffset: offset };
    }

    // For simplicity, always return as Buffer (caller can convert)
    const value = Buffer.from(buf.subarray(offset, offset + len));
    offset += len;

    return { value, newOffset: offset };
  }

  /**
   * Build the PG COPY binary header.
   *
   * @param flags - Flags (bit 0 = OIDs)
   * @returns Header buffer
   */
  static buildBinaryHeader(flags: number = 0): Buffer {
    const sig = CopyHandler.PGCOPY_BINARY_SIGNATURE;
    const flagsBuf = Buffer.alloc(4);
    flagsBuf.writeInt32BE(flags, 0);
    // No extension header area
    const extBuf = Buffer.alloc(4);
    extBuf.writeInt32BE(0, 0);
    return Buffer.concat([sig, flagsBuf, extBuf]);
  }

  /**
   * Build the PG COPY binary trailer (field count = -1).
   * @returns Trailer buffer: int16 -1
   */
  static buildBinaryTrailer(): Buffer {
    const buf = Buffer.alloc(2);
    buf.writeInt16BE(-1, 0);
    return buf;
  }

  /**
   * Encode a row as PG binary format.
   *
   * @param columns - Column names (for metadata)
   * @param values - Row values
   * @returns Buffer with binary-encoded row
   */
  static encodeBinaryRow(columns: string[], values: any[]): Buffer {
    const parts: Buffer[] = [];

    // Field count (int16)
    const fieldCount = Buffer.alloc(2);
    fieldCount.writeInt16BE(values.length, 0);
    parts.push(fieldCount);

    // Each field
    for (let i = 0; i < values.length; i++) {
      parts.push(CopyHandler.encodeBinaryValue(values[i]));
    }

    return Buffer.concat(parts);
  }

  /**
   * Encode an entire result set as PG binary format.
   *
   * @param columns - Column names
   * @param rows - Array of row values
   * @returns Buffer with header + rows + trailer
   */
  static encodeBinaryResultSet(columns: string[], rows: any[][]): Buffer {
    const parts: Buffer[] = [CopyHandler.buildBinaryHeader()];
    for (const row of rows) {
      parts.push(CopyHandler.encodeBinaryRow(columns, row));
    }
    parts.push(CopyHandler.buildBinaryTrailer());
    return Buffer.concat(parts);
  }

  /**
   * Parse a PG binary COPY input stream.
   *
   * @param data - Binary COPY data (may include header)
   * @returns Array of parsed rows (each row is an array of Buffer | null values)
   */
  static parseBinaryCopy(data: Buffer): Array<Array<Buffer | null>> {
    const rows: Array<Array<Buffer | null>> = [];
    let offset = 0;

    // Skip header if present (PGCOPY\n\377\r\n\0 = 11 bytes)
    if (data.length >= 11 && data.subarray(0, 11).equals(CopyHandler.PGCOPY_BINARY_SIGNATURE)) {
      offset = 11;
      // Skip 4-byte flags
      offset += 4;
      // Skip 4-byte extension length
      const extLen = data.readInt32BE(offset);
      offset += 4;
      if (extLen > 0) {
        offset += extLen;
      }
    }

    while (offset + 2 <= data.length) {
      const fieldCount = data.readInt16BE(offset);
      offset += 2;

      // Trailer: fieldCount = -1
      if (fieldCount === -1) break;

      const row: Array<Buffer | null> = [];
      for (let i = 0; i < fieldCount && offset <= data.length; i++) {
        const { value, newOffset } = CopyHandler.decodeBinaryValue(data, offset);
        row.push(value as Buffer | null);
        offset = newOffset;
      }
      rows.push(row);
    }

    return rows;
  }
}
