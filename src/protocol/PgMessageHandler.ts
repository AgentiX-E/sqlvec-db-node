/**
 * PgMessageHandler — PG Wire Protocol message types and handlers.
 *
 * Covers message types not handled elsewhere:
 *   - FunctionCall ('F')
 *   - Flush ('H')
 *   - Sync ('S')
 *   - CopyFail ('f')
 *
 * Also provides:
 *   - Complete PG message type enum (18 types)
 *   - Message encode/decode helpers
 *   - Standard ErrorResponse builder with S/C/M/P fields
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import {
  SQLSTATE_INTERNAL_ERROR,
  SQLSTATE_CONNECTION_EXCEPTION,
  SQLSTATE_IN_FAILED_SQL_TRANSACTION,
} from '../constants/sqlstate';

// ══════════════════════════════════════════════════════════════════
//  PG Message Type Enum
// ══════════════════════════════════════════════════════════════════

export enum PgMessageType {
  /** Authentication request */
  Authentication = 'R',
  /** Backend key data */
  BackendKeyData = 'K',
  /** Bind (Extended Query) */
  Bind = 'B',
  /** BindComplete */
  BindComplete = '2',
  /** CancelQuery */
  CancelQuery = 'F', // Note: same char as FunctionCall — context-dependent
  /** Close (Extended Query) */
  Close = 'C',
  /** CloseComplete */
  CloseComplete = '3',
  /** CommandComplete */
  CommandComplete = 'C',
  /** CopyData */
  CopyData = 'd',
  /** CopyDone */
  CopyDone = 'c',
  /** CopyFail */
  CopyFail = 'f',
  /** CopyInResponse */
  CopyInResponse = 'G',
  /** CopyOutResponse */
  CopyOutResponse = 'H',
  /** DataRow */
  DataRow = 'D',
  /** Describe (Extended Query) */
  Describe = 'D',
  /** EmptyQueryResponse */
  EmptyQueryResponse = 'I',
  /** ErrorResponse */
  ErrorResponse = 'E',
  /** Execute (Extended Query) */
  Execute = 'E',
  /** Flush */
  Flush = 'H',
  /** FunctionCall */
  FunctionCall = 'F',
  /** FunctionCallResponse */
  FunctionCallResponse = 'V',
  /** NegotiateProtocolVersion */
  NegotiateProtocolVersion = 'v',
  /** NoData */
  NoData = 'n',
  /** NoticeResponse */
  NoticeResponse = 'N',
  /** NotificationResponse */
  NotificationResponse = 'A',
  /** ParameterDescription */
  ParameterDescription = 't',
  /** ParameterStatus */
  ParameterStatus = 'S',
  /** Parse (Extended Query) */
  Parse = 'P',
  /** ParseComplete */
  ParseComplete = '1',
  /** PasswordMessage */
  PasswordMessage = 'p',
  /** PortalSuspended */
  PortalSuspended = 's',
  /** Query */
  Query = 'Q',
  /** ReadyForQuery */
  ReadyForQuery = 'Z',
  /** RowDescription */
  RowDescription = 'T',
  /** SSLRequest (no type byte — special startup) */
  SSLRequest = 'SSL',
  /** StartupMessage (no type byte) */
  StartupMessage = 'STARTUP',
  /** Sync */
  Sync = 'S',
  /** Terminate */
  Terminate = 'X',
}

// ══════════════════════════════════════════════════════════════════
//  ErrorResponse builder
// ══════════════════════════════════════════════════════════════════

export interface ErrorResponseField {
  /** Severity: 'S' = severity ('FATAL', 'ERROR', 'PANIC', 'WARNING', 'NOTICE') */
  severity: string;
  /** SQLSTATE code: 'C' = code */
  sqlstate: string;
  /** Human-readable message: 'M' = message */
  message: string;
  /** Optional detail: 'D' = detail */
  detail?: string;
  /** Optional hint: 'H' = hint */
  hint?: string;
  /** Optional position (character offset): 'P' = position */
  position?: string;
  /** Optional internal position: 'p' = internal position */
  internalPosition?: string;
  /** Optional internal query: 'q' = internal query */
  internalQuery?: string;
  /** Optional where context: 'W' = where */
  where?: string;
  /** Optional schema name: 's' = schema */
  schemaName?: string;
  /** Optional table name: 't' = table */
  tableName?: string;
  /** Optional column name: 'c' = column */
  columnName?: string;
  /** Optional data type name: 'd' = data type */
  dataTypeName?: string;
  /** Optional constraint name: 'n' = constraint */
  constraintName?: string;
  /** Optional file: 'F' = file */
  file?: string;
  /** Optional line: 'L' = line */
  line?: string;
  /** Optional routine: 'R' = routine */
  routine?: string;
}

/**
 * Build an ErrorResponse byte buffer from fields.
 * Format:
 *   char 'E'
 *   int32 length (including self)
 *   char fieldType + string value + '\0'  (repeated for each field)
 *   '\0' (terminator)
 */
export function makeErrorResponse(
  severity: string,
  sqlstate: string,
  message: string,
  extra?: Partial<Omit<ErrorResponseField, 'severity' | 'sqlstate' | 'message'>>,
): Buffer {
  const parts: Buffer[] = [];

  // Severity
  parts.push(Buffer.from('S', 'utf8'));
  parts.push(Buffer.from(severity, 'utf8'));
  parts.push(Buffer.from([0]));

  // SQLSTATE
  parts.push(Buffer.from('C', 'utf8'));
  parts.push(Buffer.from(sqlstate, 'utf8'));
  parts.push(Buffer.from([0]));

  // Message
  parts.push(Buffer.from('M', 'utf8'));
  parts.push(Buffer.from(message, 'utf8'));
  parts.push(Buffer.from([0]));

  // Optional fields
  if (extra) {
    for (const [key, value] of Object.entries(extra)) {
      if (value === undefined || value === null) continue;
      const fieldKey = fieldKeyMap[key as keyof typeof fieldKeyMap] ?? key.toUpperCase();
      parts.push(Buffer.from(fieldKey, 'utf8'));
      parts.push(Buffer.from(String(value), 'utf8'));
      parts.push(Buffer.from([0]));
    }
  }

  // Terminator
  parts.push(Buffer.from([0]));

  // Calculate total length
  const payload = Buffer.concat(parts);
  const length = 4 + payload.length; // 4 bytes for int32 length

  const header = Buffer.alloc(4);
  header.writeInt32BE(length, 0);

  return Buffer.concat([Buffer.from('E', 'utf8'), header, payload]);
}

const fieldKeyMap: Record<string, string> = {
  detail: 'D',
  hint: 'H',
  position: 'P',
  internalPosition: 'p',
  internalQuery: 'q',
  where: 'W',
  schemaName: 's',
  tableName: 't',
  columnName: 'c',
  dataTypeName: 'd',
  constraintName: 'n',
  file: 'F',
  line: 'L',
  routine: 'R',
};

// ══════════════════════════════════════════════════════════════════
//  Message encode/decode helpers
// ══════════════════════════════════════════════════════════════════

/**
 * Encode a ReadyForQuery message.
 *   char 'Z'
 *   int32 length (8)
 *   char txnStatus ('I' = idle, 'T' = txn in progress, 'E' = failed)
 */
export function encodeReadyForQuery(txnStatus: 'I' | 'T' | 'E'): Buffer {
  const buf = Buffer.alloc(6);
  buf[0] = 0x5a; // 'Z'
  buf.writeInt32BE(6, 1); // length (including self)
  buf[5] = txnStatus.charCodeAt(0);
  return buf;
}

/**
 * Encode an AuthenticationOk message (type 'R', subtype 0).
 */
export function encodeAuthenticationOk(): Buffer {
  const buf = Buffer.alloc(9);
  buf[0] = 0x52; // 'R'
  buf.writeInt32BE(9, 1); // length
  buf.writeInt32BE(0, 5); // AuthenticationOk
  return buf;
}

/**
 * Encode a CommandComplete message.
 *   char 'C'
 *   int32 length
 *   string commandTag + \0
 */
export function encodeCommandComplete(tag: string): Buffer {
  const tagBuf = Buffer.from(tag, 'utf8');
  const len = 4 + tagBuf.length + 1; // int32 + tag + \0
  const buf = Buffer.alloc(1 + len);
  buf[0] = 0x43; // 'C'
  buf.writeInt32BE(len, 1);
  tagBuf.copy(buf, 5);
  buf[5 + tagBuf.length] = 0; // null terminator
  return buf;
}

/**
 * Encode an EmptyQueryResponse message.
 *   char 'I'
 *   int32 length (5)
 */
export function encodeEmptyQueryResponse(): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x49; // 'I'
  buf.writeInt32BE(5, 1);
  return buf;
}

/**
 * Encode a ParseComplete message.
 *   char '1'
 *   int32 length (5)
 */
export function encodeParseComplete(): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x31; // '1'
  buf.writeInt32BE(5, 1);
  return buf;
}

/**
 * Encode a BindComplete message.
 *   char '2'
 *   int32 length (5)
 */
export function encodeBindComplete(): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x32; // '2'
  buf.writeInt32BE(5, 1);
  return buf;
}

/**
 * Encode a CloseComplete message.
 *   char '3'
 *   int32 length (5)
 */
export function encodeCloseComplete(): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x33; // '3'
  buf.writeInt32BE(5, 1);
  return buf;
}

/**
 * Encode a NoData message.
 *   char 'n'
 *   int32 length (5)
 */
export function encodeNoData(): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x6e; // 'n'
  buf.writeInt32BE(5, 1);
  return buf;
}

/**
 * Encode a ParameterStatus message.
 *   char 'S'
 *   int32 length
 *   string name + \0
 *   string value + \0
 */
export function encodeParameterStatus(name: string, value: string): Buffer {
  const nameBuf = Buffer.from(name, 'utf8');
  const valueBuf = Buffer.from(value, 'utf8');
  const len = 4 + nameBuf.length + 1 + valueBuf.length + 1;
  const buf = Buffer.alloc(1 + len);
  buf[0] = 0x53; // 'S'
  buf.writeInt32BE(len, 1);
  nameBuf.copy(buf, 5);
  buf[5 + nameBuf.length] = 0;
  valueBuf.copy(buf, 6 + nameBuf.length);
  buf[6 + nameBuf.length + valueBuf.length] = 0;
  return buf;
}

/**
 * Encode a NotificationResponse message.
 *   char 'A'
 *   int32 length
 *   int32 pid
 *   string channel + \0
 *   string payload + \0
 */
export function encodeNotificationResponse(pid: number, channel: string, payload: string): Buffer {
  const channelBuf = Buffer.from(channel, 'utf8');
  const payloadBuf = Buffer.from(payload, 'utf8');
  const len = 4 + 4 + channelBuf.length + 1 + payloadBuf.length + 1;
  const buf = Buffer.alloc(1 + len);
  buf[0] = 0x41; // 'A'
  buf.writeInt32BE(len, 1);
  buf.writeInt32BE(pid, 5);
  channelBuf.copy(buf, 9);
  buf[9 + channelBuf.length] = 0;
  payloadBuf.copy(buf, 10 + channelBuf.length);
  buf[10 + channelBuf.length + payloadBuf.length] = 0;
  return buf;
}

/**
 * Encode a DataRow message.
 *   char 'D'
 *   int32 length
 *   int16 ncols
 *   int32 colLen + byte[]  (for each column)
 *   Special: colLen = -1 for NULL
 */
export function encodeDataRow(row: unknown[]): Buffer {
  const colBuffers: Buffer[] = [];

  for (const col of row) {
    if (col === null || col === undefined) {
      const nullBuf = Buffer.alloc(4);
      nullBuf.writeInt32BE(-1, 0);
      colBuffers.push(nullBuf);
    } else {
      const str = typeof col === 'object' ? JSON.stringify(col) : String(col);
      const strBuf = Buffer.from(str, 'utf8');
      const entry = Buffer.alloc(4 + strBuf.length);
      entry.writeInt32BE(strBuf.length, 0);
      strBuf.copy(entry, 4);
      colBuffers.push(entry);
    }
  }

  const body = Buffer.concat(colBuffers);
  const len = 4 + 2 + body.length; // int32 length + int16 ncols + columns
  const buf = Buffer.alloc(1 + len);
  buf[0] = 0x44; // 'D'
  buf.writeInt32BE(len, 1);
  buf.writeInt16BE(row.length, 5);
  body.copy(buf, 7);
  return buf;
}

// ══════════════════════════════════════════════════════════════════
//  Message decoders
// ══════════════════════════════════════════════════════════════════

export interface StartupMessage {
  /** Protocol version (major * 256 + minor) */
  protocolVersion: number;
  /** Key-value parameters (user, database, etc.) */
  parameters: Record<string, string>;
}

/**
 * Parse a startup message (no type byte, begins with int32 length).
 * Startup messages have protocol version 3.0 (196608) or a special
 * cancel code (80877102 for CancelRequest, 80877103 for SSLRequest).
 */
export function parseStartupMessage(buf: Buffer): StartupMessage {
  const len = buf.readInt32BE(0);
  const protocolVersion = buf.readInt32BE(4);
  const params: Record<string, string> = {};

  let offset = 8;
  while (offset < len) {
    const keyEnd = buf.indexOf(0, offset);
    if (keyEnd < 0) break;
    const key = buf.toString('utf8', offset, keyEnd);
    offset = keyEnd + 1;

    if (offset >= buf.length) break;
    const valEnd = buf.indexOf(0, offset);
    const value = valEnd >= 0 ? buf.toString('utf8', offset, valEnd) : buf.toString('utf8', offset);
    offset = valEnd + 1;

    if (key) params[key] = value;
  }

  return { protocolVersion, parameters: params };
}

// ══════════════════════════════════════════════════════════════════
//  Handler: FunctionCall ('F')
// ══════════════════════════════════════════════════════════════════

export interface FunctionCallRequest {
  /** Object ID of the function (0 for unnamed) */
  functionOid: number;
  /** Parameter format codes (0=text, 1=binary) */
  argFormatCodes: number[];
  /** Parameter values (raw buffers) */
  argValues: Buffer[];
  /** Result format code (0=text, 1=binary) */
  resultFormatCode: number;
}

/**
 * Parse a FunctionCall message.
 *
 * PG wire format:
 *   char 'F'
 *   int32 len
 *   int32 functionOid
 *   int16 argFormatCodeCount
 *   int16[] argFormatCodes
 *   int16 argValueCount
 *   for each:
 *     int32 valueLen (-1 = NULL)
 *     byte[] value
 *   int16 resultFormatCode
 */
export function parseFunctionCall(buf: Buffer, offset: number): FunctionCallRequest {
  let off = offset;
  const functionOid = buf.readInt32BE(off); off += 4;

  const argFormatCount = buf.readInt16BE(off); off += 2;
  const argFormatCodes: number[] = [];
  for (let i = 0; i < argFormatCount; i++) {
    argFormatCodes.push(buf.readInt16BE(off)); off += 2;
  }

  const argValueCount = buf.readInt16BE(off); off += 2;
  const argValues: Buffer[] = [];
  for (let i = 0; i < argValueCount; i++) {
    const valueLen = buf.readInt32BE(off); off += 4;
    if (valueLen === -1) {
      argValues.push(Buffer.alloc(0)); // NULL
    } else {
      argValues.push(buf.subarray(off, off + valueLen));
      off += valueLen;
    }
  }

  const resultFormatCode = buf.readInt16BE(off);

  return { functionOid, argFormatCodes, argValues, resultFormatCode };
}

/**
 * Handle a FunctionCall message.
 * In PostgreSQL, this calls a registered function. For SQLVec, we
 * map known OIDs to SQLite built-in functions.
 *
 * @returns A FunctionCallResponse buffer ('V') on success, or ErrorResponse on failure.
 */
export function handleFunctionCall(
  req: FunctionCallRequest,
  db: { exec: (sql: string) => unknown },
): Buffer {
  try {
    const sqlFunc = resolveSqlFunction(req.functionOid);
    if (!sqlFunc) {
      return makeErrorResponse(
        'ERROR',
        SQLSTATE_INTERNAL_ERROR,
        'function with OID ' + req.functionOid + ' is not supported',
      );
    }

    // Build the SQL function call
    const paramPlaceholders = req.argValues.map((v, i) => {
      if (v.length === 0) return 'NULL';
      const fmt = req.argFormatCodes[i] ?? 0;
      if (fmt === 0) {
        // Text format — quote as string
        const str = v.toString('utf8');
        return `'${str.replace(/'/g, "''")}'`;
      }
      // Binary — hex encode
      return `X'${v.toString('hex')}'`;
    });

    const sql = `SELECT ${sqlFunc}(${paramPlaceholders.join(', ')}) AS result`;
    // Execute via raw SQLite
    const result = db.exec(sql);
    const resultBuf = Buffer.from(JSON.stringify(result), 'utf8');

    // Build FunctionCallResponse ('V'):
    // char 'V', int32 len, int16 formatCode, int32 valueLen, byte[] value
    const valLen = 1 + 4 + 2 + 4 + resultBuf.length;
    const resp = Buffer.alloc(1 + valLen);
    resp[0] = 0x56; // 'V'
    resp.writeInt32BE(valLen, 1);
    resp.writeInt16BE(req.resultFormatCode, 5);
    resp.writeInt32BE(resultBuf.length, 7);
    resultBuf.copy(resp, 11);
    return resp;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return makeErrorResponse('ERROR', SQLSTATE_INTERNAL_ERROR, 'function call failed: ' + msg);
  }
}

/**
 * Map PG function OIDs to SQLite built-in functions.
 * Only a subset is supported.
 */
function resolveSqlFunction(oid: number): string | null {
  const funcMap: Record<number, string> = {
    710: 'lower',
    711: 'upper',
    712: 'length',
    713: 'substr',
    714: 'trim',
    715: 'abs',
    716: 'hex',
    717: 'quote',
    718: 'typeof',
    719: 'instr',
    720: 'unicode',
    721: 'char',
    722: 'likelihood',
    723: 'likely',
    724: 'unlikely',
    725: 'printf',
  };
  return funcMap[oid] ?? null;
}

// ══════════════════════════════════════════════════════════════════
//  Handler: Flush ('H')
// ══════════════════════════════════════════════════════════════════

/**
 * Handle a Flush message: force the server to send any pending output.
 * In a simple implementation, this is a no-op since we write responses
 * immediately.  We return an empty buffer to signal "flush pending".
 *
 * @returns An empty buffer (Flush only forces a send, no response data).
 */
export function handleFlush(): Buffer {
  // Flush forces the server to send any pending data.
  // Since we write responses synchronously, there's nothing to queue.
  // Return empty buffer to signal "flush completed, no message to send".
  return Buffer.alloc(0);
}

// ══════════════════════════════════════════════════════════════════
//  Handler: Sync ('S')
// ══════════════════════════════════════════════════════════════════

/**
 * Handle a Sync message: commit/rollback the implicit transaction and
 * return ReadyForQuery.
 *
 * Sync in PG:
 *   1. Commit any implicit transaction
 *   2. Clear the "failed transaction" state
 *   3. Return ReadyForQuery
 *
 * @returns ReadyForQuery message.
 */
export function handleSync(
  db: { inTransaction: boolean; exec: (sql: string) => unknown },
): Buffer[] {
  try {
    // Commit any implicit transaction
    if (db.inTransaction) {
      db.exec('COMMIT');
    }
  } catch {
    // Rollback on error
    try { db.exec('ROLLBACK'); } catch { /* ignore */ }
  }

  return [encodeReadyForQuery('I')];
}

// ══════════════════════════════════════════════════════════════════
//  Handler: CopyFail ('f')
// ══════════════════════════════════════════════════════════════════

/**
 * Handle a CopyFail message: abort an active COPY operation.
 *
 * PG wire spec:
 *   Client sends CopyFail ('f') + errorMsg
 *   Server sends ErrorResponse
 *   Server returns to normal query processing
 *
 * @param errorMessage — The error message from the client.
 * @returns ErrorResponse buffer.
 */
export function handleCopyFail(errorMessage: string): Buffer {
  return makeErrorResponse(
    'ERROR',
    SQLSTATE_CONNECTION_EXCEPTION,
    'COPY failed: ' + errorMessage,
    { detail: 'The COPY operation was aborted by the client.' },
  );
}

// ══════════════════════════════════════════════════════════════════
//  Utility: extract message type and payload from a buffer
// ══════════════════════════════════════════════════════════════════

export interface PgMessage {
  type: string;
  length: number;
  payload: Buffer;
}

/**
 * Parse the next message from a buffer starting at offset.
 * Each message (except startup) has:
 *   char type
 *   int32 length (including self)
 *   byte[] payload
 *
 * @returns The parsed message, or null if incomplete.
 */
export function parseNextMessage(buf: Buffer, offset: number): PgMessage | null {
  if (offset + 5 > buf.length) return null; // Need at least type + length

  const type = String.fromCharCode(buf[offset]);
  const length = buf.readInt32BE(offset + 1);
  if (offset + length > buf.length) return null; // Incomplete

  const payload = buf.subarray(offset + 5, offset + length);
  return { type, length, payload };
}

// ══════════════════════════════════════════════════════════════════
//  CopyInResponse / CopyOutResponse encoders
// ══════════════════════════════════════════════════════════════════

/**
 * Encode a CopyInResponse message.
 *
 * PG wire format:
 *   char 'G'
 *   int32 length (including self, min 5)
 *   int8 format (0=text, 1=binary)
 *   int16 numColumns
 *   int16[formatCodes]  (one per column)
 *
 * @param format — overall format (0=text, 1=binary). Default 0.
 * @param columnFormatCodes — per-column format codes. If empty, defaults are used.
 */
export function encodeCopyInResponse(
  format: number = 0,
  columnFormatCodes: number[] = [],
): Buffer {
  const numColumns = columnFormatCodes.length;
  const bodyLen = 1 + 2 + numColumns * 2; // format(1) + numCols(2) + formatCodes(numCols*2)
  const msgLen = 1 + 4 + bodyLen; // type(1) + length(4) + body

  const buf = Buffer.alloc(msgLen);
  buf[0] = 0x47; // 'G'
  buf.writeInt32BE(bodyLen + 4, 1); // length (including self)
  buf[5] = format & 0xff; // format
  buf.writeInt16BE(numColumns, 6);

  for (let i = 0; i < numColumns; i++) {
    buf.writeInt16BE(columnFormatCodes[i] ?? 0, 8 + i * 2);
  }

  return buf;
}

/**
 * Encode a CopyOutResponse message.
 *
 * PG wire format:
 *   char 'H'
 *   int32 length (including self, min 5)
 *   int8 format (0=text, 1=binary)
 *   int16 numColumns
 *   int16[formatCodes]  (one per column)
 *
 * @param format — overall format (0=text, 1=binary). Default 0.
 * @param columnFormatCodes — per-column format codes. If empty, defaults are used.
 */
export function encodeCopyOutResponse(
  format: number = 0,
  columnFormatCodes: number[] = [],
): Buffer {
  const numColumns = columnFormatCodes.length;
  const bodyLen = 1 + 2 + numColumns * 2; // format(1) + numCols(2) + formatCodes(numCols*2)
  const msgLen = 1 + 4 + bodyLen; // type(1) + length(4) + body

  const buf = Buffer.alloc(msgLen);
  buf[0] = 0x48; // 'H'
  buf.writeInt32BE(bodyLen + 4, 1); // length (including self)
  buf[5] = format & 0xff; // format
  buf.writeInt16BE(numColumns, 6);

  for (let i = 0; i < numColumns; i++) {
    buf.writeInt16BE(columnFormatCodes[i] ?? 0, 8 + i * 2);
  }

  return buf;
}

// ══════════════════════════════════════════════════════════════════
//  RowDescription builder
// ══════════════════════════════════════════════════════════════════

export interface ColumnDescriptor {
  name: string;
  tableOid: number;
  columnAttr: number;
  typeOid: number;
  typeModifier: number;
  formatCode: number;
}

/**
 * Encode a RowDescription message.
 *   char 'T'
 *   int32 length
 *   int16 columnCount
 *   for each column:
 *     string name + \0
 *     int32 tableOid
 *     int16 columnAttr
 *     int32 typeOid
 *     int16 typeModifier
 *     int16 formatCode
 */
export function encodeRowDescription(columns: ColumnDescriptor[]): Buffer {
  const parts: Buffer[] = [];

  // Column count (int16)
  const countBuf = Buffer.alloc(2);
  countBuf.writeInt16BE(columns.length, 0);
  parts.push(countBuf);

  for (const col of columns) {
    // Name + null terminator
    const nameBuf = Buffer.from(col.name, 'utf8');
    parts.push(nameBuf);
    parts.push(Buffer.from([0]));

    // Table OID (int32)
    const tableOidBuf = Buffer.alloc(4);
    tableOidBuf.writeInt32BE(col.tableOid, 0);
    parts.push(tableOidBuf);

    // Column attribute (int16)
    const colAttrBuf = Buffer.alloc(2);
    colAttrBuf.writeInt16BE(col.columnAttr, 0);
    parts.push(colAttrBuf);

    // Type OID (int32)
    const typeOidBuf = Buffer.alloc(4);
    typeOidBuf.writeInt32BE(col.typeOid, 0);
    parts.push(typeOidBuf);

    // Type modifier (int16)
    const typeModBuf = Buffer.alloc(2);
    typeModBuf.writeInt16BE(col.typeModifier, 0);
    parts.push(typeModBuf);

    // Format code (int16)
    const formatBuf = Buffer.alloc(2);
    formatBuf.writeInt16BE(col.formatCode, 0);
    parts.push(formatBuf);
  }

  const body = Buffer.concat(parts);
  const len = 4 + body.length;
  const buf = Buffer.alloc(1 + len);
  buf[0] = 0x54; // 'T'
  buf.writeInt32BE(len, 1);
  body.copy(buf, 5);
  return buf;
}
