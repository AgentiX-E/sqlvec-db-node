/**
 * PgBinaryCodec — PostgreSQL COPY binary format encoder/decoder.
 *
 * Implements the PostgreSQL binary COPY protocol for data import/export.
 * Supports all major PG built-in types.
 *
 * ## Binary COPY Format
 *
 * The format is documented at:
 * https://www.postgresql.org/docs/current/sql-copy.html#SQL-COPY-DESCRIPTION
 *
 * Structure:
 * ```
 * Signature: 11 bytes "PGCOPY\n\377\r\n\0"
 * Flags:     4 bytes (bitmask, int32)
 * Header:    4 bytes (header extension length, typically 0)
 * Row data:  zero or more rows:
 *   Field count: 2 bytes (int16)
 *   Fields:      zero or more fields:
 *     Length:    4 bytes (int32) — -1 for NULL
 *     Data:      N bytes (length as specified)
 * Trailer:   2 bytes (int16 -1) end-of-data marker
 * ```
 *
 * ## Supported types
 *
 * | PG Type OID | Name          | Binary format     |
 * |:------------|:--------------|:------------------|
 * | 21          | int2          | 2-byte big-endian |
 * | 23          | int4          | 4-byte big-endian |
 * | 20          | int8          | 8-byte big-endian |
 * | 700         | float4        | 4-byte IEEE 754   |
 * | 701         | float8        | 8-byte IEEE 754   |
 * | 1700        | numeric       | PG numeric varlena|
 * | 25          | text          | UTF-8 string      |
 * | 1043        | varchar       | UTF-8 string      |
 * | 1082        | date          | 4-byte days since 2000-01-01 |
 * | 1114        | timestamp     | 8-byte micros since 2000-01-01 |
 * | 2950        | uuid          | 16-byte big-endian |
 *
 * @module protocol/PgBinaryCodec
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { DatabaseError } from '../error/DatabaseError';
import {
  SQLSTATE_DATA_EXCEPTION,
} from '../constants/sqlstate';

// ── Logger ───────────────────────────────────────────────────────


// ── Constants ────────────────────────────────────────────────────

/** Binary COPY signature: "PGCOPY\n\377\r\n\0" */
const PG_BINARY_SIGNATURE = Buffer.from([0x50, 0x47, 0x43, 0x4f, 0x50, 0x59, 0x0a, 0xff, 0x0d, 0x0a, 0x00]);

/** Flags: 0 (no OID, no special options) */
const PG_BINARY_FLAGS = Buffer.alloc(4);

/** Header extension length: 0 */
const PG_BINARY_HEADER_EXT = Buffer.alloc(4);

/** End-of-data marker: 2 bytes of -1 (0xFFFF) */
const PG_BINARY_END = Buffer.from([0xff, 0xff]);

// ── PG Type OIDs ─────────────────────────────────────────────────

export const PG_TYPES = {
  INT2: 21,
  INT4: 23,
  INT8: 20,
  FLOAT4: 700,
  FLOAT8: 701,
  NUMERIC: 1700,
  TEXT: 25,
  VARCHAR: 1043,
  BPCHAR: 1042,
  DATE: 1082,
  TIMESTAMP: 1114,
  TIMESTAMPTZ: 1184,
  TIME: 1083,
  TIMETZ: 1266,
  UUID: 2950,
  BOOL: 16,
  BYTEA: 17,
} as const;

/** Binary COPY header structure. */
export interface PgBinaryCopyHeader {
  /** Flags bitmask. Bit 0: OID present. */
  flags: number;
  /** Header extension length (typically 0). */
  headerExtLength: number;
}

/** Header-only buffer (signature + flags + headerExt). */
export const PG_BINARY_HEADER: Buffer = Buffer.concat([
  PG_BINARY_SIGNATURE,
  PG_BINARY_FLAGS,
  PG_BINARY_HEADER_EXT,
]);

/** Number of bytes in header: 11 + 4 + 4 = 19. */
export const PG_HEADER_BYTES = PG_BINARY_HEADER.length; // 19

/** Number of bytes in end-of-data trailer: 2. */
export const PG_TRAILER_BYTES = PG_BINARY_END.length; // 2

/** Flag: OID per-tuple present. */
export const PG_FLAG_OID = 1 << 16;

// ── PgBinaryCodec ────────────────────────────────────────────────

export class PgBinaryCodec {
  private readonly logger = PinoLogger.forComponent('pgbinarycodec');

  /**
   * Encode a row of values into PG binary COPY format bytes.
   *
   * @param values - Array of values to encode. `null` values are encoded as NULL fields.
   * @returns Buffer containing the encoded row.
   */
  encodeRow(values: (any)[]): Buffer {
    const fieldCount = Buffer.alloc(2);
    fieldCount.writeUInt16BE(values.length);

    const parts: Buffer[] = [fieldCount];

    for (const val of values) {
      if (val === null || val === undefined) {
        // NULL field: length = -1 (0xFFFFFFFF)
        parts.push(Buffer.from([0xff, 0xff, 0xff, 0xff]));
        continue;
      }

      const encoded = this.encodeValue(val);
      parts.push(encoded);
    }

    return Buffer.concat(parts);
  }

  /**
   * Encode a binary COPY header with an optional row count payload.
   * Returns the raw header bytes.
   */
  encodeHeader(): Buffer {
    return Buffer.concat([
      PG_BINARY_SIGNATURE,
      PG_BINARY_FLAGS,
      PG_BINARY_HEADER_EXT,
    ]);
  }

  /**
   * Return the compact end-of-data trailer (2 bytes).
   */
  encodeTrailer(): Buffer {
    return PG_BINARY_END;
  }

  /**
   * Get the number of rows in a binary COPY payload by counting
   * tuple markers until the end-of-data trailer.
   */
  getTupleCount(buffer: Buffer): number {
    let offset = PG_HEADER_BYTES;
    let count = 0;
    while (offset + 2 <= buffer.length) {
      const fieldCount = buffer.readUInt16BE(offset);
      offset += 2;
      if (fieldCount === 0xFFFF) break;
      count++;
      for (let i = 0; i < fieldCount; i++) {
        if (offset + 4 > buffer.length) break;
        const fieldLen = buffer.readInt32BE(offset);
        offset += 4;
        if (fieldLen === -1) continue;
        offset += fieldLen;
      }
    }
    return count;
  }

  /**
   * Encode an entire COPY payload (header + rows + trailer).
   *
   * @param rows - Array of rows, each being an array of values.
   * @returns Complete binary COPY buffer.
   */
  encodePayload(rows: any[][]): Buffer {
    const parts: Buffer[] = [
      PG_BINARY_SIGNATURE,
      PG_BINARY_FLAGS,
      PG_BINARY_HEADER_EXT,
    ];

    for (const row of rows) {
      parts.push(this.encodeRow(row));
    }

    parts.push(PG_BINARY_END);

    return Buffer.concat(parts);
  }

  /**
   * Decode a PG binary COPY payload into rows.
   *
   * @param buffer - The complete binary COPY payload.
   * @returns Array of decoded rows (each row is an array of decoded values).
   * @throws {Error} If the buffer is not a valid binary COPY payload.
   */
  decodePayload(buffer: Buffer): any[][] {
    let offset = 0;

    // Verify signature.
    const sig = buffer.subarray(offset, offset + 11);
    if (!sig.equals(PG_BINARY_SIGNATURE)) {
      throw new DatabaseError('Invalid PG binary COPY signature', SQLSTATE_DATA_EXCEPTION);
    }
    offset += 11;

    // Skip flags (4 bytes).
    offset += 4;

    // Skip header extension length (4 bytes).
    offset += 4;

    // Read rows.
    const rows: any[][] = [];
    while (offset + 2 <= buffer.length) {
      const fieldCount = buffer.readUInt16BE(offset);
      offset += 2;

      // End-of-data marker.
      if (fieldCount === 0xFFFF) break;

      const row: any[] = [];
      for (let i = 0; i < fieldCount; i++) {
        // Field length (4 bytes).
        const fieldLen = buffer.readInt32BE(offset);
        offset += 4;

        if (fieldLen === -1) {
          // NULL field.
          row.push(null);
          continue;
        }

        const fieldData = buffer.subarray(offset, offset + fieldLen);
        offset += fieldLen;

        // Decode based on heuristics — the caller should provide type info.
        row.push(this.decodeValue(fieldData));
      }

      rows.push(row);
    }

    return rows;
  }

  /**
   * Decode a PG binary COPY payload with explicit type OIDs per column.
   *
   * @param buffer  - The complete binary COPY payload.
   * @param typeOids - Array of PG type OIDs for each column (e.g. [23, 25] for int4, text).
   * @returns Array of decoded rows with types applied.
   */
  decodePayloadWithTypes(buffer: Buffer, typeOids: number[]): any[][] {
    let offset = 0;

    // Verify signature.
    const sig = buffer.subarray(offset, offset + 11);
    if (!sig.equals(PG_BINARY_SIGNATURE)) {
      throw new DatabaseError('Invalid PG binary COPY signature', SQLSTATE_DATA_EXCEPTION);
    }
    offset += 11;

    // Skip flags.
    offset += 4;
    // Skip header extension.
    offset += 4;

    const rows: any[][] = [];
    while (offset + 2 <= buffer.length) {
      const fieldCount = buffer.readUInt16BE(offset);
      offset += 2;

      if (fieldCount === 0xFFFF) break;

      const row: any[] = [];
      for (let i = 0; i < fieldCount; i++) {
        const fieldLen = buffer.readInt32BE(offset);
        offset += 4;

        if (fieldLen === -1) {
          row.push(null);
          continue;
        }

        const fieldData = buffer.subarray(offset, offset + fieldLen);
        offset += fieldLen;

        const typeOid = typeOids[i] || 25; // Default to text.
        row.push(this.decodeTypedValue(fieldData, typeOid));
      }

      rows.push(row);
    }

    return rows;
  }

  /**
   * Stream-decode a PG binary COPY payload — yields rows one at a time
   * from the buffer, WITHOUT creating the full decoded array in memory.
   *
   * This is the streaming version of `decodePayloadWithTypes`. Use for
   * large payloads (millions of rows) to avoid O(n) memory for decoded rows.
   *
   * @param buffer  - The complete binary COPY payload buffer.
   * @param typeOids - Array of PG type OIDs for each column.
   * @yields Decoded rows one-by-one as they are parsed from the buffer.
   */
  *decodeRowsGenerator(buffer: Buffer, typeOids: number[]): Generator<any[], void, unknown> {
    let offset = 0;

    // Verify signature.
    const sig = buffer.subarray(offset, offset + 11);
    if (!sig.equals(PG_BINARY_SIGNATURE)) {
      throw new DatabaseError('Invalid PG binary COPY signature', SQLSTATE_DATA_EXCEPTION);
    }
    offset += 11;

    // Skip flags.
    offset += 4;
    // Skip header extension.
    offset += 4;

    while (offset + 2 <= buffer.length) {
      const fieldCount = buffer.readUInt16BE(offset);
      offset += 2;

      // End-of-data marker.
      if (fieldCount === 0xFFFF) break;

      const row: any[] = [];
      for (let i = 0; i < fieldCount; i++) {
        const fieldLen = buffer.readInt32BE(offset);
        offset += 4;

        if (fieldLen === -1) {
          row.push(null);
          continue;
        }

        const fieldData = buffer.subarray(offset, offset + fieldLen);
        offset += fieldLen;

        const typeOid = typeOids[i] || 25;
        row.push(this.decodeTypedValue(fieldData, typeOid));
      }

      yield row;
    }
  }

  // ── Individual value encoders ─────────────────────────────────

  encodeInt2(value: number): Buffer {
    const buf = Buffer.alloc(6); // length(4) + data(2)
    buf.writeInt32BE(2, 0);
    buf.writeInt16BE(value, 4);
    return buf;
  }

  encodeInt4(value: number): Buffer {
    const buf = Buffer.alloc(8); // length(4) + data(4)
    buf.writeInt32BE(4, 0);
    buf.writeInt32BE(value, 4);
    return buf;
  }

  encodeInt8(value: bigint | number): Buffer {
    const buf = Buffer.alloc(12); // length(4) + data(8)
    buf.writeInt32BE(8, 0);
    const bigVal = typeof value === 'bigint' ? value : BigInt(value);
    buf.writeBigInt64BE(bigVal, 4);
    return buf;
  }

  encodeFloat4(value: number): Buffer {
    const buf = Buffer.alloc(8); // length(4) + data(4)
    buf.writeInt32BE(4, 0);
    buf.writeFloatBE(value, 4);
    return buf;
  }

  encodeFloat8(value: number): Buffer {
    const buf = Buffer.alloc(12); // length(4) + data(8)
    buf.writeInt32BE(8, 0);
    buf.writeDoubleBE(value, 4);
    return buf;
  }

  encodeText(value: string): Buffer {
    const strBuf = Buffer.from(value, 'utf-8');
    const buf = Buffer.alloc(4 + strBuf.length);
    buf.writeInt32BE(strBuf.length, 0);
    strBuf.copy(buf, 4);
    return buf;
  }

  encodeBoolean(value: boolean): Buffer {
    const buf = Buffer.alloc(5); // length(4) + data(1)
    buf.writeInt32BE(1, 0);
    buf[4] = value ? 1 : 0;
    return buf;
  }

  encodeDate(value: Date | string): Buffer {
    const date = typeof value === 'string' ? new Date(value) : value;
    // PG date: days since 2000-01-01.
    const pgEpoch = new Date('2000-01-01T00:00:00Z');
    const days = Math.floor((date.getTime() - pgEpoch.getTime()) / (1000 * 60 * 60 * 24));
    return this.encodeInt4(days);
  }

  encodeTimestamp(value: Date | string | number): Buffer {
    const ts = typeof value === 'string' ? new Date(value).getTime() :
               typeof value === 'number' ? value :
               value.getTime();
    // PG timestamp: microseconds since 2000-01-01.
    const pgEpoch = new Date('2000-01-01T00:00:00Z').getTime();
    const micros = (ts - pgEpoch) * 1000;
    return this.encodeInt8(micros);
  }

  /**
   * Encode time-of-day value to PG binary time (microseconds since midnight).
   * Accepts Date, ISO string ("HH:MM:SS[.us]"), or microsecond number.
   */
  encodeTime(value: Date | string | number): Buffer {
    let micros: number;
    if (typeof value === 'number') {
      micros = value;
    } else if (typeof value === 'string') {
      // Parse HH:MM:SS[.ffffff]
      const parts = value.split(':');
      const h = parseInt(parts[0], 10);
      const m = parseInt(parts[1], 10);
      const secParts = parts[2].split('.');
      const s = parseInt(secParts[0], 10);
      const us = secParts[1] ? parseInt(secParts[1].padEnd(6, '0').substring(0, 6), 10) : 0;
      micros = ((h * 3600 + m * 60 + s) * 1000000) + us;
    } else {
      // Date: use time-of-day component
      micros = ((value.getUTCHours() * 3600 + value.getUTCMinutes() * 60 + value.getUTCSeconds()) * 1000000)
        + (value.getUTCMilliseconds() * 1000);
    }
    const buf = Buffer.alloc(8);
    buf.writeBigInt64BE(BigInt(micros), 0);
    return buf;
  }

  encodeUUID(value: string): Buffer {
    // Remove UUID dashes and parse as hex.
    const hex = value.replace(/-/g, '');
    const uuidBuf = Buffer.from(hex, 'hex');
    const buf = Buffer.alloc(4 + 16);
    buf.writeInt32BE(16, 0);
    uuidBuf.copy(buf, 4);
    return buf;
  }

  encodeNumeric(value: number | string): Buffer {
    // Simplified numeric encoding — uses float8 as fallback.
    const num = typeof value === 'string' ? parseFloat(value) : value;
    return this.encodeFloat8(num);
  }

  encodeBytea(value: Buffer): Buffer {
    const buf = Buffer.alloc(4 + value.length);
    buf.writeInt32BE(value.length, 0);
    value.copy(buf, 4);
    return buf;
  }

  // ── Individual value decoders ─────────────────────────────────

  decodeInt2(buffer: Buffer, offset: number = 0): number {
    return buffer.readInt16BE(offset);
  }

  decodeInt4(buffer: Buffer, offset: number = 0): number {
    return buffer.readInt32BE(offset);
  }

  decodeInt8(buffer: Buffer, offset: number = 0): bigint {
    return buffer.readBigInt64BE(offset);
  }

  decodeFloat4(buffer: Buffer, offset: number = 0): number {
    return buffer.readFloatBE(offset);
  }

  decodeFloat8(buffer: Buffer, offset: number = 0): number {
    return buffer.readDoubleBE(offset);
  }

  decodeText(buffer: Buffer, offset: number = 0, length: number): string {
    return buffer.toString('utf-8', offset, offset + length);
  }

  decodeBoolean(buffer: Buffer, offset: number = 0): boolean {
    return buffer[offset] !== 0;
  }

  decodeDate(buffer: Buffer, offset: number = 0): Date {
    const days = this.decodeInt4(buffer, offset);
    const pgEpoch = new Date('2000-01-01T00:00:00Z');
    return new Date(pgEpoch.getTime() + days * 24 * 60 * 60 * 1000);
  }

  decodeTimestamp(buffer: Buffer, offset: number = 0): Date {
    const micros = this.decodeInt8(buffer, offset);
    const pgEpoch = new Date('2000-01-01T00:00:00Z').getTime();
    return new Date(pgEpoch + Number(micros) / 1000);
  }

  /**
   * Decode PG binary time (int8 microseconds since midnight) to ISO time string.
   */
  decodeTime(buffer: Buffer, offset: number = 0): string {
    const micros = Number(this.decodeInt8(buffer, offset));
    const totalSeconds = Math.floor(micros / 1000000);
    const us = micros % 1000000;
    const h = Math.floor(totalSeconds / 3600) % 24;
    const m = Math.floor((totalSeconds % 3600) / 60);
    const s = totalSeconds % 60;
    const hh = String(h).padStart(2, '0');
    const mm = String(m).padStart(2, '0');
    const ss = String(s).padStart(2, '0');
    if (us === 0) return `${hh}:${mm}:${ss}`;
    return `${hh}:${mm}:${ss}.${String(us).padStart(6, '0')}`;
  }

  decodeUUID(buffer: Buffer, offset: number = 0): string {
    const hex = buffer.toString('hex', offset, offset + 16);
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
  }

  // ── Private helpers ───────────────────────────────────────────

  /**
   * Encode a value to its PG binary representation, auto-detecting the type.
   */
  private encodeValue(value: any): Buffer {
    if (typeof value === 'number') {
      if (Number.isInteger(value)) {
        if (value >= -32768 && value <= 32767) return this.encodeInt2(value);
        if (value >= -2147483648 && value <= 2147483647) return this.encodeInt4(value);
        return this.encodeInt8(value);
      }
      return this.encodeFloat8(value);
    }

    if (typeof value === 'bigint') {
      return this.encodeInt8(value);
    }

    if (typeof value === 'boolean') {
      return this.encodeBoolean(value);
    }

    if (value instanceof Date) {
      return this.encodeTimestamp(value);
    }

    if (value instanceof Buffer) {
      return this.encodeBytea(value);
    }

    // Default: treat as text.
    return this.encodeText(String(value));
  }

  /**
   * Decode a value from PG binary data using heuristics.
   */
  private decodeValue(buffer: Buffer): any {
    const len = buffer.length;
    if (len === 2) return this.decodeInt2(buffer);
    if (len === 4) return this.decodeInt4(buffer);
    if (len === 8) return Number(this.decodeInt8(buffer));
    if (len === 16) return this.decodeUUID(buffer);
    return this.decodeText(buffer, 0, len);
  }

  /**
   * Decode a value from PG binary data using a specific type OID.
   */
  public decodeTypedValue(buffer: Buffer, typeOid: number): any {
    switch (typeOid) {
      case PG_TYPES.INT2:
        return this.decodeInt2(buffer);
      case PG_TYPES.INT4:
        return this.decodeInt4(buffer);
      case PG_TYPES.INT8:
        return this.decodeInt8(buffer);
      case PG_TYPES.FLOAT4:
        return this.decodeFloat4(buffer);
      case PG_TYPES.FLOAT8:
        return this.decodeFloat8(buffer);
      case PG_TYPES.NUMERIC:
        return this.decodeFloat8(buffer); // Simplified fallback
      case PG_TYPES.BOOL:
        return this.decodeBoolean(buffer);
      case PG_TYPES.DATE:
        return this.decodeDate(buffer);
      case PG_TYPES.TIMESTAMP:
      case PG_TYPES.TIMESTAMPTZ:
        return this.decodeTimestamp(buffer);
      case PG_TYPES.TIME:
        return this.decodeTime(buffer);
      case PG_TYPES.TIMETZ:
        return this.decodeTime(buffer); // Simplified — time with tz stripped (common fallback)
      case PG_TYPES.UUID:
        return this.decodeUUID(buffer);
      case PG_TYPES.TEXT:
      case PG_TYPES.VARCHAR:
      case PG_TYPES.BPCHAR:
      default:
        return this.decodeText(buffer, 0, buffer.length);
    }
  }
}
