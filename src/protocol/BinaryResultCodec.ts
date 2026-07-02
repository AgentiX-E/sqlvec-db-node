/**
 * BinaryResultCodec — PG extended query protocol binary result encoding.
 *
 * Implements binary encoding for the PostgreSQL extended query protocol.
 * This is different from the COPY binary format (PgBinaryCodec):
 * - DataRow messages have their own length-prefixed field format
 * - Binary values are encoded without the 4-byte length prefix (the protocol
 *   layer adds length via DataRow column spec)
 *
 * ## Supported type OIDs and binary formats
 *
 * | OID  | PG Type      | Binary Format                                               |
 * |:-----|:-------------|:------------------------------------------------------------|
 * | 21   | INT2         | 2 bytes, big-endian signed int16                            |
 * | 23   | INT4         | 4 bytes, big-endian signed int32                            |
 * | 20   | INT8         | 8 bytes, big-endian signed int64                            |
 * | 700  | FLOAT4       | 4 bytes, IEEE 754 single-precision                          |
 * | 701  | FLOAT8       | 8 bytes, IEEE 754 double-precision                          |
 * | 16   | BOOL         | 1 byte: 0 = false, 1 = true                                 |
 * | 25   | TEXT         | Not sent as binary (use text format)                        |
 * | 1043 | VARCHAR      | Not sent as binary (use text format)                        |
 * | 1082 | DATE         | 4 bytes, big-endian signed int32 (days since 2000-01-01)   |
 * | 1114 | TIMESTAMP    | 8 bytes, big-endian int64 (microseconds since 2000-01-01)   |
 * | 1184 | TIMESTAMPTZ  | 8 bytes, big-endian int64 (microseconds since 2000-01-01)   |
 *
 * @module protocol/BinaryResultCodec
 */

// ── PG Type OIDs (subset used by binary codec) ─────────────────────────

export const PG_BINARY_OIDS = {
  INT2: 21,
  INT4: 23,
  INT8: 20,
  FLOAT4: 700,
  FLOAT8: 701,
  BOOL: 16,
  TEXT: 25,
  VARCHAR: 1043,
  BPCHAR: 1042,
  DATE: 1082,
  TIMESTAMP: 1114,
  TIMESTAMPTZ: 1184,
  NUMERIC: 1700,
  BYTEA: 17,
  UUID: 2950,
  JSONB: 3802,
  INET: 869,
  CIDR: 650,
  MACADDR: 829,
  TIME: 1083,
  TIMETZ: 1266,
  INTERVAL: 1186,
  POINT: 600,
  LSEG: 601,
  BOX: 603,
  PATH: 602,
  POLYGON: 604,
  CIRCLE: 718,
  VARBIT: 1562,
  TXID_SNAPSHOT: 2970,
} as const;

/** Postgres epoch (2000-01-01) in milliseconds since Unix epoch. */
const PG_EPOCH_MS = Date.UTC(2000, 0, 1);

/**
 * BinaryResultCodec — encode/decode values in PG extended query binary format.
 *
 * In the extended query protocol, a DataRow in binary format sends each
 * column value as:
 *   - 4-byte int32 length (not included here — the protocol layer handles it)
 *   - N bytes of raw binary data (what `encodeValue` returns)
 *
 * This codec only handles the raw binary data portion, NOT the length prefix.
 * Use `encodeValue()` to get the raw bytes, and `encodeDataRow()` to produce
 * a complete set of column data for a row.
 */
export class BinaryResultCodec {
  // ── Encoding ──────────────────────────────────────────────────────────

  /**
   * Encode a single value in PG binary format for the extended query protocol.
   *
   * @param value - The value to encode.
   * @param oid   - The PG type OID indicating the desired binary format.
   * @returns A Buffer containing the raw binary data (without length prefix).
   * @throws If the OID is unrecognized or the value cannot be encoded.
   */
  static encodeValue(value: any, oid: number): Buffer {
    if (value === null || value === undefined) {
      return Buffer.alloc(0); // NULL is signaled by the protocol (length = -1)
    }

    switch (oid) {
      case PG_BINARY_OIDS.INT2:
        return BinaryResultCodec.encodeInt2(value);
      case PG_BINARY_OIDS.INT4:
        return BinaryResultCodec.encodeInt4(value);
      case PG_BINARY_OIDS.INT8:
        return BinaryResultCodec.encodeInt8(value);
      case PG_BINARY_OIDS.FLOAT4:
        return BinaryResultCodec.encodeFloat4(value);
      case PG_BINARY_OIDS.FLOAT8:
        return BinaryResultCodec.encodeFloat8(value);
      case PG_BINARY_OIDS.BOOL:
        return BinaryResultCodec.encodeBool(value);
      case PG_BINARY_OIDS.DATE:
        return BinaryResultCodec.encodeDate(value);
      case PG_BINARY_OIDS.TIMESTAMP:
      case PG_BINARY_OIDS.TIMESTAMPTZ:
        return BinaryResultCodec.encodeTimestamp(value);
      case PG_BINARY_OIDS.NUMERIC:
        return BinaryResultCodec.encodeNumeric(value);
      case PG_BINARY_OIDS.UUID:
        return BinaryResultCodec.encodeUuid(value);
      case PG_BINARY_OIDS.JSONB:
        return BinaryResultCodec.encodeJsonb(value);
      case PG_BINARY_OIDS.INET:
      case PG_BINARY_OIDS.CIDR:
        return BinaryResultCodec.encodeInet(value);
      case PG_BINARY_OIDS.MACADDR:
        return BinaryResultCodec.encodeMacaddr(value);
      case PG_BINARY_OIDS.TEXT:
      case PG_BINARY_OIDS.VARCHAR:
      case PG_BINARY_OIDS.BPCHAR:
        // TEXT family: fallback to UTF-8 binary (clients that request binary
        // format for text will receive the raw string bytes)
        return Buffer.from(String(value), 'utf-8');
      case PG_BINARY_OIDS.BYTEA:
        if (Buffer.isBuffer(value)) return value;
        if (typeof value === 'string') return Buffer.from(value, 'hex');
        return Buffer.from(String(value));
      case PG_BINARY_OIDS.TIME:
        return BinaryResultCodec.encodeTime(value);
      case PG_BINARY_OIDS.TIMETZ:
        return BinaryResultCodec.encodeTimetz(value);
      case PG_BINARY_OIDS.INTERVAL:
        return BinaryResultCodec.encodeInterval(value);
      case PG_BINARY_OIDS.POINT:
        return BinaryResultCodec.encodePoint(value);
      case PG_BINARY_OIDS.LSEG:
        return BinaryResultCodec.encodeLseg(value);
      case PG_BINARY_OIDS.BOX:
        return BinaryResultCodec.encodeBox(value);
      case PG_BINARY_OIDS.PATH:
        return BinaryResultCodec.encodePath(value);
      case PG_BINARY_OIDS.POLYGON:
        return BinaryResultCodec.encodePolygon(value);
      case PG_BINARY_OIDS.CIRCLE:
        return BinaryResultCodec.encodeCircle(value);
      case PG_BINARY_OIDS.VARBIT:
        return BinaryResultCodec.encodeVarbit(value);
      case PG_BINARY_OIDS.TXID_SNAPSHOT:
        return BinaryResultCodec.encodeTxidSnapshot(value);
      default:
        // Unknown OID — fallback to UTF-8 string encoding
        return Buffer.from(String(value), 'utf-8');
    }
  }

  /**
   * Decode a PG binary value back into a JavaScript value.
   *
   * @param buffer - The raw binary data (without length prefix).
   * @param oid    - The PG type OID.
   * @returns The decoded JavaScript value.
   */
  static decodeValue(buffer: Buffer, oid: number): any {
    if (!buffer || buffer.length === 0) return null;

    switch (oid) {
      case PG_BINARY_OIDS.INT2:
        return BinaryResultCodec.decodeInt2(buffer);
      case PG_BINARY_OIDS.INT4:
        return BinaryResultCodec.decodeInt4(buffer);
      case PG_BINARY_OIDS.INT8:
        return BinaryResultCodec.decodeInt8(buffer);
      case PG_BINARY_OIDS.FLOAT4:
        return BinaryResultCodec.decodeFloat4(buffer);
      case PG_BINARY_OIDS.FLOAT8:
        return BinaryResultCodec.decodeFloat8(buffer);
      case PG_BINARY_OIDS.BOOL:
        return BinaryResultCodec.decodeBool(buffer);
      case PG_BINARY_OIDS.DATE:
        return BinaryResultCodec.decodeDate(buffer);
      case PG_BINARY_OIDS.TIMESTAMP:
      case PG_BINARY_OIDS.TIMESTAMPTZ:
        return BinaryResultCodec.decodeTimestamp(buffer);
      case PG_BINARY_OIDS.NUMERIC:
        return BinaryResultCodec.decodeNumeric(buffer);
      case PG_BINARY_OIDS.UUID:
        return BinaryResultCodec.decodeUuid(buffer);
      case PG_BINARY_OIDS.JSONB:
        return BinaryResultCodec.decodeJsonb(buffer);
      case PG_BINARY_OIDS.INET:
      case PG_BINARY_OIDS.CIDR:
        return BinaryResultCodec.decodeInet(buffer);
      case PG_BINARY_OIDS.MACADDR:
        return BinaryResultCodec.decodeMacaddr(buffer);
      case PG_BINARY_OIDS.TEXT:
      case PG_BINARY_OIDS.VARCHAR:
      case PG_BINARY_OIDS.BPCHAR:
        return buffer.toString('utf-8');
      case PG_BINARY_OIDS.BYTEA:
        return buffer;
      case PG_BINARY_OIDS.TIME:
        return BinaryResultCodec.decodeTime(buffer);
      case PG_BINARY_OIDS.TIMETZ:
        return BinaryResultCodec.decodeTimetz(buffer);
      case PG_BINARY_OIDS.INTERVAL:
        return BinaryResultCodec.decodeInterval(buffer);
      case PG_BINARY_OIDS.POINT:
        return BinaryResultCodec.decodePoint(buffer);
      case PG_BINARY_OIDS.LSEG:
        return BinaryResultCodec.decodeLseg(buffer);
      case PG_BINARY_OIDS.BOX:
        return BinaryResultCodec.decodeBox(buffer);
      case PG_BINARY_OIDS.PATH:
        return BinaryResultCodec.decodePath(buffer);
      case PG_BINARY_OIDS.POLYGON:
        return BinaryResultCodec.decodePolygon(buffer);
      case PG_BINARY_OIDS.CIRCLE:
        return BinaryResultCodec.decodeCircle(buffer);
      case PG_BINARY_OIDS.VARBIT:
        return BinaryResultCodec.decodeVarbit(buffer);
      case PG_BINARY_OIDS.TXID_SNAPSHOT:
        return BinaryResultCodec.decodeTxidSnapshot(buffer);
      default:
        return buffer.toString('utf-8');
    }
  }

  /**
   * Encode multiple values as a PG binary DataRow payload.
   *
   * The output format (without the DataRow message header):
   *   - For each column i: 4-byte int32 length, then raw bytes
   *   - NULL values: 4-byte int32 (-1), no data bytes
   *
   * @param values - Array of values.
   * @param oids   - Array of PG type OIDs, one per column.
   * @returns Buffer containing the complete DataRow column data.
   */
  static encodeDataRow(values: any[], oids: number[]): Buffer {
    const parts: Buffer[] = [];
    const numColumns = values.length;

    for (let i = 0; i < numColumns; i++) {
      const val = values[i];
      if (val === null || val === undefined) {
        // NULL: length = -1
        const nullLen = Buffer.alloc(4);
        nullLen.writeInt32BE(-1, 0);
        parts.push(nullLen);
        continue;
      }

      const oid = i < oids.length ? oids[i] : PG_BINARY_OIDS.TEXT;
      const encoded = BinaryResultCodec.encodeValue(val, oid);

      // Length prefix
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32BE(encoded.length, 0);
      parts.push(lenBuf);
      parts.push(encoded);
    }

    return Buffer.concat(parts);
  }

  /**
   * Decode a PG binary DataRow payload back into values.
   *
   * @param buffer - The DataRow column data buffer.
   * @param oids   - Array of PG type OIDs, one per column.
   * @returns Array of decoded values.
   */
  static decodeDataRow(buffer: Buffer, oids: number[]): any[] {
    const values: any[] = [];
    let offset = 0;

    for (let i = 0; i < oids.length; i++) {
      if (offset + 4 > buffer.length) {
        values.push(null);
        continue;
      }

      const colLen = buffer.readInt32BE(offset);
      offset += 4;

      if (colLen === -1) {
        values.push(null);
        continue;
      }

      if (offset + colLen > buffer.length) {
        values.push(null);
        continue;
      }

      const colData = buffer.subarray(offset, offset + colLen);
      offset += colLen;

      const oid = i < oids.length ? oids[i] : PG_BINARY_OIDS.TEXT;
      values.push(BinaryResultCodec.decodeValue(colData, oid));
    }

    return values;
  }

  // ── Specific type encoders ────────────────────────────────────────────

  private static encodeInt2(value: number): Buffer {
    const buf = Buffer.alloc(2);
    buf.writeInt16BE(Math.trunc(value), 0);
    return buf;
  }

  private static encodeInt4(value: number): Buffer {
    const buf = Buffer.alloc(4);
    buf.writeInt32BE(Math.trunc(value), 0);
    return buf;
  }

  private static encodeInt8(value: number | bigint): Buffer {
    const buf = Buffer.alloc(8);
    const bigVal = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
    buf.writeBigInt64BE(bigVal, 0);
    return buf;
  }

  private static encodeFloat4(value: number): Buffer {
    const buf = Buffer.alloc(4);
    buf.writeFloatBE(value, 0);
    return buf;
  }

  private static encodeFloat8(value: number): Buffer {
    const buf = Buffer.alloc(8);
    buf.writeDoubleBE(value, 0);
    return buf;
  }

  private static encodeBool(value: boolean | number | string): Buffer {
    const buf = Buffer.alloc(1);
    if (typeof value === 'boolean') {
      buf[0] = value ? 1 : 0;
    } else if (typeof value === 'number') {
      buf[0] = value !== 0 ? 1 : 0;
    } else {
      const sv = String(value).toLowerCase();
      buf[0] = ['true', 'on', 'yes', '1'].includes(sv) ? 1 : 0;
    }
    return buf;
  }

  private static encodeDate(value: Date | string | number): Buffer {
    const ms = typeof value === 'number' ? value :
               typeof value === 'string' ? new Date(value).getTime() :
               value.getTime();
    const days = Math.floor((ms - PG_EPOCH_MS) / (86400000));
    return BinaryResultCodec.encodeInt4(days);
  }

  private static encodeTimestamp(value: Date | string | number): Buffer {
    const ms = typeof value === 'number' ? value :
               typeof value === 'string' ? new Date(value).getTime() :
               value.getTime();
    // Microseconds since 2000-01-01
    const micros = (ms - PG_EPOCH_MS) * 1000;
    return BinaryResultCodec.encodeInt8(micros);
  }

  // ── Specific type decoders ────────────────────────────────────────────

  private static decodeInt2(buffer: Buffer): number {
    return buffer.readInt16BE(0);
  }

  private static decodeInt4(buffer: Buffer): number {
    return buffer.readInt32BE(0);
  }

  private static decodeInt8(buffer: Buffer): bigint {
    return buffer.readBigInt64BE(0);
  }

  private static decodeFloat4(buffer: Buffer): number {
    const val = buffer.readFloatBE(0);
    // Handle negative zero: normalize to 0
    return Object.is(val, -0) ? 0 : val;
  }

  private static decodeFloat8(buffer: Buffer): number {
    const val = buffer.readDoubleBE(0);
    // Handle negative zero: normalize to 0
    return Object.is(val, -0) ? 0 : val;
  }

  private static decodeBool(buffer: Buffer): boolean {
    return buffer[0] !== 0;
  }

  private static decodeDate(buffer: Buffer): Date {
    const days = BinaryResultCodec.decodeInt4(buffer);
    return new Date(PG_EPOCH_MS + days * 86400000);
  }

  private static decodeTimestamp(buffer: Buffer): Date {
    const micros = Number(BinaryResultCodec.decodeInt8(buffer));
    return new Date(PG_EPOCH_MS + micros / 1000);
  }

  // ── New type encoders/decoders: UUID, JSONB, INET, NUMERIC ───────────

  /**
   * UUID format: 16 bytes raw big-endian (matching PostgreSQL uuid_send).
   * Input as standard 8-4-4-4-12 hex string.
   */
  private static encodeUuid(value: string): Buffer {
    const hex = String(value).replace(/-/g, '');
    return Buffer.from(hex, 'hex');
  }

  private static decodeUuid(buffer: Buffer): string {
    const hex = buffer.toString('hex');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  }

  /**
   * JSONB format (PG binary): 1-byte version (1) + JSON text.
   * We store as version byte + UTF-8 JSON.
   */
  private static encodeJsonb(value: any): Buffer {
    const jsonStr = typeof value === 'string' ? value : JSON.stringify(value);
    const jsonBuf = Buffer.from(jsonStr, 'utf-8');
    const buf = Buffer.alloc(1 + jsonBuf.length);
    buf[0] = 1; // JSONB version 1
    jsonBuf.copy(buf, 1);
    return buf;
  }

  private static decodeJsonb(buffer: Buffer): any {
    if (buffer.length < 1) return null;
    const version = buffer[0];
    if (version === 1) {
      return buffer.toString('utf-8', 1);
    }
    // Fallback: treat whole buffer as UTF-8 text
    return buffer.toString('utf-8');
  }

  /**
   * INET format: 4 bytes (IPv4) or 16 bytes (IPv6) + 1 byte netmask + 1 byte is-cidr.
   * Simplified: store address as text and parse on decode.
   * Standard PG binary inet uses: family(1), prefix(1), is_cidr(1), address(N).
   */
  private static encodeInet(value: string): Buffer {
    const addr = String(value).split('/')[0]; // strip netmask
    const parts = addr.split('.');
    if (parts.length === 4) {
      // IPv4: family=2, prefix=32, is_cidr=0, address=4 bytes
      const buf = Buffer.alloc(8);
      buf[0] = 2;   // AF_INET
      buf[1] = 32;  // prefix length
      buf[2] = 0;   // is_cidr flag
      for (let i = 0; i < 4; i++) buf[3 + i] = parseInt(parts[i], 10);
      return buf;
    }
    // IPv6 or unknown: store as text
    return Buffer.from(addr, 'utf-8');
  }

  private static decodeInet(buffer: Buffer): string {
    if (buffer.length === 8 && buffer[0] === 2) {
      // IPv4 format
      return `${buffer[3]}.${buffer[4]}.${buffer[5]}.${buffer[6]}`;
    }
    return buffer.toString('utf-8');
  }

  /**
   * MACADDR format: 6 bytes, colon-separated hex.
   */
  private static encodeMacaddr(value: string): Buffer {
    const hex = String(value).replace(/[:-]/g, '');
    return Buffer.from(hex, 'hex');
  }

  private static decodeMacaddr(buffer: Buffer): string {
    if (buffer.length === 6) {
      return Array.from(buffer)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':');
    }
    return buffer.toString('utf-8');
  }

  /**
   * NUMERIC format: PG binary numeric. Simplified: store as string.
   * PG binary format: uint16 ndigits, int16 weight, int16 sign, int16 dscale, then int16[] digits.
   * We store the number as text for simplicity.
   */
  public static encodeNumeric(value: number | string): Buffer {
    const str = String(value);
    return Buffer.from(str, 'utf-8');
  }

  private static decodeNumeric(buffer: Buffer): number {
    return Number(buffer.toString('utf-8'));
  }

  // ── New type encoders/decoders: TIME, TIMETZ, INTERVAL ─────────────

  /**
   * TIME format: 8 bytes, microseconds since midnight (int64).
   * Input can be a string like '12:34:56.789' or number of microseconds.
   */
  private static encodeTime(value: any): Buffer {
    if (typeof value === 'number' || typeof value === 'bigint') {
      const buf = Buffer.alloc(8);
      const bigVal = typeof value === 'bigint' ? value : BigInt(Math.trunc(value));
      buf.writeBigInt64BE(bigVal, 0);
      return buf;
    }
    // Parse from string like '12:34:56.789'
    const str = String(value);
    const match = str.match(/^(\d+):(\d+)(?::(\d+(?:\.\d+)?))?/);
    if (match) {
      const h = parseInt(match[1], 10);
      const m = parseInt(match[2], 10);
      const s = match[3] ? parseFloat(match[3]) : 0;
      const micros = BigInt(Math.round((h * 3600000000 + m * 60000000 + s * 1000000)));
      const buf = Buffer.alloc(8);
      buf.writeBigInt64BE(micros, 0);
      return buf;
    }
    return Buffer.from(str, 'utf-8');
  }

  private static decodeTime(buffer: Buffer): string {
    if (buffer.length === 8) {
      try {
        const micros = Number(buffer.readBigInt64BE(0));
        const totalSec = Math.floor(micros / 1000000);
        const frac = micros % 1000000;
        const h = Math.floor(totalSec / 3600) % 24;
        const m = Math.floor((totalSec % 3600) / 60);
        const s = totalSec % 60;
        if (frac > 0) {
          return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}.${String(frac).padStart(6, '0')}`;
        }
        return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
      } catch { /* fallthrough */ }
    }
    return buffer.toString('utf-8');
  }

  /**
   * TIMETZ format: 12 bytes (8 bytes time + 4 bytes timezone offset in seconds).
   * Input: string like '12:34:56+08:00' or '12:34:56-05:30'.
   * On decode, returns string representation.
   */
  private static encodeTimetz(value: any): Buffer {
    const str = String(value);
    const match = str.match(/^(\d+):(\d+)(?::(\d+(?:\.\d+)?))?\s*([+-]\d+):(\d+)?/);
    if (match) {
      const h = parseInt(match[1], 10);
      const m = parseInt(match[2], 10);
      const s = match[3] ? parseFloat(match[3]) : 0;
      const tzH = parseInt(match[4], 10);
      const tzM = parseInt(match[5] || '0', 10);
      const tzSign = tzH >= 0 ? 1 : -1;
      const micros = BigInt(Math.round(h * 3600000000 + m * 60000000 + s * 1000000));
      const tzOffset = tzSign * (Math.abs(tzH) * 3600 + tzM * 60);
      const buf = Buffer.alloc(12);
      buf.writeBigInt64BE(micros, 0);
      buf.writeInt32BE(tzOffset, 8);
      return buf;
    }
    // Fallback: encode time part as micros, tz = 0
    const timeBuf = BinaryResultCodec.encodeTime(value);
    const buf = Buffer.alloc(timeBuf.length + 4);
    timeBuf.copy(buf, 0);
    buf.writeInt32BE(0, timeBuf.length);
    return buf.length >= 12 ? buf : Buffer.concat([buf, Buffer.alloc(12 - buf.length)]);
  }

  private static decodeTimetz(buffer: Buffer): string {
    if (buffer.length >= 12) {
      try {
        const micros = Number(buffer.readBigInt64BE(0));
        const tzOffset = buffer.readInt32BE(8);
        const totalSec = Math.floor(micros / 1000000);
        const frac = micros % 1000000;
        const h = Math.floor(totalSec / 3600) % 24;
        const m = Math.floor((totalSec % 3600) / 60);
        const s = totalSec % 60;
        const tzH = Math.floor(tzOffset / 3600);
        const tzM = Math.floor((Math.abs(tzOffset) % 3600) / 60);
        const sign = tzOffset >= 0 ? '+' : '-';
        const timeStr = frac > 0
          ? `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}.${String(frac).padStart(6, '0')}`
          : `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
        return `${timeStr}${sign}${String(Math.abs(tzH)).padStart(2, '0')}:${String(tzM).padStart(2, '0')}`;
      } catch { /* fallthrough */ }
    }
    return buffer.toString('utf-8');
  }

  /**
   * INTERVAL format: 16 bytes [months: int32][days: int32][microseconds: int64].
   * Input: a string like '1 year 2 months 3 days 04:05:06' or an
   * object { months, days, microseconds }.
   */
  private static encodeInterval(value: any): Buffer {
    const buf = Buffer.alloc(16);
    let months = 0, days = 0, micros = 0n;

    if (typeof value === 'object' && value !== null) {
      months = value.months ?? 0;
      days = value.days ?? 0;
      micros = BigInt(value.microseconds ?? 0);
    } else {
      const str = String(value);
      // Try to parse PG interval format
      // Examples: '1 year 2 mons 3 days 04:05:06'
      const mMonths = str.match(/(\d+)\s*(?:year|years|mon|mons|month|months)/gi);
      const mDays = str.match(/(\d+)\s*(?:day|days)/gi);
      const mTime = str.match(/(\d+):(\d+)(?::(\d+(?:\.\d+)?))?/);
      if (mMonths) {
        for (const m of mMonths) {
          const n = parseInt(m.match(/\d+/)?.[0] || '0', 10);
          months += m.toLowerCase().startsWith('y') ? n * 12 : n;
        }
      }
      if (mDays) {
        for (const m of mDays) {
          days += parseInt(m.match(/\d+/)?.[0] || '0', 10);
        }
      }
      if (mTime) {
        const h = parseInt(mTime[1], 10);
        const mi = parseInt(mTime[2], 10);
        const s = mTime[3] ? parseFloat(mTime[3]) : 0;
        micros = BigInt(Math.round(h * 3600000000 + mi * 60000000 + s * 1000000));
      }
    }

    buf.writeInt32BE(months, 0);
    buf.writeInt32BE(days, 4);
    buf.writeBigInt64BE(micros, 8);
    return buf;
  }

  private static decodeInterval(buffer: Buffer): string {
    if (buffer.length === 16) {
      const months = buffer.readInt32BE(0);
      const days = buffer.readInt32BE(4);
      const micros = Number(buffer.readBigInt64BE(8));
      const parts: string[] = [];
      if (months !== 0) {
        const years = Math.floor(months / 12);
        const remMonths = months % 12;
        if (years !== 0) parts.push(`${years} year${years !== 1 ? 's' : ''}`);
        if (remMonths !== 0) parts.push(`${remMonths} mon${remMonths !== 1 ? 's' : ''}`);
      }
      if (days !== 0) parts.push(`${days} day${days !== 1 ? 's' : ''}`);
      if (micros !== 0) {
        const totalSec = Math.floor(micros / 1000000);
        const frac = micros % 1000000;
        const h = Math.floor(totalSec / 3600);
        const m = Math.floor((totalSec % 3600) / 60);
        const s = totalSec % 60;
        if (h > 0 || m > 0 || s > 0 || frac > 0) {
          const timeStr = frac > 0
            ? `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}.${String(frac).padStart(6, '0')}`
            : `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
          parts.push(timeStr);
        }
      }
      return parts.length > 0 ? parts.join(' ') : '00:00:00';
    }
    return buffer.toString('utf-8');
  }

  // ── Geometric type encoders/decoders ──────────────────────────────

  /**
   * POINT format: 16 bytes (2 doubles: x, y).
   * Input: string like '(x,y)' or array [x, y].
   */
  private static encodePoint(value: any): Buffer {
    const [x, y] = BinaryResultCodec.parsePair(value);
    const buf = Buffer.alloc(16);
    buf.writeDoubleBE(x, 0);
    buf.writeDoubleBE(y, 8);
    return buf;
  }

  private static decodePoint(buffer: Buffer): string {
    if (buffer.length === 16) {
      const x = buffer.readDoubleBE(0);
      const y = buffer.readDoubleBE(8);
      return `(${x},${y})`;
    }
    return buffer.toString('utf-8');
  }

  /**
   * LSEG format: 32 bytes (4 doubles: x1, y1, x2, y2).
   * Input: string like '[(x1,y1),(x2,y2)]' or array [[x1,y1],[x2,y2]].
   */
  private static encodeLseg(value: any): Buffer {
    const pairs = BinaryResultCodec.parsePairs(value, 2);
    const buf = Buffer.alloc(32);
    buf.writeDoubleBE(pairs[0][0], 0);
    buf.writeDoubleBE(pairs[0][1], 8);
    buf.writeDoubleBE(pairs[1][0], 16);
    buf.writeDoubleBE(pairs[1][1], 24);
    return buf;
  }

  private static decodeLseg(buffer: Buffer): string {
    if (buffer.length === 32) {
      const x1 = buffer.readDoubleBE(0);
      const y1 = buffer.readDoubleBE(8);
      const x2 = buffer.readDoubleBE(16);
      const y2 = buffer.readDoubleBE(24);
      return `[(${x1},${y1}),(${x2},${y2})]`;
    }
    return buffer.toString('utf-8');
  }

  /**
   * BOX format: 32 bytes (4 doubles: x1, y1, x2, y2 — upper-right, lower-left).
   * Input: string like '(x1,y1),(x2,y2)' or array [[x1,y1],[x2,y2]].
   */
  private static encodeBox(value: any): Buffer {
    // Same binary layout as lseg
    return BinaryResultCodec.encodeLseg(value);
  }

  private static decodeBox(buffer: Buffer): string {
    if (buffer.length === 32) {
      const x1 = buffer.readDoubleBE(0);
      const y1 = buffer.readDoubleBE(8);
      const x2 = buffer.readDoubleBE(16);
      const y2 = buffer.readDoubleBE(24);
      return `(${x1},${y1}),(${x2},${y2})`;
    }
    return buffer.toString('utf-8');
  }

  /**
   * PATH format: var-len binary.
   * PG binary format: int32 closed_flag, int32 npoints, then npoint × 16 bytes each.
   * closed_flag: 0 = open path, 1 = closed path.
   * Input: string like '[(x1,y1),(x2,y2)]' or array [[x1,y1],...].
   */
  private static encodePath(value: any): Buffer {
    const str = String(value);
    const closed = str.trim().startsWith('[') ? 0 : 1;
    const pairs = BinaryResultCodec.parsePairs(value, -1);
    const npoints = pairs.length;
    const buf = Buffer.alloc(4 + 4 + npoints * 16);
    buf.writeInt32BE(closed, 0);
    buf.writeInt32BE(npoints, 4);
    for (let i = 0; i < npoints; i++) {
      buf.writeDoubleBE(pairs[i][0], 8 + i * 16);
      buf.writeDoubleBE(pairs[i][1], 8 + i * 16 + 8);
    }
    return buf;
  }

  private static decodePath(buffer: Buffer): string {
    if (buffer.length < 8) return buffer.toString('utf-8');
    const closed = buffer.readInt32BE(0);
    const npoints = buffer.readInt32BE(4);
    const points: string[] = [];
    for (let i = 0; i < npoints; i++) {
      const off = 8 + i * 16;
      if (off + 16 > buffer.length) break;
      const x = buffer.readDoubleBE(off);
      const y = buffer.readDoubleBE(off + 8);
      points.push(`(${x},${y})`);
    }
    if (closed !== 0) return `(${points.join(',')})`;
    return `[${points.join(',')}]`;
  }

  /**
   * POLYGON format: var-len binary.
   * PG binary format: int32 npoints, then npoint × 16 bytes each.
   * Input: string like '((x1,y1),(x2,y2))' or array [[x1,y1],...].
   */
  private static encodePolygon(value: any): Buffer {
    const pairs = BinaryResultCodec.parsePairs(value, -1);
    const npoints = pairs.length;
    const buf = Buffer.alloc(4 + npoints * 16);
    buf.writeInt32BE(npoints, 0);
    for (let i = 0; i < npoints; i++) {
      buf.writeDoubleBE(pairs[i][0], 4 + i * 16);
      buf.writeDoubleBE(pairs[i][1], 4 + i * 16 + 8);
    }
    return buf;
  }

  private static decodePolygon(buffer: Buffer): string {
    if (buffer.length < 4) return buffer.toString('utf-8');
    const npoints = buffer.readInt32BE(0);
    const points: string[] = [];
    for (let i = 0; i < npoints; i++) {
      const off = 4 + i * 16;
      if (off + 16 > buffer.length) break;
      const x = buffer.readDoubleBE(off);
      const y = buffer.readDoubleBE(off + 8);
      points.push(`(${x},${y})`);
    }
    return `(${points.join(',')})`;
  }

  /**
   * CIRCLE format: 24 bytes (3 doubles: x, y, radius).
   * Input: string like '<(x,y),r>' or array [x, y, r].
   */
  private static encodeCircle(value: any): Buffer {
    if (typeof value === 'string') {
      const match = String(value).match(/<\(?([^,]+),([^)]+)\)?,\s*([^>]+)>/);
      if (match) {
        const x = parseFloat(match[1]);
        const y = parseFloat(match[2]);
        const r = parseFloat(match[3]);
        const buf = Buffer.alloc(24);
        buf.writeDoubleBE(x, 0);
        buf.writeDoubleBE(y, 8);
        buf.writeDoubleBE(r, 16);
        return buf;
      }
    }
    if (Array.isArray(value)) {
      const [x, y, r] = value.map(Number);
      const buf = Buffer.alloc(24);
      buf.writeDoubleBE(x, 0);
      buf.writeDoubleBE(y, 8);
      buf.writeDoubleBE(r, 16);
      return buf;
    }
    return Buffer.from(String(value), 'utf-8');
  }

  private static decodeCircle(buffer: Buffer): string {
    if (buffer.length === 24) {
      const x = buffer.readDoubleBE(0);
      const y = buffer.readDoubleBE(8);
      const r = buffer.readDoubleBE(16);
      return `<(${x},${y}),${r}>`;
    }
    return buffer.toString('utf-8');
  }

  /**
   * VARBIT format: variable-length bit string.
   * PG binary: int32 nbits, then ceil(nbits/8) bytes of bit data.
   * Input: string of '0' and '1' characters.
   */
  private static encodeVarbit(value: any): Buffer {
    const str = String(value).replace(/[^01]/g, '');
    const nbits = str.length;
    const nbytes = Math.ceil(nbits / 8);
    const buf = Buffer.alloc(4 + nbytes);
    buf.writeInt32BE(nbits, 0);
    for (let i = 0; i < nbits; i++) {
      if (str[i] === '1') {
        buf[4 + Math.floor(i / 8)] |= (0x80 >> (i % 8));
      }
    }
    return buf;
  }

  private static decodeVarbit(buffer: Buffer): string {
    if (buffer.length < 4) return buffer.toString('utf-8');
    const nbits = buffer.readInt32BE(0);
    let result = '';
    for (let i = 0; i < nbits; i++) {
      const byteIdx = 4 + Math.floor(i / 8);
      if (byteIdx >= buffer.length) break;
      result += (buffer[byteIdx] & (0x80 >> (i % 8))) ? '1' : '0';
    }
    return result;
  }

  /**
   * TXID_SNAPSHOT format: variable-length.
   * PG binary: int32 xmin, int32 xmax, int32 nxip, then nxip × int32.
   * Input: string like '100:200:10,20,30' or object { xmin, xmax, xip_list }.
   */
  private static encodeTxidSnapshot(value: any): Buffer {
    let xmin = 0, xmax = 0, xipList: number[] = [];
    if (typeof value === 'string') {
      const parts = String(value).split(':');
      xmin = parseInt(parts[0] || '0', 10);
      xmax = parseInt(parts[1] || '0', 10);
      if (parts[2]) {
        xipList = parts[2].split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
      }
    } else if (typeof value === 'object' && value !== null) {
      xmin = value.xmin ?? 0;
      xmax = value.xmax ?? 0;
      xipList = value.xip_list ?? value.xipList ?? [];
    }
    const buf = Buffer.alloc(4 + 4 + 4 + xipList.length * 4);
    buf.writeInt32BE(xmin, 0);
    buf.writeInt32BE(xmax, 4);
    buf.writeInt32BE(xipList.length, 8);
    for (let i = 0; i < xipList.length; i++) {
      buf.writeInt32BE(xipList[i], 12 + i * 4);
    }
    return buf;
  }

  private static decodeTxidSnapshot(buffer: Buffer): string {
    if (buffer.length < 12) return buffer.toString('utf-8');
    const xmin = buffer.readInt32BE(0);
    const xmax = buffer.readInt32BE(4);
    const nxip = buffer.readInt32BE(8);
    const xips: string[] = [];
    for (let i = 0; i < nxip; i++) {
      const off = 12 + i * 4;
      if (off + 4 > buffer.length) break;
      xips.push(String(buffer.readInt32BE(off)));
    }
    return `${xmin}:${xmax}:${xips.join(',')}`;
  }

  // ── Helper methods ──────────────────────────────────────────────────

  /**
   * Parse a pair of numbers from various input formats.
   */
  private static parsePair(value: any): [number, number] {
    if (Array.isArray(value)) {
      return [Number(value[0] ?? 0), Number(value[1] ?? 0)];
    }
    const str = String(value);
    const match = str.match(/\(?([-\d.]+)\s*,?\s*([-\d.]+)\)?/);
    if (match) {
      return [parseFloat(match[1]), parseFloat(match[2])];
    }
    return [0, 0];
  }

  /**
   * Parse multiple pairs of numbers from various input formats.
   * @param count - exact count expected, or -1 for variable.
   */
  private static parsePairs(value: any, count: number): Array<[number, number]> {
    if (Array.isArray(value)) {
      const pairs: Array<[number, number]> = [];
      for (const item of value) {
        if (Array.isArray(item) && item.length >= 2) {
          pairs.push([Number(item[0]), Number(item[1])]);
        }
      }
      return count > 0 ? pairs.slice(0, count) : pairs;
    }
    const str = String(value);
    const pairs: Array<[number, number]> = [];
    // Find all (x,y) patterns
    const pairRe = /\(?([-\d.]+)\s*,?\s*([-\d.]+)\)?/g;
    let match: RegExpExecArray | null;
    while ((match = pairRe.exec(str)) !== null) {
      pairs.push([parseFloat(match[1]), parseFloat(match[2])]);
    }
    return count > 0 ? pairs.slice(0, count) : pairs;
  }
}
