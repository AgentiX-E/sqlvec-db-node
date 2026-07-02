/**
 * WalBinaryFormat — Binary WAL record format compatible with pg_waldump output.
 *
 * Implements a PostgreSQL-inspired binary WAL format with:
 *   - XLOG record header (magic, LSN, XID, record type, length, CRC32C)
 *   - Record body (INSERT/UPDATE/DELETE/DDL payload)
 *   - Page image support (full page writes for critical operations)
 *   - CRC32C checksum per record for integrity
 *   - LSN tracking for consistent recovery points
 *   - pg_waldump-compatible human-readable output
 *
 * ## Binary record layout
 * ```
 * [2 bytes] Magic (0xA8E1)
 * [2 bytes] LSN string length (uint16 BE)
 * [N bytes] LSN string (UTF-8)
 * [2 bytes] PrevLSN string length (uint16 BE)
 * [M bytes] PrevLSN string (UTF-8)
 * [4 bytes] XID (uint32 BE)
 * [2 bytes] RecordType enum (uint16 BE)
 * [4 bytes] Body length (uint32 BE)
 * [8 bytes] Timestamp (uint64 BE)
 * [Body N bytes]  (variable)
 * [4 bytes] CRC32C (uint32 LE) — covers everything from Magic to end of body
 * ```
 *
 * ## Binary WAL file layout
 * ```
 * [WalFileHeader]  — magic, version, systemId, startLsn, endLsn, createdAt
 * [WalBinaryRecord 1]
 * [WalBinaryRecord 2]
 * ...
 * ```
 *
 * @module pitr/WalBinaryFormat
 */

import crc32 from 'buffer-crc32';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('WalBinaryFormat');

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

/** Magic number for binary WAL records and files (2 bytes) */
export const WAL_MAGIC = 0xA8E1;

/** Current binary format version */
export const WAL_VERSION = 1;

/** Header size contributed by fixed-length fields (excluding var-length strings) */
export const FIXED_HEADER_SIZE = 26; // 2(magic) + 2(len) + ... all fixed fields

/** WalRecordType enum values for binary serialization */
export const RECORD_TYPE_VALUES: Record<string, number> = {
  XLOG_CHECKPOINT_SHUTDOWN: 0,
  XLOG_CHECKPOINT_ONLINE: 1,
  XLOG_SWITCH: 2,
  XLOG_PAGE_IMAGE: 3,
  XLOG_INSERT: 4,
  XLOG_UPDATE: 5,
  XLOG_DELETE: 6,
  XLOG_DDL: 7,
  XLOG_TRUNCATE: 8,
  XLOG_HEAP2_CLEAN: 9,
  XLOG_HEAP2_FREEZE: 10,
};

/** Reverse map from enum number to type string */
export const RECORD_TYPE_NAMES: Record<number, WalRecordType> = {};
for (const [name, value] of Object.entries(RECORD_TYPE_VALUES)) {
  RECORD_TYPE_NAMES[value] = name as WalRecordType;
}

/** WalSegment filename template for binary format */
export const BINARY_SEGMENT_FILENAME_TEMPLATE = 'wal-segment-%06d.bin';

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

export type WalRecordType =
  | 'XLOG_CHECKPOINT_SHUTDOWN'
  | 'XLOG_CHECKPOINT_ONLINE'
  | 'XLOG_SWITCH'
  | 'XLOG_PAGE_IMAGE'
  | 'XLOG_INSERT'
  | 'XLOG_UPDATE'
  | 'XLOG_DELETE'
  | 'XLOG_DDL'
  | 'XLOG_TRUNCATE'
  | 'XLOG_HEAP2_CLEAN'
  | 'XLOG_HEAP2_FREEZE';

export interface WalBinaryHeader {
  /** WAL magic number (0xA8E1) */
  magic: number;
  /** LSN in PG format, e.g. '0/16B3AE8' */
  lsn: string;
  /** Previous record LSN */
  prevLsn: string;
  /** Transaction ID */
  xid: number;
  /** Record type */
  recordType: WalRecordType;
  /** Length of the record body in bytes */
  recordLength: number;
  /** CRC32C checksum of magic + header fields + body */
  crc32c: number;
  /** Unix timestamp in milliseconds */
  timestamp: number;
}

export type WalBinaryRecord = WalBinaryHeader & {
  /** Record body payload */
  body: Buffer;
};

export interface WalFileHeader {
  /** WAL magic number (0xA8E1) */
  magic: number;
  /** Binary format version */
  version: number;
  /** System identifier */
  systemId: string;
  /** Starting LSN of the file */
  startLsn: string;
  /** Ending LSN of the file */
  endLsn: string;
  /** File creation timestamp in Unix ms */
  createdAt: number;
}

// ──────────────────────────────────────────────
//  LSN Utilities
// ──────────────────────────────────────────────

/**
 * Convert a numeric LSN to PG format string '0/16B3AE8'.
 *
 * The PG LSN format is {timeline}/{offset}, where timeline is typically 0
 * and offset is an 8-digit uppercase hex value.
 *
 * @param lsn - Numeric LSN value
 * @returns LSN string in PG format
 */
export function formatLsn(lsn: number): string {
  if (lsn < 0 || !Number.isFinite(lsn)) {
    throw new Error(`Invalid LSN value: ${lsn}`);
  }
  const upper = Math.floor(lsn / 0x100000000);
  const lower = lsn % 0x100000000;
  return `${upper.toString(16).toUpperCase()}/${lower.toString(16).toUpperCase().padStart(8, '0')}`;
}

/**
 * Parse a PG-format LSN string ('0/16B3AE8') to a numeric value.
 *
 * @param lsnStr - LSN string in PG format
 * @returns Numeric LSN value
 */
export function parseLsn(lsnStr: string): number {
  if (!lsnStr || typeof lsnStr !== 'string') {
    throw new Error(`Invalid LSN string: "${lsnStr}"`);
  }
  const parts = lsnStr.split('/');
  if (parts.length !== 2) {
    throw new Error(`Invalid LSN format: "${lsnStr}"`);
  }
  const upper = parseInt(parts[0], 16);
  const lower = parseInt(parts[1], 16);
  if (isNaN(upper) || isNaN(lower)) {
    throw new Error(`Invalid LSN hex parts in: "${lsnStr}"`);
  }
  return upper * 0x100000000 + lower;
}

// ──────────────────────────────────────────────
//  CRC32C
// ──────────────────────────────────────────────

/**
 * Compute CRC32C checksum over a buffer.
 *
 * Uses Node.js `buffer-crc32` package for efficient CRC32C computation.
 *
 * @param data - Input buffer
 * @returns CRC32C as an unsigned 32-bit integer
 */
export function computeCrc32c(data: Buffer): number {
  return crc32.unsigned(data);
}

/**
 * Verify that a buffer's CRC32C matches the expected value.
 *
 * @param data - Buffer to verify
 * @param expectedCrc - Expected CRC32C value
 * @returns true if CRC matches, false otherwise
 */
export function verifyCrc32c(data: Buffer, expectedCrc: number): boolean {
  const actual = computeCrc32c(data);
  return actual === expectedCrc;
}

// ──────────────────────────────────────────────
//  Record Serialization
// ──────────────────────────────────────────────

/**
 * Create a WalBinaryRecord with auto-computed CRC32C.
 *
 * @param lsn - LSN in PG format
 * @param prevLsn - Previous LSN
 * @param xid - Transaction ID
 * @param recordType - Record type
 * @param body - Record body buffer
 * @returns A fully populated WalBinaryRecord
 */
export function createWalBinaryRecord(
  lsn: string,
  prevLsn: string,
  xid: number,
  recordType: WalRecordType,
  body: Buffer,
): WalBinaryRecord {
  const recordTypeValue = RECORD_TYPE_VALUES[recordType];
  if (recordTypeValue === undefined) {
    throw new Error(`Unknown record type: ${recordType}`);
  }

  const record: WalBinaryRecord = {
    magic: WAL_MAGIC,
    lsn,
    prevLsn,
    xid,
    recordType,
    recordLength: body.length,
    crc32c: 0, // placeholder, will be computed
    timestamp: Date.now(),
    body,
  };

  // Compute CRC32C over the serialized form (excluding the CRC field itself)
  const serializedWithoutCrc = serializeRecordBody(record);
  record.crc32c = computeCrc32c(serializedWithoutCrc);

  return record;
}

/**
 * Serialize everything EXCEPT the CRC32C field.
 * Used for CRC computation and verification.
 *
 * Layout:
 *   [2 bytes] Magic
 *   [2 bytes] LSN string length
 *   [N bytes] LSN string
 *   [2 bytes] PrevLSN string length
 *   [M bytes] PrevLSN string
 *   [4 bytes] XID
 *   [2 bytes] RecordType
 *   [4 bytes] Body length
 *   [8 bytes] Timestamp
 *   [Body bytes]
 */
function serializeRecordBody(record: WalBinaryRecord): Buffer {
  const lsnBuf = Buffer.from(record.lsn, 'utf-8');
  const prevLsnBuf = Buffer.from(record.prevLsn, 'utf-8');
  const body = record.body;

  // Calculate total size without CRC
  const totalSize = 2 + 2 + lsnBuf.length + 2 + prevLsnBuf.length + 4 + 2 + 4 + 8 + body.length;
  const buf = Buffer.alloc(totalSize);
  let offset = 0;

  // Magic (2 bytes, uint16 BE)
  buf.writeUInt16BE(WAL_MAGIC, offset);
  offset += 2;

  // LSN string length (2 bytes, uint16 BE)
  buf.writeUInt16BE(lsnBuf.length, offset);
  offset += 2;

  // LSN string
  lsnBuf.copy(buf, offset);
  offset += lsnBuf.length;

  // PrevLSN string length (2 bytes, uint16 BE)
  buf.writeUInt16BE(prevLsnBuf.length, offset);
  offset += 2;

  // PrevLSN string
  prevLsnBuf.copy(buf, offset);
  offset += prevLsnBuf.length;

  // XID (4 bytes, uint32 BE)
  buf.writeUInt32BE(record.xid, offset);
  offset += 4;

  // RecordType (2 bytes, uint16 BE)
  const recordTypeValue = RECORD_TYPE_VALUES[record.recordType];
  buf.writeUInt16BE(recordTypeValue, offset);
  offset += 2;

  // Body length (4 bytes, uint32 BE)
  buf.writeUInt32BE(record.recordLength, offset);
  offset += 4;

  // Timestamp (8 bytes, uint64 BE)
  buf.writeBigUInt64BE(BigInt(record.timestamp), offset);
  offset += 8;

  // Body
  body.copy(buf, offset);

  return buf;
}

/**
 * Serialize a WalBinaryRecord into a fully self-contained binary buffer,
 * including the CRC32C checksum at the end.
 *
 * @param record - The record to serialize
 * @returns Binary buffer containing magic + header + body + CRC
 */
export function serializeWalRecord(record: WalBinaryRecord): Buffer {
  const headerAndBody = serializeRecordBody(record);
  const crcValue = record.crc32c > 0 ? record.crc32c : computeCrc32c(headerAndBody);

  // Append CRC32C at the end (4 bytes, uint32 LE)
  const totalSize = headerAndBody.length + 4;
  const buf = Buffer.alloc(totalSize);
  headerAndBody.copy(buf, 0);
  buf.writeUInt32LE(crcValue, headerAndBody.length);

  return buf;
}

// ──────────────────────────────────────────────
//  Record Deserialization
// ──────────────────────────────────────────────

/**
 * Deserialize a binary buffer into a WalBinaryRecord.
 *
 * Expects the full record: magic + header fields + body + CRC32C.
 *
 * @param data - Binary buffer containing a single serialized record
 * @returns Deserialized WalBinaryRecord
 * @throws Error if data is invalid or CRC check fails
 */
export function deserializeWalRecord(data: Buffer): WalBinaryRecord {
  if (data.length < 14) { // Minimum viable record: magic(2) + lsnLen(2) + lsn(min 1) + prevLen(2) + prev(min 1) + xid(4) + type(2) + bodyLen(4) + time(8) + crc(4) = 30
    throw new Error(`Record too short: ${data.length} bytes`);
  }

  let offset = 0;

  // Magic (2 bytes, uint16 BE)
  const magic = data.readUInt16BE(offset);
  if (magic !== WAL_MAGIC) {
    throw new Error(`Invalid magic number: 0x${magic.toString(16)}`);
  }
  offset += 2;

  // LSN string length (2 bytes, uint16 BE)
  const lsnLen = data.readUInt16BE(offset);
  offset += 2;

  if (offset + lsnLen > data.length) {
    throw new Error(`Truncated LSN field: expected ${lsnLen} bytes, got ${data.length - offset}`);
  }

  // LSN string
  const lsn = data.toString('utf-8', offset, offset + lsnLen);
  offset += lsnLen;

  // PrevLSN string length (2 bytes, uint16 BE)
  const prevLsnLen = data.readUInt16BE(offset);
  offset += 2;

  if (offset + prevLsnLen > data.length) {
    throw new Error(`Truncated prevLSN field: expected ${prevLsnLen} bytes`);
  }

  // PrevLSN string
  const prevLsn = data.toString('utf-8', offset, offset + prevLsnLen);
  offset += prevLsnLen;

  // XID (4 bytes, uint32 BE)
  const xid = data.readUInt32BE(offset);
  offset += 4;

  // RecordType (2 bytes, uint16 BE)
  const recordTypeValue = data.readUInt16BE(offset);
  offset += 2;

  const recordType = RECORD_TYPE_NAMES[recordTypeValue];
  if (!recordType) {
    throw new Error(`Unknown record type value: ${recordTypeValue}`);
  }

  // Body length (4 bytes, uint32 BE)
  const recordLength = data.readUInt32BE(offset);
  offset += 4;

  // Timestamp (8 bytes, uint64 BE)
  const timestamp = Number(data.readBigUInt64BE(offset));
  offset += 8;

  // Validate we have enough data for body + CRC
  const expectedTotal = offset + recordLength + 4; // 4 bytes for CRC
  if (data.length < expectedTotal) {
    throw new Error(
      `Truncated record: expected body ${recordLength} + CRC 4 = ${expectedTotal}, ` +
      `got ${data.length}`,
    );
  }

  // Body
  const body = Buffer.alloc(recordLength);
  data.copy(body, 0, offset, offset + recordLength);
  offset += recordLength;

  // CRC32C (4 bytes, uint32 LE)
  const crc32cValue = data.readUInt32LE(offset);

  // Verify CRC32C — compute over everything except the CRC field itself
  const dataForCrc = Buffer.alloc(offset); // everything up to CRC
  data.copy(dataForCrc, 0, 0, offset);

  if (!verifyCrc32c(dataForCrc, crc32cValue)) {
    throw new Error(
      `CRC32C mismatch: expected 0x${crc32cValue.toString(16)}, ` +
      `computed 0x${computeCrc32c(dataForCrc).toString(16)}`,
    );
  }

  return {
    magic,
    lsn,
    prevLsn,
    xid,
    recordType,
    recordLength,
    crc32c: crc32cValue,
    timestamp,
    body,
  };
}

// ──────────────────────────────────────────────
//  WAL File Header
// ──────────────────────────────────────────────

/**
 * Create a WAL file header buffer.
 *
 * Layout:
 *   [2 bytes] Magic (0xA8E1)
 *   [2 bytes] Version (uint16 BE)
 *   [2 bytes] SystemId string length (uint16 BE)
 *   [N bytes] SystemId string (UTF-8)
 *   [2 bytes] StartLSN string length (uint16 BE)
 *   [N bytes] StartLSN string (UTF-8)
 *   [2 bytes] EndLSN string length (uint16 BE)
 *   [N bytes] EndLSN string (UTF-8)
 *   [8 bytes] CreatedAt (uint64 BE)
 *
 * @param systemId - System identifier
 * @param startLsn - Starting LSN
 * @returns Buffer containing the serialized WAL file header
 */
export function createWalFileHeader(systemId: string, startLsn: string): Buffer {
  const systemIdBuf = Buffer.from(systemId, 'utf-8');
  const startLsnBuf = Buffer.from(startLsn, 'utf-8');
  const endLsnBuf = Buffer.from(startLsn, 'utf-8'); // Initially same as startLsn
  const createdAt = Date.now();

  const totalSize = 2 + 2 + 2 + systemIdBuf.length + 2 + startLsnBuf.length + 2 + endLsnBuf.length + 8;
  const buf = Buffer.alloc(totalSize);
  let offset = 0;

  buf.writeUInt16BE(WAL_MAGIC, offset); offset += 2;
  buf.writeUInt16BE(WAL_VERSION, offset); offset += 2;
  buf.writeUInt16BE(systemIdBuf.length, offset); offset += 2;
  systemIdBuf.copy(buf, offset); offset += systemIdBuf.length;
  buf.writeUInt16BE(startLsnBuf.length, offset); offset += 2;
  startLsnBuf.copy(buf, offset); offset += startLsnBuf.length;
  buf.writeUInt16BE(endLsnBuf.length, offset); offset += 2;
  endLsnBuf.copy(buf, offset); offset += endLsnBuf.length;
  buf.writeBigUInt64BE(BigInt(createdAt), offset);

  return buf;
}

/**
 * Parse a WAL file header from a buffer.
 *
 * @param data - Buffer containing WAL file header data
 * @returns Parsed WalFileHeader
 */
export function parseWalFileHeader(data: Buffer): WalFileHeader {
  if (data.length < 20) {
    throw new Error(`File header too short: ${data.length} bytes`);
  }

  let offset = 0;

  const magic = data.readUInt16BE(offset); offset += 2;
  if (magic !== WAL_MAGIC) {
    throw new Error(`Invalid file header magic: 0x${magic.toString(16)}`);
  }

  const version = data.readUInt16BE(offset); offset += 2;
  const systemIdLen = data.readUInt16BE(offset); offset += 2;
  const systemId = data.toString('utf-8', offset, offset + systemIdLen); offset += systemIdLen;
  const startLsnLen = data.readUInt16BE(offset); offset += 2;
  const startLsn = data.toString('utf-8', offset, offset + startLsnLen); offset += startLsnLen;
  const endLsnLen = data.readUInt16BE(offset); offset += 2;
  const endLsn = data.toString('utf-8', offset, offset + endLsnLen); offset += endLsnLen;
  const createdAt = Number(data.readBigUInt64BE(offset));

  return { magic, version, systemId, startLsn, endLsn, createdAt };
}

// ──────────────────────────────────────────────
//  File Detection
// ──────────────────────────────────────────────

/**
 * Check if a buffer starts with binary WAL magic bytes (0xA8E1).
 *
 * @param data - Buffer to check
 * @returns true if the buffer starts with the WAL magic number
 */
export function isBinaryWalFile(data: Buffer): boolean {
  if (!data || data.length < 2) return false;
  return data.readUInt16BE(0) === WAL_MAGIC;
}

// ──────────────────────────────────────────────
//  Human-Readable Dump (pg_waldump compatible)
// ──────────────────────────────────────────────

/**
 * Generate a human-readable dump of binary WAL records,
 * similar to PostgreSQL's pg_waldump output.
 *
 * Format:
 * ```
 * rmgr: XLOG       lsn: 0/16B3AE8, prev 0/16B3AC0, xid 1234, len 64
 *   XLOG_INSERT: table test.t, tid (0,1), data [hex bytes...]
 * ```
 *
 * @param records - Array of WalBinaryRecords to dump
 * @returns Human-readable multi-line string
 */
export function dumpBinaryWal(records: WalBinaryRecord[]): string {
  const lines: string[] = [];

  for (const record of records) {
    // First line: resource manager + LSN + prevLSN + XID + length
    const rmgr = getRmgrForRecordType(record.recordType);
    const lsn = record.lsn;
    const prevLsn = record.prevLsn;
    const xid = record.xid;
    const len = record.recordLength + 34; // Total record size including header

    lines.push(
      `rmgr: ${rmgr.padEnd(14)} lsn: ${lsn}, prev ${prevLsn}, xid ${xid}, len ${len}`,
    );

    // Second line: record type details
    const typeLine = buildTypeDetailLine(record);
    lines.push(`  ${typeLine}`);
  }

  return lines.join('\n');
}

/**
 * Get the resource manager name for a given record type.
 */
function getRmgrForRecordType(recordType: WalRecordType): string {
  if (recordType === 'XLOG_CHECKPOINT_SHUTDOWN' || recordType === 'XLOG_CHECKPOINT_ONLINE' || recordType === 'XLOG_SWITCH' || recordType === 'XLOG_PAGE_IMAGE') {
    return 'XLOG';
  }
  if (recordType === 'XLOG_HEAP2_CLEAN' || recordType === 'XLOG_HEAP2_FREEZE') {
    return 'Heap2';
  }
  return 'Heap';
}

/**
 * Build a detail line for a specific record type (pg_waldump style).
 */
function buildTypeDetailLine(record: WalBinaryRecord): string {
  const type = record.recordType;

  switch (type) {
    case 'XLOG_CHECKPOINT_SHUTDOWN':
    case 'XLOG_CHECKPOINT_ONLINE': {
      // Try to parse checkpoint payload
      if (record.body.length >= 16) {
        const redoLSN = Number(record.body.readBigUInt64BE(0));
        const cpTime = Number(record.body.readBigUInt64BE(8));
        const cpDate = new Date(cpTime).toISOString();
        return `${type}: redo ${formatLsn(redoLSN)}; ${cpDate}`;
      }
      return `${type}`;
    }

    case 'XLOG_SWITCH':
      return `${type}`;

    case 'XLOG_PAGE_IMAGE': {
      // Page image: tag + page info if body has more than 4 bytes
      if (record.body.length >= 4) {
        const pageTag = record.body.toString('utf-8', 0, Math.min(4, record.body.length));
        return `${type}: tag ${pageTag}, page ${record.body.length} bytes`;
      }
      return `${type}: ${record.body.length} bytes`;
    }

    case 'XLOG_INSERT':
    case 'XLOG_UPDATE':
    case 'XLOG_DELETE': {
      // Parse table name from body (first 2 bytes = name length prefix)
      if (record.body.length >= 3) {
        const tblNameLen = record.body.readUInt16BE(0);
        if (tblNameLen > 0 && 2 + tblNameLen <= record.body.length) {
          const tableName = record.body.toString('utf-8', 2, 2 + tblNameLen);
          const dataHex = record.body.slice(2 + tblNameLen).toString('hex').slice(0, 64);
          return `${type}: table ${tableName}, data [${dataHex}${record.body.length - 2 - tblNameLen > 32 ? '...' : ''}]`;
        }
      }
      return `${type}: data [${record.body.toString('hex').slice(0, 64)}...]`;
    }

    case 'XLOG_DDL': {
      if (record.body.length >= 3) {
        const sqlLen = record.body.readUInt16BE(0);
        if (sqlLen > 0 && 2 + sqlLen <= record.body.length) {
          const sql = record.body.toString('utf-8', 2, 2 + sqlLen);
          return `${type}: ${sql}`;
        }
      }
      return `${type}: ${record.body.toString('utf-8').slice(0, 80)}`;
    }

    case 'XLOG_TRUNCATE': {
      if (record.body.length >= 3) {
        const tblNameLen = record.body.readUInt16BE(0);
        if (tblNameLen > 0 && 2 + tblNameLen <= record.body.length) {
          const tableName = record.body.toString('utf-8', 2, 2 + tblNameLen);
          return `${type}: table ${tableName}`;
        }
      }
      return `${type}`;
    }

    case 'XLOG_HEAP2_CLEAN':
    case 'XLOG_HEAP2_FREEZE': {
      if (record.body.length >= 4) {
        const nblocks = record.body.readUInt32BE(0);
        return `${type}: ${nblocks} blocks`;
      }
      return `${type}`;
    }

    default:
      return `${type}: data [${record.body.toString('hex').slice(0, 64)}...]`;
  }
}

// ──────────────────────────────────────────────
//  Convenience Functions
// ──────────────────────────────────────────────

/**
 * Extract all WalBinaryRecords from a binary WAL file buffer.
 * Skips the initial file header if present.
 *
 * @param data - Full binary WAL file contents
 * @returns Array of deserialized WalBinaryRecords
 */
export function extractRecords(data: Buffer): WalBinaryRecord[] {
  const records: WalBinaryRecord[] = [];
  let offset = 0;

  // Check if there's a file header (magic + version field)
  if (data.length >= 4) {
    const magic = data.readUInt16BE(offset);
    const version = data.readUInt16BE(offset + 2);
    if (magic === WAL_MAGIC && version === WAL_VERSION) {
      // Skip the file header — read systemIdLen to determine header size
      if (data.length >= 6) {
        const systemIdLen = data.readUInt16BE(offset + 4);
        // Header = 2(magic) + 2(version) + 2(sysIdLen) + sysIdLen + 2(startLsnLen) + startLsnLen + 2(endLsnLen) + endLsnLen + 8(createdAt)
        let headerEnd = 6 + systemIdLen;
        if (headerEnd + 2 <= data.length) {
          const startLsnLen = data.readUInt16BE(headerEnd);
          headerEnd += 2 + startLsnLen;
          if (headerEnd + 2 <= data.length) {
            const endLsnLen = data.readUInt16BE(headerEnd);
            headerEnd += 2 + endLsnLen + 8; // +8 for createdAt
            offset = headerEnd;
          }
        }
      }
    }
  }

  while (offset < data.length) {
    try {
      const record = deserializeWalRecord(data.slice(offset));
      records.push(record);

      // Calculate the total size of this record to advance offset
      // Header: 2(magic) + 2(lsnLen) + lsnLen + 2(prevLen) + prevLen + 4(xid) + 2(type) + 4(bodyLen) + 8(timestamp) = total header with strings
      // + body + 4(CRC)
      const lsnLen = data.readUInt16BE(offset + 2);
      const prevLsnLen = data.readUInt16BE(offset + 4 + lsnLen); // offset+4 because magic(2)+lsnLen(2)=4
      const recordSize = 2 + 2 + lsnLen + 2 + prevLsnLen + 4 + 2 + 4 + 8 + record.recordLength + 4;
      offset += recordSize;
    } catch {
      // Corrupted record or end of file
      logger.warn({ offset, remaining: data.length - offset }, 'Stopped reading records due to corruption');
      break;
    }
  }

  return records;
}
