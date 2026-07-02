/**
 * Core type definitions for Point-in-Time Recovery (PITR).
 *
 * Phase 1: Core Infrastructure
 *
 * These types define the logical WAL entry format, segment metadata,
 * recovery targets, and configuration constants used throughout the
 * PITR subsystem.
 *
 * @see design-pitr.md §3.1 for format rationale
 */

/** CRC32C checksum (hex string, 8-char) */
export type CRC32CHex = string;

/**
 * Logical Sequence Number: {segmentIndex}-{entryOffset}
 *
 * Uniquely identifies a WAL entry within the archive.
 * - segmentIndex: monotonically increasing segment counter
 * - entryOffset: zero-based offset within the segment
 *
 * Example: "000042-0007" → segment 42, entry 7
 */
export type LSN = string;

/**
 * A single WAL entry — captures one committed Raft log entry
 * at the apply callback interception point.
 *
 * This is the atomic unit of PITR recovery replay. Each entry
 * corresponds to exactly one committed Raft entry that was applied
 * to the state machine.
 *
 * Starting from Phase 5, entries also carry an optional `pgLsn` field
 * that bridges to PgWalWriter's binary WAL for LSN-level precision.
 */
export interface PitrWALEntry {
  /** Logical Sequence Number within the archive */
  lsn: LSN;
  /** Raft log index (monotonically increasing per shard) */
  raftIndex: number;
  /** Raft term at the time of commitment */
  raftTerm: number;
  /** ISO 8601 timestamp of when the entry was written */
  timestamp: string;
  /** Shard (partition) identifier */
  shardId: string;
  /** JSON string of the applied entry (the ApplyEntry data) */
  data: string;
  /** CRC32C of `data` for per-entry integrity verification */
  crc32c: CRC32CHex;
  /**
   * Optional PG-style LSN (e.g. "0/ABCDEF12") from PgWalWriter.
   * When present, enables LSN-precision PITR recovery.
   * Added in Phase 5 — undefined for entries written by legacy PITRHook.
   */
  pgLsn?: string;
}

/**
 * Metadata about a single WAL segment file.
 *
 * Maintained in the WAL manifest and used for:
 * - Fast segment lookup by LSN or timestamp range
 * - Integrity verification on read
 * - Retention policy decisions
 */
export interface SegmentMeta {
  /** Sequential segment index (matches filename) */
  segmentIndex: number;
  /** Compressed size in bytes (gzip) */
  sizeBytes: number;
  /** Number of entries in this segment */
  entryCount: number;
  /** LSN of the first entry in the segment */
  firstLSN: LSN;
  /** LSN of the last entry in the segment */
  lastLSN: LSN;
  /** ISO 8601 timestamp of the first entry */
  firstTimestamp: string;
  /** ISO 8601 timestamp of the last entry */
  lastTimestamp: string;
  /** SHA-256 checksum of the entire compressed segment file */
  checksum: CRC32CHex;
  /** Whether the segment file is gzip-compressed */
  compressed: boolean;
}

/**
 * Recovery target specification.
 *
 * Supports three target types:
 * - `timestamp`: Restore to the nearest entry at or before the given time
 * - `raft_index`: Restore to exactly this raft index (most precise)
 * - `restore_point`: Restore to a named marker created by createRestorePoint()
 *
 * Priority when multiple targets are specified:
 * 1. Named restore point (exact match)
 * 2. Raft index (exact or nearest ≤)
 * 3. Timestamp (nearest entry at or before)
 */
export interface PitrTarget {
  type: 'timestamp' | 'raft_index' | 'restore_point';
  /** For timestamp: ISO 8601 string or Unix epoch ms number.
   *  For raft_index: number.
   *  For restore_point: string name. */
  value: string | number;
  /** Optional restore point name (only used when type = 'restore_point') */
  restorePointName?: string;
}

/** Default number of entries per WAL segment */
export const DEFAULT_SEGMENT_SIZE = 10_000;

/** WAL segment filename pattern */
export const SEGMENT_FILENAME_PATTERN = /^pitr-segment-(\d{6})\.wal\.gz$/;

/** Generate the filename for a WAL segment */
export function segmentFilename(segmentIndex: number): string {
  return `pitr-segment-${String(segmentIndex).padStart(6, '0')}.wal.gz`;
}

/** WAL manifest filename */
export const MANIFEST_FILENAME = 'pitr-manifest.json';
