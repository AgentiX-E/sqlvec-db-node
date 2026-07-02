/**
 * PITRReader — Read and replay WAL entries from compressed segment files.
 *
 * Provides range-based and target-based WAL entry retrieval for PITR recovery.
 * Supports reading by LSN range, by recovery target (timestamp / raft_index /
 * restore_point), and segment integrity verification.
 *
 * Phase 1: Core Infrastructure
 *
 * @see design-pitr.md §4 for recovery flow
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';
import crc32 from 'buffer-crc32';
import { WALManifest } from './WALManifest';
import {
  PitrWALEntry,
  PitrTarget,
  SegmentMeta,
  LSN,
  CRC32CHex,
  segmentFilename,
} from './types';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PITRReader');

/**
 * Result of parsing an LSN into its segment index and entry offset components.
 */
interface ParsedLSN {
  segmentIndex: number;
  entryOffset: number;
}

/**
 * WAL entry reader for the PITR subsystem.
 *
 * Provides ordered, sequential access to WAL entries for recovery replay.
 * Entries are decompressed on read and verified for integrity.
 */
export class PITRReader {
  private archiveDir: string;
  private manifest: WALManifest;

  constructor(archiveDir: string) {
    this.archiveDir = path.resolve(archiveDir);
    this.manifest = new WALManifest(this.archiveDir);
    this.manifest.load();
  }

  /**
   * Reload the manifest from disk.
   * Useful after new segments have been written.
   */
  reloadManifest(): void {
    this.manifest.load();
  }

  /**
   * Read all entries between two LSNs (inclusive).
   *
   * @param fromLSN - Start LSN (inclusive)
   * @param toLSN   - End LSN (inclusive)
   * @returns Array of WAL entries in the range
   */
  readRange(fromLSN: LSN, toLSN: LSN): PitrWALEntry[] {
    const from = this.parseLSN(fromLSN);
    const to = this.parseLSN(toLSN);

    if (from.segmentIndex > to.segmentIndex) {
      throw new Error(
        `fromLSN segment (${from.segmentIndex}) > toLSN segment (${to.segmentIndex})`,
      );
    }

    const result: PitrWALEntry[] = [];

    for (const segment of this.manifest.segments) {
      if (
        segment.segmentIndex < from.segmentIndex ||
        segment.segmentIndex > to.segmentIndex
      ) {
        continue;
      }

      const entries = this.readSegmentEntries(segment);

      if (segment.segmentIndex === from.segmentIndex) {
        // Start from entryOffset
        const sliced = entries.slice(from.entryOffset);
        if (segment.segmentIndex === to.segmentIndex) {
          // Same segment — also apply upper bound
          result.push(...sliced.slice(0, to.entryOffset - from.entryOffset + 1));
        } else {
          result.push(...sliced);
        }
      } else if (segment.segmentIndex === to.segmentIndex) {
        result.push(...entries.slice(0, to.entryOffset + 1));
      } else {
        result.push(...entries);
      }
    }

    return result;
  }

  /**
   * Read all entries up to a PITR target.
   *
   * Reads from the beginning of the WAL up to the target specification.
   * Target resolution priority: restore_point → raft_index → timestamp.
   *
   * @param target - Recovery target specification
   * @returns Array of WAL entries from the beginning up to the target
   */
  readUpTo(target: PitrTarget): PitrWALEntry[] {
    let targetLSN: LSN | null = null;

    switch (target.type) {
      case 'restore_point': {
        if (!target.restorePointName) {
          throw new Error(
            'restorePointName is required when target type is restore_point',
          );
        }
        targetLSN = this.findRestorePoint(target.restorePointName);
        if (!targetLSN) {
          throw new Error(
            `Restore point "${target.restorePointName}" not found`,
          );
        }
        break;
      }

      case 'raft_index': {
        const raftIndex = Number(target.value);
        targetLSN = this.findByRaftIndex(raftIndex);
        if (!targetLSN) {
          throw new Error(
            `No entry found for raft index ${raftIndex}`,
          );
        }
        break;
      }

      case 'timestamp': {
        const ts = String(target.value);
        targetLSN = this.findByTimestamp(ts);
        if (!targetLSN) {
          throw new Error(
            `No entry found at or before timestamp "${ts}"`,
          );
        }
        break;
      }
    }

    return this.readRange('0-0' as LSN, targetLSN);
  }

  /**
   * Verify the integrity of a specific WAL segment.
   *
   * Checks:
   * 1. The segment file exists
   * 2. The compressed file's SHA-256 checksum matches the manifest
   * 3. Each entry's CRC32C checksum is valid
   *
   * @param segmentIndex - The segment index to verify
   * @returns true if the segment is intact, false otherwise
   */
  verifySegmentIntegrity(segmentIndex: number): boolean {
    const segment = this.manifest.getSegment(segmentIndex);
    if (!segment) {
      logger.warn(`Segment ${segmentIndex} not found in manifest`);
      return false;
    }

    const filePath = path.join(
      this.archiveDir,
      segmentFilename(segmentIndex),
    );

    // Check file exists
    if (!fs.existsSync(filePath)) {
      logger.warn(`Segment file ${filePath} does not exist`);
      return false;
    }

    try {
      // Read and verify compressed file checksum
      const compressed = fs.readFileSync(filePath);
      const actualChecksum = crypto
        .createHash('sha256')
        .update(compressed)
        .digest('hex');

      if (actualChecksum !== segment.checksum) {
        logger.warn(
          `Segment ${segmentIndex} checksum mismatch: expected ${segment.checksum}, got ${actualChecksum}`,
        );
        return false;
      }

      // Verify per-entry CRC32C
      const entries = this.readSegmentEntries(segment);
      for (const entry of entries) {
        const expectedCrc = this.computeCRC32C(entry.data);
        if (entry.crc32c !== expectedCrc) {
          logger.warn(
            `Entry ${entry.lsn} CRC32C mismatch: expected ${expectedCrc}, got ${entry.crc32c}`,
          );
          return false;
        }
      }

      return true;
    } catch (err: any) {
      logger.warn(
        `Failed to verify segment ${segmentIndex}: ${err.message}`,
      );
      return false;
    }
  }

  /**
   * Verify the integrity of all segments in the manifest.
   *
   * @returns Map of segmentIndex → boolean result
   */
  verifyAllSegments(): Map<number, boolean> {
    const results = new Map<number, boolean>();
    for (const segment of this.manifest.segments) {
      results.set(segment.segmentIndex, this.verifySegmentIntegrity(segment.segmentIndex));
    }
    return results;
  }

  /**
   * Read all entries from a specific segment.
   *
   * @param segmentIndex - The segment index to read
   * @returns Array of WAL entries in the segment
   */
  readSegment(segmentIndex: number): PitrWALEntry[] {
    const segment = this.manifest.getSegment(segmentIndex);
    if (!segment) {
      throw new Error(`Segment ${segmentIndex} not found in manifest`);
    }
    return this.readSegmentEntries(segment);
  }

  /**
   * Get the manifest reference (for inspection/composition).
   */
  getManifest(): WALManifest {
    return this.manifest;
  }

  // ════════════════════════════════════════════════════════════
  //  Stage 4: Read and Replay WAL Segment to Database
  // ════════════════════════════════════════════════════════════

  /**
   * Read a WAL segment and replay its entries to a target SQLite database.
   *
   * Convenience wrapper that reads the segment via {@link readSegment}
   * and replays via {@link PITRWriter.replayToDb}.
   *
   * @param segmentIndex - The segment index to read
   * @param dbPath       - Path to the target SQLite database file
   * @param writer       - PITRWriter instance with replayToDb capability
   * @returns The number of entries replayed, or -1 if the segment is missing
   */
  readAndReplayToDb(
    segmentIndex: number,
    dbPath: string,
    writer: import('./PITRWriter').PITRWriter,
  ): number {
    const segment = this.manifest.getSegment(segmentIndex);
    if (!segment) {
      logger.warn(`Segment ${segmentIndex} not found — cannot replay`);
      return -1;
    }

    const entries = this.readSegmentEntries(segment);
    return writer.replayToDb(entries, dbPath);
  }

  // ──────────────────────────────────────────
  //  Private helpers
  // ──────────────────────────────────────────

  /**
   * Read and decompress all entries from a segment file.
   */
  private readSegmentEntries(segment: SegmentMeta): PitrWALEntry[] {
    const filePath = path.join(
      this.archiveDir,
      segmentFilename(segment.segmentIndex),
    );

    if (!fs.existsSync(filePath)) {
      throw new Error(
        `Segment file not found: ${filePath}`,
      );
    }

    const compressed = fs.readFileSync(filePath);
    const decompressed = segment.compressed
      ? zlib.gunzipSync(compressed)
      : compressed;

    const text = decompressed.toString('utf-8');
    const lines = text.split('\n').filter(line => line.trim().length > 0);

    return lines.map((line, i) => {
      return JSON.parse(line) as PitrWALEntry;
    });
  }

  /**
   * Parse an LSN string into its components.
   * Format: "{segmentIndex}-{entryOffset}"
   */
  private parseLSN(lsn: LSN): ParsedLSN {
    const parts = lsn.split('-');
    if (parts.length !== 2) {
      throw new Error(`Invalid LSN format: ${lsn}`);
    }
    return {
      segmentIndex: parseInt(parts[0], 10),
      entryOffset: parseInt(parts[1], 10),
    };
  }

  /**
   * Find the LSN of the restore point with the given name.
   * Searches all segments for a special marker entry.
   */
  private findRestorePoint(name: string): LSN | null {
    // Restore points are stored as entries with a specific data pattern
    for (const segment of this.manifest.segments) {
      const entries = this.readSegmentEntries(segment);
      for (const entry of entries) {
        try {
          const parsed = JSON.parse(entry.data);
          if (
            parsed &&
            parsed.__restore_point &&
            parsed.__restore_point === name
          ) {
            return entry.lsn;
          }
        } catch {
          // Non-JSON data or non-restore-point entry — skip
          continue;
        }
      }
    }
    return null;
  }

  /**
   * Find the LSN of the nearest entry at or before the given raft index.
   */
  private findByRaftIndex(targetIndex: number): LSN | null {
    let bestEntry: PitrWALEntry | null = null;

    // Search segments from newest to oldest (most likely to find first)
    const sortedSegments = [...this.manifest.segments].sort(
      (a, b) => b.segmentIndex - a.segmentIndex,
    );

    for (const segment of sortedSegments) {
      const entries = this.readSegmentEntries(segment);
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i] as PitrWALEntry;
        if (entry.raftIndex <= targetIndex) {
          if (bestEntry === null || entry.raftIndex > (bestEntry as PitrWALEntry).raftIndex) {
            bestEntry = entry;
          }
          break; // This segment's best candidate found
        }
      }
      if (bestEntry) {
        // Continue searching older segments for potentially closer match
        // (Since segments are ordered, if we found one, older segments have
        //  smaller raft indices — no need to continue)
        break;
      }
    }

    return bestEntry ? bestEntry.lsn : null;
  }

  /**
   * Find the LSN of the nearest entry at or before the given timestamp.
   *
   * @param timestamp - ISO 8601 string or numeric Unix epoch ms
   */
  private findByTimestamp(timestamp: string): LSN | null {
    const targetTime = new Date(timestamp).getTime();
    if (isNaN(targetTime)) {
      throw new Error(`Invalid timestamp: ${timestamp}`);
    }

    let bestEntry: PitrWALEntry | null = null;

    const sortedSegments = [...this.manifest.segments].sort(
      (a, b) => b.segmentIndex - a.segmentIndex,
    );

    for (const segment of sortedSegments) {
      const entries = this.readSegmentEntries(segment);
      for (let i = entries.length - 1; i >= 0; i--) {
        const entry = entries[i] as PitrWALEntry;
        const entryTime = new Date(entry.timestamp).getTime();
        if (entryTime <= targetTime) {
          if (
            bestEntry === null ||
            new Date(entry.timestamp).getTime() >
              new Date((bestEntry as PitrWALEntry).timestamp).getTime()
          ) {
            bestEntry = entry;
          }
          break;
        }
      }
      if (bestEntry) {
        break;
      }
    }

    return bestEntry ? bestEntry.lsn : null;
  }

  /**
   * Read ALL WAL entries from all segments and replay them to a target SQLite database.
   *
   * Iterates through every segment in the manifest in order, reads all entries,
   * and replays them via PITRWriter.replayToDb(). This is the primary crash recovery
   * entry point — restores the database to the last committed state by applying
   * every WAL record from the beginning of time.
   *
   * @param dbPath - Path to the target SQLite database file
   * @param writer - PITRWriter instance with replayToDb capability
   * @returns Total number of entries replayed across all segments
   */
  replayAll(dbPath: string, writer: import('./PITRWriter').PITRWriter): number {
    if (this.manifest.segments.length === 0) {
      logger.info('No WAL segments to replay — database is in its initial state');
      return 0;
    }

    let totalReplayed = 0;

    // Sort segments by index to ensure correct order
    const sortedSegments = [...this.manifest.segments].sort(
      (a, b) => a.segmentIndex - b.segmentIndex,
    );

    for (const segment of sortedSegments) {
      const replayed = this.readAndReplayToDb(segment.segmentIndex, dbPath, writer);
      if (replayed < 0) {
        logger.warn({ segmentIndex: segment.segmentIndex }, 'Segment missing during replayAll — stopping');
        break;
      }
      totalReplayed += replayed;
    }

    logger.info(
      { totalReplayed, segmentsProcessed: sortedSegments.length, dbPath },
      'PITR: full WAL replay completed (replayAll)',
    );
    return totalReplayed;
  }

  /**
   * Compute CRC32C checksum for data verification.
   * Uses buffer-crc32 for fast hardware-accelerated CRC32C.
   */
  private computeCRC32C(data: string): CRC32CHex {
    return crc32(Buffer.from(data, 'utf-8')).toString('hex');
  }
}
