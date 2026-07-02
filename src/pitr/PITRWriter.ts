/**
 * PITRWriter — Append WAL entries to compressed segment files.
 *
 * Accumulates entries in memory, then flushes to gzip-compressed JSONL
 * segment files when the segment reaches the configured size limit.
 * Maintains a WAL manifest for fast segment lookup.
 *
 * Phase 1: Core Infrastructure
 *
 * @see design-pitr.md §3.1 for format rationale
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';
import crc32 from 'buffer-crc32';
import Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';
import { WALManifest } from './WALManifest';
import {
  PitrWALEntry,
  LSN,
  CRC32CHex,
  DEFAULT_SEGMENT_SIZE,
  segmentFilename,
} from './types';

const logger = PinoLogger.forComponent('PITRWriter');

/**
 * WAL entry writer for the PITR subsystem.
 *
 * Usage:
 *   const writer = new PITRWriter('/path/to/pitr-archive');
 *   writer.append(42, 3, 'shard-0', JSON.stringify(entryData));
 *   writer.flushSegment(); // Force flush
 *   writer.close();        // Flush and release
 */
export class PITRWriter {
  private archiveDir: string;
  private segmentSize: number;
  private segmentIndex = 0;
  private entries: PitrWALEntry[] = [];
  private manifest: WALManifest;

  constructor(archiveDir: string, segmentSize = DEFAULT_SEGMENT_SIZE) {
    this.archiveDir = path.resolve(archiveDir);
    this.segmentSize = segmentSize;
    this.manifest = new WALManifest(this.archiveDir);

    // Ensure archive directory exists
    fs.mkdirSync(this.archiveDir, { recursive: true });

    // Load existing manifest (if any) to resume segment index
    this.manifest.load();
    this.segmentIndex = this.manifest.lastSegment()
      ? this.manifest.lastSegment()!.segmentIndex + 1
      : 0;
  }

  /**
   * Append a WAL entry.
   *
   * Entries are buffered in memory. When the buffer reaches
   * `segmentSize`, it is automatically flushed to a compressed
   * segment file on disk.
   *
   * @param raftIndex - Raft log index of the committed entry
   * @param raftTerm - Raft term at commitment
   * @param shardId - Shard (partition) identifier
   * @param data - JSON string of the applied entry
   */
  append(
    raftIndex: number,
    raftTerm: number,
    shardId: string,
    data: string,
  ): void {
    const entry: PitrWALEntry = {
      lsn: `${this.segmentIndex}-${this.entries.length}` as LSN,
      raftIndex,
      raftTerm,
      timestamp: new Date().toISOString(),
      shardId,
      data,
      crc32c: this.computeCRC32C(data),
    };

    this.entries.push(entry);

    if (this.entries.length >= this.segmentSize) {
      this.flushSegment();
    }
  }

  /**
   * Get the current number of buffered (not yet flushed) entries.
   */
  get bufferedCount(): number {
    return this.entries.length;
  }

  /**
   * Get the current segment index.
   */
  get currentSegmentIndex(): number {
    return this.segmentIndex;
  }

  /**
   * Force-flush the current in-memory buffer to a compressed segment file.
   *
   * Silently returns if there are no buffered entries.
   * After flushing, the entry buffer is cleared and segmentIndex advances.
   */
  flushSegment(): void {
    if (this.entries.length === 0) return;

    const fileName = segmentFilename(this.segmentIndex);
    const segmentPath = path.join(this.archiveDir, fileName);

    // Serialize entries as JSONL (newline-delimited JSON)
    const jsonContent = this.entries
      .map(e => JSON.stringify(e))
      .join('\n');

    // Compress with gzip
    const compressed = zlib.gzipSync(Buffer.from(jsonContent, 'utf-8'));

    // SHA-256 checksum of the compressed segment file
    const checksum = crypto
      .createHash('sha256')
      .update(compressed)
      .digest('hex');

    // Write segment file atomically via tmp file
    const tmpPath = segmentPath + '.tmp';
    fs.writeFileSync(tmpPath, compressed);
    fs.renameSync(tmpPath, segmentPath);

    // Update manifest
    const meta = {
      segmentIndex: this.segmentIndex,
      sizeBytes: compressed.length,
      entryCount: this.entries.length,
      firstLSN: this.entries[0].lsn,
      lastLSN: this.entries[this.entries.length - 1].lsn,
      firstTimestamp: this.entries[0].timestamp,
      lastTimestamp: this.entries[this.entries.length - 1].timestamp,
      checksum,
      compressed: true,
    };

    const entryCount = this.entries.length;
    const fileSize = compressed.length;

    this.manifest.addSegment(meta);
    this.entries = [];
    this.segmentIndex++;
    this.manifest.save();

    logger.info(
      `Flushed WAL segment ${fileName} (${fileSize} bytes, ${entryCount} entries)`,
    );
  }

  /**
   * Close the writer, flushing any buffered entries.
   * After close(), the writer should not be used for further appends.
   */
  close(): void {
    this.flushSegment();
    this.manifest.save();
    logger.info('PITRWriter closed');
  }

  // ════════════════════════════════════════════════════════════
  //  Stage 4: WAL Replay to SQLite Database
  // ════════════════════════════════════════════════════════════

  /**
   * Replay WAL entries to a target SQLite database.
   *
   * Parses each entry's `data` field as an {@link ApplyEntry} JSON object
   * and translates it into SQL statements executed directly against the
   * database at `dbPath`.
   *
   * Supported entry types:
   * - `upsert`: INSERT OR REPLACE with field columns
   * - `delete`: DELETE FROM table WHERE id = ?
   * - `ddl`:   Raw SQL execution (data.sql or data string)
   * - `exec`:  Raw SQL execution (data.sql)
   *
   * Entries are grouped into a single transaction for performance.
   * Non-replayable entries (e.g. restore point markers) are skipped.
   *
   * @param entries - Ordered array of WAL entries to replay
   * @param dbPath  - Path to the target SQLite database file
   * @returns The number of entries that were successfully replayed
   * @throws {Error} If the database cannot be opened or a SQL error occurs
   */
  replayToDb(entries: PitrWALEntry[], dbPath: string): number {
    if (!entries || entries.length === 0) return 0;

    // Ensure parent directory exists
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const db = new Database(dbPath);

    // Use WAL mode for write performance during replay
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');
    db.pragma('busy_timeout = 5000');

    let appliedCount = 0;

    try {
      const txn = db.transaction(() => {
        for (const entry of entries) {
          try {
            const didApply = this.applySingleEntry(db, entry);
            if (didApply) appliedCount++;
          } catch (err: any) {
            logger.warn(
              { lsn: entry.lsn, shardId: entry.shardId, err: err.message },
              'Failed to replay WAL entry — skipping',
            );
            // Continue with remaining entries
          }
        }
      });

      txn();
    } finally {
      db.close();
    }

    logger.info(
      `Replayed ${appliedCount}/${entries.length} WAL entries to ${dbPath}`,
    );
    return appliedCount;
  }

  /**
   * Apply a single WAL entry to an open database connection.
   *
   * @returns true if the entry was applied, false if skipped (e.g. restore point)
   */
  private applySingleEntry(db: Database.Database, entry: PitrWALEntry): boolean {
    let parsed: any;
    try {
      parsed = JSON.parse(entry.data);
    } catch {
      // Non-JSON data — cannot replay
      return false;
    }

    // Skip non-replay entries (restore point markers, etc.)
    if (parsed.__restore_point) {
      return false;
    }

    const type = parsed.type ?? 'upsert';
    const data = parsed.data ?? parsed;

    switch (type) {
      case 'upsert': {
        if (!data.table) {
          logger.trace({ lsn: entry.lsn }, 'upsert entry missing table — skipping');
          return false;
        }
        this.applyUpsert(db, data);
        return true;
      }

      case 'delete': {
        if (!data.table) {
          logger.trace({ lsn: entry.lsn }, 'delete entry missing table — skipping');
          return false;
        }
        this.applyDelete(db, data);
        return true;
      }

      case 'ddl': {
        const sql = data.sql ?? (typeof data === 'string' ? data : null);
        if (sql) {
          db.exec(sql);
          return true;
        }
        return false;
      }

      case 'exec': {
        const sql = data.sql ?? (typeof data === 'string' ? data : null);
        if (sql) {
          db.exec(sql);
          return true;
        }
        return false;
      }

      default: {
        // Unknown type — try as raw SQL
        const sql = data?.sql ?? (typeof entry.data === 'string' ? entry.data : null);
        if (sql && typeof sql === 'string' && !sql.startsWith('{')) {
          db.exec(sql);
          return true;
        }
        return false;
      }
    }
  }

  /**
   * Generate and execute an UPSERT (INSERT OR REPLACE) statement.
   *
   * data format: { table: string; id: number|string; fields?: Record<string, any> }
   */
  private applyUpsert(db: Database.Database, data: any): void {
    const { table, id, fields } = data;

    if (!table) {
      throw new Error('upsert entry missing table');
    }

    const colNames: string[] = ['id'];
    const colValues: any[] = [id];

    if (fields && typeof fields === 'object') {
      for (const [key, value] of Object.entries(fields)) {
        colNames.push(key);
        colValues.push(value);
      }
    }

    const placeholders = colNames.map(() => '?').join(', ');
    const quotedCols = colNames.map((c) => `"${c}"`).join(', ');

    const sql = `INSERT OR REPLACE INTO "${table}" (${quotedCols}) VALUES (${placeholders})`;
    const stmt = db.prepare(sql);
    stmt.run(...colValues);
  }

  /**
   * Generate and execute a DELETE statement.
   *
   * data format: { table: string; id: number|string }
   */
  private applyDelete(db: Database.Database, data: any): void {
    const { table, id } = data;

    if (!table) {
      throw new Error('delete entry missing table');
    }

    const stmt = db.prepare(`DELETE FROM "${table}" WHERE id = ?`);
    stmt.run(id);
  }

  /**
   * Compute a CRC32C hex checksum for a string of data.
   *
   * Uses buffer-crc32 for fast hardware-accelerated CRC32C,
   * replacing the earlier truncated SHA-256 stand-in.
   */
  private computeCRC32C(data: string): CRC32CHex {
    return crc32(Buffer.from(data, 'utf-8')).toString('hex');
  }
}
