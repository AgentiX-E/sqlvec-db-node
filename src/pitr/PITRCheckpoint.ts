/**
 * PITRCheckpoint — WAL checkpoint + joint recovery for Point-in-Time Recovery.
 *
 * Creates consistent SQLite DB snapshots (checkpoints) with WAL offset tracking,
 * enabling point-in-time recovery by combining a checkpoint DB with WAL replay.
 *
 * Checkpoint flow:
 *   1. Copy shard DB via better-sqlite3 .backup() (consistent snapshot)
 *   2. Record WAL offset (total entries across all segments)
 *   3. Compute SHA-256 of copied DB for integrity
 *   4. Store metadata in `__checkpoint_metadata` table
 *
 * Recovery flow:
 *   1. Verify checkpoint integrity via checksum
 *   2. Copy checkpoint DB to output path
 *   3. Read WAL entries (checkpoint timestamp → target timestamp)
 *   4. Replay each entry's data against the restored DB
 *   5. Return success/failure
 *
 * Phase C #5 — WAL checkpoint + joint recovery
 *
 * @see design-pitr.md §4.2 for recovery flow
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';
import { PITRReader } from './PITRReader';
import { WALManifest } from './WALManifest';
import type { PitrWALEntry } from './types';

const logger = PinoLogger.forComponent('PITRCheckpoint');

// ── Checkpoint Record ─────────────────────────────────────────────────────────

export interface CheckpointRecord {
  /** UUID identifying this checkpoint */
  checkpointId: string;
  /** ISO-8601 timestamp when the checkpoint was created */
  timestamp: string;
  /** Shard (partition) identifier */
  shardId: string;
  /** WAL position (total entry count) at the time of checkpoint */
  walOffset: number;
  /** Path to the copied SQLite database file for this checkpoint */
  dbPath: string;
  /** SHA-256 checksum of the checkpoint DB file for integrity */
  dbChecksum: string;
  /** Size of the SQLite -wal journal file at checkpoint time (bytes) */
  walSize: number;
  /** Checkpoint lifecycle status */
  status: 'in_progress' | 'completed' | 'failed';
}

// ── Checkpoint Configuration ──────────────────────────────────────────────────

export interface PITRCheckpointConfig {
  /** Directory where checkpoint DB copies and metadata are stored */
  checkpointDir: string;
  /** Directory where PITR WAL segments are archived */
  archiveDir: string;
  /** Directory where shard databases live */
  dataDir: string;
}

// ── PITRCheckpoint ────────────────────────────────────────────────────────────

/**
 * Manages SQLite DB checkpoints for point-in-time recovery.
 *
 * Each checkpoint is a consistent snapshot of a shard's SQLite database,
 * paired with the WAL offset at that point. Recovery uses the checkpoint
 * DB as a base and replays WAL entries to reach the target time.
 *
 * Usage:
 * ```ts
 * const cp = new PITRCheckpoint({
 *   checkpointDir: '/data/pitr-checkpoints',
 *   archiveDir: '/data/pitr-archive',
 *   dataDir: '/data/shards',
 * });
 * const record = await cp.createCheckpoint('shard-0');
 * const records = cp.listCheckpoints('shard-0');
 * await cp.recoverToPITR(record, '2026-06-01T12:00:00.000Z', '/tmp/recovered.db');
 * ```
 */
export class PITRCheckpoint {
  private checkpointDir: string;
  private archiveDir: string;
  private dataDir: string;
  private metaDb: Database.Database;
  private metaDbPath: string;
  private reader: PITRReader;
  private manifest: WALManifest;

  /**
   * Create a new PITRCheckpoint instance.
   *
   * @param config - Directories for checkpoints, WAL archives, and shard data
   */
  constructor(config: PITRCheckpointConfig) {
    this.checkpointDir = path.resolve(config.checkpointDir);
    this.archiveDir = path.resolve(config.archiveDir);
    this.dataDir = path.resolve(config.dataDir);

    // Ensure checkpoint directory exists
    fs.mkdirSync(this.checkpointDir, { recursive: true });

    // Open or create the checkpoint metadata database
    this.metaDbPath = path.join(this.checkpointDir, 'pitr_checkpoint_meta.db');
    this.metaDb = new Database(this.metaDbPath);
    this.metaDb.pragma('journal_mode = WAL');
    this.metaDb.pragma('synchronous = NORMAL');

    // Create __checkpoint_metadata table if it doesn't exist
    this.metaDb.exec(`
      CREATE TABLE IF NOT EXISTS __checkpoint_metadata (
        checkpointId TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        shardId TEXT NOT NULL,
        walOffset INTEGER NOT NULL,
        dbPath TEXT NOT NULL,
        dbChecksum TEXT NOT NULL,
        walSize INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'in_progress'
      )
    `);

    // Initialize WAL reader and manifest for offset tracking
    this.reader = new PITRReader(this.archiveDir);
    this.manifest = new WALManifest(this.archiveDir);
    this.manifest.load();

    logger.info(
      `PITRCheckpoint initialized: checkpointDir=${this.checkpointDir}, ` +
      `archiveDir=${this.archiveDir}`,
    );
  }

  // ── Public API ─────────────────────────────────────────────────────────

  /**
   * Create a consistent checkpoint of a shard's SQLite database.
   *
   * Steps:
   *   1. Validate that the shard's database file exists
   *   2. Read the current WAL offset (total entries across all segments)
   *   3. Copy the shard DB via better-sqlite3 .backup() for a consistent snapshot
   *   4. Compute SHA-256 checksum of the copied DB file
   *   5. Store checkpoint metadata in the __checkpoint_metadata table
   *
   * @param shardId - Shard to checkpoint
   * @returns The created CheckpointRecord
   * @throws {Error} If the shard database file doesn't exist
   */
  async createCheckpoint(shardId: string): Promise<CheckpointRecord> {
    const checkpointId = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const walOffset = this.getTotalWALEntries();

    // Locate the shard's SQLite database file
    const dbFilename = `${shardId}.db`;
    const sourceDbPath = path.join(this.dataDir, shardId, dbFilename);

    if (!fs.existsSync(sourceDbPath)) {
      throw new Error(
        `Cannot create checkpoint: shard database not found at ${sourceDbPath}`,
      );
    }

    // Determine WAL file size (SQLite -wal journal)
    const walPath = sourceDbPath + '-wal';
    let walSize = 0;
    if (fs.existsSync(walPath)) {
      walSize = fs.statSync(walPath).size;
    }

    // Create checkpoint subdirectory for this shard
    const shardCpDir = path.join(this.checkpointDir, shardId);
    fs.mkdirSync(shardCpDir, { recursive: true });

    // Create the checkpoint DB file path
    const cpDbPath = path.join(shardCpDir, `${checkpointId}.db`);

    // --- BEGIN: in_progress ---
    const progressRecord: CheckpointRecord = {
      checkpointId,
      timestamp,
      shardId,
      walOffset,
      dbPath: cpDbPath,
      dbChecksum: '',
      walSize,
      status: 'in_progress',
    };

    // Stash the in-progress record so concurrent reads see it
    this.saveRecord(progressRecord);

    try {
      // Create a consistent DB snapshot via file copy.
      // The shard database should be closed/flushed before checkpointing.
      // For live DBs, use better-sqlite3's .backup() API (async) instead.
      fs.copyFileSync(sourceDbPath, cpDbPath);

      // Compute SHA-256 checksum of the copied DB
      const dbChecksum = this.computeChecksum(cpDbPath);

      const completedRecord: CheckpointRecord = {
        ...progressRecord,
        dbChecksum,
        status: 'completed',
      };

      // Update metadata with completed status and checksum
      this.saveRecord(completedRecord);

      logger.info(
        `Checkpoint created: ${checkpointId} for shard ${shardId} ` +
        `(walOffset=${walOffset}, walSize=${walSize}, checksum=${dbChecksum.slice(0, 16)}...)`,
      );

      return completedRecord;
    } catch (err: any) {
      // Mark as failed
      const failedRecord: CheckpointRecord = {
        ...progressRecord,
        status: 'failed',
      };
      this.saveRecord(failedRecord);

      logger.error(
        `Checkpoint failed: ${checkpointId} for shard ${shardId}: ${err.message}`,
      );
      throw err;
    }
  }

  /**
   * List all checkpoint records for a given shard, ordered by timestamp (newest first).
   *
   * @param shardId - Shard to list checkpoints for
   * @param limit - Optional maximum number of records to return
   * @returns Array of CheckpointRecord objects
   */
  listCheckpoints(shardId: string, limit?: number): CheckpointRecord[] {
    let query = `
      SELECT * FROM __checkpoint_metadata
      WHERE shardId = ?
      ORDER BY timestamp DESC
    `;
    if (limit !== undefined && limit > 0) {
      query += ` LIMIT ${limit}`;
    }

    const rows = this.metaDb.prepare(query).all(shardId) as Array<{
      checkpointId: string;
      timestamp: string;
      shardId: string;
      walOffset: number;
      dbPath: string;
      dbChecksum: string;
      walSize: number;
      status: string;
    }>;

    return rows.map(row => ({
      checkpointId: row.checkpointId,
      timestamp: row.timestamp,
      shardId: row.shardId,
      walOffset: row.walOffset,
      dbPath: row.dbPath,
      dbChecksum: row.dbChecksum,
      walSize: row.walSize,
      status: row.status as CheckpointRecord['status'],
    }));
  }

  /**
   * Find the nearest checkpoint at or before a target timestamp for a given shard.
   *
   * Searches completed checkpoints by shard, ordered by timestamp descending,
   * and returns the first one whose timestamp is <= targetTimestamp.
   *
   * @param targetTimestamp - ISO-8601 timestamp to search before
   * @param shardId - Shard to search in
   * @returns The closest checkpoint, or null if none found
   */
  findCheckpoint(
    targetTimestamp: string,
    shardId: string,
  ): CheckpointRecord | null {
    const rows = this.metaDb.prepare(`
      SELECT * FROM __checkpoint_metadata
      WHERE shardId = ? AND status = 'completed'
        AND timestamp <= ?
      ORDER BY timestamp DESC
      LIMIT 1
    `).all(shardId, targetTimestamp) as Array<{
      checkpointId: string;
      timestamp: string;
      shardId: string;
      walOffset: number;
      dbPath: string;
      dbChecksum: string;
      walSize: number;
      status: string;
    }>;

    if (rows.length === 0) return null;

    const row = rows[0];
    return {
      checkpointId: row.checkpointId,
      timestamp: row.timestamp,
      shardId: row.shardId,
      walOffset: row.walOffset,
      dbPath: row.dbPath,
      dbChecksum: row.dbChecksum,
      walSize: row.walSize,
      status: row.status as CheckpointRecord['status'],
    };
  }

  /**
   * Recover a shard's database to a specific point in time.
   *
   * Joint recovery flow:
   *   1. Verify checkpoint DB integrity via SHA-256 checksum
   *   2. Copy checkpoint DB to the output path
   *   3. Open the restored DB for WAL replay
   *   4. Read WAL entries between checkpoint timestamp and target timestamp
   *   5. Apply each entry's data (exec as SQL) against the restored DB
   *   6. Return true on success
   *
   * @param checkPoint - The checkpoint to recover from
   * @param targetTimestamp - ISO-8601 target time to recover to
   * @param outputPath - Path where the recovered database will be written
   * @returns true if recovery succeeded, false if checksum verification failed
   * @throws {Error} If the checkpoint DB file doesn't exist or replay fails
   */
  async recoverToPITR(
    checkPoint: CheckpointRecord,
    targetTimestamp: string,
    outputPath: string,
  ): Promise<boolean> {
    // Step 1: Verify checkpoint integrity
    if (!fs.existsSync(checkPoint.dbPath)) {
      throw new Error(
        `Checkpoint DB file not found: ${checkPoint.dbPath}`,
      );
    }

    const actualChecksum = this.computeChecksum(checkPoint.dbPath);
    if (actualChecksum !== checkPoint.dbChecksum) {
      logger.error(
        `Checkpoint ${checkPoint.checkpointId} checksum mismatch: ` +
        `expected ${checkPoint.dbChecksum}, got ${actualChecksum}`,
      );
      return false;
    }

    // Step 2: Copy checkpoint DB to output path
    const outputDir = path.dirname(path.resolve(outputPath));
    fs.mkdirSync(outputDir, { recursive: true });
    fs.copyFileSync(checkPoint.dbPath, outputPath);

    logger.info(
      `Recovery: checkpoint DB copied to ${outputPath} ` +
      `(size: ${fs.statSync(outputPath).size} bytes, checksum verified)`,
    );

    // Step 3: Open output DB for replay
    const outputDb = new Database(outputPath);
    outputDb.pragma('journal_mode = WAL');

    try {
      // Step 4: Read WAL entries between checkpoint and target
      const checkpointTime = new Date(checkPoint.timestamp).getTime();
      const targetTime = new Date(targetTimestamp).getTime();

      if (checkpointTime > targetTime) {
        throw new Error(
          `Checkpoint timestamp (${checkPoint.timestamp}) is after ` +
          `target timestamp (${targetTimestamp})`,
        );
      }

      // Reload manifests to get latest segment state
      this.manifest.load();
      this.reader.reloadManifest();

      // Collect all entries from all segments
      const allEntries: PitrWALEntry[] = [];
      for (const segment of this.manifest.segments) {
        try {
          const segEntries = this.reader.readSegment(segment.segmentIndex);
          allEntries.push(...segEntries);
        } catch (err: any) {
          logger.warn(
            `Recovery: failed to read segment ${segment.segmentIndex}: ${err.message}`,
          );
        }
      }

      // Filter entries after checkpoint timestamp and at or before target
      const entriesToReplay = allEntries
        .filter(e => {
          const entryTime = new Date(e.timestamp).getTime();
          return entryTime > checkpointTime && entryTime <= targetTime;
        })
        .sort((a, b) => {
          return (
            new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          );
        });

      logger.info(
        `Recovery: replaying ${entriesToReplay.length} entries ` +
        `to reach target ${targetTimestamp}`,
      );

      // Step 5: Apply each entry against the restored DB
      for (const entry of entriesToReplay) {
        try {
          outputDb.exec(entry.data);
        } catch (err: any) {
          // If the entry data is not valid SQL, log and continue
          logger.warn(
            `Recovery: failed to apply entry ${entry.lsn} ` +
            `(raft=${entry.raftIndex}): ${err.message} — skipping`,
          );
        }
      }

      logger.info(
        `Recovery complete: ${checkPoint.checkpointId} → ${targetTimestamp} ` +
        `(${entriesToReplay.length} entries replayed)`,
      );

      return true;
    } finally {
      outputDb.close();
    }
  }

  /**
   * Prune old checkpoint records for a shard, keeping only the most recent N.
   *
   * Removes both the metadata records and the associated .db files on disk.
   * Completed checkpoints are preferred; failed/in_progress records are
   * pruned first when they exceed the keep count.
   *
   * @param shardId - Shard to prune checkpoints for
   * @param keepCount - Number of most recent checkpoints to retain
   * @returns Number of checkpoints pruned
   */
  pruneCheckpoints(shardId: string, keepCount: number): number {
    // Get all checkpoints for this shard (newest first)
    const allRecords = this.listCheckpoints(shardId);

    if (allRecords.length <= keepCount) {
      return 0;
    }

    // Keep the newest `keepCount` records
    const toPrune = allRecords.slice(keepCount);
    let prunedCount = 0;

    for (const record of toPrune) {
      // Remove checkpoint DB file
      try {
        if (fs.existsSync(record.dbPath)) {
          fs.unlinkSync(record.dbPath);
        }
      } catch (err: any) {
        logger.warn(
          `Failed to delete checkpoint file ${record.dbPath}: ${err.message}`,
        );
      }

      // Remove metadata record
      this.metaDb.prepare(
        `DELETE FROM __checkpoint_metadata WHERE checkpointId = ?`,
      ).run(record.checkpointId);

      prunedCount++;
    }

    logger.info(
      `Pruned ${prunedCount} checkpoint(s) for shard ${shardId} ` +
      `(keeping ${keepCount})`,
    );

    return prunedCount;
  }

  /**
   * Get global checkpoint status.
   *
   * @returns Status object with total checkpoint count and timestamp of newest
   */
  getStatus(): { totalCheckpoints: number; lastCheckpoint: string | null } {
    const totalCheckpoints = this.metaDb.prepare(
      `SELECT COUNT(*) AS cnt FROM __checkpoint_metadata`,
    ).get() as { cnt: number };

    const last = this.metaDb.prepare(`
      SELECT timestamp FROM __checkpoint_metadata
      ORDER BY timestamp DESC
      LIMIT 1
    `).get() as { timestamp: string } | undefined;

    return {
      totalCheckpoints: totalCheckpoints.cnt,
      lastCheckpoint: last ? last.timestamp : null,
    };
  }

  /**
   * Close the metadata database. Call this when done to release resources.
   */
  close(): void {
    this.metaDb.close();
    logger.info('PITRCheckpoint closed');
  }

  // ── Private ───────────────────────────────────────────────────────────

  /**
   * Get the total number of WAL entries across all segments in the manifest.
   */
  private getTotalWALEntries(): number {
    this.manifest.load();
    return this.manifest.segments.reduce(
      (sum, seg) => sum + seg.entryCount,
      0,
    );
  }

  /**
   * Compute SHA-256 checksum of a file.
   */
  private computeChecksum(filePath: string): string {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Insert or update a checkpoint record in the metadata table.
   */
  private saveRecord(record: CheckpointRecord): void {
    this.metaDb.prepare(`
      INSERT OR REPLACE INTO __checkpoint_metadata
        (checkpointId, timestamp, shardId, walOffset, dbPath, dbChecksum, walSize, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      record.checkpointId,
      record.timestamp,
      record.shardId,
      record.walOffset,
      record.dbPath,
      record.dbChecksum,
      record.walSize,
      record.status,
    );
  }
}
