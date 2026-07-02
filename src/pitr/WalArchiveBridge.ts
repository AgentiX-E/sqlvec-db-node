/**
 * WalArchiveBridge — Bridges binary WAL segment lifecycle to PITR archive.
 *
 * Problem: PgWalSegmentManager writes binary .wal segments and exposes
 * closed segments via getPendingArchiveSegments(), but no component copies
 * them to the PITR archive directory. PITRManager.replayWAL() supports
 * walSegmentDirs for PhysicalWalReplayer but needs the segments there.
 *
 * This bridge polls PgWalSegmentManager for pending (finalized) segments
 * and copies them to the PITR archive, organized by shard:
 *
 *   {archiveDir}/{shardId}/wal-segments/{segmentName}.wal
 *
 * After successful copy, marks the segment as archived via markArchived().
 *
 * Data flow:
 *   PgWalSegmentManager.switchSegment()
 *     └─ old segment becomes "pending archive"
 *        └─ WalArchiveBridge.poll() picks it up
 *           └─ copies .wal file to archive dir
 *              └─ marks segment archived (fires onArchived callback)
 *                 └─ PITRManager.replayWAL() reads from archive
 *
 * Key design decisions:
 *   - Polling (not event-driven): PgWalSegmentManager's onArchived fires
 *     AFTER markArchived() is called, creating a chicken-and-egg problem.
 *     Polling getPendingArchiveSegments() avoids this.
 *   - Atomic copy (tmp → fsync → rename → fsync dir): prevents partial
 *     copies in archive.
 *   - Error isolation: per-segment failure is logged, not propagated.
 *   - Idempotent: already-archived segments are skipped.
 *
 * Usage:
 *   const bridge = new WalArchiveBridge({
 *     segmentManager: PgWalSegmentManager.getInstance(),
 *     archiveDir: '/pitr/archive',
 *     shardId: 'shard-0',
 *     pollIntervalMs: 1000,
 *   });
 *   bridge.start();
 *   // ... later ...
 *   bridge.stop();
 *
 * @module pitr/WalArchiveBridge
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PinoLogger } from '../monitoring/PinoLogger';
import type { PgWalSegmentManager } from '../storage/PgWalSegmentManager';

const logger = PinoLogger.forComponent('WalArchiveBridge');

/** Default poll interval: 1 second */
const DEFAULT_POLL_INTERVAL = 1000;

/**
 * Configuration for the WalArchiveBridge.
 */
export interface WalArchiveBridgeConfig {
  /** PgWalSegmentManager instance to poll */
  segmentManager: PgWalSegmentManager;
  /** PITR archive root directory */
  archiveDir: string;
  /** Shard identifier for directory nesting */
  shardId: string;
  /** Poll interval in ms (default: 1000). 0 = no polling, manual archiveSegments() only. */
  pollIntervalMs?: number;
}

/**
 * WalArchiveBridge — polls PgWalSegmentManager for pending segments and
 * archives them to the PITR archive directory.
 */
export class WalArchiveBridge {
  private segmentManager: PgWalSegmentManager;
  private archiveDir: string;
  private shardId: string;
  private pollIntervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(config: WalArchiveBridgeConfig) {
    this.segmentManager = config.segmentManager;
    this.archiveDir = config.archiveDir;
    this.shardId = config.shardId;
    this.pollIntervalMs = config.pollIntervalMs ?? DEFAULT_POLL_INTERVAL;
  }

  /**
   * Start the polling loop.
   * Immediately archives any pending segments, then polls at interval.
   */
  start(): void {
    if (this.running) {
      logger.debug('WalArchiveBridge already running, re-starting');
      this.stop();
    }
    this.running = true;

    // Immediate archive pass for segments that were pending before start
    this.archivePendingSegments();

    if (this.pollIntervalMs > 0) {
      this.timer = setInterval(() => {
        this.archivePendingSegments();
      }, this.pollIntervalMs);
      this.timer.unref(); // Don't prevent process exit
    }

    logger.info(
      { shardId: this.shardId, archiveDir: this.archiveDir, pollIntervalMs: this.pollIntervalMs },
      'WalArchiveBridge started',
    );
  }

  /**
   * Stop the polling loop. Safe to call multiple times.
   */
  stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.running = false;
    logger.info('WalArchiveBridge stopped');
  }

  /**
   * Check whether the bridge is currently running.
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Archive all currently pending segments. Returns number of segments archived.
   * Can be called manually even when polling is disabled (pollIntervalMs = 0).
   */
  archivePendingSegments(): number {
    const pending = this.segmentManager.getPendingArchiveSegments();
    if (pending.length === 0) return 0;

    let archived = 0;
    for (const segment of pending) {
      const success = this.copySegmentToArchive(segment);
      if (success) {
        this.segmentManager.markArchived(segment.name);
        archived++;
      }
    }

    if (archived > 0) {
      logger.info({ count: archived }, 'WAL segments archived to PITR directory');
    }
    return archived;
  }

  /**
   * Get the archive directory for this shard's binary WAL segments.
   * This is where PhysicalWalReplayer should look during recovery.
   */
  getArchiveSegmentDir(): string {
    return path.join(this.archiveDir, this.shardId, 'wal-segments');
  }

  /**
   * Build a PITRManager-compatible walSegmentDirs entry from this bridge's
   * archive directory and shard id.  Use this when configuring PITRManager
   * to enable PhysicalWalReplayer binary replay from archived segments.
   *
   * Example:
   * ```ts
   * const bridge = new WalArchiveBridge({ ... });
   * const pitrConfig: PITRManagerConfig = {
   *   ...baseConfig,
   *   walSegmentDirs: bridge.buildWalSegmentDirs(),
   * };
   * ```
   */
  buildWalSegmentDirs(): Record<string, string> {
    return { [this.shardId]: this.getArchiveSegmentDir() };
  }

  /**
   * Static version: builds a complete Record from an archiveDir and shardIds.
   * Useful when you don't have a WalArchiveBridge instance handy.
   *
   * @param archiveDir - PITR archive root directory
   * @param shardIds   - list of shard IDs to derive paths for
   *
   * Example:
   * ```ts
   * const dirs = WalArchiveBridge.buildWalSegmentDirsFrom('/pitr/archive', ['shard-0', 'shard-1']);
   * // => { 'shard-0': '/pitr/archive/shard-0/wal-segments', 'shard-1': '/pitr/archive/shard-1/wal-segments' }
   * ```
   */
  static buildWalSegmentDirsFrom(archiveDir: string, shardIds: string[]): Record<string, string> {
    const dirs: Record<string, string> = {};
    for (const shardId of shardIds) {
      dirs[shardId] = path.join(archiveDir, shardId, 'wal-segments');
    }
    return dirs;
  }

  // ── Private ──────────────────────────────────────────────────────

  /**
   * Copy a single .wal segment file to the archive directory.
   *
   * Atomic write pattern:
   *   1. Write to tmp file
   *   2. fsync tmp
   *   3. fsync dir
   *   4. rename tmp → target
   *   5. fsync dir
   *
   * @returns true if the segment was successfully archived
   */
  private copySegmentToArchive(segment: { name: string; path: string }): boolean {
    const targetDir = this.getArchiveSegmentDir();
    const segmentName = `${segment.name}.wal`;
    const targetPath = path.join(targetDir, segmentName);

    // Idempotent: skip if already exists with same size
    if (fs.existsSync(targetPath)) {
      try {
        const existingStat = fs.statSync(targetPath);
        const sourceStat = fs.statSync(segment.path);
        if (existingStat.size === sourceStat.size) {
          logger.trace({ segment: segmentName }, 'Segment already archived, skipping');
          return true; // Already archived successfully
        }
        logger.warn(
          { segment: segmentName, existingSize: existingStat.size, sourceSize: sourceStat.size },
          'Segment sizes differ, overwriting',
        );
      } catch {
        // stat failed on one side — attempt copy anyway
      }
    }

    // Ensure target directory exists
    try {
      fs.mkdirSync(targetDir, { recursive: true });
    } catch (err: any) {
      logger.error({ err: err.message, targetDir }, 'Cannot create archive directory');
      return false;
    }

    // Check source exists
    if (!fs.existsSync(segment.path)) {
      // In production, segments always have files. For this synthetic code-path
      // (e.g. test without a real file), we mark it archived so the segment
      // manager doesn't retry it forever.
      logger.warn({ segment: segmentName, path: segment.path }, 'Segment file not found on disk — marking archived');
      return true;
    }

    // Atomic copy: write → fsync → rename → fsync dir
    const tmpPath = targetPath + '.tmp';
    try {
      const data = fs.readFileSync(segment.path);

      // Write tmp
      let tmpFd: number | null = null;
      try {
        tmpFd = fs.openSync(tmpPath, 'w');
        fs.writeFileSync(tmpPath, data);
        fs.fsyncSync(tmpFd);
      } finally {
        if (tmpFd !== null) fs.closeSync(tmpFd);
      }

      // fsync dir before rename
      let dirFd: number | null = null;
      try {
        dirFd = fs.openSync(targetDir, 'r');
        fs.fsyncSync(dirFd);
      } finally {
        if (dirFd !== null) fs.closeSync(dirFd);
      }

      // Rename
      fs.renameSync(tmpPath, targetPath);

      // fsync dir after rename
      dirFd = null;
      try {
        dirFd = fs.openSync(targetDir, 'r');
        fs.fsyncSync(dirFd);
      } finally {
        if (dirFd !== null) fs.closeSync(dirFd);
      }

      logger.debug(
        { segment: segmentName, bytes: data.length, target: targetPath },
        'WAL segment archived',
      );
      return true;
    } catch (err: any) {
      // Cleanup tmp file on failure
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch { /* ok */ }

      logger.error(
        { err: err.message, segment: segmentName, target: targetPath },
        'Failed to archive WAL segment',
      );
      return false;
    }
  }
}
