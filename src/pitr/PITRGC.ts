/**
 * PITRGC — Garbage collection scheduler for PITR WAL segments.
 *
 * Runs periodic GC cycles that:
 *   1. Evaluate WAL segments against retention rules
 *   2. Cross-check with full backup retention
 *   3. Delete candidate segment files from disk
 *   4. Update the WAL manifest
 *
 * Phase 3: Retention & Lifecycle
 *
 * @see design-pitr.md §3.3 for retention design
 * @see design-pitr.md §7 Phase 3 for implementation plan
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PinoLogger } from '../monitoring/PinoLogger';
import { PITRRetentionPolicy, PITRRetentionRule } from './PITRRetentionPolicy';
import { WALManifest } from './WALManifest';
import { SegmentMeta, segmentFilename } from './types';

const logger = PinoLogger.forComponent('PITRGC');

// ── GC Config ─────────────────────────────────────────────────────────────────

export interface PITRGCConfig {
  /** Path to the PITR WAL archive directory */
  archiveDir: string;
  /** WALManifest instance (must have load() already called or done by GC) */
  manifest: WALManifest;
  /** Optional custom retention rules. Falls back to PITRRetentionPolicy defaults. */
  rules?: PITRRetentionRule[];
  /** Optional: oldest retained backup timestamp for cross-check (ISO 8601) */
  oldestBackupTimestamp?: string | null;
}

// ── PITRGC ────────────────────────────────────────────────────────────────────

/**
 * Garbage collection scheduler for PITR WAL segments.
 *
 * Usage:
 *   const gc = new PITRGC({ archiveDir, manifest });
 *   gc.start(); // run every 5 minutes
 *   // ... later ...
 *   gc.stop();
 */
export class PITRGC {
  private retention: PITRRetentionPolicy;
  private manifest: WALManifest;
  private archiveDir: string;
  private oldestBackupTimestamp: string | null;
  private intervalTimer?: NodeJS.Timeout;

  constructor(config: PITRGCConfig) {
    this.retention = new PITRRetentionPolicy(config.rules);
    this.manifest = config.manifest;
    this.archiveDir = path.resolve(config.archiveDir);
    this.oldestBackupTimestamp = config.oldestBackupTimestamp ?? null;
  }

  /**
   * Run a single GC cycle synchronously.
   *
   * Steps:
   *   1. Get all segments from the manifest
   *   2. Evaluate retention rules → candidate segments for deletion
   *   3. Cross-check with full backup retention
   *   4. Delete the segment files from disk
   *   5. Remove deleted segments from the manifest
   *   6. Save the updated manifest
   *
   * @returns Number of segments removed
   */
  runCycle(): number {
    const segments = [...this.manifest.segments];

    if (segments.length === 0) {
      logger.trace('GC cycle: no segments to evaluate');
      return 0;
    }

    // Step 1: Evaluate retention rules
    const candidates = this.retention.evaluate(segments);

    if (candidates.length === 0) {
      logger.trace('GC cycle: no segments marked for deletion');
      return 0;
    }

    // Step 2: Cross-check with full backup retention
    const safeToDelete = this.retention.crossCheckWithBackups(
      candidates,
      this.oldestBackupTimestamp,
    );

    if (safeToDelete.length === 0) {
      logger.info('GC cycle: no segments safe to delete after backup cross-check');
      return 0;
    }

    // Step 3: Delete segment files from disk
    let deletedCount = 0;
    for (const seg of safeToDelete) {
      const fileName = segmentFilename(seg.segmentIndex);
      const filePath = path.join(this.archiveDir, fileName);

      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          logger.debug(`Deleted WAL segment file: ${fileName}`);
        } else {
          logger.warn(
            `WAL segment file not found on disk (already deleted?): ${fileName}`,
          );
        }

        // Remove from manifest
        this.manifest.removeSegment(seg.segmentIndex);
        deletedCount++;
      } catch (err: any) {
        logger.error(
          `Failed to delete WAL segment ${fileName}: ${err.message}`,
        );
        // Continue with other segments even if one fails
      }
    }

    // Step 4: Save the updated manifest
    try {
      this.manifest.save();
    } catch (err: any) {
      logger.error(`Failed to save manifest after GC cycle: ${err.message}`);
    }

    // Log summary
    const totalBytesFreed = safeToDelete.reduce(
      (sum, s) => sum + s.sizeBytes,
      0,
    );

    logger.info(
      `GC cycle complete: removed ${deletedCount} segment(s), ` +
      `freed ${this.formatBytes(totalBytesFreed)}, ` +
      `${this.manifest.length} segment(s) remaining`,
    );

    return deletedCount;
  }

  /**
   * Start periodic GC on a timer.
   *
   * @param intervalMs - Interval between GC cycles (default: 5 minutes)
   */
  start(intervalMs = 300_000): void {
    if (this.intervalTimer) {
      logger.warn('PITRGC is already running — ignoring start()');
      return;
    }

    logger.info(
      `Starting periodic GC every ${intervalMs / 1000}s ` +
      `(retention: ${this.retention.getRules().map(r => r.type).join(', ')})`,
    );

    this.intervalTimer = setInterval(() => {
      try {
        this.runCycle();
      } catch (err: any) {
        logger.error(`GC cycle failed: ${err.message}`);
      }
    }, intervalMs);

    // Unref so it doesn't prevent process exit
    this.intervalTimer.unref();
  }

  /**
   * Stop periodic GC.
   */
  stop(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = undefined;
      logger.info('Periodic GC stopped');
    }
  }

  /**
   * Update the oldest backup timestamp for cross-check purposes.
   * Called when backups are created or removed.
   */
  updateOldestBackupTimestamp(timestamp: string | null): void {
    this.oldestBackupTimestamp = timestamp;
  }

  /**
   * Get a summary of the current GC state.
   */
  getSummary(): PITRGCSummary {
    return {
      running: this.intervalTimer !== undefined,
      segmentCount: this.manifest.length,
      retentionRules: this.retention.getRules(),
      oldestBackupTimestamp: this.oldestBackupTimestamp,
      archiveDir: this.archiveDir,
    };
  }

  /**
   * Format bytes into a human-readable string.
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const size = bytes / Math.pow(1024, i);
    return `${size.toFixed(1)} ${units[i]}`;
  }
}

// ── GC Summary ────────────────────────────────────────────────────────────────

export interface PITRGCSummary {
  /** Whether the periodic timer is running */
  running: boolean;
  /** Current number of WAL segments in the manifest */
  segmentCount: number;
  /** Active retention rules */
  retentionRules: PITRRetentionRule[];
  /** Oldest retained backup timestamp (null if no backups) */
  oldestBackupTimestamp: string | null;
  /** PITR archive directory path */
  archiveDir: string;
}
