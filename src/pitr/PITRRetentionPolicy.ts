/**
 * PITRRetentionPolicy — Retention lifecycle for PITR WAL segments.
 *
 * Evaluates WAL segments against configurable rules (count, time, size)
 * and determines which segments should be purged. Never deletes the most
 * recent segment (anchor), and cross-checks with full backup retention
 * to ensure WAL segments needed for backup replay are preserved.
 *
 * Phase 3: Retention & Lifecycle
 *
 * @see design-pitr.md §3.3 for retention policy design
 * @see design-pitr.md §7 Phase 3 for implementation plan
 */

import { SegmentMeta } from './types';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PITRRetentionPolicy');

// ── Retention Rules ──────────────────────────────────────────────────────────

/**
 * A single retention rule.
 *
 * Three types:
 * - `count`: Keep at most `value` segments (applied after other rules)
 * - `time`: Keep segments not older than `hours` hours
 * - `size`: Keep total segment size under `bytes` bytes
 */
export interface PITRRetentionRule {
  type: 'count' | 'time' | 'size';
  /** For count: max number of segments to keep.
   *  For time: max age in hours.
   *  For size: threshold value (see type-specific fields). */
  value: number;
  /** For time: max age in hours (alternative to value) */
  hours?: number;
  /** For size: max total size in bytes (alternative to value) */
  bytes?: number;
}

// ── Retention Policy ─────────────────────────────────────────────────────────

/**
 * Retention policy for PITR WAL segments.
 *
 * Applies multiple rules and returns the union of all segments marked
 * for deletion, with safety checks:
 * - Never deletes the most recent segment (anchor)
 * - Cross-checks with full backup timestamps to preserve WAL segments
 *   that full backups still depend on
 */
export class PITRRetentionPolicy {
  private rules: PITRRetentionRule[];

  constructor(rules?: PITRRetentionRule[]) {
    this.rules = rules || [
      { type: 'time', value: 24 },   // keep 24 hours by default
      { type: 'count', value: 100 },  // at most 100 segments
      // { type: 'size', value: 1_073_741_824 }, // optionally 1GB max
    ];
  }

  /**
   * Evaluate which segments to purge based on the configured rules.
   *
   * Each rule independently produces a set of segments to delete.
   * The final set is the **union** (intersection of keep sets, i.e.
   * a segment is deleted if ANY rule says it should be deleted).
   *
   * Safety: The most recent segment is never included in the result.
   *
   * @param segments - All segments from the manifest, sorted by segmentIndex
   * @returns Segments that should be deleted
   */
  evaluate(segments: SegmentMeta[]): SegmentMeta[] {
    if (segments.length === 0) return [];
    if (segments.length === 1) return []; // never delete the only segment

    const anchor = segments[segments.length - 1]; // never delete newest
    const candidates = segments.slice(0, -1); // all except anchor

    // Collect deletion candidates from each rule
    const toDeleteIndices = new Set<number>();

    for (const rule of this.rules) {
      switch (rule.type) {
        case 'count': {
          // Keep at most `value` segments. Delete the oldest ones beyond that.
          const maxKeep = Math.max(rule.value, 1); // at least 1 (anchor)
          const deleteCount = Math.max(0, candidates.length - maxKeep);
          for (let i = 0; i < deleteCount; i++) {
            toDeleteIndices.add(candidates[i].segmentIndex);
          }
          break;
        }

        case 'time': {
          // Delete segments older than `hours` (or `value` if hours not set)
          const maxAgeHours = rule.hours ?? rule.value;
          const cutoffMs = Date.now() - maxAgeHours * 3_600_000;

          for (const seg of candidates) {
            const lastTs = new Date(seg.lastTimestamp).getTime();
            if (lastTs < cutoffMs) {
              toDeleteIndices.add(seg.segmentIndex);
            }
          }
          break;
        }

        case 'size': {
          // Delete oldest segments until total size is under `bytes`
          // (or `value` if bytes not set)
          const maxBytes = rule.bytes ?? rule.value;

          // Sort oldest first, anchor excluded
          const sorted = [...candidates].sort(
            (a, b) => a.segmentIndex - b.segmentIndex,
          );

          let currentSize = segments.reduce((sum, s) => sum + s.sizeBytes, 0);

          for (const seg of sorted) {
            if (currentSize <= maxBytes) break;
            toDeleteIndices.add(seg.segmentIndex);
            currentSize -= seg.sizeBytes;
          }
          break;
        }
      }
    }

    // Anchor is always protected
    toDeleteIndices.delete(anchor.segmentIndex);

    const toDelete = segments.filter(s =>
      toDeleteIndices.has(s.segmentIndex),
    );

    if (toDelete.length > 0) {
      logger.info(
        `Retention evaluation: ${toDelete.length} of ${segments.length} ` +
        `segments marked for deletion (rules: ${this.rules.map(r => r.type).join(', ')})`,
      );
    }

    return toDelete;
  }

  /**
   * Cross-check with full backup retention.
   *
   * Ensures that no WAL segment is deleted if it is needed by a full backup
   * that is still retained. A WAL segment is "needed" if its last timestamp
   * falls after the oldest retained backup.
   *
   * If no backup exists, all WAL segments are preserved regardless of
   * retention rules — because deleting WAL without a backup anchor would
   * make PITR unrecoverable.
   *
   * @param segments - Segments proposed for deletion
   * @param oldestBackupTimestamp - ISO 8601 timestamp of the oldest retained
   *                                full backup, or null if no backups exist
   * @returns Filtered list — segments that are safe to delete
   */
  crossCheckWithBackups(
    segments: SegmentMeta[],
    oldestBackupTimestamp: string | null,
  ): SegmentMeta[] {
    if (!oldestBackupTimestamp) {
      // No backups — keep ALL WAL segments to ensure recoverability
      logger.warn(
        'No full backups available — all WAL segments preserved ' +
        '(deleting WAL without backup anchors makes PITR unrecoverable)',
      );
      return [];
    }

    const oldestBackupMs = new Date(oldestBackupTimestamp).getTime();

    const safeToDelete = segments.filter(seg => {
      // Only delete segments whose last entry is older than the oldest backup.
      // If a segment's last entry is newer than (or equal to) the oldest backup,
      // that segment might be the bridge needed to recover to a point after
      // the backup, so we preserve it.
      const segLastMs = new Date(seg.lastTimestamp).getTime();
      return segLastMs < oldestBackupMs;
    });

    const preserved = segments.length - safeToDelete.length;
    if (preserved > 0) {
      logger.info(
        `Cross-check preserved ${preserved} WAL segment(s) needed by full backups`,
      );
    }

    return safeToDelete;
  }

  /**
   * Get the current retention rules (for inspection).
   */
  getRules(): PITRRetentionRule[] {
    return [...this.rules];
  }
}
