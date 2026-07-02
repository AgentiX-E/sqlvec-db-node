/**
 * WALManifest — Index of all WAL segments.
 *
 * Maintains a serializable index of segment metadata for the PITR archive.
 * The manifest is stored as a JSON file (pitr-manifest.json) alongside
 * WAL segment files.
 *
 * Phase 1: Core Infrastructure
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { SegmentMeta, MANIFEST_FILENAME } from './types';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('WALManifest');

/**
 * Manages the WAL segment index.
 *
 * Provides load/save from a JSON file and in-memory access to segment
 * metadata for fast lookup during recovery.
 */
export class WALManifest {
  /** All known segment metadata, ordered by segmentIndex ascending */
  segments: SegmentMeta[] = [];

  /** Path to the manifest JSON file */
  private filePath: string;

  constructor(archiveDir: string) {
    this.filePath = path.join(archiveDir, MANIFEST_FILENAME);
  }

  /**
   * Load the manifest from disk.
   * If the file does not exist, starts with an empty segment list.
   */
  load(): void {
    try {
      if (!fs.existsSync(this.filePath)) {
        this.segments = [];
        return;
      }
      const raw = fs.readFileSync(this.filePath, 'utf-8');
      const parsed = JSON.parse(raw);
      this.segments = Array.isArray(parsed.segments) ? parsed.segments : [];
      logger.info(`Loaded WAL manifest: ${this.segments.length} segments`);
    } catch (err: any) {
      logger.warn(`Failed to load WAL manifest, starting fresh: ${err.message}`);
      this.segments = [];
    }
  }

  /**
   * Save the manifest to disk.
   * Creates parent directories if needed.
   */
  save(): void {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const data = JSON.stringify({ segments: this.segments }, null, 2);
      fs.writeFileSync(this.filePath, data, 'utf-8');
    } catch (err: any) {
      logger.error(`Failed to save WAL manifest: ${err.message}`);
      throw err;
    }
  }

  /**
   * Add a segment to the manifest.
   * Ensures segments remain sorted by segmentIndex.
   */
  addSegment(meta: SegmentMeta): void {
    this.segments.push(meta);
    this.segments.sort((a, b) => a.segmentIndex - b.segmentIndex);
  }

  /**
   * Remove segments with segmentIndex <= the given index.
   * Returns the removed segments.
   */
  removeSegmentsUpTo(segmentIndex: number): SegmentMeta[] {
    const removed = this.segments.filter(s => s.segmentIndex <= segmentIndex);
    this.segments = this.segments.filter(s => s.segmentIndex > segmentIndex);
    return removed;
  }

  /**
   * Remove a specific segment by index.
   */
  removeSegment(segmentIndex: number): SegmentMeta | null {
    const idx = this.segments.findIndex(s => s.segmentIndex === segmentIndex);
    if (idx === -1) return null;
    const [removed] = this.segments.splice(idx, 1);
    return removed;
  }

  /**
   * Find a segment by its segmentIndex.
   */
  getSegment(segmentIndex: number): SegmentMeta | undefined {
    return this.segments.find(s => s.segmentIndex === segmentIndex);
  }

  /**
   * Get the total number of entries across all segments (approximate).
   */
  totalEntryCount(): number {
    return this.segments.reduce((sum, s) => sum + s.entryCount, 0);
  }

  /**
   * Get the total size of all WAL segments in bytes.
   */
  totalSizeBytes(): number {
    return this.segments.reduce((sum, s) => sum + s.sizeBytes, 0);
  }

  /**
   * Get the last (newest) segment, or null if the manifest is empty.
   */
  lastSegment(): SegmentMeta | null {
    if (this.segments.length === 0) return null;
    return this.segments[this.segments.length - 1];
  }

  /**
   * Get the first (oldest) segment, or null if the manifest is empty.
   */
  firstSegment(): SegmentMeta | null {
    if (this.segments.length === 0) return null;
    return this.segments[0];
  }

  /**
   * Get the number of segments in the manifest.
   */
  get length(): number {
    return this.segments.length;
  }
}
