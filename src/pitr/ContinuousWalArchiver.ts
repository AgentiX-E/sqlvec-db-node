/**
 * ContinuousWalArchiver — Background continuous WAL archiver.
 *
 * Simulates PostgreSQL's archive_mode=on behavior:
 * - Runs a periodic background timer (every `archiveInterval` ms)
 * - Scans `{archiveDir}/ready/` directory for ready WAL segments
 * - Copies them to `{archiveDir}/archive/` on finding
 * - Removes / marks the ready segment after successful copy
 * - Checks `archiveTimeout`: if last archive was > timeout ago,
 *   forces the current WAL segment into ready state and archives it
 *
 * Integrates with PITRWalArchiver for physical segment management.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PinoLogger } from '../monitoring/PinoLogger';
import { PITRWalArchiver, type WalSegment } from './PITRWalArchiver';
import {
  serializeWalRecord,
  deserializeWalRecord,
  createWalBinaryRecord,
  parseWalFileHeader,
  createWalFileHeader,
  isBinaryWalFile,
  parseLsn,
  type WalBinaryRecord,
  type WalRecordType,
} from './WalBinaryFormat';

const logger = PinoLogger.forComponent('ContinuousWalArchiver');

// ── Configuration ────────────────────────────────────────────────────────────

export interface ContinuousWalArchiverConfig {
  /** Archive mode: 'on' enables archiving, 'off' disables (default: 'off') */
  archiveMode: 'on' | 'off';
  /** Custom archive command template (e.g. 'cp %p /archive/%f') — optional */
  archiveCommand?: string;
  /** Archive timeout in seconds — if last archive was longer ago, force switch (default: 60) */
  archiveTimeout: number;
  /** Archive directory path */
  archiveDir: string;
  /** Ready directory path (where segments await archiving) */
  readyDir: string;
  /** Check interval in milliseconds (default: 10000) */
  archiveInterval: number;
  /** Enable binary WAL format instead of JSONL (default: false) */
  binaryFormat?: boolean;
}

// ── Defaults ─────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: ContinuousWalArchiverConfig = {
  archiveMode: 'off' as const,
  archiveTimeout: 60,
  archiveDir: './pg_wal_archive/archive',
  readyDir: './pg_wal_archive/ready',
  archiveInterval: 10000,
};

// ── Main Class ───────────────────────────────────────────────────────────────

export class ContinuousWalArchiver {
  private config: ContinuousWalArchiverConfig;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  private lastArchiveTime = 0;
  private pitrArchiver: PITRWalArchiver | null = null;

  /** Whether binary WAL format is enabled */
  isBinary: boolean = false;

  /** Current binary WAL file path (when binary format is enabled) */
  private currentBinaryWalPath: string = '';

  constructor(config?: Partial<ContinuousWalArchiverConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Resolve paths
    this.config.archiveDir = path.resolve(this.config.archiveDir);
    this.config.readyDir = path.resolve(this.config.readyDir);

    // Initialize binary format flag
    this.isBinary = this.config.binaryFormat ?? false;

    // Ensure directories exist
    fs.mkdirSync(this.config.archiveDir, { recursive: true });
    fs.mkdirSync(this.config.readyDir, { recursive: true });
  }

  /**
   * Register the PITRWalArchiver for force-archiving live segments.
   */
  setPITRArchiver(archiver: PITRWalArchiver): void {
    this.pitrArchiver = archiver;
  }

  /**
   * Get the current configuration.
   */
  getConfig(): ContinuousWalArchiverConfig {
    return { ...this.config };
  }

  /**
   * Update configuration at runtime (safe to call while running).
   * Updates will take effect on the next archive cycle.
   */
  updateConfig(partial: Partial<ContinuousWalArchiverConfig>): void {
    if (partial.archiveDir !== undefined) {
      const resolved = path.resolve(partial.archiveDir);
      fs.mkdirSync(resolved, { recursive: true });
      this.config.archiveDir = resolved;
    }
    if (partial.readyDir !== undefined) {
      const resolved = path.resolve(partial.readyDir);
      fs.mkdirSync(resolved, { recursive: true });
      this.config.readyDir = resolved;
    }
    if (partial.archiveMode !== undefined) this.config.archiveMode = partial.archiveMode;
    if (partial.archiveTimeout !== undefined) this.config.archiveTimeout = partial.archiveTimeout;
    if (partial.archiveInterval !== undefined) this.config.archiveInterval = partial.archiveInterval;
    if (partial.archiveCommand !== undefined) this.config.archiveCommand = partial.archiveCommand;

    logger.info({ config: this.config }, 'ContinuousWalArchiver config updated');
  }

  /**
   * Start the background archive timer.
   * If archiveMode is 'off', logs a warning and does NOT start the timer.
   *
   * @returns true if the timer was started, false if archiveMode is 'off'
   */
  start(): boolean {
    if (this.config.archiveMode === 'off') {
      logger.warn('ContinuousWalArchiver not started: archiveMode is off');
      return false;
    }

    if (this.running) {
      logger.warn('ContinuousWalArchiver already running');
      return true;
    }

    this.running = true;
    this.lastArchiveTime = Date.now();

    this.timer = setInterval(() => {
      this.archiveLoop().catch((err) => {
        logger.error({ err: err.message }, 'ContinuousWalArchiver archiveLoop error');
      });
    }, this.config.archiveInterval);

    // Unref so it doesn't keep the process alive
    this.timer.unref();

    logger.info(
      `ContinuousWalArchiver started (mode=on, interval=${this.config.archiveInterval}ms, ` +
      `archiveTimeout=${this.config.archiveTimeout}s)`,
    );
    return true;
  }

  /**
   * Stop the background archive timer.
   */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.running = false;
    logger.info('ContinuousWalArchiver stopped');
  }

  /**
   * Check if the archiver is currently running.
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Get the timestamp (epoch ms) of the last archive operation.
   */
  getLastArchiveTime(): number {
    return this.lastArchiveTime;
  }

  // ════════════════════════════════════════════════════════════
  //  Binary Format Support
  // ════════════════════════════════════════════════════════════

  /**
   * Enable or disable binary WAL format.
   *
   * When enabled, records are serialized as binary (with magic, header, CRC32C)
   * instead of JSONL. The binary format works alongside the existing JSONL format
   * and can be toggled at runtime.
   *
   * @param enabled - true to enable binary format, false for JSONL
   */
  enableBinaryFormat(enabled: boolean): void {
    this.isBinary = enabled;
    this.config.binaryFormat = enabled;
    if (enabled) {
      logger.info('Binary WAL format enabled');
    } else {
      logger.info('Binary WAL format disabled, using JSONL');
    }
  }

  /**
   * Initialize binary WAL file with header.
   * Writes the WAL file header (magic + version + systemId + startLsn) at the
   * beginning of the current binary WAL segment file.
   *
   * @param systemId - System identifier for the WAL file
   * @param startLsn - Starting LSN for the WAL file
   */
  initBinaryWalFile(systemId: string, startLsn: string): void {
    if (!this.isBinary) return;

    const binaryWalPath = this.resolveBinaryWalPath();
    this.currentBinaryWalPath = binaryWalPath;

    const headerBuf = createWalFileHeader(systemId, startLsn);
    fs.writeFileSync(binaryWalPath, headerBuf);
    logger.info({ path: binaryWalPath, systemId, startLsn }, 'Binary WAL file initialized');
  }

  /**
   * Write a binary WAL record to the current binary WAL segment file.
   *
   * Serializes the record (including header, body, and CRC32C) and appends
   * it to the current binary WAL file.
   *
   * @param record - WalBinaryRecord to write
   */
  writeBinaryRecord(record: WalBinaryRecord): void {
    if (!this.isBinary || !this.currentBinaryWalPath) {
      logger.warn('Cannot write binary record: binary format not initialized');
      return;
    }

    const serialized = serializeWalRecord(record);
    fs.appendFileSync(this.currentBinaryWalPath, serialized);
    logger.trace(
      { lsn: record.lsn, type: record.recordType, length: serialized.length },
      'Binary WAL record written',
    );
  }

  /**
   * Read binary WAL records from a segment file within a given LSN range.
   *
   * @param fromLsn - Start LSN (inclusive, PG format '0/1')
   * @param toLsn - End LSN (exclusive, PG format '0/2')
   * @returns Array of WalBinaryRecords within the LSN range
   */
  readBinaryRecords(fromLsn: string, toLsn: string): WalBinaryRecord[] {
    const segmentDir = this.resolveBinaryWalDir();
    const records: WalBinaryRecord[] = [];

    // Collect all .bin files in the segment directory
    let files: string[];
    try {
      files = fs.readdirSync(segmentDir).filter(f => f.endsWith('.bin')).sort();
    } catch {
      logger.warn({ dir: segmentDir }, 'Binary WAL directory not found');
      return [];
    }

    const fromNum = parseLsn(fromLsn);
    const toNum = parseLsn(toLsn);

    for (const fileName of files) {
      const filePath = path.join(segmentDir, fileName);
      try {
        const data = fs.readFileSync(filePath);
        if (!isBinaryWalFile(data)) {
          logger.warn({ file: fileName }, 'Not a binary WAL file, skipping');
          continue;
        }

        // Skip the file header to get to records
        let offset = 0;
        if (data.length >= 4) {
          const magic = data.readUInt16BE(offset);
          const version = data.readUInt16BE(offset + 2);
          if (magic === 0xA8E1 && version === 1) {
            // Parse file header size
            if (data.length >= 6) {
              const systemIdLen = data.readUInt16BE(offset + 4);
              offset = 6 + systemIdLen;
              if (offset + 2 <= data.length) {
                const startLsnLen = data.readUInt16BE(offset);
                offset += 2 + startLsnLen;
                if (offset + 2 <= data.length) {
                  const endLsnLen = data.readUInt16BE(offset);
                  offset += 2 + endLsnLen + 8; // +8 for createdAt
                }
              }
            }
          }
        }

        // Read records
        while (offset < data.length) {
          try {
            const record = deserializeWalRecord(data.slice(offset));
            const lsnNum = parseLsn(record.lsn);
            if (lsnNum >= fromNum && lsnNum < toNum) {
              records.push(record);
            }

            // Advance past this record
            const lsnLen = data.readUInt16BE(offset + 2);
            const prevLsnLen = data.readUInt16BE(offset + 4 + lsnLen);
            const recordSize = 2 + 2 + lsnLen + 2 + prevLsnLen + 4 + 2 + 4 + 8 + record.recordLength + 4;
            offset += recordSize;
          } catch (err: any) {
            logger.warn({ offset, error: err.message }, 'Corrupted record in binary WAL file');
            break;
          }
        }
      } catch (err: any) {
        logger.warn({ file: fileName, error: err.message }, 'Failed to read binary WAL file');
      }
    }

    return records;
  }

  // ════════════════════════════════════════════════════════════
  //  Archive Loop (runs on every tick)
  // ════════════════════════════════════════════════════════════

  /**
   * Execute a single archive cycle.
   *
   * 1. Scans `readyDir` for files matching WAL segment pattern
   * 2. Copies each to `archiveDir`
   * 3. Deletes the ready file after successful copy
   * 4. Checks archive_timeout — if elapsed, force-switches the
   *    current active segment into ready state and archives it
   *
   * @returns Number of segments archived in this cycle
   */
  async archiveLoop(): Promise<number> {
    if (this.config.archiveMode === 'off') {
      return 0;
    }

    let archivedCount = 0;

    try {
      // Step 1: Scan ready directory for WAL segment files
      const readyFiles = this.scanReadyDir();
      logger.debug(`Found ${readyFiles.length} ready segment(s) in ${this.config.readyDir}`);

      // Step 2 & 3: Copy each ready segment to archive dir
      for (const fileName of readyFiles) {
        const sourcePath = path.join(this.config.readyDir, fileName);
        const destPath = path.join(this.config.archiveDir, fileName);

        try {
          // Skip if already archived (exact same content exists)
          if (fs.existsSync(destPath)) {
            const sourceStat = fs.statSync(sourcePath);
            const destStat = fs.statSync(destPath);
            if (sourceStat.size === destStat.size) {
              // Assume same file — remove source
              fs.unlinkSync(sourcePath);
              logger.debug(`Skipped duplicate ready segment ${fileName} (already archived)`);
              archivedCount++;
              this.lastArchiveTime = Date.now();
              continue;
            }
          }

          // Copy file
          fs.copyFileSync(sourcePath, destPath);
          fs.unlinkSync(sourcePath);

          // Execute custom archive command if configured
          if (this.config.archiveCommand) {
            this.executeArchiveCommand(sourcePath, destPath, fileName);
          }

          archivedCount++;
          this.lastArchiveTime = Date.now();

          logger.info(`Archived WAL segment: ${fileName} (${sourcePath} → ${destPath})`);
        } catch (err: any) {
          logger.error(
            { err: err.message, fileName },
            `Failed to archive segment ${fileName}`,
          );
        }
      }

      // Step 4: Check archive_timeout
      await this.checkArchiveTimeout();
    } catch (err: any) {
      logger.error({ err: err.message }, 'archiveLoop encountered unexpected error');
    }

    if (archivedCount > 0) {
      logger.info(`Archive cycle complete: ${archivedCount} segment(s) archived`);
    }

    return archivedCount;
  }

  /**
   * Force-archive the current PITRWalArchiver segment into the ready directory.
   * Triggers a segment switch and places the completed segment into ready/.
   *
   * @returns true if forced archive was triggered
   */
  async forceArchive(): Promise<boolean> {
    if (this.config.archiveMode === 'off') return false;
    if (!this.pitrArchiver) {
      logger.warn('Cannot force archive: no PITRWalArchiver registered');
      return false;
    }

    try {
      // Get the current active segment before switching
      const activeSeg = this.pitrArchiver.getActiveSegment();
      if (!activeSeg) {
        logger.warn('Cannot force archive: no active segment');
        return false;
      }

      const segId = activeSeg.id;
      const segFileName = `wal-segment-${String(segId).padStart(6, '0')}.jsonl`;

      // Switch to new segment (marks old as ready)
      this.pitrArchiver.switchSegment();

      // Copy the switched segment to ready dir
      const pgWalPath = path.join(
        path.dirname(this.config.readyDir.replace(/\/ready$/, '')),
        '..',
        'pg_wal',
        segFileName,
      );
      // The ready directory is adjacent to pg_wal in the standard layout.
      // We need to figure out the pg_wal path from config.
      // Strategy: use the PITRWalArchiver's own pgWalDir if accessible, or
      // derive from readyDir's parent.
      const sourcePath = this.resolveSegmentPath(segFileName);
      const destPath = path.join(this.config.readyDir, segFileName);
      const archiveDest = path.join(this.config.archiveDir, segFileName);

      if (fs.existsSync(sourcePath)) {
        // Copy from pg_wal to ready
        fs.copyFileSync(sourcePath, destPath);

        // Copy from pg_wal directly to archive
        fs.copyFileSync(sourcePath, archiveDest);
        this.lastArchiveTime = Date.now();

        logger.info(`Force-archived segment ${segId}: ${segFileName}`);
        return true;
      } else {
        logger.warn(`Source segment ${segFileName} not found at ${sourcePath} for force archive`);
        return false;
      }
    } catch (err: any) {
      logger.error({ err: err.message }, 'forceArchive failed');
      return false;
    }
  }

  /**
   * Execute the custom archive command (if configured).
   *
   * Template variables:
   *   %p — source path of the WAL segment
   *   %f — destination filename only
   *   %d — destination full path
   *
   * This is a synchronous, best-effort execution.
   */
  private executeArchiveCommand(sourcePath: string, destPath: string, fileName: string): void {
    if (!this.config.archiveCommand) return;

    const cmd = this.config.archiveCommand
      .replace(/%p/g, sourcePath)
      .replace(/%f/g, fileName)
      .replace(/%d/g, destPath);

    try {
      const { execSync } = require('node:child_process');
      execSync(cmd, { timeout: 30_000, stdio: 'ignore' });
      logger.debug(`Archive command executed: ${cmd}`);
    } catch (err: any) {
      logger.warn({ err: err.message, cmd }, 'Archive command failed (non-fatal)');
    }
  }

  /**
   * Check archive_timeout and force-archive if exceeded.
   */
  private async checkArchiveTimeout(): Promise<void> {
    const elapsedSec = (Date.now() - this.lastArchiveTime) / 1000;
    if (elapsedSec >= this.config.archiveTimeout) {
      logger.info(
        `archiveTimeout reached (${elapsedSec.toFixed(1)}s >= ${this.config.archiveTimeout}s) — ` +
        `forcing archive`,
      );
      await this.forceArchive();
    }
  }

  /**
   * Scan the ready directory for WAL segment files.
   * Returns filenames sorted by name (so archive order is deterministic).
   */
  private scanReadyDir(): string[] {
    try {
      if (!fs.existsSync(this.config.readyDir)) {
        fs.mkdirSync(this.config.readyDir, { recursive: true });
        return [];
      }

      const files = fs.readdirSync(this.config.readyDir);
      return files
        .filter((f) => /^wal-segment-\d{6}\.jsonl$/.test(f))
        .sort();
    } catch (err: any) {
      logger.error({ err: err.message }, 'Failed to scan ready directory');
      return [];
    }
  }

  /**
   * Resolve the full path to a WAL segment file.
   * Tries multiple potential locations since PITRWalArchiver's pgWalDir
   * might be in a standard layout relative to our config.
   */
  private resolveSegmentPath(fileName: string): string {
    const candidates = [
      // Direct relative to readyDir parent
      path.resolve(this.config.readyDir, '..', 'pg_wal', fileName),
      // Standard: ../pg_wal/
      path.resolve(this.config.readyDir, '../../pg_wal', fileName),
      // Current directory
      path.resolve(fileName),
      // Config archiveDir parent
      path.resolve(this.config.archiveDir, '..', fileName),
    ];

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) return candidate;
    }

    // Fallback: return the first candidate regardless
    return candidates[0];
  }

  /**
   * Resolve the path for the current binary WAL segment file.
   * Uses the same directory structure as JSONL segments, but with .bin extension.
   */
  private resolveBinaryWalPath(): string {
    const segDir = this.resolveBinaryWalDir();
    const fileName = `wal-segment-${Date.now()}-${Math.floor(Math.random() * 1000)}.bin`;
    return path.join(segDir, fileName);
  }

  /**
   * Resolve the directory where binary WAL segment files are stored.
   * Reuses the ready directory by default.
   */
  private resolveBinaryWalDir(): string {
    return this.config.readyDir;
  }
}
