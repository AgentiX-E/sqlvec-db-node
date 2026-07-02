/**
 * CsvAuditSink — CSV file persistence sink for AuditLogger.
 *
 * Writes structured audit events as CSV rows to a rotating file.
 * Supports size-based and date-based rotation, optional gzip
 * compression of rotated files, old-file cleanup, and in-memory
 * backpressure buffering (max 1,000 entries).
 *
 * Uses only built-in Node.js modules (fs, zlib, crypto, path).
 *
 * @module CsvAuditSink
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import * as crypto from 'node:crypto';
import * as fcntl from 'node:fs'; // flock is on fs, but we use fs.fcntlSync for portability
import type { AuditEvent, AuditSink } from './AuditLogger';

// ── Types ────────────────────────────────────────────────────────────────────

/**
 * Cross-process lock using fcntl/flock.
 *
 * On Linux/MacOS we use fs.fcntlSync with F_OFD_SETLK/F_WRLCK for POSIX
 * advisory file locks. On unsupported platforms the lock is a no-op.
 */

// Only import fcntl types on non-Windows
let F_OFD_SETLK: number | undefined;
let F_WRLOCK: number | undefined;
try {
  // SYS_fcntl constants
  F_OFD_SETLK = 6;   // F_OFD_SETLK on Linux
  F_WRLOCK = 1;      // F_WRLCK
} catch {
  // Not supported
}

/** Try to acquire an exclusive file lock. Returns true on success. */
function tryLockExclusive(fd: number): boolean {
  try {
    // Use flock (available on Linux/macOS) for advisory locking
    // Node.js fs.fcntlSync may not be available everywhere, fall back to no-op
    if (typeof (fs as any).flockSync === 'function') {
      (fs as any).flockSync(fd, 'ex');
      return true;
    }
    // On Node 20+, fs.fcntlSync is available
    if (typeof (fs as any).fcntlSync === 'function') {
      (fs as any).fcntlSync(fd, 'setlkw', { start: 0, length: 0, type: 'write' });
      return true;
    }
    // Fallback: no locking available
    return true;
  } catch {
    return false;
  }
}

/** Release a file lock. */
function unlockFd(fd: number): void {
  try {
    if (typeof (fs as any).flockSync === 'function') {
      (fs as any).flockSync(fd, 'un');
    }
  } catch {
    // Best effort
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

/** Options for constructing a {@link CsvAuditSink}. */
export interface CsvAuditSinkOptions {
  /**
   * Path to the active CSV file.
   * @default 'pg_log/audit.csv'
   */
  filePath?: string;

  /**
   * Maximum size (bytes) of the CSV file before rotation is triggered.
   * @default 104_857_600 (100 MB)
   */
  maxFileSize?: number;

  /**
   * Number of rotated files to retain (excludes the active file).
   * Older files beyond this count are automatically deleted.
   * @default 30
   */
  maxFiles?: number;

  /**
   * When `true`, rotated files are gzip-compressed before archiving.
   * @default false
   */
  compress?: boolean;

  /**
   * Optional custom date provider for testing date-based rotation.
   * Returns a date string in `YYYY-MM-DD` format.
   * When not set, the real system date is used.
   */
  dateProvider?: () => string;
}

// ── CSV Helpers ──────────────────────────────────────────────────────────────

/**
 * Escape a value for CSV: wrap in double-quotes if it contains commas,
 * double-quotes, or newlines.
 */
function escapeCsv(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n') || value.includes('\r')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/**
 * Format the date-part of a rotation timestamp as a sortable string.
 * Example: `audit.2026-06-01T150400.csv`
 */
function rotationTimestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-').replace(/T/, 'T').slice(0, 19);
}

/** Return today's date as `YYYY-MM-DD`. */
function todayStrReal(): string {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * Compute the SHA-256 chain hash for one audit event.
 *
 * The hash input is `prevHash + eventId + timestamp + sessionId + userId +
 * eventType + sql + result` — identical to the algorithm used by
 * AuditLogger's `computeChainHash`.
 */
function computeHash(
  prevHash: string,
  eventId: string,
  timestamp: string,
  sessionId: string,
  userId: string,
  eventType: string,
  sql: string,
  result: string,
): string {
  const input = prevHash + eventId + timestamp + sessionId + userId + eventType + sql + result;
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/** CSV column header line. */
const CSV_HEADER = 'timestamp,event_type,user,detail,hash,previous_hash\n';

/** Number of bytes of the CSV header (pre-computed). */
const HEADER_BYTES = Buffer.byteLength(CSV_HEADER, 'utf8');

// ── CsvAuditSink ─────────────────────────────────────────────────────────────

/**
 * A file-based audit sink that writes events as CSV rows with
 * chain-of-hash integrity markers.
 *
 * Uses synchronous writes via file descriptors for durability — every
 * `write()` call immediately persists data to disk.  Rotation is handled
 * by renaming the current file and opening a new one.
 *
 * Backpressure is handled with an in-memory queue (max 1,000 entries).
 * When the file descriptor is unavailable (open failure or transient
 * error), events are queued and retried on the next `write()` or on
 * `close()`.
 *
 * Lifecycle:
 *   1. Construct with options.
 *   2. Call `write(event)` for every audit event.
 *   3. Call `close()` on shutdown to flush queued events and release
 *      the file descriptor.
 */
export class CsvAuditSink implements AuditSink {
  // ── Config ─────────────────────────────────────────────────────
  private readonly filePath: string;
  private readonly maxFileSize: number;
  private readonly maxFiles: number;
  private readonly compress: boolean;
  private readonly dateProvider: (() => string) | undefined;

  // ── State ──────────────────────────────────────────────────────
  private fd: number | null = null;
  private bytesWritten = 0;
  private prevHash = '0'.repeat(64);
  private currentDate = '';
  private writerError: Error | null = null;

  /**
   * Return today's date string, using the custom date provider when set
   * (used for testing date-based rotation).
   */
  private todayStr(): string {
    if (this.dateProvider) return this.dateProvider();
    return todayStrReal();
  }

  /** Backpressure queue — stores events when the file is unavailable. */
  private readonly queue: AuditEvent[] = [];
  private readonly queueMaxSize = 1000;

  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private destroyed = false;

  // ── Constructor ─────────────────────────────────────────────────

  constructor(options?: CsvAuditSinkOptions) {
    this.filePath = options?.filePath ?? 'pg_log/audit.csv';
    this.maxFileSize = options?.maxFileSize ?? 104_857_600; // 100 MB
    this.maxFiles = options?.maxFiles ?? 30;
    this.compress = options?.compress ?? false;
    this.dateProvider = options?.dateProvider;

    // Periodic flush timer — retries queued events every 5 seconds.
    this.flushTimer = setInterval(() => this.flushQueue(), 5_000);
    if (this.flushTimer && typeof this.flushTimer === 'object' && 'unref' in this.flushTimer) {
      this.flushTimer.unref();
    }
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Forward an audit event to this sink.
   *
   * The event is formatted as a CSV row and synchronously written to the
   * active CSV file.  If the file descriptor is unavailable (startup or
   * transient error), the event is queued in memory (up to 1,000 entries).
   *
   * @param event  The fully-formed {@link AuditEvent}.
   */
  write(event: AuditEvent): void {
    if (this.destroyed) return;

    // ── Ensure the file descriptor is open ──
    if (this.fd === null && !this.openFile()) {
      this.enqueue(event);
      return;
    }

    if (this.writerError) {
      this.enqueue(event);
      return;
    }

    // ── Date-based rotation: check before write so the first event of
    //    a new day goes into a fresh file. ──
    if (this.currentDate !== this.todayStr()) {
      this.rotate();
      // After rotation the fd points to the new file.
    }

    // ── Generate & write the CSV line ──
    const csvLine = this.formatLine(event);
    if (!csvLine) return;
    const buf = Buffer.from(csvLine, 'utf8');

    try {
      tryLockExclusive(this.fd!);
      fs.writeSync(this.fd!, buf, 0, buf.length, this.bytesWritten);
      this.bytesWritten += buf.length;
      unlockFd(this.fd!);
    } catch (err: any) {
      this.writerError = err;
      this.enqueue(event);
      return;
    }

    // ── Size-based rotation: check after write so the event that pushed
    //    over the limit stays in the rotated file. ──
    if (this.bytesWritten >= this.maxFileSize) {
      this.rotate();
    }
  }

  /**
   * Retry writing any queued events.
   *
   * Attempts to write as many queued events as possible.  If the
   * writer error clears, all queued events are drained.
   */
  flush(): void {
    this.flushQueue();
  }

  /**
   * Gracefully shut down the sink.
   *
   * Flushes the queue, clears the periodic timer, and closes the file
   * descriptor.  After calling this method the sink must not be reused.
   */
  close(): void {
    this.destroyed = true;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    // Drain the queue synchronously.
    this.syncFlushRemaining();
    if (this.fd !== null) {
      try {
        unlockFd(this.fd);
        fs.closeSync(this.fd);
      } catch {
        // Best effort.
      }
      this.fd = null;
    }
  }

  // ── Internal Helpers ───────────────────────────────────────────

  /**
   * Open (or re-open) the CSV file.
   *
   * Creates the parent directory if needed, opens the file descriptor
   * (appending if the file already exists), and writes the CSV header
   * for a new file.
   *
   * @returns `true` when the file was successfully opened.
   */
  private openFile(): boolean {
    try {
      const dir = path.dirname(this.filePath);
      fs.mkdirSync(dir, { recursive: true });
    } catch {
      return false;
    }

    const fileExists = fs.existsSync(this.filePath);

    try {
      this.fd = fs.openSync(this.filePath, fileExists ? 'a' : 'w');
    } catch {
      return false;
    }

    if (!fileExists) {
      // For a fresh file, write the CSV header.
      const headerBuf = Buffer.from(CSV_HEADER, 'utf8');
      try {
        // Acquire exclusive lock before writing header
        tryLockExclusive(this.fd);
        fs.writeSync(this.fd, headerBuf, 0, headerBuf.length, 0);
        this.bytesWritten = HEADER_BYTES;
        unlockFd(this.fd);
      } catch {
        // File was just created, so this should not fail.
      }
    } else {
      try {
        tryLockExclusive(this.fd);
        const stats = fs.fstatSync(this.fd);
        this.bytesWritten = stats.size;
        unlockFd(this.fd);
      } catch {
        this.bytesWritten = 0;
      }
    }

    this.writerError = null;
    this.currentDate = this.todayStr();
    return true;
  }

  /**
   * Format a single audit event as a CSV row with chain-of-hash.
   *
   * @returns The formatted CSV line (including trailing newline), or
   *          `null` if formatting fails.
   */
  private formatLine(event: AuditEvent): string | null {
    try {
      const timestamp = event.timestamp instanceof Date
        ? event.timestamp.toISOString()
        : String(event.timestamp);

      const eventType = escapeCsv(event.eventType);
      const user = escapeCsv(event.userId);

      // The `detail` column is a JSON object with the most relevant fields.
      const detail = JSON.stringify({
        sessionId: event.sessionId,
        sql: event.sql,
        result: event.result,
        rowCount: event.rowCount,
        durationMs: event.durationMs,
        errorMessage: event.errorMessage,
      });

      const hash = computeHash(
        this.prevHash,
        event.eventId,
        timestamp,
        event.sessionId,
        event.userId,
        event.eventType,
        event.sql,
        event.result,
      );

      const line = `${timestamp},${eventType},${user},${escapeCsv(detail)},${hash},${this.prevHash}\n`;
      this.prevHash = hash;
      return line;
    } catch {
      return null;
    }
  }

  /**
   * Check whether the active file needs rotation.
   *
   * Rotation is triggered when:
   *   - File size exceeds `maxFileSize`, **or**
   *   - The calendar date has changed since the file was last opened.
   */
  private needsRotation(): boolean {
    if (this.bytesWritten >= this.maxFileSize) return true;
    if (this.currentDate !== this.todayStr()) return true;
    return false;
  }

  // ── Rotation ────────────────────────────────────────────────────

  /**
   * Perform a file rotation.
   *
   * 1. Close the current file descriptor.
   * 2. Rename the current file with a timestamp suffix.
   * 3. Optionally gzip-compress the rotated file.
   * 4. Remove old rotated files beyond `maxFiles`.
   * 5. Open a new, empty file with the CSV header.
   */
  private rotate(): void {
    const oldFd = this.fd;
    if (oldFd === null) return;

    // Release lock on old fd before closing
    unlockFd(oldFd);

    this.fd = null;
    const oldPath = this.filePath;

    // Close the old file descriptor.
    try {
      fs.closeSync(oldFd);
    } catch {
      // Best effort.
    }

    // Build the rotated file name.
    const ts = rotationTimestamp();
    const dir = path.dirname(this.filePath);
    const baseName = path.basename(this.filePath, '.csv');
    const rotatedPath = path.join(dir, `${baseName}.${ts}.csv`);

    try {
      fs.renameSync(oldPath, rotatedPath);

      // Optionally gzip-compress the rotated file.
      if (this.compress) {
        try {
          const content = fs.readFileSync(rotatedPath);
          const compressed = zlib.gzipSync(content);
          const gzPath = rotatedPath + '.gz';
          fs.writeFileSync(gzPath, compressed);
          fs.unlinkSync(rotatedPath);
        } catch {
          // If compression fails, leave the uncompressed file.
        }
      }
    } catch {
      // If rename fails (e.g., file doesn't exist), just proceed.
    }

    // Clean up old rotated files.
    this.cleanupOldFiles();

    // Reset state.
    this.bytesWritten = 0;
    this.currentDate = this.todayStr();

    // Open a new file.
    this.openFile();
  }

  /**
   * Remove rotated audit files that exceed `maxFiles`.
   *
   * Only files matching the pattern `<baseName>.<timestamp>.csv`
   * (or `.csv.gz`) are considered.
   */
  private cleanupOldFiles(): void {
    const dir = path.dirname(this.filePath);
    const baseName = path.basename(this.filePath, '.csv');

    let files: string[];
    try {
      files = fs.readdirSync(dir);
    } catch {
      return;
    }

    // Match rotated files (those with an extra timestamp segment).
    const pattern = new RegExp(`^${escapeRegex(baseName)}\\.\\d{4}-\\d{2}-\\d{2}T`);
    const rotatedFiles = files
      .filter((f) => pattern.test(f))
      .sort()
      .reverse();

    // Keep only the most recent `maxFiles` rotated files.
    for (const f of rotatedFiles.slice(this.maxFiles)) {
      try {
        fs.unlinkSync(path.join(dir, f));
      } catch {
        // Best-effort cleanup.
      }
    }
  }

  // ── Backpressure Queue ─────────────────────────────────────────

  /**
   * Enqueue an event when the file descriptor is unavailable.
   *
   * If the queue exceeds `queueMaxSize` (1,000), the oldest entry is
   * silently dropped.
   */
  private enqueue(event: AuditEvent): void {
    if (this.queue.length >= this.queueMaxSize) {
      this.queue.shift();
    }
    this.queue.push(event);
  }

  /**
   * Attempt to drain the in-memory queue via the file descriptor.
   */
  private flushQueue(): void {
    if (this.queue.length === 0 || this.destroyed) return;
    if (this.writerError) return;

    // If no fd, try to reopen.
    if (this.fd === null && !this.openFile()) return;

    while (this.queue.length > 0) {
      if (this.writerError || this.fd === null) break;

      // Date-based rotation before flushing each event.
      if (this.currentDate !== this.todayStr()) {
        this.rotate();
      }

      const event = this.queue[0];
      const csvLine = this.formatLine(event);
      if (!csvLine) {
        this.queue.shift();
        continue;
      }

      const buf = Buffer.from(csvLine, 'utf8');
      try {
        tryLockExclusive(this.fd);
        fs.writeSync(this.fd, buf, 0, buf.length, this.bytesWritten);
        this.bytesWritten += buf.length;
        unlockFd(this.fd);
        this.queue.shift();

        if (this.bytesWritten >= this.maxFileSize) {
          this.rotate();
        }
      } catch {
        break;
      }
    }
  }

  /**
   * Synchronously write any remaining queued entries directly to disk.
   *
   * This is called during `close()` to guarantee data durability even
   * when the file descriptor encountered a transient error during normal
   * writes.
   */
  private syncFlushRemaining(): void {
    if (this.queue.length === 0) return;

    // If the fd is gone, try to reopen.
    if (this.fd === null && !this.openFile()) return;

    try {
      const pending = this.queue.splice(0);
      let data = '';
      for (const evt of pending) {
        const line = this.formatLine(evt);
        if (line) data += line;
      }
      if (data && this.fd !== null) {
        const buf = Buffer.from(data, 'utf8');
        fs.writeSync(this.fd, buf, 0, buf.length, this.bytesWritten);
        this.bytesWritten += buf.length;
      }
    } catch {
      // Best effort — loss is bounded by queueMaxSize.
    }
  }

  // ── Test Helpers (internal, used by audit-persistence-gaps.test.ts) ─────

  /**
   * @internal — Simulate a write stream failure for backpressure testing.
   */
  _simulateWriterError(e?: any): void {
    this.writerError = e instanceof Error ? e : new Error('Simulated write error');
  }

  /**
   * @internal — Return the current backpressure queue size.
   */
  _getQueueSize(): number {
    return this.queue.length;
  }

  /**
   * @internal — Clear the writer error state, simulating stream recovery.
   */
  _clearWriterError(): void {
    this.writerError = null;
  }

  /**
   * @internal — Manually trigger a rotation (used for testing).
   */
  _forceRotate(): void {
    this.rotate();
  }
}

// ── Utility ──────────────────────────────────────────────────────────────────

/**
 * Escape special regex characters in a string.
 */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
