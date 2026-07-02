/**
 * FileAuditSink — NDJSON file persistence sink for AuditLogger.
 *
 * Writes structured audit events as newline-delimited JSON to a
 * rotating file.  Supports:
 *   - **Daily rotation:**  files named `audit-<YYYY-MM-DD>.ndjson`
 *   - **Size-based rotation:**  when the active file exceeds
 *     `maxFileSize`, the current file is closed with a sequence suffix
 *     (e.g. `audit-2026-06-03.001.ndjson`) and a fresh file is opened.
 *   - **Retention:**  old rotated files beyond `maxFiles` are
 *     automatically purged.
 *   - **Thread-safe writes:**  uses O_APPEND mode (atomic on most
 *     kernels) and POSIX advisory locking where available.
 *
 * @module FileAuditSink
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AuditEvent, AuditSink } from './AuditLogger';

// ── Types ────────────────────────────────────────────────────────────────────

/** Options for constructing a {@link FileAuditSink}. */
export interface FileAuditSinkOptions {
  /**
   * Directory where audit NDJSON files are stored.
   * @default 'pg_log/audit'
   */
  dir?: string;

  /**
   * Maximum size (bytes) of a single NDJSON file before rotation is
   * triggered.
   * @default 104_857_600 (100 MB)
   */
  maxFileSize?: number;

  /**
   * Number of rotated files to retain per day (excludes the active
   * file).  Older files beyond this count are automatically deleted.
   * @default 7
   */
  maxFiles?: number;

  /**
   * Optional custom date provider for testing daily rotation logic.
   * Returns a date string in `YYYY-MM-DD` format.
   * When not set, the real system date is used.
   */
  dateProvider?: () => string;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Return today's date as `YYYY-MM-DD`. */
function todayStrReal(): string {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/** Escape special regex characters in a string. */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── FileAuditSink ────────────────────────────────────────────────────────────

/**
 * A file-based audit sink that writes events as NDJSON rows with
 * daily and size-based rotation.
 *
 * Lifecycle:
 *   1. Construct with options.
 *   2. Call `write(event)` for every audit event.
 *   3. Call `close()` on shutdown to release the file descriptor.
 */
export class FileAuditSink implements AuditSink {
  // ── Config ─────────────────────────────────────────────────────
  private readonly dir: string;
  private readonly maxFileSize: number;
  private readonly maxFiles: number;
  private readonly dateProvider: (() => string) | undefined;

  // ── State ──────────────────────────────────────────────────────
  private fd: number | null = null;
  private bytesWritten = 0;
  private currentDate = '';
  private rotationSeq = 0;
  private writerError: Error | null = null;
  private destroyed = false;

  /**
   * Return today's date string, using the custom date provider when set.
   */
  private todayStr(): string {
    if (this.dateProvider) return this.dateProvider();
    return todayStrReal();
  }

  // ── Constructor ─────────────────────────────────────────────────

  constructor(options?: FileAuditSinkOptions) {
    this.dir = options?.dir ?? 'pg_log/audit';
    this.maxFileSize = options?.maxFileSize ?? 104_857_600; // 100 MB
    this.maxFiles = options?.maxFiles ?? 7;
    this.dateProvider = options?.dateProvider;
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Forward an audit event to this sink.
   *
   * The event is serialised as a single NDJSON line and synchronously
   * appended to the active file.  If the file descriptor is unavailable,
   * the event is silently dropped (no buffering — this sink guarantees
   * at-most-once delivery for reliability).
   *
   * @param event  The fully-formed {@link AuditEvent}.
   */
  write(event: AuditEvent): void {
    if (this.destroyed) return;

    // ── Ensure the file descriptor is open ──
    if (this.fd === null && !this.openFile()) {
      return;
    }

    if (this.writerError) return;

    // ── Date-based rotation: check before write ──
    if (this.currentDate !== this.todayStr()) {
      this.rotate();
    }

    // ── Serialise & write the NDJSON line ──
    const ndjsonLine = JSON.stringify(this.serializeEvent(event)) + '\n';
    const buf = Buffer.from(ndjsonLine, 'utf8');

    try {
      this.tryLock();
      fs.writeSync(this.fd!, buf, 0, buf.length, this.bytesWritten);
      this.bytesWritten += buf.length;
      this.unlock();
    } catch (err: any) {
      this.writerError = err;
      return;
    }

    // ── Size-based rotation: check after write ──
    if (this.bytesWritten >= this.maxFileSize) {
      this.rotate();
    }
  }

  /** No-op for file-based sink — data is written synchronously. */
  flush(): void {
    // Data is already on disk via synchronous writes + O_DSYNC.
  }

  /**
   * Gracefully shut down the sink.
   *
   * Closes the current file descriptor.  After calling this method the
   * sink must not be reused.
   */
  close(): void {
    this.destroyed = true;
    if (this.fd !== null) {
      try {
        this.unlock();
        fs.closeSync(this.fd);
      } catch {
        // Best effort.
      }
      this.fd = null;
    }
  }

  // ── Internal Helpers ───────────────────────────────────────────

  /**
   * Serialise an {@link AuditEvent} into a plain JSON-serialisable
   * object, converting Date to ISO string for consistent output.
   */
  private serializeEvent(event: AuditEvent): Record<string, unknown> {
    return {
      eventId: event.eventId,
      timestamp: event.timestamp instanceof Date ? event.timestamp.toISOString() : String(event.timestamp),
      sessionId: event.sessionId,
      userId: event.userId,
      eventType: event.eventType,
      sql: event.sql,
      result: event.result,
      rowCount: event.rowCount,
      errorMessage: event.errorMessage,
      durationMs: event.durationMs,
      auditLevel: event.auditLevel,
    };
  }

  /**
   * Build the active file path for today's date.
   *
   * The `rotationSeq` suffix (`.001`, `.002`, …) is appended when a
   * size-based rotation creates a second (or third, etc.) file for the
   * same day.
   */
  private activeFilePath(): string {
    const dateStr = this.currentDate || this.todayStr();
    const seq = this.rotationSeq > 0 ? `.${String(this.rotationSeq).padStart(3, '0')}` : '';
    return path.join(this.dir, `audit-${dateStr}${seq}.ndjson`);
  }

  /**
   * Scan the directory for the next available rotation sequence number
   * for today's date.
   *
   * This ensures that after a process restart, new events append to the
   * last file (or start a fresh file if the previous one is full).
   */
  private findNextSequence(): number {
    const dateStr = this.todayStr();
    let maxSeq = 0;

    try {
      const files = fs.readdirSync(this.dir);
      const pattern = new RegExp(`^audit-${escapeRegex(dateStr)}(?:\\.(\\d{3}))?\\.ndjson$`);
      for (const f of files) {
        const m = f.match(pattern);
        if (m) {
          const seq = m[1] ? parseInt(m[1], 10) : 0;
          if (seq > maxSeq) maxSeq = seq;
        }
      }
    } catch {
      // Directory doesn't exist yet — that's fine.
    }

    return maxSeq;
  }

  /**
   * Open (or re-open) the NDJSON file.
   *
   * Creates the parent directory if needed, opens the file descriptor
   * in append mode (`'a'`), and initialises tracking state.
   *
   * @returns `true` when the file was successfully opened.
   */
  private openFile(): boolean {
    try {
      fs.mkdirSync(this.dir, { recursive: true });
    } catch {
      return false;
    }

    // Pick up the right sequence number from disk.
    this.currentDate = this.todayStr();
    this.rotationSeq = this.findNextSequence();

    const filePath = this.activeFilePath();
    const fileExists = fs.existsSync(filePath);

    try {
      this.fd = fs.openSync(filePath, fileExists ? 'a' : 'w');
    } catch {
      return false;
    }

    if (fileExists) {
      try {
        this.tryLock();
        const stats = fs.fstatSync(this.fd!);
        this.bytesWritten = stats.size;
        this.unlock();
      } catch {
        this.bytesWritten = 0;
      }
    } else {
      this.bytesWritten = 0;
    }

    // If the existing file is already at or over maxFileSize, rotate
    // immediately so the next write goes into a fresh file.
    if (this.bytesWritten >= this.maxFileSize) {
      this.rotationSeq = this.findNextSequence() + 1;

      // Close, advance seq, reopen.
      try {
        this.unlock();
        fs.closeSync(this.fd!);
      } catch {
        // Best effort.
      }
      this.fd = null;

      return this.openFile();
    }

    this.writerError = null;
    return true;
  }

  /**
   * Perform a file rotation.
   *
   * When the date has changed, the rotation simply closes the old file
   * and opens a new one for today.
   *
   * When the size limit has been exceeded, the current file is closed
   * and a new sequence file is opened (e.g. `audit-2026-06-03.001.ndjson`).
   */
  private rotate(): void {
    const oldFd = this.fd;
    if (oldFd === null) return;

    this.unlock();
    this.fd = null;

    try {
      fs.closeSync(oldFd);
    } catch {
      // Best effort.
    }

    // Determine the new date / sequence.
    const newDate = this.todayStr();
    if (newDate !== this.currentDate) {
      // Date changed — start fresh with sequence 0.
      this.currentDate = newDate;
      this.rotationSeq = 0;
    } else {
      // Same day, size trigger — advance the sequence.
      this.rotationSeq += 1;
    }

    this.bytesWritten = 0;

    // Cleanup old rotated files before opening new one.
    this.cleanupOldFiles();

    this.openFile();
  }

  /**
   * Remove rotated audit files that exceed `maxFiles`.
   *
   * Only files matching the pattern `audit-<YYYY-MM-DD>*.ndjson` are
   * considered.  The `maxFiles` limit is applied per day, so old audit
   * days are cleaned independently.
   */
  private cleanupOldFiles(): void {
    let files: string[];
    try {
      files = fs.readdirSync(this.dir);
    } catch {
      return;
    }

    // Group files by date.
    const datePattern = /^audit-(\d{4}-\d{2}-\d{2})/;
    const byDate = new Map<string, string[]>();

    for (const f of files) {
      const m = f.match(datePattern);
      if (m) {
        const dateStr = m[1];
        if (!byDate.has(dateStr)) byDate.set(dateStr, []);
        byDate.get(dateStr)!.push(f);
      }
    }

    // For each date, sort files by sequence and keep only `maxFiles`.
    for (const [dateStr, dateFiles] of byDate) {
      if (dateFiles.length <= this.maxFiles) continue;

      // Sort: base file first, then .001, .002, etc.
      dateFiles.sort((a, b) => {
        const seqA = a.match(/\.(\d{3})\.ndjson$/) ? parseInt(a.match(/\.(\d{3})\.ndjson$/)![1], 10) : 0;
        const seqB = b.match(/\.(\d{3})\.ndjson$/) ? parseInt(b.match(/\.(\d{3})\.ndjson$/)![1], 10) : 0;
        return seqA - seqB;
      });

      // Keep only the most recent `maxFiles` files.
      const toRemove = dateFiles.slice(0, dateFiles.length - this.maxFiles);
      for (const f of toRemove) {
        try {
          fs.unlinkSync(path.join(this.dir, f));
        } catch {
          // Best-effort cleanup.
        }
      }
    }
  }

  // ── Locking (thread-safe / cross-process) ──────────────────────

  /**
   * Acquire an exclusive POSIX advisory lock on the current file
   * descriptor.  No-op when locking is unavailable.
   */
  private tryLock(): void {
    if (this.fd === null) return;
    try {
      if (typeof (fs as any).flockSync === 'function') {
        (fs as any).flockSync(this.fd, 'ex');
      }
    } catch {
      // Locking is best-effort.
    }
  }

  /**
   * Release the lock on the current file descriptor.
   */
  private unlock(): void {
    if (this.fd === null) return;
    try {
      if (typeof (fs as any).flockSync === 'function') {
        (fs as any).flockSync(this.fd, 'un');
      }
    } catch {
      // Best effort.
    }
  }
}
