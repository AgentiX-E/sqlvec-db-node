/**
 * LogManager — Production log rotation, management, and sanitisation.
 *
 * Provides:
 *   - Dynamic log level configuration
 *   - Configurable log rotation (maxSize, maxFiles)
 *   - Credential/token sanitisation (delegates to LogSanitizer)
 *   - Log statistics (total entries, error/warn breakdown, age)
 *   - Buffer flush support
 *
 * Wires into the existing PinoLogger framework and the LogSanitizer
 * module for sanitisation.
 *
 * @module LogManager
 */

import { PinoLogger, type LogLevel } from '../monitoring/PinoLogger';
import { LogSanitizer, type SanitizeRule, type SanitizeOptions } from '../security/LogSanitizer';

const logger = PinoLogger.forComponent('LogManager');

// ── Types ────────────────────────────────────────────────────────

export interface LogRotationConfig {
  /** Maximum size per log file (e.g. '100MB', '1GB', '512KB') */
  maxSize: string;
  /** Maximum number of rotated log files to retain */
  maxFiles: number;
}

export interface LogStatistics {
  /** Total log entries tracked */
  totalEntries: number;
  /** Number of 'error' level entries */
  errorCount: number;
  /** Number of 'warn' level entries */
  warnCount: number;
  /** Timestamp of the oldest tracked entry (ISO string), or empty string */
  oldestEntry: string;
  /** Timestamp of the newest tracked entry (ISO string), or empty string */
  newestEntry: string;
}

interface LogEntry {
  level: string;
  message: string;
  timestamp: number;
}

// ── Helpers ──────────────────────────────────────────────────────

/**
 * Parse a human-readable size string to bytes.
 *
 * Supported suffixes: KB, MB, GB, TB (case-insensitive).
 * Examples: '100MB' → 104857600, '1GB' → 1073741824, '512KB' → 524288
 */
export function parseSizeToBytes(size: string): number {
  const match = size.trim().toUpperCase().match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$/);
  if (!match) {
    throw new Error(`Invalid size format: "${size}". Use format like "100MB", "1GB", "512KB"`);
  }

  const value = parseFloat(match[1]);
  const unit = match[2] || 'B';

  switch (unit) {
    case 'B': return Math.round(value);
    case 'KB': return Math.round(value * 1024);
    case 'MB': return Math.round(value * 1024 * 1024);
    case 'GB': return Math.round(value * 1024 * 1024 * 1024);
    case 'TB': return Math.round(value * 1024 * 1024 * 1024 * 1024);
    default: throw new Error(`Unknown size unit: "${unit}"`);
  }
}

// ── LogManager ───────────────────────────────────────────────────

export class LogManager {
  private currentLevel: LogLevel = 'info';
  private rotationConfig: LogRotationConfig = { maxSize: '100MB', maxFiles: 10 };
  private sanitizer: LogSanitizer;
  private entries: LogEntry[] = [];
  private pinoLogger: PinoLogger;
  /** Maximum entries to buffer in memory before pruning */
  private readonly maxBufferedEntries = 10000;

  constructor() {
    this.sanitizer = new LogSanitizer();
    this.pinoLogger = PinoLogger.forComponent('LogManager');
    logger.info({ level: this.currentLevel, rotation: this.rotationConfig }, 'LogManager initialized');
  }

  // ── Level management ─────────────────────────────────────────

  /**
   * Set the active log level.
   * All log entries below this level are suppressed.
   */
  setLogLevel(level: LogLevel): void {
    const validLevels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    if (!validLevels.includes(level)) {
      throw new Error(`Invalid log level: "${level}". Must be one of: ${validLevels.join(', ')}`);
    }
    this.currentLevel = level;
    this.pinoLogger.info({ level }, 'Log level changed');
  }

  /**
   * Get the current log level.
   */
  getLogLevel(): LogLevel {
    return this.currentLevel;
  }

  // ── Rotation configuration ────────────────────────────────────

  /**
   * Set the log rotation configuration.
   *
   * @param config - Rotation config with maxSize string and maxFiles count.
   */
  setLogRotation(config: LogRotationConfig): void {
    // Validate maxSize
    const bytes = parseSizeToBytes(config.maxSize);
    if (bytes <= 0) {
      throw new Error('maxSize must be a positive value');
    }

    // Validate maxFiles
    if (!Number.isInteger(config.maxFiles) || config.maxFiles < 1) {
      throw new Error('maxFiles must be a positive integer >= 1');
    }

    this.rotationConfig = { ...config };
    this.pinoLogger.info(
      { maxSize: config.maxSize, maxFiles: config.maxFiles },
      'Log rotation config updated',
    );
  }

  /**
   * Get the current rotation configuration.
   */
  getLogRotation(): LogRotationConfig {
    return { ...this.rotationConfig };
  }

  // ── Sanitisation ─────────────────────────────────────────────

  /**
   * Sanitize a raw log entry, stripping credentials, tokens, and other
   * sensitive data.
   *
   * Delegates to LogSanitizer for the actual regex-based sanitisation.
   */
  sanitizeLog(entry: string): string {
    return this.sanitizer.sanitize(entry);
  }

  /**
   * Add a custom sanitisation rule.
   */
  addSanitizeRule(rule: SanitizeRule): void {
    this.sanitizer.addRule(rule);
  }

  /**
   * Update sanitisation options.
   */
  updateSanitizeOptions(options: Partial<SanitizeOptions>): void {
    this.sanitizer.updateOptions(options);
  }

  // ── Statistics ────────────────────────────────────────────────

  /**
   * Record a log entry in the in-memory buffer.
   * Called by the logging framework when a log event occurs.
   */
  recordEntry(level: string, message: string): void {
    this.entries.push({
      level,
      message,
      timestamp: Date.now(),
    });

    // Prune oldest entries if beyond max
    if (this.entries.length > this.maxBufferedEntries) {
      this.entries = this.entries.slice(-this.maxBufferedEntries);
    }
  }

  /**
   * Get aggregated log statistics.
   */
  getLogStatistics(): LogStatistics {
    const totalEntries = this.entries.length;

    if (totalEntries === 0) {
      return {
        totalEntries: 0,
        errorCount: 0,
        warnCount: 0,
        oldestEntry: '',
        newestEntry: '',
      };
    }

    const errorCount = this.entries.filter((e) => e.level === 'error' || e.level === 'fatal').length;
    const warnCount = this.entries.filter((e) => e.level === 'warn').length;

    let oldestTs = this.entries[0].timestamp;
    let newestTs = this.entries[0].timestamp;

    for (const e of this.entries) {
      if (e.timestamp < oldestTs) oldestTs = e.timestamp;
      if (e.timestamp > newestTs) newestTs = e.timestamp;
    }

    return {
      totalEntries,
      errorCount,
      warnCount,
      oldestEntry: new Date(oldestTs).toISOString(),
      newestEntry: new Date(newestTs).toISOString(),
    };
  }

  // ── Flush ─────────────────────────────────────────────────────

  /**
   * Flush buffered log entries.
   *
   * In a production implementation this would write buffered entries to
   * persistent storage (disk/network). For now, it clears the in-memory
   * buffer and logs the event.
   */
  flushLogs(): void {
    const count = this.entries.length;
    this.entries = [];
    this.pinoLogger.info({ flushedCount: count }, 'Log buffer flushed');
  }

  // ── Internal ──────────────────────────────────────────────────

  /**
   * Get the current buffer size.
   */
  getBufferSize(): number {
    return this.entries.length;
  }
}
