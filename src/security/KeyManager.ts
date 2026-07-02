/**
 * KeyManager — Abstract key management with key version rotation.
 *
 * Enc-02 gap resolution:
 *   - Abstract KeyManager interface for KMS integration
 *   - Argon2id password-based key derivation (replacing PBKDF2)
 *   - Key version rotation support
 *   - Backup Encryption Manager and PITR Crypto integration
 *
 * Supported key derivation:
 *   1. Argon2id (via hash-wasm) — modern, memory-hard KDF
 *   2. PBKDF2 (Node.js crypto) — fallback when hash-wasm unavailable
 *
 * @module security/KeyManager
 */

import * as crypto from 'node:crypto';

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('KeyManager');

// ── Types ────────────────────────────────────────────────────────

export interface KeyDescriptor {
  /** Key version identifier (integer, monotonic). */
  version: number;
  /** Raw key material (32 bytes for AES-256). */
  key: Buffer;
  /** Creation timestamp (epoch ms). */
  createdAt: number;
  /** Whether this is the active (latest) key. */
  isActive: boolean;
}

export interface KeyManagerConfig {
  /** Key derivation method: 'argon2id' or 'pbkdf2' */
  method: 'argon2id' | 'pbkdf2';
  /** Salt length in bytes (default: 16). */
  saltLength: number;
  /** Derived key length in bytes (default: 32 for AES-256). */
  keyLength: number;
  /** PBKDF2 iterations (default: 100000). */
  pbkdf2Iterations: number;
  /** Argon2id time cost (default: 3). */
  argon2TimeCost: number;
  /** Argon2id memory cost in KiB (default: 65536 = 64 MB). */
  argon2MemoryCost: number;
  /** Argon2id parallelism (default: 4). */
  argon2Parallelism: number;
  /** Default TTL for key versions in ms (default: 90 days). */
  keyVersionTtlMs: number;
}

const DEFAULT_CONFIG: KeyManagerConfig = {
  method: 'argon2id',
  saltLength: 16,
  keyLength: 32,
  pbkdf2Iterations: 100_000,
  argon2TimeCost: 3,
  argon2MemoryCost: 65536,
  argon2Parallelism: 4,
  keyVersionTtlMs: 90 * 24 * 60 * 60 * 1000, // 90 days
};

// ══════════════════════════════════════════════════════════════════
//  Auto-rotation types
// ══════════════════════════════════════════════════════════════════

export interface RotationSchedule {
  enabled: boolean;
  intervalDays: number;
  lastRotation: number | null;
  nextRotation: number | null;
}

export type RotationCallback = (newKey: KeyDescriptor) => void;

// ══════════════════════════════════════════════════════════════════
//  KeyManager
// ══════════════════════════════════════════════════════════════════

export class KeyManager {
  private config: KeyManagerConfig;
  private keyVersions: Map<number, KeyDescriptor> = new Map();
  private activeVersion: number = 0;
  private hashWasmLoaded = false;
  private logger: PinoLogger;

  // ── Auto-rotation state ────────────────────────────────────────
  private autoRotationEnabled: boolean = false;
  private autoRotationIntervalDays: number = 90;
  private autoRotationTimer: ReturnType<typeof setInterval> | null = null;
  private lastRotation: number | null = null;
  private nextRotation: number | null = null;
  private rotationCallbacks: RotationCallback[] = [];

  constructor(config?: Partial<KeyManagerConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = PinoLogger.forComponent('KeyManager');

    // Try to preload hash-wasm for Argon2id
    if (this.config.method === 'argon2id') {
      this.tryLoadHashWasm();
    }
  }

  /**
   * Derive an encryption key from a password.
   * Returns { key, salt } where salt is needed for repeatability.
   */
  async deriveKeyFromPassword(password: string, salt?: Buffer): Promise<{ key: Buffer; salt: Buffer }> {
    const keySalt = salt || crypto.randomBytes(this.config.saltLength);

    if (this.config.method === 'argon2id' && this.hashWasmLoaded) {
      return this.argon2idDeriveKey(password, keySalt);
    }

    return this.pbkdf2DeriveKey(password, keySalt);
  }

  /**
   * Derive key using Argon2id (hash-wasm).
   */
  private async argon2idDeriveKey(password: string, salt: Buffer): Promise<{ key: Buffer; salt: Buffer }> {
    try {
      const { argon2id } = require('hash-wasm');
      const result = await argon2id({
        password,
        salt: salt.toString('base64'),
        parallelism: this.config.argon2Parallelism,
        iterations: this.config.argon2TimeCost,
        memorySize: this.config.argon2MemoryCost,
        hashLength: this.config.keyLength,
        outputType: 'binary',
      });

      return {
        key: Buffer.from(result),
        salt,
      };
    } catch (err) {
      this.logger.warn('[KeyManager] Argon2id failed, falling back to PBKDF2:', (err as Error).message);
      return this.pbkdf2DeriveKey(password, salt);
    }
  }

  /**
   * Derive key using PBKDF2 (Node.js crypto — fallback).
   */
  private pbkdf2DeriveKey(password: string, salt: Buffer): Promise<{ key: Buffer; salt: Buffer }> {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, this.config.pbkdf2Iterations, this.config.keyLength, 'sha512', (err, key) => {
        if (err) reject(err);
        else resolve({ key, salt });
      });
    });
  }

  /**
   * Get the current active key descriptor.
   */
  getActiveKey(): KeyDescriptor | null {
    const key = this.keyVersions.get(this.activeVersion);
    return key || null;
  }

  /**
   * List all key versions, ordered most recent first.
   * Alias for getAllKeyVersions().
   */
  listKeyVersions(): KeyDescriptor[] {
    return this.getAllKeyVersions();
  }

  /**
   * Get a key descriptor by version number.
   * Alias for getKeyVersion().
   *
   * @param version - Key version number
   * @returns KeyDescriptor or null if not found
   */
  getKeyByVersion(version: number): KeyDescriptor | null {
    return this.getKeyVersion(version);
  }

  // ── Auto-rotation ──────────────────────────────────────────────

  /**
   * Start automatic key rotation at the specified interval.
   *
   * When the timer fires, rotateKey() is called and all registered
   * rotation callbacks are notified with the new key descriptor.
   *
   * If a PgCronScheduler instance is provided, the rotation job is
   * scheduled via cron for persistence across restarts.
   *
   * @param intervalDays - How often to rotate keys (in days, e.g. 90)
   * @param cronScheduler - Optional PgCronScheduler for persistent scheduling
   */
  startAutoRotation(intervalDays: number, cronScheduler?: any): void {
    if (intervalDays <= 0) {
      throw new Error('intervalDays must be positive');
    }

    this.stopAutoRotation(); // Stop any existing rotation
    this.autoRotationEnabled = true;
    this.autoRotationIntervalDays = intervalDays;

    const intervalMs = intervalDays * 24 * 60 * 60 * 1000;
    this.nextRotation = Date.now() + intervalMs;

    if (cronScheduler && typeof cronScheduler.schedule === 'function') {
      // Use cron scheduler for persistence
      const cronExpression = `0 0 */${intervalDays} * *`; // Every N days at midnight
      const jobName = `key-rotation-auto-${Date.now()}`;

      try {
        cronScheduler.schedule(
          jobName,
          cronExpression,
          `ROTATE KEY every ${intervalDays} days`,
          async () => {
            await this.performScheduledRotation();
          },
        );
        this.logger.info(
          { intervalDays, cronExpression, jobName },
          'Auto key rotation scheduled via cron',
        );
      } catch (err: any) {
        this.logger.warn(
          { err: err.message },
          'Failed to schedule via cron — falling back to timer',
        );
        this.startTimerRotation(intervalMs);
      }
    } else {
      // Fallback: use setInterval
      this.startTimerRotation(intervalMs);
    }
  }

  /**
   * Stop automatic key rotation.
   */
  stopAutoRotation(): void {
    this.autoRotationEnabled = false;
    if (this.autoRotationTimer) {
      clearInterval(this.autoRotationTimer);
      this.autoRotationTimer = null;
    }
    this.nextRotation = null;
    this.logger.info('Auto key rotation stopped');
  }

  /**
   * Get the current rotation schedule status.
   */
  getRotationSchedule(): RotationSchedule {
    return {
      enabled: this.autoRotationEnabled,
      intervalDays: this.autoRotationIntervalDays,
      lastRotation: this.lastRotation,
      nextRotation: this.nextRotation,
    };
  }

  /**
   * Register a callback that fires when a rotation occurs.
   *
   * @param callback - Function receiving the new KeyDescriptor
   */
  onRotation(callback: RotationCallback): void {
    this.rotationCallbacks.push(callback);
  }

  // ── Private auto-rotation helpers ───────────────────────────────

  /**
   * Start rotation via setInterval.
   */
  private startTimerRotation(intervalMs: number): void {
    this.autoRotationTimer = setInterval(() => {
      this.performScheduledRotation().catch((err: any) => {
        this.logger.error({ err: err.message }, 'Scheduled key rotation failed');
      });
    }, intervalMs);

    // Don't prevent process exit
    if (this.autoRotationTimer && typeof this.autoRotationTimer === 'object' && 'unref' in this.autoRotationTimer) {
      (this.autoRotationTimer as any).unref();
    }

    this.logger.info(
      { intervalDays: this.autoRotationIntervalDays, intervalMs },
      'Auto key rotation started via timer',
    );
  }

  /**
   * Perform the scheduled key rotation and notify callbacks.
   */
  private async performScheduledRotation(): Promise<void> {
    if (!this.autoRotationEnabled) return;

    this.logger.info('Performing scheduled key rotation');
    const newKey = this.rotateKey();
    this.lastRotation = Date.now();
    this.nextRotation = this.lastRotation + this.autoRotationIntervalDays * 24 * 60 * 60 * 1000;

    // Notify all registered callbacks
    for (const callback of this.rotationCallbacks) {
      try {
        callback(newKey);
      } catch (err: any) {
        this.logger.warn(
          { err: err.message },
          'Rotation callback threw an error',
        );
      }
    }

    this.logger.info(
      { newVersion: newKey.version, lastRotation: this.lastRotation, nextRotation: this.nextRotation },
      'Scheduled key rotation completed',
    );
  }

  /**
   * Rotate to a new key version.
   *
   * @param newKey - Optional new key material. If omitted, generates a random key.
   * @returns The new key descriptor.
   */
  rotateKey(newKey?: Buffer): KeyDescriptor {
    const nextVersion = this.activeVersion + 1;
    const keyMaterial = newKey || crypto.randomBytes(this.config.keyLength);

    const descriptor: KeyDescriptor = {
      version: nextVersion,
      key: keyMaterial,
      createdAt: Date.now(),
      isActive: true,
    };

    // Deactivate old active key
    const oldKey = this.keyVersions.get(this.activeVersion);
    if (oldKey) {
      oldKey.isActive = false;
    }

    this.keyVersions.set(nextVersion, descriptor);
    this.activeVersion = nextVersion;

    this.logger.info({ keyVersion: nextVersion }, 'Key rotated');
    return descriptor;
  }

  /**
   * Get a specific key version.
   */
  getKeyVersion(version: number): KeyDescriptor | null {
    return this.keyVersions.get(version) || null;
  }

  /**
   * Get all key versions.
   */
  getAllKeyVersions(): KeyDescriptor[] {
    return Array.from(this.keyVersions.values()).sort((a, b) => b.version - a.version);
  }

  /**
   * Get the current active version number.
   */
  getActiveVersion(): number {
    return this.activeVersion;
  }

  /**
   * Prune expired key versions (older than TTL).
   * Never prunes the active key.
   */
  pruneExpiredKeys(): number {
    const cutoff = Date.now() - this.config.keyVersionTtlMs;
    let pruned = 0;

    for (const [version, descriptor] of this.keyVersions) {
      if (version === this.activeVersion) continue;
      if (descriptor.createdAt < cutoff) {
        this.keyVersions.delete(version);
        pruned++;
      }
    }

    if (pruned > 0) {
      this.logger.info({ pruned, activeVersion: this.activeVersion }, 'Pruned expired key versions');
    }

    return pruned;
  }

  /**
   * Update configuration (currently only detects method changes).
   */
  updateConfig(config: Partial<KeyManagerConfig>): void {
    const methodChanged = config.method && config.method !== this.config.method;
    Object.assign(this.config, config);

    if (methodChanged && this.config.method === 'argon2id') {
      this.tryLoadHashWasm();
    }

    this.logger.info({ method: this.config.method }, 'KeyManager config updated');
  }

  /**
   * Get current configuration.
   */
  getConfig(): Readonly<KeyManagerConfig> {
    return { ...this.config };
  }

  /**
   * Clean up resources.
   */
  destroy(): void {
    this.stopAutoRotation();
    this.rotationCallbacks = [];
    this.keyVersions.clear();
    this.logger.info('KeyManager destroyed');
  }

  // ── Private ────────────────────────────────────────────────────

  private async tryLoadHashWasm(): Promise<void> {
    try {
      require.resolve('hash-wasm');
      this.hashWasmLoaded = true;
      this.logger.info('hash-wasm loaded for Argon2id key derivation');
    } catch {
      this.hashWasmLoaded = false;
      this.logger.warn('hash-wasm not available, falling back to PBKDF2');
    }
  }
}
