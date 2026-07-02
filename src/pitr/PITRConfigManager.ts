/**
 * PITRConfigManager — Runtime PITR configuration via __pitr_config table.
 *
 * Manages a dedicated SQLite database (pitr_config.db) with a key-value
 * config table. Supports encrypted credential storage and runtime change
 * detection via config version polling.
 *
 * Configuration flow:
 *   1. PITRManager reads config from this manager
 *   2. Admin UPDATEs __pitr_config (via SQL interface)
 *   3. Manager detects version change, emits event
 *   4. PITRManager reconfigure/start/stop accordingly
 *
 * Table schema:
 *   __pitr_config (
 *     key   TEXT PRIMARY KEY,
 *     value TEXT NOT NULL,
 *     enc   INTEGER DEFAULT 0   -- 1 = value is encrypted
 *   )
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';
import { pitrEncrypt, pitrDecrypt } from './PITRCrypto';
import type { RemoteStorageBackend, PITRRemoteStorageConfig } from './PITRRemoteStorage';

const logger = PinoLogger.forComponent('PITRConfigManager');

const CONFIG_TABLE = '__pitr_config';

// ── Event types ───────────────────────────────────────────────────────────────

export interface PITRConfigEvent {
  type: 'config_changed' | 'credential_updated' | 'enabled_toggled';
  enabled: boolean;
  storageConfig: PITRRemoteStorageConfig | null;
}

export type ConfigChangeHandler = (event: PITRConfigEvent) => void;

// ── Config Manager ────────────────────────────────────────────────────────────

export class PITRConfigManager {
  private db: Database.Database;
  private dbPath: string;
  private version = 0;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private listeners: ConfigChangeHandler[] = [];
  private closed = false;
  private readonly POLL_INTERVAL_MS = 5_000;

  constructor(configDir?: string) {
    configDir ??= process.env.SQLVEC_PITR_CONFIG_DIR || '.';
    this.dbPath = path.resolve(configDir, 'pitr_config.db');

    // Ensure directory exists
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');

    // Create config table if not exists
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ${CONFIG_TABLE} (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        enc   INTEGER DEFAULT 0 CHECK(enc IN (0,1))
      )
    `);
  }

  // ── Public API ─────────────────────────────────────────────────────────

  /**
   * Get a config value by key.
   * Returns the plaintext value, or undefined if key doesn't exist.
   * Auto-decrypts if stored encrypted.
   */
  get(key: string): string | undefined {
    const row = this.db.prepare(
      `SELECT value, enc FROM ${CONFIG_TABLE} WHERE key = ?`,
    ).get(key) as { value: string; enc: number } | undefined;

    if (!row) return undefined;
    if (row.enc) return pitrDecrypt(row.value) ?? undefined;
    return row.value;
  }

  /**
   * Set a config value (plaintext, stored as-is).
   */
  set(key: string, value: string): void {
    this.db.prepare(
      `INSERT OR REPLACE INTO ${CONFIG_TABLE} (key, value, enc) VALUES (?, ?, 0)`,
    ).run(key, value);
    this.version++;
  }

  /**
   * Set a credential value (plaintext in, encrypted on disk).
   */
  setEncrypted(key: string, plaintext: string): void {
    const encrypted = pitrEncrypt(plaintext);
    this.db.prepare(
      `INSERT OR REPLACE INTO ${CONFIG_TABLE} (key, value, enc) VALUES (?, ?, 1)`,
    ).run(key, encrypted);
    this.version++;
  }

  /**
   * Delete a config key.
   */
  delete(key: string): void {
    this.db.prepare(`DELETE FROM ${CONFIG_TABLE} WHERE key = ?`).run(key);
    this.version++;
  }

  /**
   * Get all config keys.
   */
  keys(): string[] {
    const rows = this.db.prepare(`SELECT key FROM ${CONFIG_TABLE}`).all() as { key: string }[];
    return rows.map(r => r.key);
  }

  /**
   * Build a PITRRemoteStorageConfig from the stored config values.
   * Returns null if required fields are missing.
   */
  buildStorageConfig(): PITRRemoteStorageConfig | null {
    const backend = this.get('pitr.remote_backend') as RemoteStorageBackend | undefined;
    if (!backend) return null;
    if (backend === 'nas') {
      return {
        backend,
        nasPath: this.get('pitr.remote_nas_path')!,
        prefix: this.get('pitr.remote_prefix') || 'pitr/',
      };
    }
    // s3 / gcs
    const bucket = this.get('pitr.remote_bucket');
    const accessKeyId = this.get('pitr.remote_access_key');
    const secretAccessKey = this.get('pitr.remote_secret_key');
    if (!bucket || !accessKeyId || !secretAccessKey) return null;

    return {
      backend,
      bucket,
      prefix: this.get('pitr.remote_prefix') || 'pitr/',
      endpoint: this.get('pitr.remote_endpoint') || undefined,
      region: this.get('pitr.remote_region') || undefined,
      accessKeyId,
      secretAccessKey,
      maxConcurrent: Number(this.get('pitr.remote_max_concurrent') || 4),
    };
  }

  /**
   * Check if PITR remote sync is enabled.
   */
  isEnabled(): boolean {
    return this.get('pitr.enabled') === 'true';
  }

  /**
   * Subscribe to config change events.
   */
  onChange(handler: ConfigChangeHandler): void {
    this.listeners.push(handler);
  }

  /**
   * Start polling for config changes.
   */
  startPolling(): void {
    if (this.pollTimer) return;
    this.pollTimer = setInterval(() => this.checkForChanges(), this.POLL_INTERVAL_MS);
    logger.info(`PITR config polling started (interval: ${this.POLL_INTERVAL_MS / 1000}s)`);
  }

  /**
   * Stop polling.
   */
  stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  /**
   * Close the database.
   */
  close(): void {
    this.closed = true;
    this.stopPolling();
    this.db.close();
  }

  // ── Internal ──────────────────────────────────────────────────────────

  private prevEnabled: boolean | null = null;
  private prevStorageConfig: PITRRemoteStorageConfig | null = null;

  private checkForChanges(): void {
    if (this.closed) return;

    // Track version via row count + a hash of keys
    const currentEnabled = this.isEnabled();
    const currentStorageConfig = this.buildStorageConfig();

    const enabledChanged = this.prevEnabled !== null && currentEnabled !== this.prevEnabled;
    const configChanged = JSON.stringify(currentStorageConfig) !== JSON.stringify(this.prevStorageConfig);

    if (enabledChanged || configChanged) {
      logger.info(
        `PITR config change detected (enabled: ${this.prevEnabled}→${currentEnabled}, ` +
        `config changed: ${configChanged})`,
      );

      const event: PITRConfigEvent = {
        type: enabledChanged ? 'enabled_toggled' : 'config_changed',
        enabled: currentEnabled,
        storageConfig: currentStorageConfig,
      };

      if (enabledChanged && this.prevEnabled !== null) {
        event.type = 'enabled_toggled';
      }

      for (const handler of this.listeners) {
        try { handler(event); } catch (err: any) {
          logger.error(`PITR config change handler error: ${err.message}`);
        }
      }
    }

    this.prevEnabled = currentEnabled;
    this.prevStorageConfig = currentStorageConfig;
  }
}
