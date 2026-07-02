/**
 * ConfigWatcher — File-system-watching config hot-reload.
 *
 * Monitors a JSON config file for changes and fires registered
 * callbacks when specific sections change.  Also exposes a
 * `reloadNow()` method for programmatic reload (e.g. via
 * `pg_reload_conf()`).
 *
 * ## Supported config sections
 *
 * ```json
 * {
 *   "logging": { "level": "info" },
 *   "pool": { "min": 2, "max": 10 },
 *   "pitr": { "enabled": true }
 * }
 * ```
 *
 * Expand {@link ConfigChangeCallbacks} and {@link AppConfig} as
 * additional config sections are needed.
 *
 * @module ConfigWatcher
 */

import * as chokidar from 'chokidar';
import * as fs from 'fs';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('ConfigWatcher');

// ── Types ────────────────────────────────────────────────────────────

export interface PitrConfig {
  enabled: boolean;
  [key: string]: unknown;
}

export interface AppConfig {
  logging?: { level?: string };
  pool?: { min?: number; max?: number };
  pitr?: PitrConfig;
  [key: string]: unknown;
}

export interface ConfigChangeCallbacks {
  /** Called when the `logging.level` field changes */
  onLogLevel?: (level: string) => void;
  /** Called when the `pool.min` / `pool.max` fields change */
  onPoolSize?: (min: number, max: number) => void;
  /** Called when the `pitr.enabled` field changes */
  onPitrEnabled?: (enabled: boolean) => void;
}

// ── ConfigWatcher ────────────────────────────────────────────────────

export class ConfigWatcher {
  private watcher: chokidar.FSWatcher | null = null;
  private configPath: string = '';
  private callbacks: ConfigChangeCallbacks = {};
  private currentConfig: AppConfig = {};

  /**
   * Start watching the given config file.
   *
   * Reads the initial config immediately, then sets up a file-system
   * watcher that fires the registered callbacks on each change.
   *
   * @param configPath  Absolute or relative path to a JSON config file
   * @param callbacks   Set of callbacks keyed by config section
   */
  watch(configPath: string, callbacks: ConfigChangeCallbacks): void {
    this.configPath = configPath;
    this.callbacks = callbacks;

    // Read initial config and apply callbacks.
    this.reloadNow();

    // Watch for file changes (detects all common write patterns:
    // writeFileSync, write+rename, editor save, etc.)
    this.watcher = chokidar.watch(configPath, {
      persistent: true,
      ignoreInitial: true,
    });

    this.watcher.on('change', (_path: string) => {
      logger.info({ path: configPath }, 'Config file changed — hot-reloading');
      this.reloadNow();
    });

    this.watcher.on('error', (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error({ err: msg }, 'ConfigWatcher chokidar error');
    });
  }

  /**
   * Stop watching the config file and release resources.
   */
  unwatch(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
  }

  /**
   * Immediately re-read the config file from disk and fire all
   * registered callbacks with the new values.
   *
   * Called automatically on file-change events, but can also be
   * invoked programmatically (e.g. from `pg_reload_conf()`).
   */
  reloadNow(): void {
    try {
      const raw = fs.readFileSync(this.configPath, 'utf-8');
      const config: AppConfig = JSON.parse(raw);
      const prev = this.currentConfig;
      this.currentConfig = config;
      this.applyConfigChanges(config, prev);
      logger.info('Config reloaded successfully');
    } catch (err: any) {
      logger.error({ err: err.message }, 'Failed to reload config');
    }
  }

  /**
   * Return a shallow copy of the currently-loaded config.
   */
  getConfig(): AppConfig {
    return { ...this.currentConfig };
  }

  /**
   * Compare new config against previous and fire callbacks
   * for changed fields only.
   */
  private applyConfigChanges(config: AppConfig, prev: AppConfig): void {
    // ── Log level ──────────────────────────────────────────────
    const newLevel = config.logging?.level;
    const oldLevel = prev.logging?.level;
    if (newLevel !== undefined && newLevel !== oldLevel && this.callbacks.onLogLevel) {
      logger.info({ from: oldLevel, to: newLevel }, 'Applying log-level change');
      this.callbacks.onLogLevel(newLevel);
    }

    // ── Pool size ──────────────────────────────────────────────
    const newMin = config.pool?.min;
    const newMax = config.pool?.max;
    const oldMin = prev.pool?.min;
    const oldMax = prev.pool?.max;
    if (
      (newMin !== undefined && newMin !== oldMin) ||
      (newMax !== undefined && newMax !== oldMax)
    ) {
      if (this.callbacks.onPoolSize) {
        const min = newMin ?? oldMin ?? 2;
        const max = newMax ?? oldMax ?? 10;
        logger.info(
          { from: { min: oldMin, max: oldMax }, to: { min, max } },
          'Applying pool-size change',
        );
        this.callbacks.onPoolSize(min, max);
      }
    }

    // ── PITR enabled ───────────────────────────────────────────
    const newPitrEnabled = config.pitr?.enabled;
    const oldPitrEnabled = prev.pitr?.enabled;
    if (newPitrEnabled !== undefined && newPitrEnabled !== oldPitrEnabled && this.callbacks.onPitrEnabled) {
      logger.info(
        { from: oldPitrEnabled, to: newPitrEnabled },
        'Applying PITR enabled/disabled change',
      );
      this.callbacks.onPitrEnabled(newPitrEnabled);
    }
  }
}
