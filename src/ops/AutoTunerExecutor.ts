/**
 * AutoTunerExecutor — Connects AutoTuner actions to actual SQLite PRAGMAs.
 *
 * Maps auto-tuning action types (from `AutoTuner.evaluate()`) to concrete
 * SQLite PRAGMA statements that modify database behavior at runtime.
 *
 * Action type mapping:
 *   ADJUST_CACHE       → PRAGMA cache_size = <value>
 *   ADJUST_MMAP        → PRAGMA mmap_size = <value>
 *   SET_PAGE_SIZE      → No-op (page_size can only be set at DB creation)
 *   ADJUST_SYNCHRONOUS → PRAGMA synchronous = <value>
 *   ADJUST_JOURNAL     → PRAGMA journal_mode = <value>
 *   ADJUST_TEMP_STORE  → PRAGMA temp_store = <value>
 *   ADJUST_LOCK_MODE   → PRAGMA locking_mode = <value>
 *
 * Also provides `getPragmas()` to read the current SQLite performance state.
 *
 * @module AutoTunerExecutor
 */

import type Database from 'better-sqlite3';

export interface AutoTunerAction {
  type: string;
  value: any;
}

/**
 * Executes auto-tuning actions by applying corresponding SQLite PRAGMAs.
 */
export class AutoTunerExecutor {
  constructor(private db: Database.Database) {}

  /**
   * Apply a single auto-tune action by executing the appropriate SQLite PRAGMA.
   *
   * @param action - The tuning action to apply.
   */
  applyAction(action: AutoTunerAction): void {
    switch (action.type) {
      case 'ADJUST_CACHE':
        this.db.pragma(`cache_size = ${action.value}`);
        break;

      case 'ADJUST_MMAP':
        this.db.pragma(`mmap_size = ${action.value}`);
        break;

      case 'SET_PAGE_SIZE':
        // page_size can only be set at database creation time
        break;

      case 'ADJUST_SYNCHRONOUS':
        this.db.pragma(`synchronous = ${action.value}`);
        break;

      case 'ADJUST_JOURNAL':
        this.db.pragma(`journal_mode = ${action.value}`);
        break;

      case 'ADJUST_TEMP_STORE':
        this.db.pragma(`temp_store = ${action.value}`);
        break;

      case 'ADJUST_LOCK_MODE':
        this.db.pragma(`locking_mode = ${action.value}`);
        break;

      case 'SHRINK_MEMORY':
        // No direct PRAGMA equivalent. Could use `PRAGMA shrink_memory`
        // but that's optional. We trigger a manual memory release.
        try {
          // @ts-ignore: Not all SQLite builds support this
          this.db.pragma('shrink_memory');
        } catch {
          // Silently ignore if unsupported
        }
        break;

      case 'COMPACT_WAL':
        // Force a WAL checkpoint
        this.db.pragma('wal_checkpoint(TRUNCATE)');
        break;

      default:
        // Unknown action type — silently ignore
        break;
    }
  }

  /**
   * Get current SQLite performance PRAGMA values.
   *
   * @returns A dictionary of current PRAGMA values.
   */
  getPragmas(): Record<string, any> {
    return {
      cache_size: this.db.pragma('cache_size', { simple: true }),
      page_size: this.db.pragma('page_size', { simple: true }),
      synchronous: this.db.pragma('synchronous', { simple: true }),
      journal_mode: this.db.pragma('journal_mode', { simple: true }),
      temp_store: this.db.pragma('temp_store', { simple: true }),
      mmap_size: this.db.pragma('mmap_size', { simple: true }),
    };
  }

  // ── GUC-backed tuning ──────────────────────────────────────────

  /**
   * Tune the database engine using a config object.
   * Maps high-level config keys to GUCs and applies SQLite PRAGMAs accordingly.
   *
   * @param config - Tuning configuration with optional workMem, sharedBuffers, etc.
   */
  tune(config: { workMem?: number; sharedBuffers?: number; effectiveCacheSize?: number }): void {
    const { GucSystem } = require('../core/GucSystem');

    if (config.workMem) {
      GucSystem.set('work_mem', String(config.workMem));
    }
    if (config.sharedBuffers) {
      GucSystem.set('shared_buffers', String(config.sharedBuffers));
    }
    if (config.effectiveCacheSize) {
      GucSystem.set('effective_cache_size', String(config.effectiveCacheSize));
    }

    this.applyPragmaMappings();
  }

  /**
   * Apply SQLite PRAGMA mappings from GUC values.
   * - work_mem → cache_size
   */
  private applyPragmaMappings(): void {
    const { GucSystem } = require('../core/GucSystem');
    const workMem = GucSystem.get('work_mem');
    if (workMem) {
      const cachePages = Math.floor(parseInt(workMem, 10) / 4096);
      if (cachePages > 0) {
        this.db.pragma(`cache_size = ${cachePages}`);
      }
    }

    const sharedBuffers = GucSystem.get('shared_buffers');
    if (sharedBuffers) {
      const sbVal = parseInt(sharedBuffers, 10);
      if (sbVal > 0) {
        // shared_buffers → additional mmap for in-memory caching
        this.db.pragma(`mmap_size = ${sbVal}`);
      }
    }
  }
}
