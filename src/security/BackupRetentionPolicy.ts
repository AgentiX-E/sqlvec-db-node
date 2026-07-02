/**
 * BackupRetentionPolicy — Backup lifecycle management with configurable retention policies
 *
 * Evaluates a set of backup entries against a retention configuration and
 * produces a list of backups to keep and a list to delete. Complements
 * BackupEncryptionManager by managing the lifecycle side of backups —
 * encryption/decryption is handled by BackupEncryptionManager, while
 * this module decides which backups should survive.
 *
 * Retention rules (applied in order):
 * 1. Keep at least `minKeepCount` backups (trumps all other rules)
 * 2. Keep the most recent `keepFullBackups` full backups
 * 3. Remove incremental backups older than `incrementalRetentionDays`
 * 4. Remove full backups older than `fullRetentionDays`
 * 5. If `keepMonthly`, keep at least one backup per calendar month
 * 6. If `keepYearly`, keep at least one backup per calendar year
 *
 * @module BackupRetentionPolicy
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('BackupRetentionPolicy');

// ── Constants ─────────────────────────────────────────────────────────────────

/** Hours in a day. */
const HOURS_PER_DAY = 24;
/** Minutes in an hour. */
const MINUTES_PER_HOUR = 60;
/** Seconds in a minute. */
const SECONDS_PER_MINUTE = 60;
/** Milliseconds in a second. */
const MS_PER_SECOND = 1_000;
/** Milliseconds in a day. */
const MS_PER_DAY = HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE * MS_PER_SECOND;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface BackupEntry {
  /** 备份文件路径 */
  filePath: string;
  /** 备份时间 */
  createdAt: Date;
  /** 备份大小 (bytes) */
  sizeBytes: number;
  /** 备份类型 */
  type: 'full' | 'incremental' | 'differential';
  /** 备份标签 */
  label?: string;
}

export interface RetentionConfig {
  /** 保留最近的全量备份数（默认 7） */
  keepFullBackups: number;
  /** 增量备份保留天数（默认 30） */
  incrementalRetentionDays: number;
  /** 全量备份保留天数（默认 90） */
  fullRetentionDays: number;
  /** 最小保留备份数（防止全部被清空，默认 1） */
  minKeepCount: number;
  /** 每月至少保留一个备份（默认 true） */
  keepMonthly: boolean;
  /** 每年至少保留一个备份（默认 true） */
  keepYearly: boolean;
}

export interface RetentionResult {
  /** 应删除的备份列表 */
  toDelete: BackupEntry[];
  /** 保留的备份列表 */
  toKeep: BackupEntry[];
  /** 清理后释放的空间 (bytes) */
  freedBytes: number;
}

export interface BackupHealth {
  /** Whether the backup set is considered healthy */
  healthy: boolean;
  /** Age of the most recent backup in days */
  lastBackupAge: number;
  /** Total size of all backups in bytes */
  totalSizeBytes: number;
  /** Total number of backup entries */
  backupCount: number;
  /** Non-fatal warnings about the backup set */
  warnings: string[];
}

// ── Default Configuration ─────────────────────────────────────────────────────

/** 默认保留策略 */
export const DEFAULT_RETENTION: RetentionConfig = Object.freeze({
  keepFullBackups: 7,
  incrementalRetentionDays: 30,
  fullRetentionDays: 90,
  minKeepCount: 1,
  keepMonthly: true,
  keepYearly: true,
});

// ── Date Helpers ──────────────────────────────────────────────────────────────

/**
 * Calculate the difference in days between two dates.
 */
function daysBetween(a: Date, b: Date): number {
  return (a.getTime() - b.getTime()) / MS_PER_DAY;
}

/**
 * Get the calendar month key (e.g. "2026-05") for grouping backups.
 */
function monthKey(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
}

/**
 * Get the calendar year key (e.g. "2026") for grouping backups.
 */
function yearKey(date: Date): string {
  return String(date.getFullYear());
}

/**
 * Sort backups descending by createdAt (newest first).
 */
function sortByNewest(backups: BackupEntry[]): BackupEntry[] {
  return [...backups].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
}

// ── BackupRetentionPolicy ─────────────────────────────────────────────────────

export class BackupRetentionPolicy {
  private config: RetentionConfig;

  constructor(config?: Partial<RetentionConfig>) {
    this.config = {
      keepFullBackups: config?.keepFullBackups ?? DEFAULT_RETENTION.keepFullBackups,
      incrementalRetentionDays: config?.incrementalRetentionDays ?? DEFAULT_RETENTION.incrementalRetentionDays,
      fullRetentionDays: config?.fullRetentionDays ?? DEFAULT_RETENTION.fullRetentionDays,
      minKeepCount: config?.minKeepCount ?? DEFAULT_RETENTION.minKeepCount,
      keepMonthly: config?.keepMonthly ?? DEFAULT_RETENTION.keepMonthly,
      keepYearly: config?.keepYearly ?? DEFAULT_RETENTION.keepYearly,
    };

    this.validateConfig();

    logger.info({ config: this.config }, 'BackupRetentionPolicy initialized');
  }

  /**
   * Validate the current retention configuration, clamping out-of-range values
   * and logging warnings for degenerate configurations.
   */
  private validateConfig(): void {
    if (this.config.minKeepCount < 1) {
      logger.warn(
        { minKeepCount: this.config.minKeepCount },
        'minKeepCount must be >= 1, clamping to 1',
      );
      this.config.minKeepCount = 1;
    }

    if (this.config.keepFullBackups < 0) {
      logger.warn(
        { keepFullBackups: this.config.keepFullBackups },
        'keepFullBackups must be >= 0, clamping to 0',
      );
      this.config.keepFullBackups = 0;
    }

    if (this.config.incrementalRetentionDays < 0) {
      logger.warn(
        { incrementalRetentionDays: this.config.incrementalRetentionDays },
        'incrementalRetentionDays must be >= 0, clamping to 0',
      );
      this.config.incrementalRetentionDays = 0;
    }

    if (this.config.fullRetentionDays < 0) {
      logger.warn(
        { fullRetentionDays: this.config.fullRetentionDays },
        'fullRetentionDays must be >= 0, clamping to 0',
      );
      this.config.fullRetentionDays = 0;
    }

    // Warn if minKeepCount > total number of full backups we'd keep
    // (this can cause unbounded retention, but is not necessarily wrong).
    if (this.config.minKeepCount > this.config.keepFullBackups && this.config.keepFullBackups > 0) {
      logger.warn(
        {
          minKeepCount: this.config.minKeepCount,
          keepFullBackups: this.config.keepFullBackups,
        },
        'minKeepCount exceeds keepFullBackups — may retain more backups than configured keepFullBackups',
      );
    }
  }

  /**
   * 评估应保留/删除的备份
   *
   * The evaluation applies retention rules in the following order:
   *
   * 1. **Minimum keep count** — If the total backup count is <= `minKeepCount`,
   *    all backups are retained regardless of other rules.
   * 2. **Recent full backups** — Keep the most recent `keepFullBackups` full backups.
   * 3. **Incremental retention** — Remove incremental backups older than
   *    `incrementalRetentionDays`.
   * 4. **Full backup retention** — Remove full backups older than
   *    `fullRetentionDays`, except those already protected by rule #2.
   * 5. **Monthly retention** — If enabled, keep at least one backup per
   *    calendar month (the newest in each month).
   * 6. **Yearly retention** — If enabled, keep at least one backup per
   *    calendar year (the newest in each year).
   */
  evaluate(backups: BackupEntry[]): RetentionResult {
    if (backups.length === 0) {
      logger.debug('evaluate: no backups to evaluate');
      return { toDelete: [], toKeep: [], freedBytes: 0 };
    }

    const now = new Date();
    const toKeep = new Set<BackupEntry>();

    // ── Rule 1: Minimum keep count (trumps all) ──
    if (backups.length <= this.config.minKeepCount) {
      logger.debug(
        { backupCount: backups.length, minKeepCount: this.config.minKeepCount },
        'Backup count <= minKeepCount, retaining all',
      );
      const all = [...backups];
      return { toDelete: [], toKeep: all, freedBytes: 0 };
    }

    // Sort newest-first for rule evaluation
    const sorted = sortByNewest(backups);

    // ── Rule 2: Keep recent full backups ──
    const fullBackups = sorted.filter((b) => b.type === 'full');
    const recentFulls = fullBackups.slice(0, this.config.keepFullBackups);
    for (const fb of recentFulls) {
      toKeep.add(fb);
    }

    logger.debug(
      {
        totalFulls: fullBackups.length,
        keptFulls: recentFulls.length,
        keepFullBackups: this.config.keepFullBackups,
      },
      'Rule 2: Recent full backup selection complete',
    );

    // ── Rule 3: Remove old incremental backups ──
    // Keep all incrementals that are still within the retention window,
    // plus any that are already in the keep set.
    for (const b of sorted) {
      if (b.type === 'incremental' || b.type === 'differential') {
        const age = daysBetween(now, b.createdAt);
        // Use the stricter of fullRetentionDays / incrementalRetentionDays for
        // differential backups (they depend on a full base).
        const retentionDays =
          b.type === 'differential'
            ? Math.max(this.config.incrementalRetentionDays, this.config.fullRetentionDays)
            : this.config.incrementalRetentionDays;

        if (age <= retentionDays) {
          toKeep.add(b);
        }
      }
    }

    logger.debug(
      {
        keptAfterTime: toKeep.size,
        incrementalRetentionDays: this.config.incrementalRetentionDays,
      },
      'Rule 3: Incremental/differential time-based retention complete',
    );

    // ── Rule 4: Remove old full backups (outside keepFullBackups window) ──
    for (const b of sorted) {
      if (b.type === 'full') {
        const age = daysBetween(now, b.createdAt);
        if (age <= this.config.fullRetentionDays) {
          toKeep.add(b);
        }
      }
    }

    logger.debug(
      {
        keptAfterFullTime: toKeep.size,
        fullRetentionDays: this.config.fullRetentionDays,
      },
      'Rule 4: Full backup time-based retention complete',
    );

    // ── Rule 5: Monthly retention ──
    if (this.config.keepMonthly) {
      const keptByMonth = new Map<string, BackupEntry[]>();

      // Group currently-kept backups by month
      for (const b of toKeep) {
        const mk = monthKey(b.createdAt);
        const group = keptByMonth.get(mk) ?? [];
        group.push(b);
        keptByMonth.set(mk, group);
      }

      // Find months that have NO kept backups from the full backup set
      // and add the newest backup in that month (from the sorted list).
      const allMonths = new Set(backups.map((b) => monthKey(b.createdAt)));
      for (const mk of allMonths) {
        if (!keptByMonth.has(mk)) {
          // Find the newest backup from this month
          const candidates = sortByNewest(backups.filter((b) => monthKey(b.createdAt) === mk));
          if (candidates.length > 0) {
            toKeep.add(candidates[0]);
            logger.debug(
              { month: mk, keptBy: candidates[0].filePath },
              'Rule 5: Monthly retention — kept backup for month',
            );
          }
        }
      }
    }

    // ── Rule 6: Yearly retention ──
    if (this.config.keepYearly) {
      const keptByYear = new Map<string, BackupEntry[]>();

      for (const b of toKeep) {
        const yk = yearKey(b.createdAt);
        const group = keptByYear.get(yk) ?? [];
        group.push(b);
        keptByYear.set(yk, group);
      }

      const allYears = new Set(backups.map((b) => yearKey(b.createdAt)));
      for (const yk of allYears) {
        if (!keptByYear.has(yk)) {
          const candidates = sortByNewest(backups.filter((b) => yearKey(b.createdAt) === yk));
          if (candidates.length > 0) {
            toKeep.add(candidates[0]);
            logger.debug(
              { year: yk, keptBy: candidates[0].filePath },
              'Rule 6: Yearly retention — kept backup for year',
            );
          }
        }
      }
    }

    // ── Final assembly ──
    const toKeepArr = [...toKeep].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const toDeleteArr = backups.filter((b) => !toKeep.has(b));
    const freedBytes = toDeleteArr.reduce((sum, b) => sum + b.sizeBytes, 0);

    logger.info(
      {
        totalBackups: backups.length,
        toKeep: toKeepArr.length,
        toDelete: toDeleteArr.length,
        freedBytes,
      },
      'Retention evaluation complete',
    );

    return {
      toDelete: toDeleteArr,
      toKeep: toKeepArr,
      freedBytes,
    };
  }

  /**
   * 更新配置
   *
   * Merges the provided partial configuration into the current config
   * and validates the result.
   *
   * @param config - Partial retention configuration to apply.
   */
  updateConfig(config: Partial<RetentionConfig>): void {
    const before = { ...this.config };

    if (config.keepFullBackups !== undefined) {
      this.config.keepFullBackups = config.keepFullBackups;
    }
    if (config.incrementalRetentionDays !== undefined) {
      this.config.incrementalRetentionDays = config.incrementalRetentionDays;
    }
    if (config.fullRetentionDays !== undefined) {
      this.config.fullRetentionDays = config.fullRetentionDays;
    }
    if (config.minKeepCount !== undefined) {
      this.config.minKeepCount = config.minKeepCount;
    }
    if (config.keepMonthly !== undefined) {
      this.config.keepMonthly = config.keepMonthly;
    }
    if (config.keepYearly !== undefined) {
      this.config.keepYearly = config.keepYearly;
    }

    this.validateConfig();

    logger.info(
      { before, after: this.config },
      'Retention configuration updated',
    );
  }

  /**
   * 获取配置
   *
   * Returns the current retention configuration as a read-only snapshot.
   */
  getConfig(): Readonly<RetentionConfig> {
    return Object.freeze({ ...this.config });
  }

  /**
   * 检查是否需要触发备份（距离上次超过 N 天）
   *
   * @param lastBackup     - The date of the last known backup.
   * @param maxIntervalDays - Maximum allowed interval in days (default: 1).
   * @returns `true` if a new backup should be triggered.
   */
  shouldBackup(lastBackup: Date, maxIntervalDays?: number): boolean {
    const maxDays = maxIntervalDays ?? 1;
    const now = new Date();
    const age = daysBetween(now, lastBackup);

    if (age >= maxDays) {
      logger.info(
        { lastBackup: lastBackup.toISOString(), ageDays: Math.round(age * 100) / 100, maxIntervalDays: maxDays },
        'Backup interval exceeded — should trigger backup',
      );
      return true;
    }

    logger.debug(
      { lastBackup: lastBackup.toISOString(), ageDays: Math.round(age * 100) / 100, maxIntervalDays: maxDays },
      'Backup interval not yet exceeded',
    );
    return false;
  }

  /**
   * 获取备份健康状态
   *
   * Evaluates the overall health of the backup set, producing warnings for
   * common issues such as missing recent backups, empty backup sets, or
   * configurations that may lead to data loss.
   *
   * @param backups - The list of backup entries to evaluate.
   * @returns A BackupHealth object describing the state of backups.
   */
  getHealth(backups: BackupEntry[]): BackupHealth {
    const warnings: string[] = [];
    const now = new Date();

    // Empty backup set
    if (backups.length === 0) {
      return {
        healthy: false,
        lastBackupAge: Infinity,
        totalSizeBytes: 0,
        backupCount: 0,
        warnings: ['No backups exist — data is unprotected'],
      };
    }

    // Find the newest backup
    const sorted = sortByNewest(backups);
    const newest = sorted[0];
    const lastBackupAge = daysBetween(now, newest.createdAt);
    const totalSizeBytes = backups.reduce((sum, b) => sum + b.sizeBytes, 0);

    // Check for very old backups
    const newestFull = sorted.find((b) => b.type === 'full');
    if (!newestFull) {
      warnings.push('No full backup found — recovery may require incremental chain');
    }

    // Check no recent full backup
    if (newestFull) {
      const fullAge = daysBetween(now, newestFull.createdAt);
      if (fullAge > this.config.fullRetentionDays * 2) {
        warnings.push(
          `Most recent full backup is ${Math.round(fullAge)} days old (retention: ${this.config.fullRetentionDays} days)`,
        );
      }
    }

    // Check for very old latest backup
    if (lastBackupAge > 7) {
      warnings.push(`Most recent backup is ${Math.round(lastBackupAge)} days old`);
    }

    // Check minKeepCount / keepFullBackups ratio
    if (this.config.minKeepCount > this.config.keepFullBackups && this.config.keepFullBackups > 0) {
      warnings.push(
        `minKeepCount (${this.config.minKeepCount}) > keepFullBackups (${this.config.keepFullBackups}) ` +
          '— may retain more backups than intended',
      );
    }

    // Check small number of backups
    if (backups.length <= this.config.minKeepCount) {
      warnings.push(
        `Only ${backups.length} backup(s) exist — consider increasing backup frequency`,
      );
    }

    const healthy = warnings.length === 0;

    logger.debug(
      {
        healthy,
        lastBackupAge: Math.round(lastBackupAge * 100) / 100,
        totalSizeBytes,
        backupCount: backups.length,
        warningCount: warnings.length,
      },
      'Backup health check complete',
    );

    return {
      healthy,
      lastBackupAge,
      totalSizeBytes,
      backupCount: backups.length,
      warnings,
    };
  }
}
