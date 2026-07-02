/**
 * PgCronScheduler — pg_cron job scheduling with SQLite persistence.
 *
 * Provides PostgreSQL pg_cron extension-compatible job scheduling
 * using node-cron for execution and an in-memory / SQLite-backed
 * `__cron_jobs` table for persistence.
 *
 * ## Supported operations
 *
 * | Function                          | SQL Equivalent                                |
 * |-----------------------------------|-----------------------------------------------|
 * | schedule(name, cronExpr, sql)     | `SELECT cron.schedule('name', '0 * * * *', 'VACUUM')` |
 * | unschedule(name)                  | `SELECT cron.unschedule('name')`              |
 * | listJobs()                        | `SELECT * FROM cron.job`                      |
 * | getJob(name)                      | Get a specific job by name                    |
 * | isRunning()                       | Check if the scheduler is active              |
 *
 * ## Features
 * - Persists jobs to SQLite `__cron_jobs` table.
 * - Store & resume across restarts.
 * - Execution callback with SQL statement.
 * - Job listing, unscheduling, and status checking.
 *
 * @module cron/PgCronScheduler
 */

import { CronJob } from 'cron';
import { PinoLogger } from '../monitoring/PinoLogger';

// ── Types ────────────────────────────────────────────────────────

export interface CronJobEntry {
  /** Unique job name */
  jobName: string;
  /** Cron expression (e.g. '0 * * * *') */
  cronExpr: string;
  /** SQL statement to execute when the job fires */
  command: string;
  /** When this job was created (epoch ms) */
  createdAt: number;
  /** Whether the job is active */
  active: boolean;
  /** Node.js cron job ID (runtime-only) */
  _internalJobId?: string;
}

export interface CronExecutionResult {
  jobName: string;
  sql: string;
  startedAt: number;
  completedAt: number;
  success: boolean;
  error?: string;
}

export type CronJobCallback = (sql: string, jobName: string) => Promise<void> | void;

// ── Logger ───────────────────────────────────────────────────────

// ── Storage interface ────────────────────────────────────────────

export interface CronStorage {
  save(job: CronJobEntry): void;
  remove(jobName: string): void;
  list(): CronJobEntry[];
  find(jobName: string): CronJobEntry | undefined;
  update(job: CronJobEntry): void;
}

// ── In-memory storage ────────────────────────────────────────────

class InMemoryCronStorage implements CronStorage {
  private jobs: Map<string, CronJobEntry> = new Map();

  save(job: CronJobEntry): void {
    this.jobs.set(job.jobName, job);
  }

  remove(jobName: string): void {
    this.jobs.delete(jobName);
  }

  list(): CronJobEntry[] {
    return Array.from(this.jobs.values());
  }

  find(jobName: string): CronJobEntry | undefined {
    return this.jobs.get(jobName);
  }

  update(job: CronJobEntry): void {
    this.jobs.set(job.jobName, job);
  }
}

// ── SQLite-backed storage ────────────────────────────────────────

class SqliteCronStorage implements CronStorage {
  private readonly logger = PinoLogger.forComponent('cron-sqlite');
  private db: any = null;
  private inMemory: Map<string, CronJobEntry> = new Map();

  constructor() {
    // Start with in-memory; try connecting to better-sqlite3 later
  }

  async connect(dbInstance?: any): Promise<void> {
    if (dbInstance) {
      this.db = dbInstance;
      await this.initTable();
      return;
    }

    // Try to auto-connect to better-sqlite3
    try {
      const Database = require('better-sqlite3');
      this.db = new Database(':memory:');
      await this.initTable();
      this.logger.info('Connected to SQLite (in-memory)');
    } catch {
      this.logger.info('Using in-memory storage for cron jobs');
    }
  }

  private async initTable(): Promise<void> {
    if (!this.db) return;
    try {
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS __cron_jobs (
          job_name TEXT PRIMARY KEY,
          cron_expr TEXT NOT NULL,
          command TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          active INTEGER NOT NULL DEFAULT 1
        )
      `);

      // Load existing jobs from DB
      const rows = this.db.prepare('SELECT * FROM __cron_jobs WHERE active = 1').all();
      for (const row of rows) {
        this.inMemory.set(row.job_name, {
          jobName: row.job_name,
          cronExpr: row.cron_expr,
          command: row.command,
          createdAt: row.created_at,
          active: row.active === 1,
        });
      }
      this.logger.info({ loaded: rows.length }, 'Loaded cron jobs from SQLite');
    } catch (err: any) {
      this.logger.error({ err: err.message }, 'Failed to init __cron_jobs table');
    }
  }

  save(job: CronJobEntry): void {
    this.inMemory.set(job.jobName, job);
    if (this.db) {
      try {
        this.db.prepare(`
          INSERT OR REPLACE INTO __cron_jobs (job_name, cron_expr, command, created_at, active)
          VALUES (?, ?, ?, ?, ?)
        `).run(job.jobName, job.cronExpr, job.command, job.createdAt, job.active ? 1 : 0);
      } catch (err: any) {
        this.logger.error({ err: err.message, job: job.jobName }, 'Failed to persist cron job');
      }
    }
  }

  remove(jobName: string): void {
    this.inMemory.delete(jobName);
    if (this.db) {
      try {
        this.db.prepare('DELETE FROM __cron_jobs WHERE job_name = ?').run(jobName);
      } catch (err: any) {
        this.logger.error({ err: err.message, job: jobName }, 'Failed to remove cron job');
      }
    }
  }

  list(): CronJobEntry[] {
    return Array.from(this.inMemory.values());
  }

  find(jobName: string): CronJobEntry | undefined {
    return this.inMemory.get(jobName);
  }

  update(job: CronJobEntry): void {
    this.save(job); // Same as save (upsert)
  }
}

// ── PgCronScheduler ──────────────────────────────────────────────

/**
 * PgCronScheduler — PostgreSQL pg_cron-compatible job scheduler.
 *
 * Manages scheduled SQL jobs using node-cron, with job persistence
 * stored in a SQLite `__cron_jobs` table.
 *
 * @example
 * ```typescript
 * const scheduler = new PgCronScheduler();
 * await scheduler.connect();
 *
 * // Schedule a job
 * scheduler.schedule('vacuum-job', '0 * * * *', 'VACUUM');
 *
 * // List all jobs
 * const jobs = scheduler.listJobs();
 *
 * // Unschedule a job
 * scheduler.unschedule('vacuum-job');
 * ```
 */
export class PgCronScheduler {
  private readonly logger = PinoLogger.forComponent('pg-cron-scheduler');

  /** Map of jobName -> internal CronJob handle */
  private activeJobs: Map<string, CronJob> = new Map();

  /** Job metadata (name, cron expression, SQL, etc.) */
  private jobEntries: Map<string, CronJobEntry> = new Map();

  /** Storage backend */
  private storage: CronStorage = new InMemoryCronStorage();

  /** Callback for executing SQL statements */
  private sqlExecutor?: CronJobCallback;

  /** Whether the scheduler has been connected */
  private connected: boolean = false;

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Connect the scheduler to its storage backend.
   *
   * @param options Options for connecting
   * @param options.dbInstance Optional better-sqlite3 Database instance
   * @param options.sqlCallback Optional callback for SQL execution
   */
  async connect(options?: {
    dbInstance?: any;
    sqlCallback?: CronJobCallback;
  }): Promise<void> {
    // Create SQLite-backed storage
    this.storage = new SqliteCronStorage();
    await (this.storage as SqliteCronStorage).connect(options?.dbInstance);

    if (options?.sqlCallback) {
      this.sqlExecutor = options.sqlCallback;
    }

    // Resume any persisted jobs
    await this.resumeJobs();

    this.connected = true;
    this.logger.info('PgCronScheduler connected and ready');
  }

  /**
   * Resume any persisted cron jobs from storage.
   * Called automatically on connect().
   */
  async resumeJobs(): Promise<void> {
    const jobs = this.storage.list();
    let resumed = 0;

    for (const job of jobs) {
      if (job.active && !this.activeJobs.has(job.jobName)) {
        try {
          this.startCronJob(job);
          this.jobEntries.set(job.jobName, job);
          resumed++;
        } catch (err: any) {
          this.logger.warn({ job: job.jobName, err: err.message }, 'Failed to resume cron job');
        }
      }
    }

    if (resumed > 0) {
      this.logger.info({ resumed }, 'Resumed cron jobs from storage');
    }
  }

  /**
   * Schedule a new cron job.
   *
   * Equivalent to: `SELECT cron.schedule('job-name', '0 * * * *', 'VACUUM')`
   *
   * @param jobName  Unique name for the job
   * @param cronExpr Standard cron expression (e.g. '0 * * * *' for hourly)
   * @param command  SQL statement to execute when the job fires
   * @param callback Optional custom callback override
   * @returns The newly created CronJobEntry
   * @throws If a job with the same name already exists
   */
  schedule(
    jobName: string,
    cronExpr: string,
    command: string,
    callback?: CronJobCallback,
  ): CronJobEntry {
    if (this.jobEntries.has(jobName)) {
      throw new Error(`Cron job "${jobName}" already exists`);
    }

    const entry: CronJobEntry = {
      jobName,
      cronExpr,
      command,
      createdAt: Date.now(),
      active: true,
    };

    // Start the cron job
    this.startCronJob(entry, callback);

    // Store in memory and persist
    this.jobEntries.set(jobName, entry);
    this.storage.save(entry);

    this.logger.info({ jobName, cronExpr, command: command.substring(0, 60) },
      'Cron job scheduled');

    return entry;
  }

  /**
   * Schedule a job using the pg_cron SQL-like syntax.
   *
   * Parses: `SELECT cron.schedule('name', 'expr', 'SQL')`
   *
   * @param sql - A SQL statement mimicking SELECT cron.schedule(...)
   * @returns The job name, or null if parsing failed
   */
  scheduleFromSQL(sql: string): string | null {
    const match = sql.match(
      /cron\s*\.\s*schedule\s*\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]\s*\)/i,
    );
    if (!match) return null;

    const [, jobName, cronExpr, command] = match;
    this.schedule(jobName, cronExpr, command);
    return jobName;
  }

  /**
   * Unschedule a cron job by name.
   *
   * Equivalent to: `SELECT cron.unschedule('job-name')`
   *
   * @param jobName Name of the job to unschedule
   * @returns true if the job was removed, false if not found
   */
  unschedule(jobName: string): boolean {
    const entry = this.jobEntries.get(jobName);
    if (!entry) {
      this.logger.warn({ jobName }, 'Cannot unschedule: job not found');
      return false;
    }

    // Stop and remove the active CronJob
    const activeJob = this.activeJobs.get(jobName);
    if (activeJob) {
      activeJob.stop();
      this.activeJobs.delete(jobName);
    }

    // Update state
    entry.active = false;
    this.jobEntries.delete(jobName);
    this.storage.remove(jobName);

    this.logger.info({ jobName }, 'Cron job unscheduled');
    return true;
  }

  /**
   * Unschedule a job using pg_cron SQL-like syntax.
   *
   * Parses: `SELECT cron.unschedule('name')`
   *
   * @param sql - SQL mimicking SELECT cron.unschedule(...)
   * @returns true if successful
   */
  unscheduleFromSQL(sql: string): boolean {
    const match = sql.match(
      /cron\s*\.\s*unschedule\s*\(\s*['"]([^'"]+)['"]\s*\)/i,
    );
    if (!match) return false;
    return this.unschedule(match[1]);
  }

  /**
   * List all scheduled cron jobs.
   *
   * Equivalent to: `SELECT * FROM cron.job`
   *
   * @returns Array of all job entries
   */
  listJobs(): CronJobEntry[] {
    return Array.from(this.jobEntries.values());
  }

  /**
   * Get a specific job by name.
   *
   * @param jobName - Job name
   * @returns The job entry, or undefined
   */
  getJob(jobName: string): CronJobEntry | undefined {
    return this.jobEntries.get(jobName);
  }

  /**
   * Check if jobs are running (scheduler is active).
   */
  isRunning(): boolean {
    return this.activeJobs.size > 0;
  }

  /**
   * Get the count of active jobs.
   */
  getActiveJobCount(): number {
    return this.activeJobs.size;
  }

  /**
   * Get the count of all registered jobs (including inactive).
   */
  getTotalJobCount(): number {
    return this.jobEntries.size;
  }

  /**
   * Register a custom SQL executor callback.
   * This is called when a cron job fires.
   *
   * @param executor - Callback receiving (sql, jobName)
   */
  setSqlExecutor(executor: CronJobCallback): void {
    this.sqlExecutor = executor;
  }

  /**
   * Execute a cron job immediately (for testing).
   *
   * @param jobName - Name of the job to execute
   * @param executor - Optional executor for SQL execution
   * @returns Execution result
   */
  async executeJobNow(
    jobName: string,
    executor?: CronJobCallback,
  ): Promise<CronExecutionResult> {
    const entry = this.jobEntries.get(jobName);
    if (!entry) {
      return {
        jobName,
        sql: '',
        startedAt: Date.now(),
        completedAt: Date.now(),
        success: false,
        error: `Job "${jobName}" not found`,
      };
    }

    const startedAt = Date.now();
    try {
      if (executor) {
        await executor(entry.command, jobName);
      } else if (this.sqlExecutor) {
        await this.sqlExecutor(entry.command, jobName);
      }
      return {
        jobName,
        sql: entry.command,
        startedAt,
        completedAt: Date.now(),
        success: true,
      };
    } catch (err: any) {
      return {
        jobName,
        sql: entry.command,
        startedAt,
        completedAt: Date.now(),
        success: false,
        error: err.message,
      };
    }
  }

  /**
   * Stop all scheduled jobs and release resources.
   */
  stopAll(): void {
    for (const [name, job] of this.activeJobs) {
      job.stop();
      this.logger.info({ jobName: name }, 'Cron job stopped');
    }
    this.activeJobs.clear();
    this.logger.info('All cron jobs stopped');
  }

  /**
   * Reset the scheduler (for testing).
   */
  reset(): void {
    this.stopAll();
    this.jobEntries.clear();
    this.logger.info('PgCronScheduler reset');
  }

  // ── Private ─────────────────────────────────────────────────────

  private startCronJob(entry: CronJobEntry, callback?: CronJobCallback): void {
    const jobCallback = callback || this.sqlExecutor;

    const job = new CronJob(
      entry.cronExpr,
      async () => {
        this.logger.info({ job: entry.jobName, sql: entry.command.substring(0, 60) },
          'Cron job executing');
        if (jobCallback) {
          try {
            await jobCallback(entry.command, entry.jobName);
            this.logger.info({ job: entry.jobName }, 'Cron job completed');
          } catch (err: any) {
            this.logger.error({ job: entry.jobName, err: err.message }, 'Cron job failed');
          }
        } else {
          this.logger.warn({ job: entry.jobName }, 'No SQL executor registered for cron job');
        }
      },
      null,          // onComplete
      true,          // start
      'Asia/Shanghai',
    );

    this.activeJobs.set(entry.jobName, job);
  }
}
