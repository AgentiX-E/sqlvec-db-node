/**
 * LogicalBackupWorker — Piscina worker for parallel SQL restore.
 *
 * Each worker opens its own connection to the same database file and
 * executes a batch of table-specific SQL statements in a transaction.
 * INSERTs to the same table are always sequential within a single worker.
 *
 * This file is loaded by Piscina at runtime.
 */

import Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';
const logger = PinoLogger.forComponent('LogicalBackupWorker');

// ── Types ────────────────────────────────────────────────────────────────────

export interface WorkerTask {
  /** Path to the SQLite database file */
  dbPath: string;
  /** Groups of statements, one per table.  Each group runs sequentially. */
  tableGroups: Array<{
    table: string;
    statements: string[];
  }>;
}

export interface WorkerResult {
  /** Total rows affected */
  rows: number;
  /** Total statements executed (including skipped) */
  statements: number;
}

// ── Worker entry point ───────────────────────────────────────────────────────

/**
 * Default export — called by Piscina for each task.
 *
 * Opens a dedicated database connection and executes each table group
 * in its own transaction for performance.
 */
export default function run(task: WorkerTask): WorkerResult {
  const db = new Database(task.dbPath);

  // Enable WAL mode for better concurrent read/write performance
  db.pragma('journal_mode = WAL');

  let totalRows = 0;
  let totalStatements = 0;

  for (const group of task.tableGroups) {
    // Each table group runs in its own transaction for batching
    const tx = db.transaction(() => {
      let groupRows = 0;
      for (const stmt of group.statements) {
        try {
          const info = db.prepare(stmt).run();
          groupRows += info.changes;
          totalStatements++;
        } catch (err: any) {
          // Log and skip non-fatal errors
          logger.warn(
            `[LogicalBackupWorker] Skipping statement for "${group.table}": ${err.message}`,
          );
          totalStatements++;
        }
      }
      return groupRows;
    });

    totalRows += tx();
  }

  db.close();
  return { rows: totalRows, statements: totalStatements };
}
