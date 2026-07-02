/**
 * CertMappingStore — certificate CN/SN ↔ PostgreSQL user mapping table.
 *
 * Stores mappings between X.509 certificate Common Names (CN) and database
 * user names. Used by the mTLS authentication flow to skip password verification
 * when a valid certificate-to-user mapping exists.
 *
 * Backed by better-sqlite3 (already in project dependencies). By default runs
 * in-memory; call {@link getInstance} with a dbPath for persistent storage.
 *
 * @module auth/CertMappingStore
 */

import Database from 'better-sqlite3';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('CertMappingStore');

const TABLE_DDL = `
  CREATE TABLE IF NOT EXISTS __cert_map (
    cert_cn   TEXT PRIMARY KEY,
    db_user   TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
` as const;

const INSERT_SQL = `
  INSERT INTO __cert_map (cert_cn, db_user)
  VALUES (?, ?)
  ON CONFLICT(cert_cn) DO UPDATE SET
    db_user = excluded.db_user,
    created_at = datetime('now')
` as const;

const SELECT_SQL = `
  SELECT db_user FROM __cert_map WHERE cert_cn = ?
` as const;

const DELETE_SQL = `
  DELETE FROM __cert_map WHERE cert_cn = ?
` as const;

const DELETE_BY_USER_SQL = `
  DELETE FROM __cert_map WHERE db_user = ?
` as const;

// ──────────────────────────────────────────────
//  Singleton / Instance management
// ──────────────────────────────────────────────

let _instance: CertMappingStore | null = null;

/**
 * Reset the global singleton (for test teardown).
 * Call after each test that uses the global instance.
 */
export function resetStore(): void {
  if (_instance) {
    try {
      _instance.close();
    } catch {
      // ignore if already closed
    }
    _instance = null;
  }
}

/**
 * Get (or create) the global CertMappingStore singleton.
 *
 * @param dbPath  Path to SQLite database file. Default ':memory:' for ephemeral storage.
 *                Supply a file path for persistent mappings across restarts.
 * @returns       The shared CertMappingStore instance.
 */
export function getInstance(dbPath?: string): CertMappingStore {
  if (!_instance) {
    _instance = new CertMappingStore(dbPath ?? ':memory:');
  }
  return _instance;
}

// ──────────────────────────────────────────────
//  CertMappingStore class
// ──────────────────────────────────────────────

export class CertMappingStore {
  private db: Database.Database;
  private stmtInsert: Database.Statement<[string, string]>;
  private stmtSelect: Database.Statement<[string]>;
  private stmtDelete: Database.Statement<[string]>;
  private stmtDeleteByUser: Database.Statement<[string]>;

  /**
   * @param dbPath  SQLite database path. Use ':memory:' for ephemeral storage.
   */
  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(TABLE_DDL);

    this.stmtInsert = this.db.prepare(INSERT_SQL);
    this.stmtSelect = this.db.prepare(SELECT_SQL);
    this.stmtDelete = this.db.prepare(DELETE_SQL);
    this.stmtDeleteByUser = this.db.prepare(DELETE_BY_USER_SQL);

    logger.info({ dbPath }, 'CertMappingStore initialized');
  }

  /**
   * Record (or update) a mapping from certificate CN to database user.
   * Uses ON CONFLICT to upsert, so calling with an existing cert_cn
   * will update the db_user and refresh created_at.
   */
  setMapping(certCN: string, dbUser: string): void {
    if (typeof certCN !== 'string' || certCN.length === 0) {
      throw new Error('certCN must be a non-empty string');
    }
    if (typeof dbUser !== 'string' || dbUser.length === 0) {
      throw new Error('dbUser must be a non-empty string');
    }

    this.stmtInsert.run(certCN, dbUser);
    logger.debug({ certCN, dbUser }, 'Cert mapping set');
  }

  /**
   * Look up the database user associated with a certificate CN.
   *
   * @param certCN  The certificate Common Name (from `getPeerCertificate().subject.CN`)
   * @returns       The mapped database user, or `null` if no mapping exists.
   */
  getUserByCertCN(certCN: string): string | null {
    if (typeof certCN !== 'string' || certCN.length === 0) {
      return null;
    }

    const row = this.stmtSelect.get(certCN) as { db_user: string } | undefined;
    if (!row) {
      logger.debug({ certCN }, 'No cert mapping found');
      return null;
    }

    logger.debug({ certCN, dbUser: row.db_user }, 'Cert mapping resolved');
    return row.db_user;
  }

  /**
   * Remove a certificate-to-user mapping.
   *
   * @param certCN  The certificate Common Name to remove.
   * @returns       `true` if a row was deleted, `false` if no mapping existed.
   */
  removeMapping(certCN: string): boolean {
    if (typeof certCN !== 'string' || certCN.length === 0) {
      return false;
    }

    const result = this.stmtDelete.run(certCN);
    const deleted = result.changes > 0;
    if (deleted) {
      logger.debug({ certCN }, 'Cert mapping removed');
    } else {
      logger.debug({ certCN }, 'Cert mapping not found for removal');
    }
    return deleted;
  }

  /**
   * Remove all mappings for a given database user.
   * Useful for `DROP USER MAPPING` statements that only provide the db_user.
   *
   * @param dbUser  The database user whose mapping(s) should be removed.
   * @returns       The number of mappings removed (should be 0 or 1).
   */
  removeMappingByDbUser(dbUser: string): number {
    if (typeof dbUser !== 'string' || dbUser.length === 0) {
      return 0;
    }

    const result = this.stmtDeleteByUser.run(dbUser);
    if (result.changes > 0) {
      logger.debug({ dbUser, removed: result.changes }, 'Cert mapping(s) removed by db_user');
    } else {
      logger.debug({ dbUser }, 'No cert mapping found for removal by db_user');
    }
    return result.changes;
  }

  /**
   * Remove all mappings (useful in tests).
   */
  clear(): void {
    this.db.exec('DELETE FROM __cert_map');
    logger.debug('All cert mappings cleared');
  }

  /**
   * Return the number of stored mappings.
   */
  get size(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS cnt FROM __cert_map').get() as { cnt: number };
    return row.cnt;
  }

  /**
   * Close the underlying database connection.
   */
  close(): void {
    this.db.close();
    logger.debug('CertMappingStore db connection closed');
  }
}
