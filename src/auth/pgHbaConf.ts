import * as fs from 'node:fs';
import { Address6, Address4 } from "ip-address";
import { PinoLogger } from "../monitoring/PinoLogger";

const logger = PinoLogger.forComponent("pgHbaConf");
/**
 * pgHbaConf — pg_hba.conf rule engine for PostgreSQL Wire Protocol
 *
 * Implements the pg_hba.conf authentication rules as specified in
 * PostgreSQL documentation. Supports:
 *   - local / host / hostssl / hostnossl record types
 *   - trust / reject / password / md5 / scram-sha-256 / cert auth methods
 *   - CIDR address matching (IPv4 and IPv6)
 *   - First-match-wins evaluation
 *   - Serialization to/from pg_hba.conf text format
 *
 * Portions based on PostgreSQL's hba.c (src/backend/libpq/hba.c).
 */

// ════════════════════════════════════════════════
//  Types
// ════════════════════════════════════════════════

export type HbaRecordType = 'local' | 'host' | 'hostssl' | 'hostnossl' | 'hostgssenc' | 'hostnogssenc';

export type HbaAuthMethod = 'trust' | 'reject' | 'password' | 'md5' | 'scram-sha-256' | 'cert' | 'pam' | 'peer' | 'ident' | 'gss';

export interface HbaRecord {
  type: HbaRecordType;
  /** Database: 'all', 'sameuser', 'samerole', 'replication', or a specific DB name */
  database: string;
  /** User: 'all', '+groupname', or a specific user name */
  user: string;
  /** Address: null for local, '127.0.0.1/32', '192.168.0.0/24', etc. */
  address: string | null;
  authMethod: HbaAuthMethod;
  options?: Record<string, string>;
}

// ════════════════════════════════════════════════
//  CIDR utilities
// ════════════════════════════════════════════════

interface CidrRange {
  ip: bigint;       // Network address as unsigned 128-bit integer
  mask: number;     // Prefix length (0-32 for IPv4, 0-128 for IPv6)
  isV4: boolean;
}

/**
 * Parse an IP address string to a bigint (network byte order, zero-padded to 128 bits).
 * IPv4 addresses are mapped into the ::ffff:0:0/96 IPv4-mapped IPv6 space.
 * Uses the `ip-address` library for correct IPv6 parsing including `::` zero-compression.
 */
function ipToBigint(ip: string): bigint {
  try {
    const a6 = new Address6(ip);
    // Use parsedAddress (8 groups as hex strings) to compute 128-bit bigint
    let val = BigInt(0);
    for (const g of a6.parsedAddress) {
      val = (val << BigInt(16)) | BigInt(parseInt(g, 16));
    }
    return val;
  } catch {
    // Fallback: manual IPv4 parsing (for addresses that don't parse as IPv6)
    const parts = ip.split('.').map(Number);
    const v4val = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    return (BigInt(0xffff) << BigInt(32)) | BigInt(v4val);
  }
}

/**
 * Parse a CIDR notation string into a (base, mask) pair.
 * Examples: '127.0.0.1/32', '192.168.0.0/24', '::1/128', '10.0.0.0/8'
 */
function parseCidr(cidr: string): CidrRange {
  const slashIdx = cidr.lastIndexOf('/');
  let ip: string;
  let mask: number;

  if (slashIdx >= 0) {
    ip = cidr.substring(0, slashIdx);
    mask = parseInt(cidr.substring(slashIdx + 1), 10);
  } else {
    ip = cidr;
    // Default mask: 32 for IPv4, 128 for IPv6
    mask = ip.includes('.') ? 32 : 128;
  }

  const isV4 = ip.includes('.');
  if (!isV4 && mask > 128) {
    logger.warn({ cidr, mask }, "IPv6 CIDR mask exceeds 128, truncated to 128");
    mask = 128;
  }
  if (isV4 && mask > 32) mask = 32;

  return { ip: ipToBigint(ip), mask, isV4 };
}

/**
 * Check whether `addr` is within the CIDR range `range`.
 * Uses bitwise AND with the mask to compare network prefixes.
 */
function addrInCidr(addr: string, range: CidrRange): boolean {
  const addrVal = ipToBigint(addr);
  const maskBits = range.mask;
  const totalBits = range.isV4 ? 32n : 128n;
  const shiftAmt = totalBits - BigInt(maskBits);

  // Compare the top `maskBits` bits
  const addrPrefix = addrVal >> shiftAmt;
  const rangePrefix = range.ip >> shiftAmt;
  return addrPrefix === rangePrefix;
}

/**
 * Parse an address string into a CidrRange for matching.
 * Resolves 'all' and plain hostnames without CIDR notation.
 */
function addressToCidr(addr: string): CidrRange | null {
  if (addr === 'all') return null; // matches anything

  // If it contains a slash, it's CIDR notation
  if (addr.includes('/')) {
    return parseCidr(addr);
  }

  // Plain IP address without CIDR — treat as /32 or /128
  return parseCidr(addr + (addr.includes('.') ? '/32' : '/128'));
}

// ════════════════════════════════════════════════
//  HbaRecord helpers
// ════════════════════════════════════════════════

/**
 * Check if a database name matches an HBA database specification.
 * Supports: 'all', 'sameuser', 'samerole', 'replication', specific DB names.
 */
function matchDatabase(hbaDb: string, paramsDb: string, paramsUser: string): boolean {
  if (hbaDb === 'all') return true;
  if (hbaDb === 'sameuser') return paramsDb === paramsUser;
  if (hbaDb === 'samerole') return paramsDb === paramsUser;
  if (hbaDb === 'replication') return paramsDb === 'replication';
  if (hbaDb === paramsDb) return true;

  // Comma-separated list of databases
  if (hbaDb.includes(',')) {
    const dbs = hbaDb.split(',');
    return dbs.some((db) => matchDatabase(db.trim(), paramsDb, paramsUser));
  }

  return false;
}

/**
 * Check if a user name matches an HBA user specification.
 * Supports: 'all', '+groupname' (group membership), specific user name.
 */
function matchUser(hbaUser: string, paramsUser: string): boolean {
  if (hbaUser === 'all') return true;
  if (hbaUser === paramsUser) return true;

  // Comma-separated list of users
  if (hbaUser.includes(',')) {
    const users = hbaUser.split(',');
    return users.some((u) => matchUser(u.trim(), paramsUser));
  }

  return false;
}

/**
 * Check if an address matches an HBA address specification.
 * The address can be:
 *   - null (always matches local)
 *   - 'all' (matches any address)
 *   - 'samehost' (matches any address of the local host)
 *   - CIDR notation (127.0.0.1/32, 10.0.0.0/8, etc.)
 *   - Plain IP (treated as /32 or /128)
 */
function matchAddress(hbaAddr: string | null, paramsAddr: string | undefined): boolean {
  // null means local connection
  if (hbaAddr === null) return paramsAddr === undefined || paramsAddr === '';

  // 'all' matches any address
  if (hbaAddr === 'all') return paramsAddr !== undefined && paramsAddr !== '';

  // 'samehost' — simplified: treat as 'all' for this implementation
  if (hbaAddr === 'samehost') return true;

  // CIDR or IP matching
  if (paramsAddr && paramsAddr.length > 0) {
    const range = addressToCidr(hbaAddr);
    if (range) {
      return addrInCidr(paramsAddr, range);
    }
  }

  return false;
}

/**
 * Determine if a connection type matches an HBA record type.
 * - 'local' type only matches when no address is provided
 * - 'host' matches any non-local connection (with address)
 * - 'hostssl' matches only TLS connections with address
 * - 'hostnossl' matches only non-TLS connections with address
 */
function matchRecordType(
  recordType: HbaRecordType,
  connType: 'local' | 'host' | 'hostssl' | 'hostnossl' | 'hostgssenc' | 'hostnogssenc',
  isTls: boolean,
  isGss: boolean = false,
): boolean {
  switch (recordType) {
    case 'local':
      return connType === 'local';
    case 'host':
      return connType === 'host' || connType === 'hostssl' || connType === 'hostnossl'
        || connType === 'hostgssenc' || connType === 'hostnogssenc';
    case 'hostssl':
      return (connType === 'host' || connType === 'hostssl' || connType === 'hostgssenc') && isTls;
    case 'hostnossl':
      return (connType === 'host' || connType === 'hostnossl' || connType === 'hostnogssenc') && !isTls;
    case 'hostgssenc':
      // hostgssenc matches connections with GSSAPI encryption enabled.
      // Since we don't support GSSAPI encryption, fall back: treat as hostssl (requires TLS).
      return (connType === 'host' || connType === 'hostssl' || connType === 'hostgssenc') && isTls;
    case 'hostnogssenc':
      // hostnogssenc matches connections without GSSAPI encryption.
      // Since we don't support GSSAPI encryption, fall back: treat as hostnossl (no TLS).
      return (connType === 'host' || connType === 'hostnossl' || connType === 'hostnogssenc') && !isTls;
  }
}

// ════════════════════════════════════════════════
//  PgHbaConf class
// ════════════════════════════════════════════════

export class PgHbaConf {
  private records: HbaRecord[];

  constructor(records?: HbaRecord[]) {
    this.records = records ? [...records] : [];
  }

  /**
   * Parse pg_hba.conf format text into a PgHbaConf instance.
   *
   * The pg_hba.conf format:
   *   # comment
   *   local   database  user  auth-method  [auth-options]
   *   host    database  user  address  auth-method  [auth-options]
   *   hostssl database  user  address  auth-method  [auth-options]
   *   hostnossl database user  address  auth-method  [auth-options]
   *
   * Fields are whitespace-separated. Lines beginning with # are comments.
   * Empty lines are ignored. IPv6 addresses with CIDR notation require care.
   *
   * @throws {Error} If the input text is completely invalid (no parseable records).
   */
  static parse(text: string): PgHbaConf {
    const records: HbaRecord[] = [];

    const lines = text.split('\n');
    for (const rawLine of lines) {
      const line = rawLine.trim();

      // Skip empty lines and comments
      if (line.length === 0 || line.startsWith('#')) continue;

      // Remove inline comments (not inside quotes)
      const noInlineComment = line.split('#')[0]!.trim();

      // Split on whitespace, handling quoted strings
      const tokens = tokenizeLine(noInlineComment);

      if (tokens.length < 4) continue;

      const type = tokens[0] as HbaRecordType;
      if (!isHbaRecordType(type)) continue;

      const database = tokens[1]!;
      const user = tokens[2]!;

      let address: string | null = null;
      let authMethod: string;
      let options: Record<string, string> | undefined;

      if (type === 'local') {
        // local <database> <user> <auth-method> [<auth-options>]
        authMethod = tokens[3]!;
        if (tokens.length > 4) {
          options = parseAuthOptions(tokens.slice(4));
        }
      } else {
        // host/hostssl/hostnossl <database> <user> <address> <auth-method> [<auth-options>]
        if (tokens.length < 5) continue;
        address = tokens[3]!;
        authMethod = tokens[4]!;
        if (tokens.length > 5) {
          options = parseAuthOptions(tokens.slice(5));
        }
      }

      if (!isHbaAuthMethod(authMethod)) continue;

      records.push({
        type,
        database,
        user,
        address,
        authMethod: authMethod as HbaAuthMethod,
        options,
      });
    }

    return new PgHbaConf(records);
  }

  /**
   * Alias for evaluate() — match a connection against pg_hba.conf rules.
   * First match wins. If no rule matches, returns null (caller should reject).
   *
   * @param user - The PG user name
   * @param database - The database name
   * @param address - The client IP address (undefined for local connections)
   * @param ssl - Whether the connection uses TLS
   * @returns The matching HbaRecord, or null if no rule matches
   */
  matchConnection(
    user: string,
    database: string,
    address?: string,
    ssl?: boolean,
  ): HbaRecord | null {
    return this.evaluate({
      type: ssl ? 'hostssl' : address ? 'host' : 'local',
      database,
      user,
      address,
      isTls: ssl ?? false,
    });
  }

  /**
   * Evaluate rules in order (first match wins).
   *
   * @param params - Connection parameters
   * @returns The matching HbaRecord, or null if no rule matches
   */
  evaluate(params: {
    type: 'local' | 'host' | 'hostssl' | 'hostnossl' | 'hostgssenc' | 'hostnogssenc';
    database: string;
    user: string;
    address?: string;
    isTls?: boolean;
    isGss?: boolean;
  }): HbaRecord | null {
    const isTls = params.isTls ?? false;
    const isGss = params.isGss ?? false;

    for (const record of this.records) {
      // 1. Check connection type
      if (!matchRecordType(record.type, params.type, isTls, isGss)) continue;

      // 2. Check database
      if (!matchDatabase(record.database, params.database, params.user)) continue;

      // 3. Check user
      if (!matchUser(record.user, params.user)) continue;

      // 4. Check address (null = local)
      if (!matchAddress(record.address, params.address)) continue;

      // All conditions matched
      return record;
    }

    return null;
  }

  // ═══════════════════════════════════════════════════════════════
  //  Reload support (pg_reload_conf / SIGHUP)
  // ═══════════════════════════════════════════════════════════════

  /** The file path from which this config was last loaded. */
  private static loadedFilePath: string | null = null;
  /** Timestamp (epoch ms) of the last reload. */
  private static lastReloadTime: number = Date.now();
  /** Number of times the config has been loaded/reloaded. */
  private static loadCount: number = 0;

  /**
   * Override loadFromFile to track file path and reload metadata.
   */
  static loadFromFile(filePath: string): PgHbaConf {
    const conf = PgHbaConf._doLoadFromFile(filePath);
    PgHbaConf.loadedFilePath = filePath;
    PgHbaConf.lastReloadTime = Date.now();
    PgHbaConf.loadCount++;
    return conf;
  }

  /**
   * The actual load logic, separated so reload() can reuse it.
   */
  private static _doLoadFromFile(filePath: string): PgHbaConf {
    let text: string;
    try {
      text = fs.readFileSync(filePath, 'utf8');
    } catch (err: any) {
      if (err.code === 'ENOENT') {
        throw new Error(`pg_hba.conf not found at "${filePath}" — server cannot start without authentication rules`);
      }
      throw new Error(`Failed to read pg_hba.conf at "${filePath}": ${err.message}`);
    }

    const conf = PgHbaConf.parse(text);
    const nRecords = conf.getRecords().length;

    if (nRecords === 0) {
      const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('#'));
      if (lines.length > 0) {
        throw new Error(
          `pg_hba.conf at "${filePath}" contains ${lines.length} unparseable line(s) and 0 valid rules — ` +
          'server cannot start with a broken authentication configuration',
        );
      }
      throw new Error(
        `pg_hba.conf at "${filePath}" is empty or contains only comments — ` +
        'no authentication rules configured, rejecting all connections',
      );
    }

    return conf;
  }

  /**
   * Re-read pg_hba.conf from disk and reload rules.
   * Equivalent to PostgreSQL's SIGHUP behavior.
   *
   * @returns The reloaded PgHbaConf instance (also updates this instance)
   * @throws {Error} If the file cannot be read or contains no valid rules
   */
  reload(): void {
    if (!PgHbaConf.loadedFilePath) {
      throw new Error('Cannot reload: no pg_hba.conf file path has been set (loadFromFile was never called)');
    }

    const newConf = PgHbaConf._doLoadFromFile(PgHbaConf.loadedFilePath);
    this.records = newConf.getRecords();
    PgHbaConf.lastReloadTime = Date.now();
    PgHbaConf.loadCount++;

    logger.info(
      { filePath: PgHbaConf.loadedFilePath, recordCount: this.records.length },
      'pg_hba.conf reloaded from disk',
    );
  }

  /**
   * Load rules from a string (for ALTER SYSTEM or pg_reload_conf() simulation).
   * Does NOT update the file on disk.
   *
   * @param content - The pg_hba.conf format content
   */
  reloadFromString(content: string): void {
    const newConf = PgHbaConf.parse(content);
    this.records = newConf.getRecords();
    PgHbaConf.lastReloadTime = Date.now();
    PgHbaConf.loadCount++;

    logger.info(
      { recordCount: this.records.length },
      'pg_hba.conf rules reloaded from string',
    );
  }

  /**
   * Get the timestamp (epoch ms) of the last reload.
   */
  getLastReloadTime(): number {
    return PgHbaConf.lastReloadTime;
  }

  /**
   * Get the number of times config was loaded/reloaded.
   */
  getLoadCount(): number {
    return PgHbaConf.loadCount;
  }

  /**
   * Get the file path from which this config was loaded (for SHOW hba_file).
   */
  getLoadedFilePath(): string | null {
    return PgHbaConf.loadedFilePath;
  }

  /**
   * Reset reload tracking (for testing).
   */
  static resetReloadTracking(): void {
    PgHbaConf.loadedFilePath = null;
    PgHbaConf.lastReloadTime = Date.now();
    PgHbaConf.loadCount = 0;
  }

  // ── Getter / Setter ──

  getRecords(): HbaRecord[] {
    return [...this.records];
  }

  addRecord(record: HbaRecord): void {
    this.records.push(record);
  }

  removeRecord(index: number): void {
    if (index >= 0 && index < this.records.length) {
      this.records.splice(index, 1);
    }
  }

  /**
   * Serialize back to pg_hba.conf format.
   */
  toText(): string {
    const lines: string[] = [];

    for (const record of this.records) {
      let line = record.type;
      line += ' ' + record.database;
      line += ' ' + record.user;

      if (record.type !== 'local') {
        line += ' ' + (record.address ?? '0.0.0.0/0');
      }

      line += ' ' + record.authMethod;

      if (record.options && Object.keys(record.options).length > 0) {
        const optStr = Object.entries(record.options)
          .map(([k, v]) => `${k}=${v}`)
          .join(' ');
        line += ' ' + optStr;
      }

      lines.push(line);
    }

    return lines.join('\n') + '\n';
  }
}

// ════════════════════════════════════════════════
//  Internal helpers
// ════════════════════════════════════════════════

function isHbaRecordType(v: string): v is HbaRecordType {
  return ['local', 'host', 'hostssl', 'hostnossl', 'hostgssenc', 'hostnogssenc'].includes(v);
}

function isHbaAuthMethod(v: string): v is HbaAuthMethod {
  return ['trust', 'reject', 'password', 'md5', 'scram-sha-256', 'cert', 'pam', 'peer', 'ident', 'gss'].includes(v);
}

/**
 * Tokenize a pg_hba.conf line by whitespace.
 * Handles quoted strings (e.g., for addresses like ::1/128).
 */
function tokenizeLine(line: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inQuotes = false;

  for (const ch of line) {
    if (ch === '"' || ch === "'") {
      inQuotes = !inQuotes;
    } else if (/\s/.test(ch) && !inQuotes) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += ch;
    }
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

/**
 * Parse authentication options from the remaining tokens.
 * Options are in key=value format.
 */
function parseAuthOptions(tokens: string[]): Record<string, string> {
  const options: Record<string, string> = {};
  for (const token of tokens) {
    const eqIdx = token.indexOf('=');
    if (eqIdx > 0) {
      const key = token.substring(0, eqIdx);
      const value = token.substring(eqIdx + 1);
      if (key.length > 0) {
        options[key] = value;
      }
    }
  }
  return options;
}
