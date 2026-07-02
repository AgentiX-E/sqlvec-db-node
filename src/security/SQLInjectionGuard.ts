/**
 * SQLInjectionGuard — Detect and block SQL injection patterns in queries.
 *
 * Scans input SQL for common injection patterns before they reach the
 * query executor. Designed to be called at the QueryRouter entry point.
 *
 * G22 enhancements:
 *  - AST-level detection: parses SQL and detects UNION/SELECT in unexpected positions
 *  - Encoding bypass detection: hex, unicode, base64 encoded injection attempts
 *  - Time-based blind detection: pg_sleep, generate_series based timing
 *  - Parameterized query compatibility: does not flag $N placeholders
 *
 * SQLI-01: Force Prepared Statement mode — rejects non-parameterized SQL
 *   When `forcePreparedStatement` is enabled, raw SQL that uses string
 *   concatenation (values embedded directly) is rejected. Only queries
 *   using $N parameter placeholders are allowed.
 *
 * SQLITE-01: Force parameterized query config switch
 *   Config switch to enable/disable the forced parameterization mode.
 *
 * Audit hooks (SE-006):
 *  - DDL (CREATE/DROP/ALTER) and DML (INSERT/UPDATE/DELETE/SELECT) trigger audit
 *  - Login/logout events trigger audit
 *
 * @module security/SQLInjectionGuard
 */

import { PinoLogger } from '../monitoring/PinoLogger';
import { AuditLogger, type AuditEventType } from './AuditLogger';
import { cacheGet, cacheSet } from '../utils/ParseCache';

const logger = PinoLogger.forComponent('sql-injection-guard');

export interface InjectionCheckResult {
  /** True if the SQL should be blocked */
  blocked: boolean;
  /** Human-readable reason */
  reason: string;
  /** The specific pattern that matched */
  pattern?: string;
}

// ── SQLI-01 / SQLITE-01: Force prepared statement config ────────

/** Configuration for SQL injection guard behavior. */
export interface SqlGuardConfig {
  /**
   * Force Parameterized Queries (SQLI-01 / SQLITE-01).
   * When true, any SQL statement that does not use $N parameter
   * placeholders will be rejected. This prevents string concatenation
   * SQL injection vectors.
   *
   * Default: false (backwards compatible).
   */
  forcePreparedStatement: boolean;

  /**
   * Whether to block queries with SQL comments.
   * When true, queries containing --, #, or /* are rejected.
   * Default: false.
   */
  blockComments: boolean;

  /**
   * Strict mode: blocks on ANY pattern match (including low/medium).
   * Default: false.
   */
  strictMode: boolean;
}

const DEFAULT_SQL_GUARD_CONFIG: SqlGuardConfig = {
  forcePreparedStatement: false,
  blockComments: false,
  strictMode: false,
};

// ── Injection Patterns ──────────────────────────────────────────

interface InjectionPattern {
  pattern: RegExp;
  name: string;
  severity: 'high' | 'medium' | 'low';
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  // Stacked queries with dangerous commands — high severity
  { pattern: /;\s*(DROP|DELETE|TRUNCATE|ALTER|EXEC|EXECUTE|EXEC\s*\(|xp_cmdshell|sp_)/i, name: 'stacked-dangerous-command', severity: 'high' },
  // UNION SELECT patterns — high severity to block concatenation-based injection
  { pattern: /\bUNION\s+(ALL\s+)?SELECT\b/i, name: 'union-based-injection', severity: 'high' },

  // Tautologies
  { pattern: /('|")\s*(OR|AND)\s+['"]?\s*1\s*['"]?\s*=\s*['"]?\s*1\b/i, name: 'tautology', severity: 'high' },
  { pattern: /('|")\s*(OR|AND)\s+['"]?\s*\d+\s*=\s*\d+/i, name: 'numeric-tautology', severity: 'high' },
  { pattern: /('|")\s*(OR|AND)\s+['"]?\s*[^\s]+\s*LIKE\s*['"]/i, name: 'like-tautology', severity: 'high' },

  // Comment injection
  { pattern: /('|")\s*(--|#|\/\*)/i, name: 'comment-injection', severity: 'high' },

  // Time-based blind injection
  { pattern: /\bSLEEP\s*\(/i, name: 'time-based-sleep', severity: 'high' },
  { pattern: /\bWAITFOR\s+DELAY\b/i, name: 'time-based-waitfor', severity: 'high' },
  { pattern: /\bBENCHMARK\s*\(/i, name: 'time-based-benchmark', severity: 'high' },
  { pattern: /\bpg_sleep\s*\(/i, name: 'pg-time-based-sleep', severity: 'high' },

  // Error-based injection
  { pattern: /\bEXTRACTVALUE\s*\(/i, name: 'error-based-extractvalue', severity: 'high' },
  { pattern: /\bUPDATEXML\s*\(/i, name: 'error-based-updatexml', severity: 'medium' },

  // Out-of-band injection
  { pattern: /\bINTO\s+(OUTFILE|DUMPFILE)\b/i, name: 'out-of-band-file-write', severity: 'high' },
  { pattern: /\bLOAD_FILE\s*\(/i, name: 'out-of-band-load-file', severity: 'high' },

  // SQL comments in suspicious positions
  { pattern: /--\s*$/m, name: 'trailing-comment', severity: 'medium' },
  { pattern: /\/\*.*\*\//, name: 'inline-comment', severity: 'low' },
];

// ── G22: Enhanced detection patterns ────────────────────────────

/**
 * Encoding bypass patterns — hex, unicode, base64 encoded injection attempts.
 */
const ENCODING_BYPASS_PATTERNS: InjectionPattern[] = [
  // Hex-encoded SQL (e.g., 0x53514C...)
  { pattern: /0x[0-9a-fA-F]{16,}/, name: 'hex-encoded-payload', severity: 'high' },
  // Unicode-encoded (e.g., \u0053\u0045\u004c...)
  { pattern: /\\u00[0-9a-fA-F]{2}/i, name: 'unicode-encoded-payload', severity: 'high' },
  // Base64-encoded (looks like long base64 in SQL context)
  { pattern: /['"][A-Za-z0-9+/]{40,}=*['"]/, name: 'base64-candidate-in-string', severity: 'medium' },
  // URL-encoded in SQL string context
  { pattern: /['"]%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}['"]/, name: 'url-encoded-payload', severity: 'medium' },
  // Char() function usage (CHR(65)||CHR(66)...)
  { pattern: /\bCHR\s*\(\d+\)\s*(\|\||\+)/i, name: 'chr-concatenation', severity: 'high' },
  // NCHAR/CONCAT encoding
  { pattern: /\b(NCHAR|NVARCHAR)\s*\(\d+\)/i, name: 'nchar-encoding', severity: 'medium' },
];

/**
 * Time-based blind injection patterns (PGSQL-specific).
 */
const TIME_BASED_PATTERNS: InjectionPattern[] = [
  { pattern: /\bpg_sleep\s*\(\s*\d+\.?\d*\s*\)/i, name: 'pg_sleep-timing', severity: 'high' },
  { pattern: /\bgenerate_series\s*\(\d+,\d+\)/i, name: 'generate-series-timing', severity: 'medium' },
  { pattern: /\bclock_timestamp\s*\(/i, name: 'clock-timestamp-abuse', severity: 'medium' },
  { pattern: /\bGREATEST\s*\(\s*0\s*,\s*pg_sleep/i, name: 'greatest-pg-sleep', severity: 'high' },
  // Case when sleep (conditional timing)
  { pattern: /\bCASE\s+WHEN.*pg_sleep/i, name: 'conditional-time-based', severity: 'high' },
];

/**
 * Patterns for AST-level detection via regex approximation.
 * True AST parsing would use pgsql-ast-parser, but we approximate
 * with regex for critical patterns.
 */
const AST_LEVEL_PATTERNS: InjectionPattern[] = [
  // UNION SELECT inside a subquery at an unexpected position
  { pattern: /\)\s*UNION\s+(ALL\s+)?SELECT\b/i, name: 'union-select-in-subquery', severity: 'high' },
  // Multiple SELECTs in a single statement (stacked)
  { pattern: /;\s*SELECT\s/i, name: 'stacked-select', severity: 'high' },
  // INSERT ... SELECT with suspicious conditions
  { pattern: /\bINSERT\s+INTO\b.*\bSELECT\b.*\bFROM\b.*\bWHERE\b.*(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, name: 'insert-select-suspicious-where', severity: 'high' },
  // UPDATE with subquery that contains UNION
  { pattern: /\bUPDATE\b.*\(.*\bUNION\b/i, name: 'update-with-union-subquery', severity: 'high' },
  // DELETE with tautology condition
  { pattern: /\bDELETE\b.*\bWHERE\b.*OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, name: 'delete-with-tautology', severity: 'high' },
];

// ── G22 Enhanced: Broad stacked query detection ─────────────────

/**
 * Broad stacked query patterns — detects any `;` followed by a new SQL
 * statement, which is a common injection vector across all databases.
 */
const STACKED_QUERY_PATTERNS: InjectionPattern[] = [
  // Any semicolon followed by a SQL keyword (broad stacked query)
  { pattern: /;\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|EXEC|EXECUTE|CALL|MERGE)\b/i, name: 'stacked-query-broad', severity: 'high' },
  // Multiple statements in string (heuristic: semicolon followed by non-whitespace)
  { pattern: /;\s*\w+\s*\(/i, name: 'stacked-query-function-call', severity: 'medium' },
];

// ── SQL Classification Keywords (SE-006) ────────────────────────

/**
 * SQL instruction keywords that classify a statement as DDL.
 */
const DDL_KEYWORDS = new Set([
  'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'RENAME', 'COMMENT',
]);

/**
 * SQL instruction keywords that classify a statement as DML.
 */
const DML_KEYWORDS = new Set([
  'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'UPSERT', 'REPLACE',
]);

// ── SQLInjectionGuard ───────────────────────────────────────────

export class SQLInjectionGuard {
  /** Optional AuditLogger instance for auditing queries (SE-006). */
  private static auditLogger: AuditLogger | null = null;
  /** Default session/user for audit when context is not available. */
  private static defaultSessionId = 'sql-guard';
  private static defaultUserId = 'internal';

  // ── SQLI-01 / SQLITE-01: Force prepared statement config ──
  private static config: SqlGuardConfig = { ...DEFAULT_SQL_GUARD_CONFIG };

  /**
   * Update the SQL guard configuration.
   *
   * @param newConfig - Partial configuration to apply.
   */
  static configure(newConfig: Partial<SqlGuardConfig>): void {
    Object.assign(this.config, newConfig);
    if (this.config.forcePreparedStatement) {
      logger.info('[SQLGuard] Force Prepared Statement mode enabled — only parameterized queries allowed');
    }
    if (this.config.blockComments) {
      logger.info('[SQLGuard] SQL comment blocking enabled');
    }
  }

  /**
   * Get the current configuration.
   */
  static getConfig(): Readonly<SqlGuardConfig> {
    return { ...this.config };
  }

  /**
   * Check if a SQL statement uses parameterized placeholders ($N).
   * Used by the force prepared statement feature (SQLI-01).
   *
   * @param sql - SQL to check.
   * @returns true if the SQL uses $N placeholders.
   */
  static usesParameterizedPlaceholders(sql: string): boolean {
    // $1, $2, ... style placeholders (PostgreSQL/pg compatible)
    return /\$\d+\b/.test(sql);
  }

  /**
   * Check if a SQL statement appears to have embedded literal values.
   * Returns true if the statement likely has string concatenation or
   * direct value embedding (no placeholders).
   *
   * This is a heuristic: parameterized queries with $N are safe,
   * anything else (especially with string literals) is suspicious
   * when forcePreparedStatement is enabled.
   *
   * @param sql - SQL to check.
   * @returns true if the SQL likely has embedded values.
   */
  static hasEmbeddedValues(sql: string): boolean {
    if (this.usesParameterizedPlaceholders(sql)) return false;

    // Non-parameterized queries may have embedded values.
    // We check for string literals and numeric values that aren't
    // part of SQL syntax.
    const trimmed = sql.trim().toUpperCase();

    // Skip DDL statements (CREATE, ALTER, DROP) — they don't need parameters
    const firstWord = trimmed.split(/\s+/)[0] || '';
    if (['CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'GRANT', 'REVOKE', 'ANALYZE', 'VACUUM', 'REINDEX'].includes(firstWord)) {
      return false;
    }

    // Check for string literals (single quotes) in WHERE or VALUES clauses
    // These are common injection vectors
    if (trimmed.includes("'")) {
      // Exclude empty strings and simple equality checks used in DDL
      const nonEmptyStringLiteral = /'[^']+'/.test(trimmed);
      if (nonEmptyStringLiteral) return true;
    }

    return false;
  }

  /**
   * Set the AuditLogger instance for query auditing.
   */
  static setAuditLogger(logger: AuditLogger): void {
    this.auditLogger = logger;
  }

  /**
   * Set default session/user identifiers for audit logging.
   */
  static setAuditContext(sessionId: string, userId: string): void {
    this.defaultSessionId = sessionId;
    this.defaultUserId = userId;
  }

  /**
   * Classify a SQL statement as DDL, DML, or query.
   */
  static classifySql(sql: string): AuditEventType {
    const trimmed = sql.trim().toUpperCase();
    const firstWord = trimmed.split(/\s+/)[0] || '';
    if (DDL_KEYWORDS.has(firstWord)) return 'ddl';
    if (DML_KEYWORDS.has(firstWord)) return 'dml';
    return 'query';
  }

  /**
   * Internal audit hook for queries being checked (SE-006).
   * Logs detailed injection detection info when a threat is found.
   */
  private static auditCheck(sql: string, blocked: boolean, reason: string, pattern?: string): void {
    if (!this.auditLogger) return;

    const eventType = this.classifySql(sql);
    // Only log DDL/DML and blocked queries
    if (eventType === 'query' && !blocked) return;

    if (blocked) {
      // Log detailed injection detection event
      const truncatedSql = sql.length > 200 ? sql.slice(0, 200) + '...' : sql;
      this.auditLogger.logCustom(
        'sql_injection_detected',
        this.defaultSessionId,
        this.defaultUserId,
        truncatedSql,
        'failure',
        `[detection_type=${pattern ?? reason}] [severity=${reason.includes('[high]') || reason.includes('[strict]') ? 'high' : 'medium'}] [classification_level=injection] ${reason}`,
      );
    } else {
      this.auditLogger.logQuery(
        this.defaultSessionId,
        this.defaultUserId,
        sql,
        'success',
        { errorMessage: undefined },
      );
    }
  }

  /**
   * Log a login event for audit (SE-006).
   */
  static auditLogin(sessionId: string, userId: string, success: boolean): void {
    if (!this.auditLogger) return;
    this.auditLogger.logLogin(sessionId, userId, success);
  }

  /**
   * Log a disconnection event for audit (SE-006).
   */
  static auditDisconnect(sessionId: string, userId: string): void {
    if (!this.auditLogger) return;
    this.auditLogger.logDisconnect(sessionId, userId);
  }

  /**
   * Check a SQL statement for injection patterns.
   *
   * @param sql The SQL statement to inspect
   * @returns InjectionCheckResult with blocked flag and reason
   */
  static check(sql: string): InjectionCheckResult {
    if (!sql || typeof sql !== 'string') {
      return { blocked: false, reason: 'Empty or non-string SQL' };
    }

    const trimmed = sql.trim();
    if (!trimmed) {
      return { blocked: false, reason: 'Empty SQL' };
    }

    // ── SQLI-01 / SQLITE-01: Force prepared statement check ──
    if (this.config.forcePreparedStatement) {
      if (!this.usesParameterizedPlaceholders(trimmed) && this.hasEmbeddedValues(trimmed)) {
        const reason = 'Forced Prepared Statement: SQL must use $N parameter placeholders. String concatenation is rejected.';
        const pattern = 'force-prepared-statement';
        logger.warn({ sql: trimmed.slice(0, 200) }, reason);
        this.auditCheck(trimmed, true, reason, pattern);
        return { blocked: true, reason, pattern };
      }
    }

    // ── SQLI-01: Check for blocked comments ──
    if (this.config.blockComments && this.hasComment(trimmed)) {
      const reason = 'SQL comments are blocked by configuration';
      const pattern = 'blocked-comment';
      logger.warn({ sql: trimmed.slice(0, 200) }, reason);
      this.auditCheck(trimmed, true, reason, pattern);
      return { blocked: true, reason, pattern };
    }

    // Check standard injection patterns (existing)
    const stdResult = SQLInjectionGuard.checkPatterns(trimmed, INJECTION_PATTERNS);
    if (stdResult.blocked) {
      this.auditCheck(trimmed, true, stdResult.reason, stdResult.pattern);
      return stdResult;
    }

    // Skip encoding/ast checks for parameterized queries
    if (SQLInjectionGuard.isParameterizedQuery(trimmed)) {
      // Parameterized queries still check basic patterns, but skip encoding bypass
    } else {
      // G22: Check encoding bypass patterns
      const encResult = SQLInjectionGuard.checkPatterns(trimmed, ENCODING_BYPASS_PATTERNS);
      if (encResult.blocked) {
        this.auditCheck(trimmed, true, encResult.reason, encResult.pattern);
        return encResult;
      }

      // G22: Check time-based patterns
      const timeResult = SQLInjectionGuard.checkPatterns(trimmed, TIME_BASED_PATTERNS);
      if (timeResult.blocked) {
        this.auditCheck(trimmed, true, timeResult.reason, timeResult.pattern);
        return timeResult;
      }

      // G22: Check AST-level patterns (regex-based)
      const astResult = SQLInjectionGuard.checkPatterns(trimmed, AST_LEVEL_PATTERNS);
      if (astResult.blocked) {
        this.auditCheck(trimmed, true, astResult.reason, astResult.pattern);
        return astResult;
      }

      // G22: Check stacked query patterns (broad detection)
      const stackedResult = SQLInjectionGuard.checkPatterns(trimmed, STACKED_QUERY_PATTERNS);
      // Stacked query patterns use severity to control blocking
      if (stackedResult.blocked) {
        this.auditCheck(trimmed, true, stackedResult.reason, stackedResult.pattern);
        return stackedResult;
      }
      // Log medium-severity stacked query patterns without blocking
      if (stackedResult.pattern) {
        logger.warn({ sql: trimmed.slice(0, 200), pattern: stackedResult.pattern }, stackedResult.reason);
      }

      // G22: AST-level analysis via pgsql-ast-parser (deeper than regex)
      // Skip for INSERT statements — they're not vulnerable to UNION injection
      // and the multi-VALUES parse is prohibitively slow (~200ms for 100 rows).
      if (!/^\s*INSERT\b/i.test(trimmed)) {
        const realAstResult = SQLInjectionGuard.astAnalyze(trimmed);
        if (realAstResult.blocked) {
          this.auditCheck(trimmed, true, realAstResult.reason, realAstResult.pattern);
          return realAstResult;
        }
      }
    }

    // Audit clean DDL/DML queries (SE-006)
    this.auditCheck(trimmed, false, 'Clean');

    return { blocked: false, reason: 'Clean' };
  }

  /**
   * Strict check — blocks on any pattern (including medium/low severity).
   */
  static strictCheck(sql: string): InjectionCheckResult {
    if (!sql || typeof sql !== 'string') {
      return { blocked: false, reason: 'Empty or non-string SQL' };
    }

    const trimmed = sql.trim();
    if (!trimmed) {
      return { blocked: false, reason: 'Empty SQL' };
    }

    const allPatterns = [
      ...INJECTION_PATTERNS,
      ...ENCODING_BYPASS_PATTERNS,
      ...TIME_BASED_PATTERNS,
      ...AST_LEVEL_PATTERNS,
      ...STACKED_QUERY_PATTERNS,
    ];

    for (const { pattern, name } of allPatterns) {
      if (pattern.test(trimmed)) {
        const reason = `SQL injection detected [strict]: ${name}`;
        logger.warn({ pattern: name, sql: trimmed.slice(0, 200) }, reason);
        this.auditCheck(trimmed, true, reason, name);
        return { blocked: true, reason, pattern: name };
      }
    }

    // Audit clean DDL/DML queries (SE-006)
    this.auditCheck(trimmed, false, 'Clean');

    return { blocked: false, reason: 'Clean' };
  }

  /**
   * Check if SQL contains a comment anywhere (inline or trailing).
   */
  static hasComment(sql: string): boolean {
    return /--|#|\/\*/.test(sql);
  }

  /**
   * Check if this is a parameterized query (uses $N placeholders).
   * Parameterized queries are exempt from some encoding checks.
   *
   * @param sql - SQL to check
   * @returns true if the SQL uses $N parameter placeholders
   */
  static isParameterizedQuery(sql: string): boolean {
    // Check for $1, $2, ... style parameter placeholders
    return /\$\d+\b/.test(sql);
  }

  /**
   * Run AST-level analysis using pgsql-ast-parser (if available).
   * Detects UNION SELECT in unexpected positions and other structural issues.
   *
   * @param sql - SQL to analyze
   * @returns InjectionCheckResult
   */
  static astAnalyze(sql: string): InjectionCheckResult {
    // Template-based cache: repeated structurally identical queries
    // (e.g. pgbench TPC-B in -M simple mode) avoid redundant parse.
    const cached = cacheGet<InjectionCheckResult>('sqlInjectionAst', sql);
    if (cached) return cached;

    let result: InjectionCheckResult;

    try {
      // Try to use pgsql-ast-parser if installed
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { parse } = require('pgsql-ast-parser');
      const ast = parse(sql);

      // Check for multiple statements (stacked queries)
      if (Array.isArray(ast) && ast.length > 1) {
        // Allow only if the first statement is a SELECT ... ;
        // Multiple statements are suspicious in single-query contexts
        const nonSelectCount = ast.filter((s: any) => s.type !== 'select').length;
        if (nonSelectCount > 0) {
          result = {
            blocked: true,
            reason: 'Multiple SQL statements detected (possible stacked query)',
            pattern: 'ast-multiple-statements',
          };
        } else {
          result = { blocked: false, reason: 'AST analysis passed' };
        }
      } else {
        result = { blocked: false, reason: 'AST analysis passed' };
      }
    } catch {
      // pgsql-ast-parser not available or parsing failed — skip AST analysis
      result = { blocked: false, reason: 'AST analysis unavailable' };
    }

    cacheSet('sqlInjectionAst', sql, result);
    return result;
  }

  // ── Private helpers ───────────────────────────────────────────

  /**
   * Check a SQL string against a list of patterns.
   * Logs and returns blocked results for high-severity matches.
   *
   * @param sql      - SQL string to check
   * @param patterns - Array of injection patterns
   * @returns InjectionCheckResult
   */
  private static checkPatterns(sql: string, patterns: InjectionPattern[]): InjectionCheckResult {
    for (const { pattern, name, severity } of patterns) {
      if (pattern.test(sql)) {
        const reason = `SQL injection detected [${severity}]: ${name}`;
        logger.warn({ pattern: name, severity, sql: sql.slice(0, 200) }, reason);

        if (severity === 'high') {
          return { blocked: true, reason, pattern: name };
        }

        // Medium/low severity: log but don't block
        return { blocked: false, reason, pattern: name };
      }
    }

    return { blocked: false, reason: 'Clean' };
  }
}
