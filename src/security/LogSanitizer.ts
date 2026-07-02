/**
 * LogSanitizer — Configurable log sanitisation module.
 *
 * Provides built-in rules to mask sensitive information in log output:
 *   - SQL password literals (PASSWORD '…')
 *   - IP addresses (keep first two octets visible)
 *   - Email addresses (keep first & last 2 characters)
 *   - Credit card numbers (keep first 6 & last 4 digits)
 *   - Chinese national ID numbers (keep first & last 2 characters)
 *   - Phone numbers (keep first 2 & last 2 characters)
 *
 * Also supports user-defined custom rules and recursive JSON sanitisation
 * that fully masks known sensitive keys (password, token, secret, etc.).
 *
 * Usage:
 *   const sanitizer = new LogSanitizer();
 *
 *   // Sanitise a log line
 *   const safe = sanitizer.sanitise(
 *     "User admin@example.com from 192.168.1.100 logged in"
 *   );
 *
 *   // Sanitise a JSON payload (recursive)
 *   const safeObj = sanitizer.sanitiseJson({
 *     email: 'admin@example.com',
 *     password: 'secret123',
 *     metadata: { ip: '10.0.0.1', phone: '13800138000' },
 *   });
 *
 * @module LogSanitizer
 */

import { PinoLogger } from '../monitoring/PinoLogger';

// ── Types ────────────────────────────────────────────────────────

export interface SanitizeRule {
  /** 正则匹配模式 */
  pattern: RegExp;
  /** 替换字符串（支持 $1, $2, … 引用捕获组） */
  replacement: string;
  /** 规则名称 */
  name: string;
}

export interface SanitizeOptions {
  /** 是否脱敏 SQL 中的密码 */
  sanitizePasswords: boolean;
  /** 是否脱敏 IP 地址 */
  sanitizeIPs: boolean;
  /** 是否脱敏电子邮件 */
  sanitizeEmails: boolean;
  /** 是否脱敏信用卡号 */
  sanitizeCreditCards: boolean;
  /** 是否脱敏身份证号 */
  sanitizeChineseID: boolean;
  /** 是否脱敏手机号 */
  sanitizePhoneNumbers: boolean;
  /** 自定义脱敏规则 */
  customRules: SanitizeRule[];
}

// ── Default Options ──────────────────────────────────────────────

export const DEFAULT_OPTIONS: SanitizeOptions = {
  sanitizePasswords: true,
  sanitizeIPs: true,
  sanitizeEmails: true,
  sanitizeCreditCards: true,
  sanitizeChineseID: true,
  sanitizePhoneNumbers: true,
  customRules: [],
};

// ── Known sensitive JSON keys ────────────────────────────────────

const SENSITIVE_KEYS = new Set([
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'authorization',
  'auth',
  'apiKey',
  'api_key',
  'apikey',
  'privateKey',
  'private_key',
  'accessKey',
  'access_key',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'sessionKey',
  'session_key',
  'signingKey',
  'signing_key',
]);

// ── Built-in rule factories ──────────────────────────────────────

function buildPasswordRule(): SanitizeRule {
  return {
    name: 'sql-password',
    // Matches `PASSWORD '…'` literals in SQL (case-insensitive)
    pattern: /PASSWORD\s+'[^']*'/gi,
    replacement: "PASSWORD '***'",
  };
}

function buildIpRule(): SanitizeRule {
  return {
    name: 'ip-address',
    // Keeps first two octets; masks the last two
    pattern: /\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b/g,
    replacement: '$1.xxx.xxx',
  };
}

function buildEmailRule(): SanitizeRule {
  return {
    name: 'email',
    // Keeps first 2 characters and last 2 characters of the local part;
    // the domain portion is replaced entirely so the full match
    // becomes `ab***yz`.
    //
    // The pattern below matches the entire email address but captures
    // the first 2 and last 2 characters of the local-part.
    pattern:
      /\b([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{2})[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]*?([a-zA-Z0-9]{2})@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b/g,
    replacement: '$1***$2',
  };
}

function buildCreditCardRule(): SanitizeRule {
  return {
    name: 'credit-card',
    // Keeps first 6 digits, masks 6–9 middle digits, keeps last 4
    pattern: /\b(\d{6})\d{6,9}(\d{4})\b/g,
    replacement: '$1******$2',
  };
}

function buildChineseIdRule(): SanitizeRule {
  return {
    name: 'chinese-id',
    // Chinese citizen ID: 17 digits + 1 digit or 'X'/'x' (18 chars)
    // Keeps first 2 chars, masks middle 14, keeps last 2
    pattern: /\b(\d{2})\d{14}((?:\d{2})|(?:\d[Xx]))\b/g,
    replacement: '$1***$2',
  };
}

function buildPhoneRule(): SanitizeRule {
  return {
    name: 'phone-number',
    // Chinese mobile: starts with 1, then 3-9, then 7 digits + last 2 kept
    // Pattern captures first 2 and last 2 digits
    pattern: /\b(1[3-9])\d{7}(\d{2})\b/g,
    replacement: '$1***$2',
  };
}

// ── LogSanitizer ─────────────────────────────────────────────────

export class LogSanitizer {
  private options: SanitizeOptions;
  private rules: SanitizeRule[] = [];
  private readonly logger: PinoLogger;

  constructor(options?: Partial<SanitizeOptions>) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.logger = PinoLogger.forComponent('LogSanitizer');
    this.rebuildRules();
  }

  /**
   * Sanitize a log line by applying all active rules sequentially.
   *
   * Rules are applied in order: built-in rules first (passwords, IPs,
   * emails, credit cards, Chinese IDs, phone numbers), then custom
   * rules in the order they were added.
   *
   * @param logLine  The raw log line to sanitize.
   * @returns       The sanitized log line.
   */
  sanitize(logLine: string): string {
    let result = logLine;
    for (const rule of this.rules) {
      result = result.replace(rule.pattern, rule.replacement);
    }
    return result;
  }

  /**
   * Recursively sanitize all string values in a JSON-serialisable object.
   *
   * - String values nested at any depth are sanitised via `sanitize()`.
   * - Keys that match known sensitive names (password, token, secret, etc.)
   *   are **fully replaced** with `'***'` regardless of their content.
   * - Arrays are traversed recursively.
   * - Non-string values (numbers, booleans, null) are passed through unchanged.
   *
   * @param obj  The object to sanitize (shallow clone — original is not mutated).
   * @returns    A new object with sanitized values.
   */
  sanitizeJson(obj: Record<string, unknown>): Record<string, unknown> {
    const walk = (value: unknown, key?: string): unknown => {
      // Primitives / null
      if (value == null) return value;

      // String — apply key-sensitive check first, then general rules
      if (typeof value === 'string') {
        if (key !== undefined && SENSITIVE_KEYS.has(key.toLowerCase())) {
          return '***';
        }
        return this.sanitize(value);
      }

      // Nested object
      if (typeof value === 'object' && !Array.isArray(value)) {
        const result: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          result[k] = walk(v, k);
        }
        return result;
      }

      // Array
      if (Array.isArray(value)) {
        return value.map((item) => walk(item));
      }

      // Numbers, booleans — pass through
      return value;
    };

    return walk(obj) as Record<string, unknown>;
  }

  /**
   * Add a custom sanitisation rule.
   *
   * If a rule with the same `name` already exists it is replaced.
   *
   * @param rule  The rule to add.
   */
  addRule(rule: SanitizeRule): void {
    this.removeRule(rule.name);
    const newRule: SanitizeRule = { ...rule };
    this.rules.push(newRule);
    // Keep custom rules list in sync so getOptions() returns them
    this.options.customRules = this.options.customRules.filter((r) => r.name !== rule.name);
    this.options.customRules.push(newRule);
  }

  /**
   * Remove a sanitisation rule by name.
   *
   * @param name  The rule name to remove.
   */
  removeRule(name: string): void {
    this.rules = this.rules.filter((r) => r.name !== name);
    this.options.customRules = this.options.customRules.filter((r) => r.name !== name);
  }

  /**
   * Update sanitisation options at runtime.
   *
   * Calling this method rebuilds the internal rule list from the new
   * options. Previously-added custom rules are preserved and re-appended
   * unless explicitly removed or overridden via `addRule`.
   *
   * @param options  Partial options to merge over the current ones.
   */
  updateOptions(options: Partial<SanitizeOptions>): void {
    this.options = { ...this.options, ...options };
    this.logger.info({ sanitizeOptions: this.options }, 'LogSanitizer options updated');
    this.rebuildRules();
  }

  /**
   * Return a read-only snapshot of the current configuration.
   *
   * The returned object is a shallow copy; mutating it has no effect on
   * the sanitizer's internal state.
   */
  getOptions(): Readonly<SanitizeOptions> {
    return {
      ...this.options,
      customRules: [...this.options.customRules],
    };
  }

  // ── Private ────────────────────────────────────────────────────

  /**
   * Rebuild the internal ordered rule list from `this.options`.
   *
   * Order: built-in flags first (passwords → IPs → emails → credit cards →
   * Chinese IDs → phone numbers), then custom rules appended in order.
   */
  private rebuildRules(): void {
    this.rules = [];

    if (this.options.sanitizePasswords) {
      this.rules.push(buildPasswordRule());
    }

    if (this.options.sanitizeIPs) {
      this.rules.push(buildIpRule());
    }

    if (this.options.sanitizeEmails) {
      this.rules.push(buildEmailRule());
    }

    if (this.options.sanitizeCreditCards) {
      this.rules.push(buildCreditCardRule());
    }

    if (this.options.sanitizeChineseID) {
      this.rules.push(buildChineseIdRule());
    }

    if (this.options.sanitizePhoneNumbers) {
      this.rules.push(buildPhoneRule());
    }

    // Append custom rules — each expects a pattern + replacement string
    for (const rule of this.options.customRules) {
      this.rules.push({ ...rule });
    }
  }
}
