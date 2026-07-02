/**
 * PasswordPolicy — Configurable password complexity validation
 *
 * Provides a comprehensive password policy engine with:
 *   - Length, character-class, banned-password validation
 *   - Password strength scoring (0–100)
 *   - Compliant random password generation
 *
 * This addresses gap SE14 (P1): password complexity policies were previously
 * absent from the system.
 *
 * Default policy (OWASP-recommended baseline):
 *   - Minimum length: 8 characters
 *   - Requires at least one uppercase letter
 *   - Requires at least one lowercase letter
 *   - Requires at least one digit
 *   - Requires at least one special character
 *   - Maximum length: 128 characters
 *
 * @module PasswordPolicy
 */

import * as crypto from 'node:crypto';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PasswordPolicy');

// ── Default constants ────────────────────────────────────────────────────────

/** Default minimum password length. */
const DEFAULT_MIN_LENGTH = 8;
/** Default maximum password length. */
const DEFAULT_MAX_LENGTH = 128;
/** Default set of allowed special characters. */
const DEFAULT_SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?';
/** Default empty banned list. */
const DEFAULT_BANNED: string[] = [];

// ── Typedefs ─────────────────────────────────────────────────────────────────

export interface PolicyConfig {
  /** Minimum password length (default 8). */
  minLength: number;
  /** Maximum password length (default 128). */
  maxLength: number;
  /** Require at least one uppercase letter. */
  requireUppercase: boolean;
  /** Require at least one lowercase letter. */
  requireLowercase: boolean;
  /** Require at least one digit. */
  requireDigit: boolean;
  /** Require at least one special character. */
  requireSpecialChar: boolean;
  /** Allowed special character set (default: !@#$%^&*()_+-=[]{}|;:,.<>?). */
  specialChars: string;
  /** List of banned passwords (case-insensitive comparison). */
  bannedPasswords: string[];
  /** Minimum number of special characters required (effective only when requireSpecialChar is true). */
  minSpecialChars: number;
  /** Minimum number of digits required (effective only when requireDigit is true). */
  minDigits: number;
  /**
   * SEC006: Password expiry period in days.
   * If set, passwords must be changed after this many days.
   * 0 or undefined = no expiry.
   */
  expiryDays?: number;
  /**
   * SEC006: Number of previous passwords to remember.
   * Prevents password reuse.
   * 0 or undefined = no history check.
   */
  historyCount?: number;
}

export interface PolicyResult {
  /** Whether the password satisfies the current policy. */
  valid: boolean;
  /** Human-readable error messages describing every policy violation. */
  errors: string[];
}

// ── Default policy ───────────────────────────────────────────────────────────

/**
 * Default password policy configuration.
 *
 * This baseline aligns with NIST SP 800-63B and OWASP recommendations for
 * general-purpose application passwords.
 */
export const DEFAULT_POLICY: PolicyConfig = Object.freeze({
  minLength: DEFAULT_MIN_LENGTH,
  maxLength: DEFAULT_MAX_LENGTH,
  requireUppercase: true,
  requireLowercase: true,
  requireDigit: true,
  requireSpecialChar: true,
  specialChars: DEFAULT_SPECIAL_CHARS,
  bannedPasswords: DEFAULT_BANNED,
  minSpecialChars: 1,
  minDigits: 1,
});

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Regex pattern for matching uppercase letters (ASCII + Unicode). */
const RX_UPPERCASE = /\p{Lu}/u;
/** Regex pattern for matching lowercase letters (ASCII + Unicode). */
const RX_LOWERCASE = /\p{Ll}/u;

/**
 * Count occurrences of characters from `charset` in `password`.
 */
function countChars(password: string, charset: string): number {
  if (charset.length === 0) return 0;
  const set = new Set(charset);
  let count = 0;
  for (const ch of password) {
    if (set.has(ch)) count++;
  }
  return count;
}

/**
 * Count digit characters in `password`.
 */
function countDigits(password: string): number {
  let count = 0;
  for (const ch of password) {
    if (ch >= '0' && ch <= '9') count++;
  }
  return count;
}

// ── PasswordPolicy class ─────────────────────────────────────────────────────

export class PasswordPolicy {
  private config: PolicyConfig;

  /**
   * SEC006: Password history store.
   * Maps username → array of {hash, changedAt} entries (most recent first).
   */
  private passwordHistory: Map<string, Array<{ hash: string; changedAt: Date }>> = new Map();

  /**
   * SEC006: Track when each user's password was last changed.
   * Maps username → date of last password change.
   */
  private lastChanged: Map<string, Date> = new Map();

  /**
   * @param config Partial configuration to merge over the default policy.
   */
  constructor(config?: Partial<PolicyConfig>) {
    this.config = { ...DEFAULT_POLICY };
    if (config !== undefined) {
      this.applyConfig(config);
    }
    logger.debug('PasswordPolicy initialised');
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Validate a password against the current policy.
   *
   * @param password  The password to validate.
   * @param username  Optional username / user-identifier to prevent passwords
   *                  that contain the username (case-insensitive).
   * @returns A `PolicyResult` with `valid` and a list of `errors`.
   */
  validate(password: string, username?: string): PolicyResult {
    const errors: string[] = [];
    const cfg = this.config;

    // Ensure it's a string
    if (typeof password !== 'string') {
      return { valid: false, errors: ['Password must be a string'] };
    }

    const len = password.length;

    // Length checks
    if (len < cfg.minLength) {
      errors.push(
        `Password must be at least ${cfg.minLength} characters long (got ${len})`,
      );
    }
    if (len > cfg.maxLength) {
      errors.push(
        `Password must be no more than ${cfg.maxLength} characters long (got ${len})`,
      );
    }

    // Uppercase check
    if (cfg.requireUppercase && !RX_UPPERCASE.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    // Lowercase check
    if (cfg.requireLowercase && !RX_LOWERCASE.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    // Digit check
    if (cfg.requireDigit) {
      const digitCount = countDigits(password);
      if (digitCount < cfg.minDigits) {
        errors.push(
          `Password must contain at least ${cfg.minDigits} digit(s) (found ${digitCount})`,
        );
      }
    }

    // Special character check
    if (cfg.requireSpecialChar) {
      const specialCount = countChars(password, cfg.specialChars);
      if (specialCount < cfg.minSpecialChars) {
        errors.push(
          `Password must contain at least ${cfg.minSpecialChars} special character(s) from: ${cfg.specialChars} (found ${specialCount})`,
        );
      }
    }

    // Banned-password check (case-insensitive)
    if (cfg.bannedPasswords.length > 0) {
      const lowerPassword = password.toLowerCase();
      for (const banned of cfg.bannedPasswords) {
        if (lowerPassword === banned.toLowerCase()) {
          errors.push('This password is banned because it is too common or compromised');
          break;
        }
      }
    }

    // Username substring check (prevent password containing the username)
    if (username !== undefined && username.length > 0) {
      const lowerPassword = password.toLowerCase();
      const lowerUsername = username.toLowerCase();
      if (lowerPassword.includes(lowerUsername)) {
        errors.push('Password must not contain the username');
      }
    }

    // SEC006: Password history check — prevent reuse
    if (username !== undefined && cfg.historyCount && cfg.historyCount > 0) {
      const history = this.passwordHistory.get(username) || [];
      for (const entry of history.slice(0, cfg.historyCount)) {
        if (this.comparePasswordHash(password, entry.hash)) {
          errors.push(
            `Password has been used recently. Cannot reuse one of the last ${cfg.historyCount} passwords.`,
          );
          break;
        }
      }
    }

    // SEC006: Password expiry check — warn if too old
    if (username !== undefined && cfg.expiryDays && cfg.expiryDays > 0) {
      const lastChange = this.lastChanged.get(username);
      if (lastChange) {
        const daysSinceChange = (Date.now() - lastChange.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceChange > cfg.expiryDays) {
          errors.push(
            `Password has expired (${Math.floor(daysSinceChange)} days since last change, max ${cfg.expiryDays} days). Please change your password.`,
          );
        }
      }
    }

    const valid = errors.length === 0;

    if (!valid) {
      logger.warn({ passwordLength: len, errorCount: errors.length }, 'Password validation failed');
    }

    return { valid, errors };
  }

  /**
   * Return a read-only view of the current policy configuration.
   */
  getConfig(): Readonly<PolicyConfig> {
    return Object.freeze({ ...this.config }) as Readonly<PolicyConfig>;
  }

  /**
   * Update the policy configuration by merging the provided partial config.
   *
   * Only the keys explicitly provided in `config` will be updated; unset keys
   * retain their current values.
   */
  updateConfig(config: Partial<PolicyConfig>): void {
    this.applyConfig(config);
    logger.debug('PasswordPolicy configuration updated');
  }

  // ── SEC006: Password History Management ─────────────────────────────────────

  /**
   * Record a password change for a user.
   * Stores the hashed password in the history.
   *
   * @param username - The user whose password changed.
   * @param newPassword - The new plaintext password (will be hashed for storage).
   */
  recordPasswordChange(username: string, newPassword: string): void {
    const hash = this.hashPassword(newPassword);
    const now = new Date();

    // Update history
    const history = this.passwordHistory.get(username) || [];
    history.unshift({ hash, changedAt: now });
    this.passwordHistory.set(username, history);

    // Update last change time
    this.lastChanged.set(username, now);

    // Trim history to max stored entries (historyCount * 2 for buffer)
    const maxHistory = (this.config.historyCount || 10) * 2;
    if (history.length > maxHistory) {
      history.length = maxHistory;
    }

    logger.debug(
      { username, historySize: history.length },
      'Password change recorded in history',
    );
  }

  /**
   * Check if a user's password is expired.
   *
   * @param username - The user to check.
   * @returns `true` if the password is past the expiry date.
   */
  isPasswordExpired(username: string): boolean {
    if (!this.config.expiryDays || this.config.expiryDays <= 0) return false;

    const lastChange = this.lastChanged.get(username);
    if (!lastChange) return false; // No record — assume not expired

    const daysSinceChange = (Date.now() - lastChange.getTime()) / (1000 * 60 * 60 * 24);
    return daysSinceChange > this.config.expiryDays;
  }

  /**
   * Get the days remaining before password expiry.
   *
   * @param username - The user to check.
   * @returns Days remaining (positive = valid, negative = expired, null = no expiry configured).
   */
  getDaysUntilExpiry(username: string): number | null {
    if (!this.config.expiryDays || this.config.expiryDays <= 0) return null;

    const lastChange = this.lastChanged.get(username);
    if (!lastChange) return null;

    const daysSinceChange = (Date.now() - lastChange.getTime()) / (1000 * 60 * 60 * 24);
    return this.config.expiryDays - daysSinceChange;
  }

  /**
   * Get password change history for a user.
   *
   * @param username - The user to query.
   * @param maxEntries - Maximum number of history entries to return.
   * @returns Array of { hash, changedAt } entries (most recent first).
   */
  getHistory(username: string, maxEntries?: number): Array<{ hash: string; changedAt: Date }> {
    const history = this.passwordHistory.get(username) || [];
    if (maxEntries && maxEntries > 0) {
      return history.slice(0, maxEntries);
    }
    return [...history];
  }

  /**
   * Clear password history for a user.
   *
   * @param username - The user to clear.
   */
  clearHistory(username: string): void {
    this.passwordHistory.delete(username);
    this.lastChanged.delete(username);
    logger.debug({ username }, 'Password history cleared');
  }

  /**
   * Reset all password history state.
   */
  resetHistory(): void {
    this.passwordHistory.clear();
    this.lastChanged.clear();
    logger.debug('All password history reset');
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  /**
   * Hash a password for history storage (SHA-256, not for production auth).
   */
  private hashPassword(password: string): string {
    return crypto.createHash('sha256').update(password, 'utf8').digest('hex');
  }

  /**
   * Compare a plaintext password against a stored hash.
   */
  private comparePasswordHash(password: string, hash: string): boolean {
    const computed = this.hashPassword(password);
    return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(hash, 'hex'));
  }

  /**
   * Calculate a password strength score from 0 (worst) to 100 (best).
   *
   * The scoring algorithm considers:
   *   - Length (up to 40 pts)
   *   - Character class diversity (up to 30 pts)
   *   - Use of digits (up to 10 pts)
   *   - Use of special characters (up to 10 pts)
   *   - Combination bonus (up to 10 pts)
   *
   * A score ≥ 80 is considered strong, ≥ 60 moderate, < 60 weak.
   */
  score(password: string): number {
    if (typeof password !== 'string' || password.length === 0) {
      return 0;
    }

    const len = password.length;
    let score = 0;

    // 1. Length score (up to 40 pts)
    //    0 pts for < 6 chars, 5 pts at 6, then +2 per char up to 40
    if (len >= 6) {
      score += Math.min(5 + (len - 6) * 2, 40);
    }

    // 2. Character class diversity (up to 30 pts)
    let classes = 0;
    if (RX_UPPERCASE.test(password)) classes++;
    if (RX_LOWERCASE.test(password)) classes++;
    // We count digit class (always at most 1)
    if (countDigits(password) > 0) classes++;
    // Special char class
    if (countChars(password, DEFAULT_SPECIAL_CHARS) > 0) classes++;

    score += classes * 7.5; // up to 30

    // 3. Digit usage bonus (up to 10 pts)
    const digitCount = countDigits(password);
    score += Math.min(digitCount * 3, 10);

    // 4. Special char usage bonus (up to 10 pts)
    const specialCount = countChars(password, DEFAULT_SPECIAL_CHARS);
    score += Math.min(specialCount * 3, 10);

    // 5. Combination bonus (up to 10 pts)
    //    If password has at least 3 character classes and length >= 12
    if (classes >= 3 && len >= 12) {
      score += 10;
    } else if (classes >= 2 && len >= 10) {
      score += 5;
    }

    // Clamp to [0, 100]
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  /**
   * Generate a cryptographically random password that satisfies the current
   * policy configuration.
   *
   * @param length  Desired password length. Defaults to `config.minLength + 4`
   *                (i.e. slightly above the minimum for better usability).  Must
   *                be ≥ the configured `minLength` and ≤ `maxLength`.
   * @returns A randomly generated password that passes `validate()`.
   * @throws {Error} If `length` is outside the allowed range or if an
   *                 unreasonably restrictive policy cannot be satisfied.
   */
  generatePassword(length?: number): string {
    const cfg = this.config;
    const targetLen =
      length ?? Math.min(cfg.minLength + 4, cfg.maxLength);

    if (targetLen < cfg.minLength || targetLen > cfg.maxLength) {
      throw new Error(
        `Requested password length ${targetLen} is outside the allowed range [${cfg.minLength}, ${cfg.maxLength}]`,
      );
    }

    // Minimum required characters from each enforced class
    const required: string[] = [];

    if (cfg.requireUppercase) {
      required.push(sampleFromRange('uppercase'));
    }
    if (cfg.requireLowercase) {
      required.push(sampleFromRange('lowercase'));
    }
    if (cfg.requireDigit) {
      // Add as many digits as minDigits requires
      for (let i = 0; i < Math.max(cfg.minDigits, 1); i++) {
        required.push(sampleFromRange('digit'));
      }
    }
    if (cfg.requireSpecialChar) {
      // Add as many special chars as minSpecialChars requires
      for (let i = 0; i < Math.max(cfg.minSpecialChars, 1); i++) {
        required.push(sampleFromRange('special', cfg.specialChars));
      }
    }

    // Build the full pool of allowed characters
    let pool = '';
    if (cfg.requireUppercase) pool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (cfg.requireLowercase) pool += 'abcdefghijklmnopqrstuvwxyz';
    if (cfg.requireDigit) pool += '0123456789';
    if (cfg.requireSpecialChar) pool += cfg.specialChars;
    // If no character class is required, default to alphanumeric
    if (pool.length === 0) {
      pool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    }

    // Guard against unreasonably restrictive policies
    if (required.length > targetLen) {
      throw new Error(
        `Password policy requires at least ${required.length} characters but target length is ${targetLen}. Increase target length or relax the policy.`,
      );
    }

    // Fill remaining slots with random characters from the pool
    const fillCount = targetLen - required.length;
    const chars: string[] = [...required];
    for (let i = 0; i < fillCount; i++) {
      chars.push(pool[randomIndex(pool.length)]);
    }

    // Shuffle using Fisher-Yates to avoid deterministic ordering
    shuffleArray(chars);

    const password = chars.join('');

    logger.debug('Generated a compliant password');

    return password;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private applyConfig(config: Partial<PolicyConfig>): void {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const target = this.config as any;
    const keys = Object.keys(config) as Array<keyof PolicyConfig>;
    for (const key of keys) {
      if (config[key] !== undefined) {
        target[key] = config[key];
      }
    }
    // Validate: minLength <= maxLength, clamp if necessary
    if (this.config.minLength > this.config.maxLength) {
      this.config.maxLength = this.config.minLength;
      logger.warn('minLength > maxLength detected; maxLength adjusted to minLength');
    }
    // Validate: non-negative counts
    this.config.minSpecialChars = Math.max(0, this.config.minSpecialChars);
    this.config.minDigits = Math.max(0, this.config.minDigits);
  }
}

// ── Private utility functions (module-scoped) ─────────────────────────────────

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';

/**
 * Sample a single random character from a named character range.
 *
 * @param range  One of 'uppercase', 'lowercase', 'digit', 'special'.
 * @param specialChars  The special character set (used when range === 'special').
 */
function sampleFromRange(
  range: 'uppercase' | 'lowercase' | 'digit' | 'special',
  specialChars?: string,
): string {
  switch (range) {
    case 'uppercase':
      return UPPER[randomIndex(UPPER.length)];
    case 'lowercase':
      return LOWER[randomIndex(LOWER.length)];
    case 'digit':
      return DIGITS[randomIndex(DIGITS.length)];
    case 'special': {
      const chars = specialChars ?? DEFAULT_SPECIAL_CHARS;
      if (chars.length === 0) return '!'; // fallback
      return chars[randomIndex(chars.length)];
    }
  }
}

/**
 * Return a cryptographically random integer in [0, max).
 */
function randomIndex(max: number): number {
  // 8-byte buffer gives enough entropy for any reasonable max
  const buf = crypto.getRandomValues(new Uint32Array(1));
  return buf[0]! % max;
}

/**
 * Fisher-Yates shuffle (in-place).
 */
function shuffleArray(arr: unknown[]): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [arr[i], arr[j]] = [arr[j]!, arr[i]!];
  }
}
