/**
 * MFAManager — TOTP-based Multi-Factor Authentication
 *
 * Provides a complete TOTP (Time-based One-Time Password) implementation
 * per RFC 6238 using only Node.js built-in crypto (HMAC-SHA1). No external
 * packages are required.
 *
 * Features:
 *   - Generate cryptographically random base32-encoded secrets
 *   - Compute 6-digit TOTP codes with 30-second time windows
 *   - Verify TOTP codes with ±1 window tolerance (to handle clock skew)
 *   - In-memory per-user MFA secret storage (enable/disable/check)
 *
 * This addresses gap M02 (P1): MFA was previously a no-op.
 *
 * @module security/MFAManager
 */

import * as crypto from 'node:crypto';

// ── Constants ──────────────────────────────────────────────────────────────

/** RFC 4648 base32 alphabet. */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** TOTP time-step in seconds (RFC 6238 §5.2 recommends 30 s). */
const TIME_STEP_S = 30;

/** Number of digits in the generated TOTP code. */
const TOTP_DIGITS = 6;

/** TOTP secret length in bytes (32 bytes → 256-bit key). */
const SECRET_BYTES = 32;

/** TOTP secret length in base32 chars (ceil(32*8/5) = 52 but we use full padding). */
// 32 bytes = 256 bits = 52 base32 chars + padding to 55 (multiple of 8)
// Actually: ceil(32*8/5) = 52, then pad to next multiple of 8 = 56
const EXPECTED_BASE32_LEN = 56;

// ── Base32 helpers ─────────────────────────────────────────────────────────

/**
 * Encode a Buffer to a base32 string (RFC 4648).
 *
 * @param buf  The raw bytes to encode.
 * @returns  Uppercase base32-encoded string with padding.
 */
function base32Encode(buf: Buffer): string {
  const bytes = Array.from(buf);
  let bits = 0;
  let bitBuffer = 0;
  const result: string[] = [];

  for (const byte of bytes) {
    bitBuffer = (bitBuffer << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      const index = (bitBuffer >> bits) & 0x1f;
      result.push(BASE32_ALPHABET[index]);
    }
  }

  // Flush remaining bits
  if (bits > 0) {
    const index = (bitBuffer << (5 - bits)) & 0x1f;
    result.push(BASE32_ALPHABET[index]);
  }

  // Pad to multiple of 8
  const padLen = (8 - (result.length % 8)) % 8;
  for (let i = 0; i < padLen; i++) {
    result.push('=');
  }

  return result.join('');
}

/**
 * Decode a base32 string to a Buffer (RFC 4648).
 *
 * @param str  Uppercase base32-encoded string (with or without padding).
 * @returns  Decoded bytes.
 * @throws {Error}  If the string contains invalid characters.
 */
function base32Decode(str: string): Buffer {
  // Remove padding and whitespace, uppercase
  const cleaned = str.replace(/=+$/, '').replace(/\s/g, '').toUpperCase();
  const bytes: number[] = [];
  let bits = 0;
  let bitBuffer = 0;

  for (const ch of cleaned) {
    const index = BASE32_ALPHABET.indexOf(ch);
    if (index === -1) {
      throw new Error(`Invalid base32 character: ${ch}`);
    }
    bitBuffer = (bitBuffer << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((bitBuffer >> bits) & 0xff);
    }
  }

  return Buffer.from(bytes);
}

// ── TOTP core ──────────────────────────────────────────────────────────────

/**
 * Compute a TOTP code for a given counter value using HMAC-SHA1.
 *
 * Implements the HOTP truncation and modulo reduction as defined in
 * RFC 4226 §5.3 (HOTP) and RFC 6238 §4 (TOTP).
 *
 * @param keyBytes  The decoded (raw byte) secret key.
 * @param counter   The 8-byte big-endian counter value.
 * @returns  A 6-digit TOTP code string.
 */
function hotp(keyBytes: Buffer, counter: Buffer): string {
  // HMAC-SHA1 produces a 20-byte digest
  const hmac = crypto.createHmac('sha1', keyBytes).update(counter).digest();

  // Dynamic truncation (RFC 4226 §5.3)
  const offset = hmac[19]! & 0x0f;

  const binaryCode =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);

  // Modulo 10^TOTP_DIGITS to get the code
  const code = binaryCode % Math.pow(10, TOTP_DIGITS);

  // Pad with leading zeros to TOTP_DIGITS
  return String(code).padStart(TOTP_DIGITS, '0');
}

/**
 * Compute the TOTP time-window counter for a given timestamp.
 *
 * @param timestampMs  Unix timestamp in milliseconds. Defaults to Date.now().
 * @returns  The counter value (number of 30-second intervals since Unix epoch).
 */
function timeCounter(timestampMs?: number): number {
  const ms = timestampMs !== undefined ? timestampMs : Date.now();
  return Math.floor(ms / 1000 / TIME_STEP_S);
}

// ── MFAManager class ───────────────────────────────────────────────────────

export class MFAManager {
  /** In-memory store: userId → base32-encoded secret */
  private secrets: Map<string, string> = new Map();

  // ── Secret generation ──────────────────────────────────────────────────

  /**
   * Generate a cryptographically random TOTP secret.
   *
   * The secret is 32 random bytes encoded in base32 (RFC 4648), which yields
   * a 56-character string (52 data chars + 4 padding chars). This provides
   * 256 bits of entropy.
   *
   * @returns  A base32-encoded secret string suitable for use with authenticator
   *           apps (Google Authenticator, Authy, etc.).
   */
  generateSecret(): string {
    const rawBytes = crypto.randomBytes(SECRET_BYTES);
    return base32Encode(rawBytes);
  }

  // ── TOTP generation & verification ─────────────────────────────────────

  /**
   * Generate a 6-digit TOTP code for the given secret and timestamp.
   *
   * @param secret      Base32-encoded secret (as produced by `generateSecret`).
   * @param timestampMs  Unix timestamp in milliseconds. Defaults to Date.now().
   * @returns  A 6-digit TOTP code string (with leading zeros if needed).
   * @throws {Error}  If the secret contains invalid base32 characters.
   */
  generateTOTP(secret: string, timestampMs?: number): string {
    const keyBytes = base32Decode(secret);
    const counter = timeCounter(timestampMs);
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    return hotp(keyBytes, counterBuf);
  }

  /**
   * Verify a TOTP code for the given secret.
   *
   * Tolerates ±1 time window (30 s each) to account for minor clock skew
   * between the server and the authenticator app.
   *
   * @param secret  Base32-encoded secret.
   * @param token   The 6-digit token to verify.
   * @returns  `true` if the token matches any of the valid windows,
   *           `false` otherwise.
   */
  verifyTOTP(secret: string, token: string): boolean {
    const now = Date.now();
    // Check the current window and ±1 windows
    for (let offset = -1; offset <= 1; offset++) {
      const ts = now + offset * TIME_STEP_S * 1000;
      const expected = this.generateTOTP(secret, ts);
      if (expected === token) {
        return true;
      }
    }
    return false;
  }

  // ── User state management ──────────────────────────────────────────────

  /**
   * Enable MFA for a user by storing their TOTP secret.
   *
   * If the user already has a secret registered, it will be overwritten.
   *
   * @param userId  Unique user identifier.
   * @param secret  Base32-encoded TOTP secret (as produced by `generateSecret`).
   */
  enableMFA(userId: string, secret: string): void {
    if (!userId || userId.trim().length === 0) {
      throw new Error('userId must be a non-empty string');
    }
    if (!secret || secret.trim().length === 0) {
      throw new Error('secret must be a non-empty string');
    }
    this.secrets.set(userId, secret);
  }

  /**
   * Disable MFA for a user by removing their stored secret.
   *
   * No-op if the user does not have MFA enabled.
   *
   * @param userId  Unique user identifier.
   */
  disableMFA(userId: string): void {
    this.secrets.delete(userId);
  }

  /**
   * Check whether MFA is currently enabled for a user.
   *
   * @param userId  Unique user identifier.
   * @returns  `true` if the user has an MFA secret registered, `false` otherwise.
   */
  isMFAEnabled(userId: string): boolean {
    return this.secrets.has(userId);
  }

  /**
   * Get the stored MFA secret for a user, if any.
   *
   * @param userId  Unique user identifier.
   * @returns  The base32-encoded secret, or `undefined` if MFA is not enabled.
   */
  getSecret(userId: string): string | undefined {
    return this.secrets.get(userId);
  }

  /**
   * Remove all stored secrets (resets the manager to its initial state).
   */
  clearAll(): void {
    this.secrets.clear();
  }
}
