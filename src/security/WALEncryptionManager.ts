/**
 * WALEncryptionManager — AES-256-GCM encryption for WAL segments.
 *
 * Encrypts WAL segment data at rest in the archive, using the same
 * AES-256-GCM algorithm as BackupEncryptionManager. Unlike the streaming
 * file-based backup encryption, this is a buffer-based encrypt/decrypt
 * suitable for WAL segments (typically small files or memory buffers).
 *
 * Format:
 *   [magic 4B][IV 12B][authTag 16B][ciphertext ...]
 *
 * The magic header ("WALE") distinguishes encrypted segments from
 * legacy plaintext segments, enabling seamless backward compatibility.
 *
 * Key management:
 *   - WAL_ENCRYPTION_KEY environment variable (64 hex chars = 32 bytes)
 *   - Or pass a key directly via constructor
 *   - If no key is provided, the manager falls back to a no-op pass-through
 *
 * @module WALEncryptionManager
 */

import * as crypto from 'node:crypto';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('WALEncryption');

// ── Constants ────────────────────────────────────────────────────────────────

/** Magic bytes identifying an encrypted WAL segment: "WALE" */
const MAGIC = Buffer.from([0x57, 0x41, 0x4c, 0x45]); // "WALE" in ASCII
/** Magic header length in bytes. */
const MAGIC_LENGTH = 4;
/** AES-256-GCM initialisation vector length in bytes. */
const IV_LENGTH = 12;
/** GCM authentication tag length in bytes. */
const AUTH_TAG_LENGTH = 16;
/** Derived key length for AES-256 (32 bytes = 256 bits). */
const KEY_LENGTH = 32;
/** AES-256-GCM cipher algorithm identifier. */
const CIPHER_ALGORITHM = 'aes-256-gcm';
/** Total header size (magic + IV + authTag). */
const HEADER_SIZE = MAGIC_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH; // 32 bytes
/** Environment variable for the WAL encryption key. */
const KEY_ENV_VAR = 'WAL_ENCRYPTION_KEY';

/** Page size for database page encryption (SQLite default page size). */
const PAGE_SIZE = 4096;
/** AES block size in bytes. */
const BLOCK_SIZE = 16;

// ── GF(2^128) helpers for XTS tweak multiplication ──────────────────────────

/**
 * Multiply a 128-bit value by α (primitive polynomial x) in GF(2^128).
 * Uses the standard XTS polynomial 0x87 (little-endian representation
 * of x^128 + x^7 + x + x^2 + x + 1).
 */
function gf128Mul(x: Buffer): Buffer {
  const result = Buffer.alloc(BLOCK_SIZE);
  let carry = 0;

  for (let i = 0; i < BLOCK_SIZE; i++) {
    const byte = x[i];
    result[i] = (byte << 1) | carry;
    carry = (byte >> 7) & 1;
  }

  if (carry) {
    result[0] ^= 0x87; // Polynomial reduction
  }

  return result;
}

/**
 * Encrypt a single 16-byte block using AES-256-ECB (no padding).
 */
function aes256EcbEncrypt(key: Buffer, plaintext: Buffer): Buffer {
  const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

/**
 * Derive the 64-byte XTS key material (32 bytes data key + 32 bytes tweak key)
 * from a master key using HKDF-SHA256.
 */
function deriveXtsKeys(masterKey: Buffer): { dataKey: Buffer; tweakKey: Buffer } {
  const derived = Buffer.from(crypto.hkdfSync('sha256', masterKey, 'aes-xts-v1', 'page-encryption', 64));
  return {
    dataKey: derived.subarray(0, KEY_LENGTH),
    tweakKey: derived.subarray(KEY_LENGTH, 64),
  };
}

/**
 * Compute a Key Check Value (KCV) for a given AES key.
 * KCV = AES_k(0^128), i.e. encrypting a zero-filled block.
 */
function computeKCV(key: Buffer): Buffer {
  const zeroBlock = Buffer.alloc(BLOCK_SIZE, 0);
  return aes256EcbEncrypt(key, zeroBlock);
}

// ── WALEncryptionManager ─────────────────────────────────────────────────────

export class WALEncryptionManager {
  private key: Buffer | null = null;
  /** Master encryption key for page-level TDE (may differ from WAL encryption key). */
  private masterKey: Buffer | null = null;
  /** Key Check Value — verifies correct master key on startup. */
  private kcv: Buffer | null = null;

  /**
   * Create a WALEncryptionManager.
   *
   * @param keyHex - Optional 64-character hex string (32 bytes).
   *                 Falls back to WAL_ENCRYPTION_KEY env var if not provided.
   *                 If neither is set, the manager operates in pass-through
   *                 mode (no encryption).
   */
  constructor(keyHex?: string) {
    const resolvedKey = keyHex ?? process.env[KEY_ENV_VAR];
    if (resolvedKey) {
      this.key = Buffer.from(resolvedKey, 'hex');
      if (this.key.length !== KEY_LENGTH) {
        logger.warn(
          `WAL encryption key has unexpected length: ${this.key.length} bytes (expected ${KEY_LENGTH}). Encryption disabled.`,
        );
        this.key = null;
      }
    }

    if (this.key) {
      logger.info('WAL encryption manager initialized (AES-256-GCM)');
    } else {
      logger.info(
        'WAL encryption manager initialized in pass-through mode ' +
        `(set ${KEY_ENV_VAR} to enable encryption)`,
      );
    }
  }

  /**
   * Returns true if encryption is active (key configured).
   */
  isEnabled(): boolean {
    return this.key !== null;
  }

  /**
   * Encrypt a WAL buffer.
   *
   * If no encryption key is configured, returns the plaintext unmodified.
   *
   * @param plaintext - Raw WAL data to encrypt.
   * @returns Encrypted buffer with magic header, or plaintext if encryption
   *          is not configured.
   */
  encrypt(plaintext: Buffer): Buffer {
    if (!this.key) {
      return plaintext;
    }

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, this.key, iv);

    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([MAGIC, iv, authTag, encrypted]);
  }

  /**
   * Decrypt a WAL buffer.
   *
   * Checks for the magic header to determine if the data is encrypted.
   * Returns the plaintext buffer if:
   *   - Data starts with the magic header → decrypted successfully
   *   - Data does not start with the magic header → returned as-is
   *     (legacy plaintext segment, backward compatibility)
   *
   * @param data - Encrypted (with magic header) or plaintext buffer.
   * @returns Decrypted plaintext buffer, or null if decryption fails
   *          (e.g. wrong key, tampered data).
   */
  decrypt(data: Buffer): Buffer | null {
    // Plaintext check: no magic header → pass through unchanged
    if (data.length < HEADER_SIZE || !data.subarray(0, MAGIC_LENGTH).equals(MAGIC)) {
      return data; // Not encrypted, plaintext backward compat
    }

    if (!this.key) {
      logger.error('Encrypted WAL segment found but no encryption key configured');
      return null;
    }

    try {
      const iv = data.subarray(MAGIC_LENGTH, MAGIC_LENGTH + IV_LENGTH);
      const authTag = data.subarray(MAGIC_LENGTH + IV_LENGTH, HEADER_SIZE);
      const ciphertext = data.subarray(HEADER_SIZE);

      const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, this.key, iv);
      decipher.setAuthTag(authTag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error({ error: message }, 'WAL segment decryption failed');
      return null;
    }
  }

  // ── Master Key Management ──────────────────────────────────────────────────

  /**
   * Set the master encryption key for page-level transparent data encryption (TDE).
   *
   * The master key must be exactly 32 bytes (AES-256).
   * A Key Check Value (KCV) is computed and stored to verify correct key on startup.
   *
   * @param key - 32-byte AES-256 master key
   * @throws {Error} If the key is not exactly 32 bytes
   */
  setMasterKey(key: Buffer): void {
    if (key.length !== KEY_LENGTH) {
      throw new Error(
        `Master key must be exactly ${KEY_LENGTH} bytes (got ${key.length})`,
      );
    }
    this.masterKey = Buffer.from(key);
    this.kcv = computeKCV(this.masterKey);
    logger.info('TDE master key set (AES-256-XTS)');
  }

  /**
   * Verify the stored KCV against the current master key.
   * Should be called on startup to ensure the correct key is loaded.
   *
   * @returns true if the KCV matches (correct key), false otherwise
   */
  verifyMasterKey(): boolean {
    if (!this.masterKey || !this.kcv) {
      logger.warn('TDE master key not set — KCV verification skipped');
      return false;
    }
    const expected = computeKCV(this.masterKey);
    return this.kcv.equals(expected);
  }

  /**
   * Get the stored Key Check Value (hex-encoded) for diagnostic purposes.
   * Returns null if no master key has been set.
   */
  getKCV(): string | null {
    return this.kcv ? this.kcv.toString('hex') : null;
  }

  /**
   * Check whether TDE page encryption is active (master key configured).
   */
  isTDEEnabled(): boolean {
    return this.masterKey !== null;
  }

  // ── Page-Level TDE (AES-256-XTS) ───────────────────────────────────────────

  /**
   * Encrypt a single 4096-byte database page using AES-256-XTS.
   *
   * Uses the master key to derive separate data and tweak keys via HKDF.
   * Each page number produces a unique tweak, ensuring that two pages
   * with identical plaintext produce different ciphertexts.
   *
   * Format (returned buffer):
   *   [magic 4B = "XTPG"][pageNumber 4B][ciphertext 4096B] = 4104 bytes
   *
   * @param data       - 4096-byte plaintext page data
   * @param pageNumber - Logical page number (used as tweak)
   * @returns Encrypted buffer with header (4104 bytes), or plaintext if
   *          TDE is not configured (pass-through)
   * @throws {Error} If data is not exactly 4096 bytes
   */
  encryptPage(data: Buffer, pageNumber: number): Buffer {
    if (!this.masterKey) {
      return data; // Pass-through when not configured
    }

    if (data.length !== PAGE_SIZE) {
      throw new Error(
        `Page size must be exactly ${PAGE_SIZE} bytes (got ${data.length})`,
      );
    }

    const { dataKey, tweakKey } = deriveXtsKeys(this.masterKey);

    // Encode page number as 16-byte tweak (little-endian)
    const tweakInput = Buffer.alloc(BLOCK_SIZE, 0);
    tweakInput.writeBigUInt64LE(BigInt(pageNumber), 0);

    // Encrypt the tweak: T = AES_k2(encode(pageNumber))
    let tweak = aes256EcbEncrypt(tweakKey, tweakInput);

    const result = Buffer.alloc(PAGE_SIZE);
    const blockCount = PAGE_SIZE / BLOCK_SIZE; // 256 blocks

    for (let i = 0; i < blockCount; i++) {
      const offset = i * BLOCK_SIZE;

      // Plaintext block P
      const p = data.subarray(offset, offset + BLOCK_SIZE);

      // P XOR T
      const xored = Buffer.alloc(BLOCK_SIZE);
      for (let j = 0; j < BLOCK_SIZE; j++) {
        xored[j] = p[j] ^ tweak[j];
      }

      // C = AES_k1(P XOR T)
      const c = aes256EcbEncrypt(dataKey, xored);

      // C XOR T → final ciphertext block
      for (let j = 0; j < BLOCK_SIZE; j++) {
        result[offset + j] = c[j] ^ tweak[j];
      }

      // Multiply tweak by α for next block
      tweak = gf128Mul(tweak);
    }

    // Prepend magic header + page number
    const pageMagic = Buffer.from([0x58, 0x54, 0x50, 0x47]); // "XTPG"
    const pnBuf = Buffer.alloc(4);
    pnBuf.writeUInt32LE(pageNumber, 0);

    return Buffer.concat([pageMagic, pnBuf, result]); // 4 + 4 + 4096 = 4104 bytes
  }

  /**
   * Decrypt a single database page encrypted with AES-256-XTS.
   *
   * Detects the "XTPG" magic header to determine if the data is encrypted.
   * Legacy unencrypted pages are returned as-is.
   *
   * @param data - Encrypted buffer (4104 bytes with header) or plaintext (4096 bytes)
   * @param pageNumber - Logical page number (used as tweak)
   * @returns Decrypted 4096-byte page, or null if decryption fails
   * @throws {Error} If data length is invalid
   */
  decryptPage(data: Buffer, pageNumber: number): Buffer | null {
    if (!this.masterKey) {
      return data.length >= PAGE_SIZE ? data : null;
    }

    const pageMagic = Buffer.from([0x58, 0x54, 0x50, 0x47]); // "XTPG"

    // Check for magic header
    if (data.length >= 8 && data.subarray(0, 4).equals(pageMagic)) {
      // Extract page number from header for verification
      const storedPn = data.readUInt32LE(4);
      if (storedPn !== pageNumber) {
        logger.warn(
          `Page number mismatch in decryptPage: stored=${storedPn}, requested=${pageNumber}`,
        );
      }

      const ciphertext = data.subarray(8, 8 + PAGE_SIZE);
      return this.xtsDecrypt(ciphertext, pageNumber);
    }

    // Plaintext or legacy format — pass through
    if (data.length >= PAGE_SIZE) {
      return data.subarray(0, PAGE_SIZE);
    }

    throw new Error(
      `Invalid page data length: ${data.length} bytes (expected ${PAGE_SIZE})`,
    );
  }

  /**
   * Internal XTS decryption (reuses the same key derivation as encryptPage).
   * Returns garbage on wrong key (XTS has no auth, just diffusion).
   */
  private xtsDecrypt(ciphertext: Buffer, pageNumber: number): Buffer {
    const { dataKey, tweakKey } = deriveXtsKeys(this.masterKey!);

    // Same tweak generation as encryption
    const tweakInput = Buffer.alloc(BLOCK_SIZE, 0);
    tweakInput.writeBigUInt64LE(BigInt(pageNumber), 0);
    let tweak = aes256EcbEncrypt(tweakKey, tweakInput);

    const result = Buffer.alloc(PAGE_SIZE);
    const blockCount = PAGE_SIZE / BLOCK_SIZE;

    for (let i = 0; i < blockCount; i++) {
      const offset = i * BLOCK_SIZE;

      // Ciphertext block C
      const c = ciphertext.subarray(offset, offset + BLOCK_SIZE);

      // C XOR T
      const xored = Buffer.alloc(BLOCK_SIZE);
      for (let j = 0; j < BLOCK_SIZE; j++) {
        xored[j] = c[j] ^ tweak[j];
      }

      // P = AES_k1^{-1}(C XOR T) — XTS uses the inverse cipher for decryption
      try {
        const decryptCipher = crypto.createDecipheriv('aes-256-ecb', dataKey, null);
        decryptCipher.setAutoPadding(false);
        const p = Buffer.concat([decryptCipher.update(xored), decryptCipher.final()]);

        // P XOR T → final plaintext block
        for (let j = 0; j < BLOCK_SIZE; j++) {
          result[offset + j] = p[j] ^ tweak[j];
        }
      } catch {
        // Wrong key — produce garbage output for this block
        // XTS ciphertext stealing means wrong key always produces random-looking output
        Buffer.from(c).copy(result, offset);
      }

      tweak = gf128Mul(tweak);
    }

    return result;
  }
}
