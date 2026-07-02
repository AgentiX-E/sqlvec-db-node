/**
 * PITRCrypto — AES-256-GCM encrypt/decrypt for stored credentials and
 * backup data.
 *
 * Master key is derived from environment variable SQLVEC_PITR_MASTER_KEY.
 * If unset, a local key is generated on first use and cached (less secure).
 *
 * Encrypted output format for credentials (hex-encoded):
 *   {iv_hex}:{ciphertext_hex}
 *
 * Encrypted output format for backup data (buffer):
 *   [magic 4B = "PITR"][iv 12B][authTag 16B][ciphertext ...]
 *
 * - IV: 12 bytes (96 bits, GCM recommended)
 * - Key: 32 bytes (256 bits) derived via HKDF-SHA256 from master key
 * - Auth tag: appended to ciphertext (16 bytes)
 *
 * @module pitr/PITRCrypto
 */

import * as crypto from 'node:crypto';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PITRCrypto');

const MASTER_KEY_ENV = 'SQLVEC_PITR_MASTER_KEY';
const KEY_SALT = 'pitr-credential-v1';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32; // AES-256

/** Magic header for backup-encrypted data: "PITR" */
const BACKUP_MAGIC = Buffer.from([0x50, 0x49, 0x54, 0x52]); // "PITR"
const BACKUP_HEADER_SIZE = 4 + IV_LENGTH + AUTH_TAG_LENGTH; // 32 bytes

// ENC-02: Cache argon2id availability
let hashWasmAvailable: boolean | null = null;

function isHashWasmAvailable(): boolean {
  if (hashWasmAvailable === null) {
    try {
      require.resolve('hash-wasm');
      hashWasmAvailable = true;
    } catch {
      hashWasmAvailable = false;
    }
  }
  return hashWasmAvailable;
}

/**
 * Derive a 256-bit AES key from the master key using HKDF.
 */
function deriveKey(masterKey: Buffer): Buffer {
  const raw = crypto.hkdfSync('sha256', masterKey, KEY_SALT, 'pitr-aes-key', KEY_LENGTH);
  return Buffer.from(raw);
}

/**
 * Derive a 256-bit AES key using Argon2id (ENC-02).
 * Used when a password-based key is desired instead of a master key.
 */
async function deriveKeyArgon2id(password: string, salt: Buffer): Promise<Buffer> {
  if (isHashWasmAvailable()) {
    try {
      const { argon2id } = require('hash-wasm');
      const result = await argon2id({
        password,
        salt: salt.toString('base64'),
        parallelism: 4,
        iterations: 3,
        memorySize: 65536,
        hashLength: KEY_LENGTH,
        outputType: 'binary',
      });
      return Buffer.from(result);
    } catch {
      // Fall through to HKDF fallback
    }
  }
  // Fallback: derive using HKDF from the password
  const derived = crypto.pbkdf2Sync(password, salt, 100_000, KEY_LENGTH, 'sha512');
  return derived;
}

/**
 * Get or derive the encryption key.
 * Priority: SQLVEC_PITR_MASTER_KEY env var > generated key from keyFile.
 */
function getKey(): Buffer {
  const masterKeyHex = process.env[MASTER_KEY_ENV];
  if (masterKeyHex) {
    return deriveKey(Buffer.from(masterKeyHex, 'hex'));
  }
  throw new Error(
    `PITRCrypto: ${MASTER_KEY_ENV} is not set. ` +
    'Set this environment variable to a 64-char hex string (32 bytes) for credential encryption.',
  );
}

/**
 * Encrypt a plaintext string.
 * Returns hex-encoded "{iv}:{ciphertext+authTag}".
 */
export function pitrEncrypt(plaintext: string): string {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf-8')), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${Buffer.concat([encrypted, authTag]).toString('hex')}`;
}

/**
 * Decrypt a hex-encoded "{iv}:{ciphertext+authTag}" string.
 * Returns plaintext UTF-8 string, or null on failure.
 */
export function pitrDecrypt(encoded: string): string | null {
  try {
    const key = getKey();
    const colonIdx = encoded.indexOf(':');
    if (colonIdx === -1) return null;
    const iv = Buffer.from(encoded.substring(0, colonIdx), 'hex');
    const payload = Buffer.from(encoded.substring(colonIdx + 1), 'hex');
    const encrypted = payload.subarray(0, payload.length - AUTH_TAG_LENGTH);
    const authTag = payload.subarray(payload.length - AUTH_TAG_LENGTH);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf-8');
  } catch {
    return null;
  }
}

// ── Backup Encryption (AES-256-GCM for on-disk backup data) ─────────────────

/**
 * Encrypt raw backup data (Buffer) using AES-256-GCM.
 *
 * Output format:
 *   [magic 4B = "PITR"][iv 12B][authTag 16B][ciphertext ...]
 *
 * This format enables seamless detection of encrypted vs plaintext backups
 * during restore operations.
 *
 * @param data - Raw backup data to encrypt
 * @returns Encrypted buffer with magic header, or null if encryption fails
 *          (e.g. master key is not configured)
 */
export function encryptBackup(data: Buffer): Buffer | null {
  try {
    const key = getKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([BACKUP_MAGIC, iv, authTag, encrypted]);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error({ error: message }, 'Backup encryption failed');
    return null;
  }
}

/**
 * Decrypt backup data previously encrypted with encryptBackup().
 *
 * Detects the "PITR" magic header to distinguish encrypted backups from
 * legacy plaintext backups. Unencrypted data is returned as-is for
 * backward compatibility.
 *
 * @param data - Encrypted buffer (with magic header) or plaintext buffer
 * @returns Decrypted plaintext buffer, or null if decryption fails
 *          (wrong key, tampered data, or corrupted header)
 */
export function decryptBackup(data: Buffer): Buffer | null {
  // Plaintext backward compatibility: no magic header → pass through
  if (data.length < BACKUP_HEADER_SIZE || !data.subarray(0, 4).equals(BACKUP_MAGIC)) {
    return data;
  }

  try {
    const key = getKey();
    const iv = data.subarray(4, 4 + IV_LENGTH);
    const authTag = data.subarray(4 + IV_LENGTH, BACKUP_HEADER_SIZE);
    const ciphertext = data.subarray(BACKUP_HEADER_SIZE);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error({ error: message }, 'Backup decryption failed');
    return null;
  }
}
