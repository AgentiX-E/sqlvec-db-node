/**
 * BackupEncryptionManager — AES-256-GCM backup encryption and decryption
 *
 * Provides AES-256-GCM authenticated encryption for SQLite backup files,
 * using PBKDF2 for password-based key derivation. This addresses gap SE04 (P0):
 * backup files were previously stored unencrypted.
 *
 * Format:
 *   [salt 16B][IV 12B][authTag 16B][ciphertext ...]
 *
 * @module BackupEncryptionManager
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';

import { PinoLogger } from '../monitoring/PinoLogger';
import { KeyManager } from './KeyManager';

const logger = PinoLogger.forComponent('BackupEncryption');

// ── Constants ────────────────────────────────────────────────────────────────

/** PBKDF2 salt length in bytes. */
const SALT_LENGTH = 16;
/** AES-256-GCM initialisation vector length in bytes. */
const IV_LENGTH = 12;
/** GCM authentication tag length in bytes. */
const AUTH_TAG_LENGTH = 16;
/** Derived key length for AES-256 (32 bytes = 256 bits). */
const KEY_LENGTH = 32;
/** PBKDF2 iteration count. */
const PBKDF2_ITERATIONS = 100_000;
/** PBKDF2 hash algorithm. */
const PBKDF2_DIGEST = 'sha512';
/** AES-256-GCM cipher algorithm identifier. */
const CIPHER_ALGORITHM = 'aes-256-gcm';
/** Total header size (salt + IV + authTag). */
const HEADER_SIZE = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH; // 44
/** Size of a header chunk read at once. */
const READ_CHUNK_SIZE = 65_536;

// ── Types ────────────────────────────────────────────────────────────────────

export interface EncryptBackupInput {
  /** 备份文件路径 */
  inputPath: string;
  /** 输出加密文件路径 */
  outputPath: string;
  /** 加密密码（用于派生 AES 密钥） */
  password: string;
}

export interface DecryptBackupInput {
  /** 加密备份文件路径 */
  inputPath: string;
  /** 输出解密文件路径 */
  outputPath: string;
  /** 解密密码 */
  password: string;
}

export interface EncryptionResult {
  success: boolean;
  outputPath: string;
  algorithm: string;
  error?: string;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Derive an AES-256 key from a password and salt using PBKDF2.
 *
 * @param password - The user-supplied password.
 * @param salt     - Cryptographic salt (16 bytes).
 * @returns A 32-byte (256-bit) key suitable for AES-256-GCM.
 */
function deriveKey(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    PBKDF2_DIGEST,
  );
}

// ── ENC-02: Argon2id key derivation (async) ─────────────────────

let hashWasmAvailable: boolean | null = null;

/**
 * Check if hash-wasm is available for Argon2id.
 */
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
 * Derive an AES-256 key using Argon2id (memory-hard KDF).
 * Falls back to PBKDF2 if hash-wasm is not available.
 *
 * @param password - User-supplied password.
 * @param salt     - Cryptographic salt (16 bytes).
 * @param keyLength - Desired key length in bytes (default: 32).
 * @returns A Buffer containing the derived key.
 */
async function deriveKeyArgon2id(password: string, salt: Buffer, keyLength: number = KEY_LENGTH): Promise<Buffer> {
  if (isHashWasmAvailable()) {
    try {
      const { argon2id } = require('hash-wasm');
      const result = await argon2id({
        password,
        salt: salt.toString('base64'),
        parallelism: 4,
        iterations: 3,
        memorySize: 65536, // 64 MB
        hashLength: keyLength,
        outputType: 'binary',
      });
      return Buffer.from(result);
    } catch (err) {
      logger.warn('[BackupEncryption] Argon2id failed, falling back to PBKDF2:', (err as Error).message);
    }
  }
  return deriveKey(password, salt);
}

/**
 * Generate a version-tagged header for key rotation.
 *
 * Format: [version 4B][salt 16B][IV 12B]
 * The version corresponds to a KeyManager key version.
 */
function createVersionedHeader(version: number, salt: Buffer, iv: Buffer): Buffer {
  const versionBuf = Buffer.alloc(4);
  versionBuf.writeUInt32BE(version);
  return Buffer.concat([versionBuf, salt, iv]);
}

/**
 * Parse a version-tagged header to extract key version.
 * Returns null if no version header (legacy format).
 */
function parseVersionedHeader(header: Buffer): { version: number; salt: Buffer; iv: Buffer } | null {
  if (header.length < SALT_LENGTH + IV_LENGTH + 4) return null;

  // Check if first 4 bytes look like a version number (1-99999)
  const version = header.readUInt32BE(0);
  if (version >= 1 && version <= 99999) {
    return {
      version,
      salt: header.subarray(4, 4 + SALT_LENGTH),
      iv: header.subarray(4 + SALT_LENGTH, 4 + SALT_LENGTH + IV_LENGTH),
    };
  }

  return null;
}

/**
 * Create a Transform stream that encrypts data using the provided Cipher.
 * On flush, the GCM authentication tag is appended to the stream.
 */
function createEncryptTransform(cipher: crypto.CipherGCM): Transform {
  return new Transform({
    highWaterMark: READ_CHUNK_SIZE,
    transform(chunk: Buffer, _encoding: string, callback) {
      try {
        callback(null, cipher.update(chunk));
      } catch (err) {
        callback(err as Error);
      }
    },
    flush(callback) {
      try {
        const final = cipher.final();
        const authTag = cipher.getAuthTag();
        callback(null, Buffer.concat([final, authTag]));
      } catch (err) {
        callback(err as Error);
      }
    },
  });
}

/**
 * Create a Transform stream that decrypts data using the provided Decipher.
 * The authentication tag must be set on the Decipher before the first
 * `decipher.update()` call.
 */
function createDecryptTransform(decipher: crypto.DecipherGCM): Transform {
  return new Transform({
    highWaterMark: READ_CHUNK_SIZE,
    transform(chunk: Buffer, _encoding: string, callback) {
      try {
        callback(null, decipher.update(chunk));
      } catch (err) {
        callback(err as Error);
      }
    },
    flush(callback) {
      try {
        callback(null, decipher.final());
      } catch (err) {
        callback(err as Error);
      }
    },
  });
}

// ── Core API ─────────────────────────────────────────────────────────────────

/**
 * Encrypt backup file using AES-256-GCM.
 *
 * Steps:
 * 1. Generate random salt (16B) and IV (12B)
 * 2. Derive AES-256 key via PBKDF2 (100 000 iterations, SHA-512)
 * 3. Write [salt || IV] header to output
 * 4. Stream input through AES-256-GCM cipher into output
 * 5. Append GCM authentication tag (16B) to output
 *
 * @param input - Encryption parameters (source file, destination, password).
 * @returns EncryptionResult indicating success or failure.
 */
export async function encryptBackup(
  input: EncryptBackupInput,
): Promise<EncryptionResult> {
  const { inputPath, outputPath, password } = input;

  try {
    const resolvedInput = path.resolve(inputPath);
    const resolvedOutput = path.resolve(outputPath);

    if (!fs.existsSync(resolvedInput)) {
      return {
        success: false,
        outputPath: resolvedOutput,
        algorithm: CIPHER_ALGORITHM,
        error: `Input file not found: ${resolvedInput}`,
      };
    }

    // Ensure output directory exists
    const outputDir = path.dirname(resolvedOutput);
    fs.mkdirSync(outputDir, { recursive: true });

    const salt = crypto.randomBytes(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveKey(password, salt);

    const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv);

    const readStream = fs.createReadStream(resolvedInput, {
      highWaterMark: READ_CHUNK_SIZE,
    });
    const writeStream = fs.createWriteStream(resolvedOutput);
    const encryptTransform = createEncryptTransform(cipher);

    // Write header first
    writeStream.write(salt);
    writeStream.write(iv);

    await pipeline(readStream, encryptTransform, writeStream);

    logger.info({
      action: 'encrypt',
      inputPath: resolvedInput,
      outputPath: resolvedOutput,
      algorithm: CIPHER_ALGORITHM,
      pbkdf2Iterations: PBKDF2_ITERATIONS,
    }, 'Backup encrypted successfully');

    return {
      success: true,
      outputPath: resolvedOutput,
      algorithm: CIPHER_ALGORITHM,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error({
      action: 'encrypt',
      inputPath,
      outputPath,
      error: message,
    }, 'Backup encryption failed');

    return {
      success: false,
      outputPath: path.resolve(outputPath),
      algorithm: CIPHER_ALGORITHM,
      error: message,
    };
  }
}

/**
 * Decrypt backup file that was encrypted with `encryptBackup`.
 *
 * Steps:
 * 1. Read header: salt (16B) || IV (12B) || authTag (16B)
 * 2. Derive AES-256 key via PBKDF2
 * 3. Set authentication tag on decipher
 * 4. Stream remaining ciphertext through AES-256-GCM decipher into output
 *
 * @param input - Decryption parameters (encrypted file path, destination, password).
 * @returns EncryptionResult indicating success or failure.
 */
export async function decryptBackup(
  input: DecryptBackupInput,
): Promise<EncryptionResult> {
  const { inputPath, outputPath, password } = input;

  try {
    const resolvedInput = path.resolve(inputPath);
    const resolvedOutput = path.resolve(outputPath);

    if (!fs.existsSync(resolvedInput)) {
      return {
        success: false,
        outputPath: resolvedOutput,
        algorithm: CIPHER_ALGORITHM,
        error: `Input file not found: ${resolvedInput}`,
      };
    }

    // Open file for reading header + authTag from end
    const fd = fs.openSync(resolvedInput, 'r');
    const fileSize = fs.fstatSync(fd).size;

    // Minimum file size: salt (16) + IV (12) + authTag (16) = 44 bytes
    if (fileSize < HEADER_SIZE) {
      fs.closeSync(fd);
      return {
        success: false,
        outputPath: resolvedOutput,
        algorithm: CIPHER_ALGORITHM,
        error: `Corrupt encrypted file: file too small (${fileSize} < ${HEADER_SIZE})`,
      };
    }

    // Read header: salt (16B) + IV (12B)
    const headerSize = SALT_LENGTH + IV_LENGTH;
    const header = Buffer.alloc(headerSize);
    const bytesRead = fs.readSync(fd, header, 0, headerSize, 0);

    if (bytesRead < headerSize) {
      fs.closeSync(fd);
      return {
        success: false,
        outputPath: resolvedOutput,
        algorithm: CIPHER_ALGORITHM,
        error: `Corrupt encrypted file: header too short (${bytesRead} < ${headerSize})`,
      };
    }

    const salt = header.subarray(0, SALT_LENGTH);
    const iv = header.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);

    // Read authTag (16B) from the end of the file (appended by encryptTransform flush)
    const authTag = Buffer.alloc(AUTH_TAG_LENGTH);
    const authTagBytesRead = fs.readSync(fd, authTag, 0, AUTH_TAG_LENGTH, fileSize - AUTH_TAG_LENGTH);
    if (authTagBytesRead < AUTH_TAG_LENGTH) {
      fs.closeSync(fd);
      return {
        success: false,
        outputPath: resolvedOutput,
        algorithm: CIPHER_ALGORITHM,
        error: `Corrupt encrypted file: could not read authTag (${authTagBytesRead} < ${AUTH_TAG_LENGTH})`,
      };
    }

    const key = deriveKey(password, salt);
    const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    // Stream bytes between header and authTag through decipher
    const readStream = fs.createReadStream(resolvedInput, {
      start: headerSize,
      end: fileSize - AUTH_TAG_LENGTH - 1,
      highWaterMark: READ_CHUNK_SIZE,
    });

    // Ensure output directory exists
    const outputDir = path.dirname(resolvedOutput);
    fs.mkdirSync(outputDir, { recursive: true });

    const writeStream = fs.createWriteStream(resolvedOutput);
    const decryptTransform = createDecryptTransform(decipher);

    await pipeline(readStream, decryptTransform, writeStream);

    fs.closeSync(fd);

    logger.info({
      action: 'decrypt',
      inputPath: resolvedInput,
      outputPath: resolvedOutput,
      algorithm: CIPHER_ALGORITHM,
    }, 'Backup decrypted successfully');

    return {
      success: true,
      outputPath: resolvedOutput,
      algorithm: CIPHER_ALGORITHM,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    // Distinguish authentication failures (wrong password / tampered data)
    // from other errors.
    if (err instanceof crypto.Certificate) {
      // AES-GCM authentication failures manifest as an error from decipher.final()
      // with a message containing "bad decrypt" or "auth tag" etc.
    }

    logger.error({
      action: 'decrypt',
      inputPath,
      outputPath,
      error: message,
    }, 'Backup decryption failed');

    return {
      success: false,
      outputPath: path.resolve(outputPath),
      algorithm: CIPHER_ALGORITHM,
      error: message,
    };
  }
}

/**
 * Verify that a file starts with the standard SQLite database header.
 *
 * The SQLite header magic bytes are: `SQLite format 3\0` (16 bytes).
 *
 * @param filePath - Path to the file to check.
 * @returns `true` if the file begins with the SQLite header magic, `false` otherwise.
 */
export function verifySqliteHeader(filePath: string): boolean {
  try {
    const resolvedPath = path.resolve(filePath);

    if (!fs.existsSync(resolvedPath)) {
      logger.warn({ filePath: resolvedPath }, 'File not found for SQLite header check');
      return false;
    }

    const fd = fs.openSync(resolvedPath, 'r');
    const header = Buffer.alloc(16);
    const bytesRead = fs.readSync(fd, header, 0, 16, 0);
    fs.closeSync(fd);

    if (bytesRead < 16) {
      return false;
    }

    // SQLite header magic: 0x53 0x51 0x4c 0x69 0x74 0x65 0x20 0x66 0x6f 0x72 0x6d 0x61 0x74 0x20 0x33 0x00
    // which is "SQLite format 3\0"
    const sqliteMagic = Buffer.from('SQLite format 3\0', 'utf8');
    return header.equals(sqliteMagic);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error({ filePath, error: message }, 'SQLite header verification failed');
    return false;
  }
}

/**
 * Generate a cryptographically random 256-bit hex-encoded key.
 *
 * The returned string can be used directly as a password for
 * `encryptBackup` / `decryptBackup` in non-interactive scenarios
 * (e.g. automated backup pipelines).
 *
 * @returns A 64-character hex string (256 bits).
 */
export function generateEncryptionKey(): string {
  return crypto.randomBytes(32).toString('hex');
}
