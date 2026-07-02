/**
 * PITRRemoteStorage — Remote storage abstraction for PITR WAL segments.
 *
 * Supports three backends:
 *   - 'nas': filesystem copy/move (NFS mount — network-attached storage)
 *   - 's3':  S3-compatible object storage (AWS, MinIO, etc.)
 *   - 'gcs': GCS-compatible object storage (simplified; uses S3-compatible API subset)
 *
 * For 's3' backend: uses the standard S3 HTTP API with AWS Signature V4
 * via the built-in `fetch` API — no external SDK required.
 *
 * Phase 5: Remote Storage
 *
 * @see design-pitr.md §7 Phase 5
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('PITRRemoteStorage');

// ── Types ─────────────────────────────────────────────────────────────────────

export type RemoteStorageBackend = 'nas' | 's3' | 'gcs' | 'custom';

export interface PITRRemoteStorageConfig {
  /** Storage backend type */
  backend: RemoteStorageBackend;
  /** S3/GCS bucket name */
  bucket?: string;
  /** Key prefix (e.g. "pitr/") */
  prefix?: string;
  /** For 'nas' backend: base path for storage (NFS mount point) */
  nasPath?: string;
  /** For S3-compatible: endpoint URL (e.g. "https://s3.amazonaws.com") */
  endpoint?: string;
  /** For S3/GCS: region (e.g. "us-east-1") */
  region?: string;
  /** AWS access key ID */
  accessKeyId?: string;
  /** AWS secret access key */
  secretAccessKey?: string;
  /** Maximum concurrent uploads/downloads (default: 4) */
  maxConcurrent?: number;
}

export interface RemoteStorageStatus {
  backend: RemoteStorageBackend;
  connected: boolean;
  lastSync: string | null;
}

// ── PITRRemoteStorage ─────────────────────────────────────────────────────────

/**
 * Remote storage for PITR WAL segment archival and retrieval.
 *
 * Usage:
 * ```ts
 * const remote = new PITRRemoteStorage({
 *   backend: 's3',
 *   bucket: 'my-pitr-backups',
 *   prefix: 'pitr/cluster-1/',
 *   region: 'us-east-1',
 *   accessKeyId: process.env.AWS_ACCESS_KEY_ID,
 *   secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
 * });
 *
 * await remote.uploadSegment('/data/pitr/pitr-segment-000001.wal.gz', 'pitr-segment-000001.wal.gz');
 * ```
 */
export class PITRRemoteStorage {
  private config: PITRRemoteStorageConfig;
  private lastSync: string | null = null;
  private activeRequests = 0;
  private maxConcurrent: number;

  constructor(config: PITRRemoteStorageConfig) {
    this.config = {
      ...config,
      maxConcurrent: config.maxConcurrent ?? 4,
      prefix: config.prefix || '',
    };
    this.maxConcurrent = this.config.maxConcurrent!;

    // Validate required fields based on backend
    if (this.config.backend === 'nas' && !this.config.nasPath) {
      throw new Error('PITRRemoteStorage: nasPath is required for backend "nas"');
    }
    if ((this.config.backend === 's3' || this.config.backend === 'gcs') && !this.config.bucket) {
      throw new Error(`PITRRemoteStorage: bucket is required for backend "${this.config.backend}"`);
    }

    // For 'nas' backend, ensure the storage path exists
    if (this.config.backend === 'nas' && this.config.nasPath) {
      fs.mkdirSync(path.resolve(this.config.nasPath), { recursive: true });
    }

    logger.info(
      `PITRRemoteStorage initialized: backend=${this.config.backend}` +
      `${this.config.bucket ? ` bucket=${this.config.bucket}` : ''}` +
      `${this.config.prefix ? ` prefix=${this.config.prefix}` : ''}`,
    );
  }

  /**
   * Upload a WAL segment to remote storage.
   *
   * @param localPath - Full path to the local segment file
   * @param segmentName - Remote key name (filename only; prefix is prepended)
   */
  async uploadSegment(localPath: string, segmentName: string): Promise<void> {
    await this.acquireSlot();

    try {
      const resolvedLocalPath = path.resolve(localPath);

      if (!fs.existsSync(resolvedLocalPath)) {
        throw new Error(`Local segment file not found: ${resolvedLocalPath}`);
      }

      const remoteKey = this.buildKey(segmentName);

      switch (this.config.backend) {
        case 'nas':
          await this.uploadNAS(resolvedLocalPath, remoteKey);
          break;
        case 's3':
        case 'gcs':
          await this.uploadS3(resolvedLocalPath, remoteKey);
          break;
        default:
          throw new Error(`Unsupported backend: ${this.config.backend}`);
      }

      this.lastSync = new Date().toISOString();
      logger.info(`Uploaded segment: ${segmentName} → ${remoteKey}`);
    } finally {
      this.releaseSlot();
    }
  }

  /**
   * Download a WAL segment from remote storage to a local path.
   *
   * @param segmentName - Remote key name (filename only; prefix is prepended)
   * @param destPath - Full local path to write the downloaded file
   */
  async downloadSegment(segmentName: string, destPath: string): Promise<void> {
    await this.acquireSlot();

    try {
      const remoteKey = this.buildKey(segmentName);
      const resolvedDest = path.resolve(destPath);
      const destDir = path.dirname(resolvedDest);

      if (!fs.existsSync(destDir)) {
        fs.mkdirSync(destDir, { recursive: true });
      }

      switch (this.config.backend) {
        case 'nas':
          await this.downloadNAS(remoteKey, resolvedDest);
          break;
        case 's3':
        case 'gcs':
          await this.downloadS3(remoteKey, resolvedDest);
          break;
        default:
          throw new Error(`Unsupported backend: ${this.config.backend}`);
      }

      logger.info(`Downloaded segment: ${remoteKey} → ${resolvedDest}`);
    } finally {
      this.releaseSlot();
    }
  }

  /**
   * List available segments in remote storage.
   *
   * @param prefix - Optional prefix filter (appended to configured prefix)
   * @returns Array of segment key names (without the configured prefix)
   */
  async listSegments(prefix?: string): Promise<string[]> {
    await this.acquireSlot();

    try {
      const listPrefix = this.buildKey(prefix || '');

      switch (this.config.backend) {
        case 'nas':
          return this.listNAS(listPrefix);
        case 's3':
        case 'gcs':
          return this.listS3(listPrefix);
        default:
          throw new Error(`Unsupported backend: ${this.config.backend}`);
      }
    } finally {
      this.releaseSlot();
    }
  }

  /**
   * Delete a segment from remote storage.
   *
   * @param segmentName - Remote key name (filename only; prefix is prepended)
   */
  async deleteSegment(segmentName: string): Promise<void> {
    await this.acquireSlot();

    try {
      const remoteKey = this.buildKey(segmentName);

      switch (this.config.backend) {
        case 'nas':
          await this.deleteNAS(remoteKey);
          break;
        case 's3':
        case 'gcs':
          await this.deleteS3(remoteKey);
          break;
        default:
          throw new Error(`Unsupported backend: ${this.config.backend}`);
      }

      logger.info(`Deleted segment: ${remoteKey}`);
    } finally {
      this.releaseSlot();
    }
  }

  /**
   * Check if a segment exists in remote storage.
   *
   * @param segmentName - Remote key name (filename only; prefix is prepended)
   */
  async segmentExists(segmentName: string): Promise<boolean> {
    const remoteKey = this.buildKey(segmentName);

    switch (this.config.backend) {
      case 'nas': {
        const localFilePath = path.resolve(this.config.nasPath!, remoteKey);
        return fs.existsSync(localFilePath);
      }
      case 's3':
      case 'gcs': {
        // Use a HEAD request to check existence
        const url = this.buildS3Url(remoteKey);
        const headers = await this.signHeaders('HEAD', remoteKey, {});

        try {
          const response = await fetch(url, {
            method: 'HEAD',
            headers,
          });
          return response.status === 200;
        } catch {
          return false;
        }
      }
      default:
        return false;
    }
  }

  /**
   * Get the current status of the remote storage connection.
   */
  getStatus(): RemoteStorageStatus {
    let connected = false;

    if (this.config.backend === 'nas') {
      connected = this.config.nasPath ? fs.existsSync(path.resolve(this.config.nasPath)) : false;
    } else {
      // For S3/GCS, we assume connected if credentials are configured
      connected = !!(this.config.accessKeyId && this.config.secretAccessKey);
    }

    return {
      backend: this.config.backend,
      connected,
      lastSync: this.lastSync,
    };
  }

  // ── Config Helpers ──────────────────────────────────────────────────

  /** Build the full remote key by prepending the configured prefix. */
  private buildKey(name: string): string {
    return this.config.prefix ? `${this.config.prefix}${name}` : name;
  }

  /** Build the S3 endpoint URL for a given key. */
  private buildS3Url(key: string): string {
    const endpoint = this.config.endpoint || `https://s3.${this.config.region || 'us-east-1'}.amazonaws.com`;
    return `${endpoint.replace(/\/+$/, '')}/${this.config.bucket}/${key}`;
  }

  // ── Concurrency Control ─────────────────────────────────────────────

  private async acquireSlot(): Promise<void> {
    while (this.activeRequests >= this.maxConcurrent) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    this.activeRequests++;
  }

  private releaseSlot(): void {
    this.activeRequests--;
  }

  // ══════════════════════════════════════════════════════════════════════
  //  NAS Backend (filesystem copy — network-attached storage / NFS mount)
  // ══════════════════════════════════════════════════════════════════════

  private async uploadNAS(srcPath: string, remoteKey: string): Promise<void> {
    const destPath = path.resolve(this.config.nasPath!, remoteKey);
    const destDir = path.dirname(destPath);

    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }

    // Copy instead of move so the original segment remains locally
    fs.copyFileSync(srcPath, destPath);
  }

  private async downloadNAS(remoteKey: string, destPath: string): Promise<void> {
    const srcPath = path.resolve(this.config.nasPath!, remoteKey);

    if (!fs.existsSync(srcPath)) {
      throw new Error(`Remote segment not found (nas backend): ${srcPath}`);
    }

    fs.copyFileSync(srcPath, destPath);
  }

  private async listNAS(prefix: string): Promise<string[]> {
    const basePath = path.resolve(this.config.nasPath!);
    const resolvedPrefix = path.resolve(basePath, prefix);

    if (!fs.existsSync(resolvedPrefix)) {
      return [];
    }

    const entries: string[] = [];

    const walkDir = (dir: string, relativePath: string): void => {
      const items = fs.readdirSync(dir, { withFileTypes: true });
      for (const item of items) {
        const fullPath = path.join(dir, item.name);
        // Strip trailing slash to avoid // in combined paths when prefix ends with /
        const normalized = relativePath.replace(/\/+$/, '');
        const relPath = normalized ? `${normalized}/${item.name}` : item.name;

        if (item.isDirectory()) {
          walkDir(fullPath, relPath);
        } else {
          entries.push(relPath);
        }
      }
    };

    if (fs.statSync(resolvedPrefix).isDirectory()) {
      walkDir(resolvedPrefix, prefix);
    }

    // Strip the list prefix from each entry so callers get relative segment names
    const normalizedPrefix = prefix.replace(/\/+$/, '') + '/';
    return entries.map((entry) =>
      entry.startsWith(normalizedPrefix) ? entry.substring(normalizedPrefix.length) : entry,
    );
  }

  private async deleteNAS(remoteKey: string): Promise<void> {
    const filePath = path.resolve(this.config.nasPath!, remoteKey);

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  // ══════════════════════════════════════════════════════════════════════
  //  S3 Backend (AWS Signature V4 via fetch)
  // ══════════════════════════════════════════════════════════════════════

  private async uploadS3(srcPath: string, key: string): Promise<void> {
    const fileContent = fs.readFileSync(srcPath);
    const url = this.buildS3Url(key);

    const headers = await this.signHeaders('PUT', key, {
      'Content-Length': String(fileContent.length),
      'Content-Type': 'application/octet-stream',
      'x-amz-content-sha256': this.sha256Hex(fileContent),
    });

    const response = await fetch(url, {
      method: 'PUT',
      headers,
      body: fileContent,
    });

    if (response.status !== 200) {
      const body = await response.text();
      throw new Error(`S3 upload failed (${response.status}): ${body}`);
    }
  }

  private async downloadS3(key: string, destPath: string): Promise<void> {
    const url = this.buildS3Url(key);

    const headers = await this.signHeaders('GET', key, {
      'x-amz-content-sha256': this.sha256Hex(Buffer.from('')),
    });

    const response = await fetch(url, {
      method: 'GET',
      headers,
    });

    if (response.status !== 200) {
      const body = await response.text();
      throw new Error(`S3 download failed (${response.status}): ${body}`);
    }

    const buffer = Buffer.from(await response.arrayBuffer());
    fs.writeFileSync(destPath, buffer);
  }

  private async listS3(prefix: string): Promise<string[]> {
    const bucket = this.config.bucket!;
    const endpoint = this.config.endpoint || `https://s3.${this.config.region || 'us-east-1'}.amazonaws.com`;
    const queryString = `list-type=2&prefix=${encodeURIComponent(prefix)}`;
    const url = `${endpoint.replace(/\/+$/, '')}/${bucket}?${queryString}`;

    // Path-style list:
    //   URL:  https://{endpoint}/{bucket}?list-type=2&prefix=...
    //   Canonical URI: /{bucket}/
    //   Canonical query string: list-type=2&prefix=...
    const headers = await this.signHeaders('GET', '/', {}, queryString);

    const response = await fetch(url, {
      method: 'GET',
      headers,
    });

    if (response.status !== 200) {
      const body = await response.text();
      throw new Error(`S3 list failed (${response.status}): ${body}`);
    }

    const body = await response.text();
    return this.parseS3ListResponse(body, prefix);
  }

  private async deleteS3(key: string): Promise<void> {
    const url = this.buildS3Url(key);

    const headers = await this.signHeaders('DELETE', key, {
      'x-amz-content-sha256': this.sha256Hex(Buffer.from('')),
    });

    const response = await fetch(url, {
      method: 'DELETE',
      headers,
    });

    if (response.status !== 204 && response.status !== 200) {
      const body = await response.text();
      throw new Error(`S3 delete failed (${response.status}): ${body}`);
    }
  }

  /**
   * Parse an S3 ListObjectsV2 XML response and extract keys.
   */
  private parseS3ListResponse(xml: string, prefix: string): string[] {
    const keys: string[] = [];
    const contentMatch = xml.match(/<Contents>([\s\S]*?)<\/Contents>/g);

    if (!contentMatch) return [];

    for (const content of contentMatch) {
      const keyMatch = content.match(/<Key>([^<]+)<\/Key>/);
      if (keyMatch && keyMatch[1]) {
        const key = keyMatch[1];
        // Strip the prefix to return relative names
        const relativeKey = key.startsWith(prefix) ? key.substring(prefix.length) : key;
        keys.push(relativeKey);
      }
    }

    return keys;
  }

  // ══════════════════════════════════════════════════════════════════════
  //  AWS Signature V4
  // ══════════════════════════════════════════════════════════════════════

  /**
   * Create AWS Signature V4 signed headers for S3 requests.
   *
   * Uses PATH-STYLE: the bucket name is part of the canonical URI path,
   * not in the Host header. Works with both AWS S3 and S3-compatible
   * storage (MinIO, Ceph, etc.) on any port.
   *
   * Implements the AWS SigV4 process described at:
   * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
   *
   * @param method - HTTP method (GET, PUT, DELETE, HEAD)
   * @param key - Object key path (e.g. 'my-segment.wal.gz'). For operations
   *              that target the bucket root (e.g. ListObjectsV2), pass '/'.
   * @param extraHeaders - Additional headers to include and sign
   * @param queryString - Query string for the canonical request (e.g.
   *                      'list-type=2&prefix=pitr/'). Empty string by default.
   */
  private async signHeaders(
    method: string,
    key: string,
    extraHeaders: Record<string, string>,
    queryString: string = '',
  ): Promise<Record<string, string>> {
    const accessKey = this.config.accessKeyId || '';
    const secretKey = this.config.secretAccessKey || '';
    const region = this.config.region || 'us-east-1';
    const service = 's3';
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = now.toISOString().substring(0, 10).replace(/-/g, '');

    const headers: Record<string, string> = {
      'x-amz-date': amzDate,
      ...extraHeaders,
    };

    // Set Host header from endpoint URL
    // Path-style: host is just the endpoint (s3.region.amazonaws.com for AWS,
    // or custom host:port for MinIO/etc.)
    if (this.config.endpoint) {
      const urlObj = new URL(this.config.endpoint);
      headers['host'] = urlObj.host;
    } else {
      headers['host'] = `s3.${region}.amazonaws.com`;
    }

    if (!headers['x-amz-content-sha256']) {
      headers['x-amz-content-sha256'] = this.sha256Hex(Buffer.from(''));
    }

    // Build Canonical Request
    // PATH-STYLE: canonical URI includes /{bucket}/{key}
    // For bucket-level operations (list), key='/' → /{bucket} (no trailing slash)
    // https://docs.aws.amazon.com/AmazonS3/latest/userguide/path-style-access.html
    const canonicalPath = key === '/' ? `/${this.config.bucket}` : `/${this.config.bucket}/${key}`;
    const canonicalUri = canonicalPath;
    const canonicalQueryString = queryString;
    const signedHeaders = Object.keys(headers)
      .map(h => h.toLowerCase())
      .sort()
      .join(';');

    const canonicalHeaders = Object.keys(headers)
      .sort()
      .map(h => `${h.toLowerCase()}:${headers[h]}\n`)
      .join('');

    const canonicalRequest = [
      method,
      canonicalUri,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      headers['x-amz-content-sha256'],
    ].join('\n');

    const canonicalRequestHash = this.sha256Hex(Buffer.from(canonicalRequest, 'utf-8'));

    // Build String to Sign
    const algorithm = 'AWS4-HMAC-SHA256';
    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = [
      algorithm,
      amzDate,
      credentialScope,
      canonicalRequestHash,
    ].join('\n');

    // Compute Signature
    const signingKey = await this.getSignatureKey(secretKey, dateStamp, region, service);
    const signature = this.hmacHex(signingKey, stringToSign);

    // Add Authorization header
    const credential = `${accessKey}/${credentialScope}`;
    headers['Authorization'] = `${algorithm} Credential=${credential}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return headers;
  }

  /**
   * Derive the AWS Signature V4 signing key.
   *
   * kSecret = "AWS4" + secretAccessKey
   * kDate = HMAC-SHA256(kSecret, dateStamp)
   * kRegion = HMAC-SHA256(kDate, region)
   * kService = HMAC-SHA256(kRegion, service)
   * kSigning = HMAC-SHA256(kService, "aws4_request")
   */
  private async getSignatureKey(
    key: string,
    dateStamp: string,
    region: string,
    service: string,
  ): Promise<Buffer> {
    const kSecret = Buffer.from(`AWS4${key}`, 'utf-8');
    const kDate = this.hmac(kSecret, dateStamp);
    const kRegion = this.hmac(kDate, region);
    const kService = this.hmac(kRegion, service);
    const kSigning = this.hmac(kService, 'aws4_request');
    return kSigning;
  }

  private sha256Hex(data: Buffer): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private hmac(key: Buffer, data: string): Buffer {
    return crypto.createHmac('sha256', key).update(data, 'utf-8').digest();
  }

  private hmacHex(key: Buffer, data: string): string {
    return crypto.createHmac('sha256', key).update(data, 'utf-8').digest('hex');
  }
}
