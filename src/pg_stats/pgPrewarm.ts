/**
 * pgPrewarm — Track frequently accessed pages.
 *
 * While PostgreSQL's pg_prewarm loads data into the OS page cache,
 * this module tracks page access patterns to enable intelligent
 * prewarming decisions. Maintains a hot page list based on access
 * frequency and recency.
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-prewarm');

export interface PageAccessRecord {
  tableName: string;
  pageId: number;
  accessCount: number;
  lastAccessMs: number;
  firstAccessMs: number;
}

export interface PrewarmRecommendation {
  tableName: string;
  pageIds: number[];
  score: number; // access frequency * recency factor
}

export class PgPrewarm {
  /** pageKey (tableName:pageId) → PageAccessRecord */
  private pageMap: Map<string, PageAccessRecord> = new Map();
  private totalAccesses = 0;
  private maxTrackedPages = 10000;

  constructor(maxTrackedPages?: number) {
    if (maxTrackedPages !== undefined) {
      this.maxTrackedPages = maxTrackedPages;
    }
  }

  /**
   * Record a page access. Creates or updates the access record.
   */
  recordAccess(tableName: string, pageId: number): void {
    const key = `${tableName}:${pageId}`;
    const existing = this.pageMap.get(key);

    if (existing) {
      existing.accessCount++;
      existing.lastAccessMs = Date.now();
    } else {
      // Evict oldest if at capacity
      if (this.pageMap.size >= this.maxTrackedPages) {
        this.evictOldest();
      }

      this.pageMap.set(key, {
        tableName,
        pageId,
        accessCount: 1,
        lastAccessMs: Date.now(),
        firstAccessMs: Date.now(),
      });
    }

    this.totalAccesses++;
  }

  /**
   * Record multiple page accesses for a table.
   */
  recordBatch(tableName: string, pageIds: number[]): void {
    for (const pageId of pageIds) {
      this.recordAccess(tableName, pageId);
    }
  }

  /**
   * Remove tracked pages for a given table.
   */
  dropTable(tableName: string): void {
    for (const [key, record] of this.pageMap) {
      if (record.tableName === tableName) {
        this.pageMap.delete(key);
      }
    }
    logger.info({ tableName }, 'Dropped prewarm tracking for table');
  }

  // ── Query ────────────────────────────────────────────────────

  /**
   * Get all page access records for a table.
   */
  getTablePages(tableName: string): PageAccessRecord[] {
    const results: PageAccessRecord[] = [];
    for (const [, record] of this.pageMap) {
      if (record.tableName === tableName) {
        results.push({ ...record });
      }
    }
    return results.sort((a, b) => b.accessCount - a.accessCount);
  }

  /**
   * Get the most frequently accessed pages across all tables.
   */
  getHotPages(limit: number = 100): PageAccessRecord[] {
    const all = Array.from(this.pageMap.values());
    all.sort((a, b) => b.accessCount - a.accessCount);
    return all.slice(0, limit).map(r => ({ ...r }));
  }

  /**
   * Get prewarm recommendations: hot pages that are candidates
   * for prewarming. Includes a composite score.
   */
  getPrewarmRecommendations(limit: number = 50, decayHours: number = 24): PrewarmRecommendation[] {
    const now = Date.now();
    const decayMs = decayHours * 60 * 60 * 1000;
    const tableMap = new Map<string, { pageIds: number[]; score: number }>();

    const sorted = Array.from(this.pageMap.values())
      .sort((a, b) => {
        // Score: accessCount * recency factor
        const ageA = now - a.lastAccessMs;
        const ageB = now - b.lastAccessMs;
        const recencyA = Math.max(0, 1 - ageA / decayMs);
        const recencyB = Math.max(0, 1 - ageB / decayMs);
        const scoreA = a.accessCount * (0.5 + 0.5 * recencyA);
        const scoreB = b.accessCount * (0.5 + 0.5 * recencyB);
        return scoreB - scoreA;
      })
      .slice(0, limit);

    for (const record of sorted) {
      if (!tableMap.has(record.tableName)) {
        const age = now - record.lastAccessMs;
        const recency = Math.max(0, 1 - age / decayMs);
        tableMap.set(record.tableName, {
          pageIds: [],
          score: record.accessCount * (0.5 + 0.5 * recency),
        });
      }
      tableMap.get(record.tableName)!.pageIds.push(record.pageId);
    }

    return Array.from(tableMap.entries()).map(([tableName, info]) => ({
      tableName,
      pageIds: info.pageIds,
      score: Math.round(info.score * 100) / 100,
    }));
  }

  /**
   * Get total access statistics.
   */
  getStats(): { totalAccesses: number; trackedPages: number; maxTrackedPages: number } {
    return {
      totalAccesses: this.totalAccesses,
      trackedPages: this.pageMap.size,
      maxTrackedPages: this.maxTrackedPages,
    };
  }

  /** Clear all tracked pages. */
  clear(): void {
    this.pageMap.clear();
    this.totalAccesses = 0;
  }

  // ── Internal ─────────────────────────────────────────────────

  /** Evict the oldest (by lastAccessMs) tracked page. */
  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestAccess = Infinity;

    for (const [key, record] of this.pageMap) {
      if (record.lastAccessMs < oldestAccess) {
        oldestAccess = record.lastAccessMs;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.pageMap.delete(oldestKey);
    }
  }
}
