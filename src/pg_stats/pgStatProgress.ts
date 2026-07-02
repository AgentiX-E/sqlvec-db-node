/**
 * pgStatProgress — PostgreSQL pg_stat_progress_* view compatibility.
 *
 * Tracks progress for:
 *   - VACUUM (pg_stat_progress_vacuum)
 *   - CREATE INDEX (pg_stat_progress_create_index)
 *   - COPY (pg_stat_progress_copy)
 *
 * Each operation reports progress as a fraction (0.0 – 1.0) and
 * phase-specific metadata.
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('pg-stat-progress');

// ── Vacuum ──────────────────────────────────────────────────────

export enum VacuumPhase {
  INITIALIZING = 'initializing',
  SCANNING_HEAP = 'scanning heap',
  VACUUMING_INDEXES = 'vacuuming indexes',
  VACUUMING_HEAP = 'vacuuming heap',
  CLEANING_INDEXES = 'cleaning indexes',
  TRUNCATING = 'truncating',
  FINAL_CLEANUP = 'final cleanup',
}

export interface VacuumProgress {
  pid: number;
  datid: string;
  datname: string;
  relid: string;
  phase: VacuumPhase;
  heapBlksTotal: number;
  heapBlksScanned: number;
  heapBlksVacuumed: number;
  indexVacuumCount: number;
  maxDeadTuples: number;
  numDeadTuples: number;
  progress: number; // 0.0 – 1.0
}

// ── Create Index ────────────────────────────────────────────────

export enum CreateIndexPhase {
  INITIALIZING = 'initializing',
  BUILDING_INDEX = 'building index',
  SORTING_TUPLES = 'sorting tuples',
  PERFORMING_SORT = 'performing sort',
  WAITING_WRITERS = 'waiting for writers',
  BUILDING_HISTOGRAM = 'building histogram',
  FINALIZING = 'finalizing',
}

export interface CreateIndexProgress {
  pid: number;
  datid: string;
  datname: string;
  relid: string;
  indexRelid: string;
  phase: CreateIndexPhase;
  tuplesTotal: number;
  tuplesDone: number;
  partitionsTotal: number;
  partitionsDone: number;
  progress: number; // 0.0 – 1.0
}

// ── COPY ────────────────────────────────────────────────────────

export interface CopyProgress {
  pid: number;
  datid: string;
  datname: string;
  relid: string;
  command: string; // 'COPY FROM' | 'COPY TO'
  tuplesTotal: number;
  tuplesExcluded: number;
  bytesTotal: number;
  bytesProcessed: number;
  progress: number; // 0.0 – 1.0
}

// ── Aggregator ──────────────────────────────────────────────────

export class PgStatProgress {
  private vacuums: Map<number, VacuumProgress> = new Map();
  private indexes: Map<number, CreateIndexProgress> = new Map();
  private copies: Map<number, CopyProgress> = new Map();
  private pidCounter = 50000;

  // ── Vacuum ────────────────────────────────────────────────────

  startVacuum(opts: {
    datname?: string;
    relid?: string;
    heapBlksTotal?: number;
  }): VacuumProgress {
    const pid = ++this.pidCounter;
    const progress: VacuumProgress = {
      pid,
      datid: '0',
      datname: opts.datname || 'sqlvec',
      relid: opts.relid || '0',
      phase: VacuumPhase.INITIALIZING,
      heapBlksTotal: opts.heapBlksTotal || 0,
      heapBlksScanned: 0,
      heapBlksVacuumed: 0,
      indexVacuumCount: 0,
      maxDeadTuples: 0,
      numDeadTuples: 0,
      progress: 0,
    };
    this.vacuums.set(pid, progress);
    logger.debug({ pid, relid: opts.relid }, 'Vacuum started');
    return progress;
  }

  updateVacuum(pid: number, update: Partial<VacuumProgress>): void {
    const existing = this.vacuums.get(pid);
    if (!existing) return;
    Object.assign(existing, update);
    if (existing.heapBlksTotal > 0) {
      existing.progress = Math.min(
        1.0,
        (existing.heapBlksScanned + existing.heapBlksVacuumed) / existing.heapBlksTotal,
      );
    }
  }

  completeVacuum(pid: number): void {
    const vac = this.vacuums.get(pid);
    if (vac) {
      vac.phase = VacuumPhase.FINAL_CLEANUP;
      vac.progress = 1.0;
      this.vacuums.delete(pid);
      logger.debug({ pid }, 'Vacuum completed');
    }
  }

  getVacuumProgress(pid?: number): VacuumProgress[] {
    if (pid !== undefined) {
      const p = this.vacuums.get(pid);
      return p ? [p] : [];
    }
    return Array.from(this.vacuums.values());
  }

  // ── Create Index ─────────────────────────────────────────────

  startCreateIndex(opts: {
    datname?: string;
    relid?: string;
    indexRelid?: string;
    tuplesTotal?: number;
    partitionsTotal?: number;
  }): CreateIndexProgress {
    const pid = ++this.pidCounter;
    const progress: CreateIndexProgress = {
      pid,
      datid: '0',
      datname: opts.datname || 'sqlvec',
      relid: opts.relid || '0',
      indexRelid: opts.indexRelid || '0',
      phase: CreateIndexPhase.INITIALIZING,
      tuplesTotal: opts.tuplesTotal || 0,
      tuplesDone: 0,
      partitionsTotal: opts.partitionsTotal || 0,
      partitionsDone: 0,
      progress: 0,
    };
    this.indexes.set(pid, progress);
    logger.debug({ pid, relid: opts.relid }, 'Create index started');
    return progress;
  }

  updateCreateIndex(pid: number, update: Partial<CreateIndexProgress>): void {
    const existing = this.indexes.get(pid);
    if (!existing) return;
    Object.assign(existing, update);
    if (existing.tuplesTotal > 0) {
      existing.progress = Math.min(1.0, existing.tuplesDone / existing.tuplesTotal);
    } else if (existing.partitionsTotal > 0) {
      existing.progress = Math.min(1.0, existing.partitionsDone / existing.partitionsTotal);
    }
  }

  completeCreateIndex(pid: number): void {
    const idx = this.indexes.get(pid);
    if (idx) {
      idx.phase = CreateIndexPhase.FINALIZING;
      idx.progress = 1.0;
      this.indexes.delete(pid);
      logger.debug({ pid }, 'Create index completed');
    }
  }

  getCreateIndexProgress(pid?: number): CreateIndexProgress[] {
    if (pid !== undefined) {
      const p = this.indexes.get(pid);
      return p ? [p] : [];
    }
    return Array.from(this.indexes.values());
  }

  // ── COPY ─────────────────────────────────────────────────────

  startCopy(opts: {
    datname?: string;
    relid?: string;
    command?: 'COPY FROM' | 'COPY TO';
    tuplesTotal?: number;
    bytesTotal?: number;
  }): CopyProgress {
    const pid = ++this.pidCounter;
    const progress: CopyProgress = {
      pid,
      datid: '0',
      datname: opts.datname || 'sqlvec',
      relid: opts.relid || '0',
      command: opts.command || 'COPY FROM',
      tuplesTotal: opts.tuplesTotal || 0,
      tuplesExcluded: 0,
      bytesTotal: opts.bytesTotal || 0,
      bytesProcessed: 0,
      progress: 0,
    };
    this.copies.set(pid, progress);
    logger.debug({ pid, relid: opts.relid, command: opts.command }, 'COPY started');
    return progress;
  }

  updateCopy(pid: number, update: Partial<CopyProgress>): void {
    const existing = this.copies.get(pid);
    if (!existing) return;
    Object.assign(existing, update);
    if (existing.bytesTotal > 0) {
      existing.progress = Math.min(1.0, existing.bytesProcessed / existing.bytesTotal);
    } else if (existing.tuplesTotal > 0) {
      existing.progress = Math.min(
        1.0,
        (existing.tuplesTotal - existing.tuplesExcluded) / existing.tuplesTotal,
      );
    }
  }

  completeCopy(pid: number): void {
    const cp = this.copies.get(pid);
    if (cp) {
      cp.progress = 1.0;
      cp.bytesProcessed = cp.bytesTotal;
      this.copies.delete(pid);
      logger.debug({ pid }, 'COPY completed');
    }
  }

  getCopyProgress(pid?: number): CopyProgress[] {
    if (pid !== undefined) {
      const p = this.copies.get(pid);
      return p ? [p] : [];
    }
    return Array.from(this.copies.values());
  }

  // ── Summary ──────────────────────────────────────────────────

  /** Get progress summary across all operation types. */
  getSummary(): {
    activeVacuums: number;
    activeIndexBuilds: number;
    activeCopies: number;
  } {
    return {
      activeVacuums: this.vacuums.size,
      activeIndexBuilds: this.indexes.size,
      activeCopies: this.copies.size,
    };
  }

  /** Clear all progress state. */
  clear(): void {
    this.vacuums.clear();
    this.indexes.clear();
    this.copies.clear();
  }
}
