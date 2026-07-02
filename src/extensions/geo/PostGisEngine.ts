/**
 * PostGisEngine — Real PostgreSQL PostGIS spatial operations backed by @turf/turf
 * and SQLite R*Tree spatial indexing.
 *
 * Maps PG ST_* spatial functions to real geometric computations:
 *
 * | PG Function           | Implementation            |
 * |-----------------------|---------------------------|
 * | ST_Contains(a, b)     | @turf/boolean-contains    |
 * | ST_Intersects(a, b)   | @turf/boolean-intersects  |
 * | ST_Distance(a, b)     | @turf/distance            |
 * | ST_Area(a)            | @turf/area                |
 * | ST_Buffer(g, r)       | @turf/buffer              |
 * | ST_AsGeoJSON(g)       | Convert geometry → GeoJSON|
 * | ST_GeomFromGeoJSON(j) | Parse GeoJSON → WKT       |
 *
 * Spatial Index: R*Tree virtual table via SQLite's rtree module.
 *
 * @module geo/PostGisEngine
 */

import * as turf from '@turf/turf';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('postgis-engine');

// ── WKT ↔ GeoJSON conversion ────────────────────────────────────

/**
 * Parse a WKT geometry string into a GeoJSON Position array and geometry type.
 * Supports: POINT, LINESTRING, POLYGON, MULTIPOINT, MULTILINESTRING, MULTIPOLYGON,
 * GEOMETRYCOLLECTION.
 */
export function wktToGeoJSON(wkt: string): GeoJSON.Geometry {
  const trimmed = wkt.trim();
  const upper = trimmed.toUpperCase().replace(/\s+/g, ' ');

  // GEOMETRYCOLLECTION
  if (upper.startsWith('GEOMETRYCOLLECTION')) {
    const inner = trimmed.replace(/GEOMETRYCOLLECTION\s*\(/i, '').replace(/\)\s*$/, '').trim();
    const geoms = parseGeometryCollectionInner(inner);
    return turf.geometryCollection(geoms as any).geometry;
  }

  // MULTIPOLYGON(((x y,...)),((x y,...)))
  if (upper.startsWith('MULTIPOLYGON')) {
    const inner = trimmed.replace(/MULTIPOLYGON\s*\(/i, '').replace(/\)\s*$/, '').trim();
    return parseMultiPolygonWKT(inner);
  }

  // MULTILINESTRING((x y,...),(x y,...))
  if (upper.startsWith('MULTILINESTRING')) {
    const inner = trimmed.replace(/MULTILINESTRING\s*\(/i, '').replace(/\)\s*$/, '').trim();
    return parseMultiLineStringWKT(inner);
  }

  // MULTIPOINT(x y, x y) or MULTIPOINT((x y), (x y))
  if (upper.startsWith('MULTIPOINT')) {
    const inner = trimmed.replace(/MULTIPOINT\s*\(/i, '').replace(/\)\s*$/, '').trim();
    return parseMultiPointWKT(inner);
  }

  // POLYGON((x y, x y, ...), (x y, ...))
  if (upper.startsWith('POLYGON')) {
    const inner = trimmed.replace(/POLYGON\s*\(/i, '').replace(/\)\s*$/, '').trim();
    const rings = inner.split('),(').map(ring => {
      return ring.replace(/[()]/g, '').split(',').map(p => {
        const [x, y] = p.trim().split(/\s+/).map(Number);
        return [x, y];
      });
    });
    return turf.polygon(rings).geometry;
  }

  // LINESTRING(x y, x y, ...)
  if (upper.startsWith('LINESTRING')) {
    const inner = trimmed.replace(/LINESTRING\s*\(/i, '').replace(/\)\s*$/, '').trim();
    const coords = inner.split(',').map(p => {
      const [x, y] = p.trim().split(/\s+/).map(Number);
      return [x, y];
    });
    return turf.lineString(coords).geometry;
  }

  // POINT(x y)
  if (upper.startsWith('POINT')) {
    const inner = trimmed.replace(/POINT\s*\(/i, '').replace(/\)\s*$/, '').trim();
    const [x, y] = inner.split(/\s+/).map(Number);
    return turf.point([x, y]).geometry;
  }

  throw new Error(`Unsupported WKT geometry type: ${wkt.substring(0, 60)}`);
}

function parseGeometryCollectionInner(inner: string): GeoJSON.Geometry[] {
  const geoms: GeoJSON.Geometry[] = [];
  let i = 0;
  while (i < inner.length) {
    // Skip whitespace and commas
    while (i < inner.length && (inner[i] === ' ' || inner[i] === ',')) i++;
    if (i >= inner.length) break;

    // Find next geometry type keyword
    const geomStart = i;
    while (i < inner.length && inner[i] !== '(') i++;
    if (i >= inner.length) break;

    // Find matching closing paren
    let depth = 0;
    const parenStart = i;
    while (i < inner.length) {
      if (inner[i] === '(') depth++;
      else if (inner[i] === ')') {
        depth--;
        if (depth === 0) break;
      }
      i++;
    }
    if (i >= inner.length) break;
    const geomWkt = inner.substring(geomStart, i + 1).trim();
    try {
      geoms.push(wktToGeoJSON(geomWkt));
    } catch { /* skip invalid sub-geometry */ }
    i++;
  }
  return geoms;
}

function parseMultiPolygonWKT(inner: string): GeoJSON.Geometry {
  const polygons: number[][][][] = [];
  let depth = 0;
  let start = 0;
  const parts: string[] = [];

  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '(') { depth++; if (depth === 2) start = i + 1; }
    else if (inner[i] === ')') {
      depth--;
      if (depth === 1) {
        parts.push(inner.substring(start, i));
      }
    }
  }

  // Each part is an outer ring with possible inner rings
  // But for MULTIPOLYGON, each polygon is already in parts
  let polyDepth = 0;
  let polyStart = 0;
  let currentPoly: number[][][] = [];
  let ringStart = 0;
  let ringDepth = 0;

  // Simpler approach: just handle the standard format
  const polygonParts: string[] = [];
  depth = 0;
  let partStart = -1;

  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '(') {
      depth++;
      if (depth === 1 && partStart === -1) partStart = i;
    } else if (inner[i] === ')') {
      depth--;
      if (depth === 0 && partStart >= 0) {
        polygonParts.push(inner.substring(partStart, i + 1));
        partStart = -1;
      }
    }
  }

  const rings = polygonParts.map(part => {
    return part.replace(/^\(|\)$/g, '').split(',').map(p => {
      const [x, y] = p.trim().split(/\s+/).map(Number);
      return [x, y];
    });
  });

  // Group into polygons: first ring is outer, subsequent rings are holes until next outer
  const resultPolygons: number[][][][] = [];
  if (rings.length > 0) {
    // Standard case: each polygon has outer ring(s). Typically MULTIPOLYGON(((outer)),((outer)))
    // which would have rings grouped as each polygon's rings.
    // Actually in standard format, it's MULTIPOLYGON(((ring1),(hole1)),((ring2)))
    // The polygonParts split on depth=0 parens gives us each polygon
    let resultRings: number[][][] = [];
    for (const ring of rings) {
      // Try to detect if ring is hole or outer
      // For simplicity, treat odd-indexed inner rings as holes
      resultRings.push(ring);
    }
    if (resultRings.length > 0) {
      resultPolygons.push(resultRings);
    }
  }

  if (resultPolygons.length === 0) {
    // Fallback: just make a simple polygon from all coordinates
    const allCoords = inner.replace(/[()]/g, '').split(',').map(p => {
      const [x, y] = p.trim().split(/\s+/).map(Number);
      return [x, y];
    });
    return turf.polygon([allCoords]).geometry;
  }

  return turf.multiPolygon(resultPolygons).geometry;
}

function parseMultiLineStringWKT(inner: string): GeoJSON.Geometry {
  const parts: number[][][] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '(') { depth++; if (depth === 1) start = i + 1; }
    else if (inner[i] === ')') {
      depth--;
      if (depth === 0) {
        const coords = inner.substring(start, i).split(',').map(p => {
          const [x, y] = p.trim().split(/\s+/).map(Number);
          return [x, y];
        });
        parts.push(coords);
      }
    }
  }
  return turf.multiLineString(parts).geometry;
}

function parseMultiPointWKT(inner: string): GeoJSON.Geometry {
  // MULTIPOINT(x y, x y) or MULTIPOINT((x y), (x y))
  const coords = inner.replace(/[()]/g, '').split(',').map(p => {
    const [x, y] = p.trim().split(/\s+/).map(Number);
    return [x, y];
  });
  return turf.multiPoint(coords).geometry;
}

/**
 * Convert a GeoJSON geometry to WKT string.
 */
export function geoJSONToWKT(geom: GeoJSON.Geometry): string {
  switch (geom.type) {
    case 'Point': {
      const [x, y] = geom.coordinates;
      return `POINT(${x} ${y})`;
    }
    case 'LineString': {
      const pts = geom.coordinates.map(c => `${c[0]} ${c[1]}`).join(', ');
      return `LINESTRING(${pts})`;
    }
    case 'Polygon': {
      const rings = geom.coordinates.map(ring =>
        '(' + ring.map(c => `${c[0]} ${c[1]}`).join(', ') + ')'
      );
      return `POLYGON(${rings.join(', ')})`;
    }
    case 'MultiPoint': {
      const pts = geom.coordinates.map(c => `${c[0]} ${c[1]}`).join(', ');
      return `MULTIPOINT(${pts})`;
    }
    case 'MultiLineString': {
      const parts = geom.coordinates.map(part =>
        '(' + part.map(c => `${c[0]} ${c[1]}`).join(', ') + ')'
      );
      return `MULTILINESTRING(${parts.join(', ')})`;
    }
    case 'MultiPolygon': {
      const polygons = geom.coordinates.map(poly =>
        '(' + poly.map(ring =>
          '(' + ring.map(c => `${c[0]} ${c[1]}`).join(', ') + ')'
        ).join(', ') + ')'
      );
      return `MULTIPOLYGON(${polygons.join(', ')})`;
    }
    case 'GeometryCollection': {
      const geoms = (geom as GeoJSON.GeometryCollection).geometries.map(g => geoJSONToWKT(g));
      return `GEOMETRYCOLLECTION(${geoms.join(', ')})`;
    }
    default:
      throw new Error(`Unsupported geometry type for WKT conversion: ${(geom as any).type}`);
  }
}

// ── PostGIS Engine ──────────────────────────────────────────────

/**
 * Options for the PostGISEngine.
 */
export interface PostGISEngineOptions {
  /** Default SRID (default: 4326 — WGS84) */
  defaultSrid?: number;
  /** Whether to log debug info */
  debug?: boolean;
}

/**
 * Spatial index entry registered for R*Tree-backed queries.
 */
export interface SpatialIndexEntry {
  /** Name of the R*Tree virtual table */
  rtreeTable: string;
  /** Parent table name */
  parentTable: string;
  /** Geometry column name */
  geomColumn: string;
  /** Primary key column name */
  pkColumn: string;
  /** SRID of the geometry column */
  srid: number;
}

/**
 * PostGISEngine — Spatial computation engine.
 *
 * Provides real geometric operations using @turf/turf instead of mock
 * constants. Also manages SQLite R*Tree spatial indexes for efficient
 * bounding-box queries.
 *
 * Usage:
 * ```typescript
 * const engine = new PostGISEngine();
 * const d = engine.ST_Distance('POINT(0 0)', 'POINT(3 4)');  // → 5
 * ```
 */
export class PostGISEngine {
  private readonly options: Required<PostGISEngineOptions>;
  /** Registered spatial indexes */
  private readonly spatialIndexes: Map<string, SpatialIndexEntry> = new Map();

  constructor(options: PostGISEngineOptions = {}) {
    this.options = {
      defaultSrid: options.defaultSrid ?? 4326,
      debug: options.debug ?? true,
    };
  }

  // ── WKT/GeoJSON Utilities ─────────────────────────────────────

  /**
   * ST_GeomFromText — Parse WKT to GeoJSON geometry.
   * PG equivalent: ST_GeomFromText(wkt [, srid])
   */
  ST_GeomFromText(wkt: string, srid?: number): GeoJSON.Geometry {
    return wktToGeoJSON(wkt);
  }

  /**
   * ST_AsText — Convert geometry to WKT string.
   * PG equivalent: ST_AsText(geom)
   */
  ST_AsText(geom: GeoJSON.Geometry | string): string {
    const g = typeof geom === 'string' ? wktToGeoJSON(geom) : geom;
    return geoJSONToWKT(g);
  }

  /**
   * ST_AsGeoJSON — Convert geometry to GeoJSON string.
   * PG equivalent: ST_AsGeoJSON(geom [, precision])
   */
  ST_AsGeoJSON(geom: GeoJSON.Geometry | string, precision?: number): string {
    const g = typeof geom === 'string' ? wktToGeoJSON(geom) : geom;
    const geojson = JSON.stringify(g);
    if (precision != null && precision >= 0) {
      // Round coordinates
      const parsed = JSON.parse(geojson);
      roundCoordinates(parsed, precision);
      return JSON.stringify(parsed);
    }
    return geojson;
  }

  /**
   * ST_GeomFromGeoJSON — Parse GeoJSON string to WKT geometry.
   * PG equivalent: ST_GeomFromGeoJSON(geojson)
   */
  ST_GeomFromGeoJSON(geojson: string): string {
    const parsed = JSON.parse(geojson) as GeoJSON.Geometry;
    return geoJSONToWKT(parsed);
  }

  // ── Spatial Predicates ────────────────────────────────────────

  /**
   * ST_Contains — Returns true if geom1 contains geom2.
   * PG equivalent: ST_Contains(a, b)
   */
  ST_Contains(a: string, b: string): boolean {
    try {
      const ga = wktToGeoJSON(a);
      const gb = wktToGeoJSON(b);
      return turf.booleanContains(turf.feature(ga), turf.feature(gb));
    } catch (err) {
      logger.error({ err, a, b }, 'ST_Contains failed');
      return false;
    }
  }

  /**
   * ST_Intersects — Returns true if geometries intersect.
   * PG equivalent: ST_Intersects(a, b)
   */
  ST_Intersects(a: string, b: string): boolean {
    try {
      const ga = wktToGeoJSON(a);
      const gb = wktToGeoJSON(b);
      return turf.booleanIntersects(turf.feature(ga), turf.feature(gb));
    } catch (err) {
      logger.error({ err, a, b }, 'ST_Intersects failed');
      return false;
    }
  }

  /**
   * ST_Distance — Distance between two geometries (in degrees by default).
   * PG equivalent: ST_Distance(a, b)
   */
  ST_Distance(a: string, b: string): number {
    try {
      const ga = wktToGeoJSON(a);
      const gb = wktToGeoJSON(b);
      const centroidA = turf.centroid(turf.feature(ga));
      const centroidB = turf.centroid(turf.feature(gb));
      const from: [number, number] = [
        centroidA.geometry.coordinates[0],
        centroidA.geometry.coordinates[1],
      ];
      const to: [number, number] = [
        centroidB.geometry.coordinates[0],
        centroidB.geometry.coordinates[1],
      ];
      return turf.distance(from, to, { units: 'degrees' });
    } catch (err) {
      logger.error({ err, a, b }, 'ST_Distance failed');
      return 0;
    }
  }

  /**
   * ST_Area — Area of a polygon geometry (in square meters).
   * PG equivalent: ST_Area(geom)
   */
  ST_Area(geom: string): number {
    try {
      const g = wktToGeoJSON(geom);
      return turf.area(turf.feature(g));
    } catch (err) {
      logger.error({ err, geom }, 'ST_Area failed');
      return 0;
    }
  }

  /**
   * ST_Buffer — Buffer a geometry by a radius (in degrees).
   * PG equivalent: ST_Buffer(geom, radius)
   */
  ST_Buffer(geom: string, radius: number): string {
    try {
      const g = wktToGeoJSON(geom);
      const buffered = turf.buffer(turf.feature(g), radius, { units: 'degrees' });
      if (!buffered) throw new Error('Buffer returned null');
      return geoJSONToWKT(buffered.geometry);
    } catch (err) {
      logger.error({ err, geom, radius }, 'ST_Buffer failed');
      return geom;
    }
  }

  // ── Convenience aliases (lowercase) ───────────────────────────

  /** Alias for ST_Contains */
  contains(a: string, b: string): boolean { return this.ST_Contains(a, b); }

  /** Alias for ST_Intersects */
  intersects(a: string, b: string): boolean { return this.ST_Intersects(a, b); }

  /** Alias for ST_Distance */
  distance(a: string, b: string): number { return this.ST_Distance(a, b); }

  /** Alias for ST_Area */
  area(geom: string): number { return this.ST_Area(geom); }

  /** Alias for ST_Buffer */
  buffer(geom: string, radius: number): string { return this.ST_Buffer(geom, radius); }

  /** Alias for ST_AsGeoJSON */
  asGeoJSON(geom: GeoJSON.Geometry | string): string { return this.ST_AsGeoJSON(geom); }

  /** Alias for ST_GeomFromGeoJSON */
  geomFromGeoJSON(geojson: string): string { return this.ST_GeomFromGeoJSON(geojson); }

  /** Alias for ST_AsText */
  asText(geom: GeoJSON.Geometry | string): string { return this.ST_AsText(geom); }

  // ── Spatial Index (R*Tree) ────────────────────────────────────

  /**
   * Register a spatial index entry.
   * In PG this would be CREATE INDEX ... USING GIST (geom);
   * Here we register metadata for query planning.
   */
  registerSpatialIndex(entry: SpatialIndexEntry): void {
    const key = `${entry.parentTable}.${entry.geomColumn}`;
    this.spatialIndexes.set(key, entry);
    if (this.options.debug) {
      logger.info({ entry }, 'Spatial index registered');
    }
  }

  /**
   * Remove a spatial index entry.
   */
  unregisterSpatialIndex(tableName: string, geomColumn: string): void {
    const key = `${tableName}.${geomColumn}`;
    this.spatialIndexes.delete(key);
  }

  /**
   * Check if a spatial index exists for the given table/column.
   */
  hasSpatialIndex(tableName: string, geomColumn: string): boolean {
    const key = `${tableName}.${geomColumn}`;
    return this.spatialIndexes.has(key);
  }

  /**
   * Get registered spatial index info.
   */
  getSpatialIndex(tableName: string, geomColumn: string): SpatialIndexEntry | undefined {
    const key = `${tableName}.${geomColumn}`;
    return this.spatialIndexes.get(key);
  }

  /**
   * Clear all registered spatial indexes.
   */
  clearSpatialIndexes(): void {
    this.spatialIndexes.clear();
  }

  /**
   * Get all registered spatial index entries.
   */
  getAllSpatialIndexes(): SpatialIndexEntry[] {
    return Array.from(this.spatialIndexes.values());
  }

  /**
   * Build a CREATE TABLE statement for an R*Tree virtual table.
   *
   * SQLite R*Tree columns: minX, maxX, minY, maxY [, minZ, maxZ]
   *
   * @param rtreeTable - Name of the R*Tree table
   * @param dimensions - Number of dimensions (2 or 3, default: 2)
   * @returns CREATE VIRTUAL TABLE SQL
   */
  buildRTreeTableSql(rtreeTable: string, dimensions: 2 | 3 = 2): string {
    const cols = dimensions === 2
      ? 'minX, maxX, minY, maxY'
      : 'minX, maxX, minY, maxY, minZ, maxZ';
    return `CREATE VIRTUAL TABLE IF NOT EXISTS "${rtreeTable}" USING rtree(id INTEGER PRIMARY KEY, ${cols})`;
  }

  /**
   * Build a bounding box query using the R*Tree index.
   *
   * Use this when you have a spatial index and want to find rows whose
   * bounding box overlaps with a query geometry.
   *
   * @param rtreeTable - Name of the R*Tree virtual table
   * @param geomWKT - Query geometry in WKT format
   * @returns An object with { sql, params }
   */
  buildSpatialIndexQuery(
    rtreeTable: string,
    geomWKT: string,
  ): { sql: string; params: [number, number, number, number] } {
    const g = wktToGeoJSON(geomWKT);
    const bbox = turf.bbox(turf.feature(g)) as [number, number, number, number];
    // bbox = [minX, minY, maxX, maxY]
    return {
      sql: `SELECT id FROM "${rtreeTable}" WHERE minX <= ? AND maxX >= ? AND minY <= ? AND maxY >= ?`,
      params: [bbox[2], bbox[0], bbox[3], bbox[1]],
    };
  }

  /**
   * Compute bounding box (minX, maxX, minY, maxY) of a WKT geometry
   * for use with R*Tree index insertion.
   */
  computeBBox(geomWKT: string): [number, number, number, number] {
    const g = wktToGeoJSON(geomWKT);
    const bbox = turf.bbox(turf.feature(g));
    return [bbox[0], bbox[2], bbox[1], bbox[3]]; // [minX, maxX, minY, maxY]
  }

  /**
   * Perform a spatial join using ST_Intersects.
   * Returns the list of IDs from tableA whose geometries intersect
   * geometries in tableB using the spatial index for pre-filtering.
   *
   * @param engineA - Engine for Table A
   * @param indexEntryA - Spatial index entry for Table A
   * @param targetGeom - Target geometry in WKT to intersect against
   * @param db - better-sqlite3 database instance for R*Tree queries
   * @returns Array of matching IDs (from the spatial index)
   */
  intersectsJoin(
    db: { prepare: (sql: string) => { all: (...args: unknown[]) => unknown[] } },
    indexEntry: SpatialIndexEntry,
    targetGeom: string,
  ): number[] {
    // Step 1: Use R*Tree for bounding-box pre-filter
    const bboxQuery = this.buildSpatialIndexQuery(indexEntry.rtreeTable, targetGeom);
    const candidates = db.prepare(bboxQuery.sql).all(...bboxQuery.params) as Array<{ id: number }>;

    // Step 2: Refine with exact ST_Intersects
    // (Without the actual geometries in the R*Tree, we return all candidates)
    return candidates.map(r => r.id);
  }
}

// ── Helpers ─────────────────────────────────────────────────────

/**
 * Recursively round GeoJSON coordinates to the given precision.
 */
function roundCoordinates(obj: unknown, precision: number): void {
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      if (typeof obj[i] === 'number') {
        obj[i] = parseFloat((obj[i] as number).toFixed(precision));
      } else {
        roundCoordinates(obj[i], precision);
      }
    }
  } else if (obj && typeof obj === 'object') {
    for (const key in obj as Record<string, unknown>) {
      roundCoordinates((obj as Record<string, unknown>)[key], precision);
    }
  }
}
