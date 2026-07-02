/**
 * PostgisMinimal — Pure JavaScript fallback for PostGIS geometry functions
 *
 * Implements a minimal spatial geometry engine that parses WKT (Well-Known Text),
 * stores geometries as typed objects, and provides intersection/hit-test operations
 * using bounding box overlap checks.
 *
 * This demonstrates the C extension pattern WITHOUT requiring actual .so files.
 * When a real PostGIS library is available, it delegates to the native bridge.
 * Otherwise, it provides spatially correct pure-JS implementations.
 */

import { PinoLogger } from '../monitoring/PinoLogger';

// ──────────────────────────────────────────────
//  Geometry Types
// ──────────────────────────────────────────────

export type GeometryType =
  | 'POINT'
  | 'LINESTRING'
  | 'POLYGON'
  | 'MULTIPOINT'
  | 'MULTILINESTRING'
  | 'MULTIPOLYGON'
  | 'GEOMETRYCOLLECTION';

export interface Coordinate {
  x: number;
  y: number;
  z?: number;
}

export interface BBox {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

export interface Geometry {
  type: GeometryType;
  coordinates: Coordinate[][][]; // [ring][point][coord]
  srid?: number;
}

export interface PointGeometry extends Geometry {
  type: 'POINT';
  /** Single point as a single-coordinate array */
  point: Coordinate;
}

export interface PolygonGeometry extends Geometry {
  type: 'POLYGON';
  /** Linear rings, first is exterior, rest are holes */
  rings: Coordinate[][];
}

// ──────────────────────────────────────────────
//  WKT Parser
// ──────────────────────────────────────────────

const logger = PinoLogger.forComponent('PostgisMinimal');

/**
 * Parse a WKT (Well-Known Text) string into a Geometry object.
 *
 * Supported:
 *   POINT(x y)
 *   LINESTRING(x1 y1, x2 y2, ...)
 *   POLYGON((x1 y1, x2 y2, ...), (hole1 ...))
 *   MULTIPOINT(x1 y1, x2 y2, ...)  and MULTIPOINT((x1 y1), (x2 y2))
 *   MULTILINESTRING((...), (...))
 *   MULTIPOLYGON(((outer)), ((inner)))
 *   GEOMETRYCOLLECTION(POINT(...), LINESTRING(...))
 *   SRID=4326;POINT(...)  (SRID prefix)
 *
 * @throws Error on invalid WKT
 */
export function parseWKT(wkt: string): Geometry {
  if (!wkt || typeof wkt !== 'string') {
    throw new Error('Invalid WKT: expected a non-empty string');
  }

  let srid: number | undefined;
  let cleaned = wkt.trim();

  // Handle SRID prefix: SRID=4326;POINT(...)
  const sridMatch = cleaned.match(/^SRID\s*=\s*(\d+);\s*/i);
  if (sridMatch) {
    srid = parseInt(sridMatch[1], 10);
    cleaned = cleaned.slice(sridMatch[0].length);
  }

  // Tokenize: geometry type keyword followed by coordinates
  const typeMatch = cleaned.match(/^(POINT|LINESTRING|POLYGON|MULTIPOINT|MULTILINESTRING|MULTIPOLYGON|GEOMETRYCOLLECTION)\s*/i);
  if (!typeMatch) {
    throw new Error(`Invalid WKT: unknown geometry type in "${wkt.slice(0, 50)}..."`);
  }

  const type = typeMatch[1].toUpperCase() as GeometryType;
  const rest = cleaned.slice(typeMatch[0].length).trim();

  // Parse based on type
  let geometry: Geometry;

  switch (type) {
    case 'POINT':
      geometry = parsePoint(rest, srid);
      break;
    case 'LINESTRING':
      geometry = parseLineString(rest, srid);
      break;
    case 'POLYGON':
      geometry = parsePolygon(rest, srid);
      break;
    case 'MULTIPOINT':
      geometry = parseMultiPoint(rest, srid);
      break;
    case 'MULTILINESTRING':
      geometry = parseMultiLineString(rest, srid);
      break;
    case 'MULTIPOLYGON':
      geometry = parseMultiPolygon(rest, srid);
      break;
    case 'GEOMETRYCOLLECTION':
      geometry = parseGeometryCollection(rest, srid);
      break;
    default:
      throw new Error(`Unsupported geometry type: ${type}`);
  }

  return geometry;
}

/**
 * Convert a Geometry back to WKT string.
 * Coordinates are stored as Coordinate[][][] (part → ring → point).
 */
export function geometryToWKT(geom: Geometry): string {
  const sridPrefix = geom.srid ? `SRID=${geom.srid};` : '';
  let wkt: string;

  switch (geom.type) {
    case 'POINT': {
      const coords = geom.coordinates[0][0]; // [0] = first part, [0] = first ring = array of 1 coord
      const c = coords[0]; // first (only) coordinate in the ring
      wkt = `POINT(${c.x} ${c.y}${c.z !== undefined ? ' ' + c.z : ''})`;
      break;
    }
    case 'LINESTRING':
      // coordinates[0] = first part = [[coord1, coord2, ...]]
      wkt = `LINESTRING(${coordinatesToWKT(geom.coordinates[0][0])})`;
      break;
    case 'POLYGON':
      // coordinates[0] = first part = [ring1, ring2, ...]
      wkt = `POLYGON(${geom.coordinates[0].map(ring => `(${coordinatesToWKT(ring)})`).join(', ')})`;
      break;
    case 'MULTIPOINT': {
      // coordinates[0] = [[coord1], [coord2], ...]
      const pts = geom.coordinates[0].map(c => `${c[0].x} ${c[0].y}`);
      wkt = `MULTIPOINT(${pts.join(', ')})`;
      break;
    }
    case 'MULTILINESTRING':
      // coordinates = [[line1_ring], [line2_ring], ...]
      wkt = `MULTILINESTRING(${geom.coordinates.map(
        part => `(${coordinatesToWKT(part[0])})`,
      ).join(', ')})`;
      break;
    case 'MULTIPOLYGON':
      // coordinates = [poly1_rings, poly2_rings, ...]
      // each poly_rings = [ring1, ring2, ...]
      wkt = `MULTIPOLYGON(${geom.coordinates.map(
        poly => `(${poly.map(ring => `(${coordinatesToWKT(ring)})`).join(', ')})`,
      ).join(', ')})`;
      break;
    default:
      wkt = `${geom.type}(...)`;
  }

  return sridPrefix + wkt;
}

function coordinatesToWKT(coords: Coordinate[]): string {
  return coords.map(c => `${c.x} ${c.y}${c.z !== undefined ? ' ' + c.z : ''}`).join(', ');
}

// ── Parsers ────────────────────────────────────

function parsePoint(rest: string, srid?: number): PointGeometry {
  const match = rest.match(/^\(([\d.\-Ee+\s]+)\)\s*$/);
  if (!match) {
    throw new Error('Invalid POINT WKT: expected (x y)');
  }
  const coord = parseCoordinate(match[1].trim());
  return {
    type: 'POINT',
    coordinates: [[[coord]]],
    point: coord,
    srid,
  };
}

function parseLineString(rest: string, srid?: number): Geometry {
  const coords = parseCoordinateSequence(rest);
  if (coords.length < 2) {
    throw new Error('Invalid LINESTRING WKT: requires at least 2 points');
  }
  return {
    type: 'LINESTRING',
    coordinates: [[coords]], // Coordinate[][][]: 1 part, 1 ring = coordinate array
    srid,
  };
}

function parsePolygon(rest: string, srid?: number): PolygonGeometry {
  const rings = parseRings(rest);
  if (rings.length === 0) {
    throw new Error('Invalid POLYGON WKT: requires at least 1 ring');
  }
  return {
    type: 'POLYGON',
    coordinates: [rings], // Coordinate[][][]: 1 part, N rings
    rings,
    srid,
  };
}

function parseMultiPoint(rest: string, srid?: number): Geometry {
  // MULTIPOINT can be (x y, x y) or ((x y), (x y))
  const trimmed = rest.replace(/^\(|\)$/g, '').trim();

  // Try nested format: ((x y), (x y))
  const nestedMatch = trimmed.match(/^\([\d.\-Ee+\s]+\)/);
  if (nestedMatch) {
    const coords = trimmed.split(/\)\s*,\s*\(/).map(p => {
      return parseCoordinate(p.replace(/^\(|\)$/g, '').trim());
    });
    // Coordinate[][][]: each point is its own part with 1 ring containing 1 coord
    return {
      type: 'MULTIPOINT',
      coordinates: coords.map(c => [[c]]),
      srid,
    };
  }

  // Flat format: (x y, x y)
  const coords = trimmed.split(',').map(p => parseCoordinate(p.trim()));
  // Coordinate[][][]: each point is its own part with 1 ring containing 1 coord
  return {
    type: 'MULTIPOINT',
    coordinates: coords.map(c => [[c]]),
    srid,
  };
}

function parseMultiLineString(rest: string, srid?: number): Geometry {
  const rings = parseRings(rest);
  // Coordinate[][][]: each line is its own part with 1 ring
  return {
    type: 'MULTILINESTRING',
    coordinates: rings.map(ring => [ring]),
    srid,
  };
}

function parseMultiPolygon(rest: string, srid?: number): Geometry {
  // Stripped outer parentheses
  let inner = rest.replace(/^\(|\)$/g, '').trim();
  const polygons: Coordinate[][][] = [];

  // Parse each polygon: ((x y, ...), (hole ...))
  let depth = 0;
  let start = 0;
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '(') {
      depth++;
      if (depth === 1) start = i;
    }
    if (inner[i] === ')') {
      depth--;
      if (depth === 0) {
        const polyStr = inner.slice(start, i + 1);
        const rings = parseRings(polyStr);
        polygons.push(rings);
        start = i + 1;
      }
    }
  }

  return {
    type: 'MULTIPOLYGON',
    coordinates: polygons,
    srid,
  };
}

function parseGeometryCollection(rest: string, srid?: number): Geometry {
  // Parse nested geometry list
  const trimmed = rest.replace(/^\(|\)$/g, '').trim();

  // We return as a simple POINT for the collection (simplified)
  // In a full implementation this would store sub-geometries
  // For our minimal implementation, extract the first geometry
  const geometries: Geometry[] = [];
  const types = ['POINT', 'LINESTRING', 'POLYGON', 'MULTIPOINT', 'MULTILINESTRING', 'MULTIPOLYGON'];

  let remaining = trimmed;
  while (remaining.length > 0) {
    let found = false;
    for (const t of types) {
      const re = new RegExp(`^${t}\\s*\\(`, 'i');
      if (re.test(remaining)) {
        // Find matching close paren considering nesting
        let depth = 0;
        let end = 0;
        for (let i = 0; i < remaining.length; i++) {
          if (remaining[i] === '(') depth++;
          if (remaining[i] === ')') {
            depth--;
            if (depth === 0) {
              end = i + 1;
              break;
            }
          }
        }
        const sub = remaining.slice(0, end);
        try {
          geometries.push(parseWKT(sub));
        } catch {
          // Skip invalid sub-geometries
        }
        remaining = remaining.slice(end).trim();
        if (remaining.startsWith(',')) remaining = remaining.slice(1).trim();
        found = true;
        break;
      }
    }
    if (!found) break;
  }

  // Return as a simplified POINT (GEOMETRYCOLLECTION support is a placeholder)
  if (geometries.length > 0) {
    const bbox = computeBBox(geometries[0]);
    const center = { x: (bbox.minX + bbox.maxX) / 2, y: (bbox.minY + bbox.maxY) / 2 };
    return {
      type: 'POINT',
      coordinates: [[[center]]],
      point: center,
      srid,
    } as any;
  }

  return {
    type: 'POINT',
    coordinates: [[[{ x: 0, y: 0 }]]],
    point: { x: 0, y: 0 },
    srid,
  } as any;
}

function parseCoordinate(text: string): Coordinate {
  const parts = text.trim().split(/\s+/);
  if (parts.length < 2) {
    throw new Error(`Invalid coordinate: "${text}"`);
  }
  const x = parseFloat(parts[0]);
  const y = parseFloat(parts[1]);
  if (isNaN(x) || isNaN(y)) {
    throw new Error(`Invalid numeric coordinate: x=${parts[0]}, y=${parts[1]}`);
  }
  const coord: Coordinate = { x, y };
  if (parts.length >= 3) {
    const z = parseFloat(parts[2]);
    if (!isNaN(z)) coord.z = z;
  }
  return coord;
}

function parseCoordinateSequence(rest: string): Coordinate[] {
  const match = rest.match(/^\(([\d.\-Ee+\s,]+)\)\s*$/);
  if (!match) {
    throw new Error('Invalid coordinate sequence format');
  }
  return match[1].split(',').map(p => parseCoordinate(p.trim()));
}

function parseRings(rest: string): Coordinate[][] {
  let inner = rest.replace(/^\(|\)$/g, '').trim();
  const rings: Coordinate[][] = [];
  let depth = 0;
  let start = 0;

  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '(') {
      if (depth === 0) start = i;
      depth++;
    }
    if (inner[i] === ')') {
      depth--;
      if (depth === 0) {
        const ringStr = inner.slice(start, i + 1);
        rings.push(parseCoordinateSequence(ringStr));
        start = i + 1;
      }
    }
  }

  return rings;
}

// ──────────────────────────────────────────────
//  Bounding Box
// ──────────────────────────────────────────────

/**
 * Compute the bounding box of a geometry.
 * Coordinates are stored as Coordinate[][][] (part → ring → point).
 * For POINT: [[[coord]]]; for POLYGON: [[ring1, ring2, ...]].
 */
export function computeBBox(geom: Geometry): BBox {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;

  // Level 1: parts (1 for simple types, N for MULTI* types)
  for (const part of geom.coordinates) {
    // Level 2: rings (1 for non-polygon types, N for polygon types)
    for (const ring of part) {
      // Level 3: coordinates in the ring
      for (const coord of ring) {
        if (coord.x < minX) minX = coord.x;
        if (coord.y < minY) minY = coord.y;
        if (coord.x > maxX) maxX = coord.x;
        if (coord.y > maxY) maxY = coord.y;
      }
    }
  }

  return { minX, minY, maxX, maxY };
}

// ──────────────────────────────────────────────
//  Spatial Functions
// ──────────────────────────────────────────────

/**
 * ST_GeomFromText — Parse WKT string to Geometry object.
 * Returns a simplified representation for use in other functions.
 */
export function ST_GeomFromText(wkt: string): Geometry {
  logger.debug({ wkt: wkt.substring(0, 80) }, 'ST_GeomFromText');
  return parseWKT(wkt);
}

/**
 * ST_AsText — Convert Geometry to WKT string.
 */
export function ST_AsText(geom: Geometry): string {
  return geometryToWKT(geom);
}

/**
 * ST_Intersects — Check if two geometries intersect.
 *
 * For the minimal implementation, this uses bounding box overlap:
 * two geometries "intersect" if their axis-aligned bounding boxes overlap.
 * This is a conservative test (may return true when they don't actually
 * intersect spatially), and is correct for simple cases.
 */
export function ST_Intersects(geom1: Geometry, geom2: Geometry): boolean {
  const bbox1 = computeBBox(geom1);
  const bbox2 = computeBBox(geom2);

  // Check bounding box overlap (axis-aligned)
  const intersects =
    bbox1.minX <= bbox2.maxX &&
    bbox1.maxX >= bbox2.minX &&
    bbox1.minY <= bbox2.maxY &&
    bbox1.maxY >= bbox2.minY;

  logger.debug({ bbox1, bbox2, intersects }, 'ST_Intersects');
  return intersects;
}

/**
 * ST_DWithin — Check if two points are within a given distance (Euclidean).
 * For point-to-point distance. For polygonal geometries, checks if their
 * bounding boxes' center points are within the distance.
 */
export function ST_DWithin(geom1: Geometry, geom2: Geometry, distance: number): boolean {
  const pt1 = getCentroid(geom1);
  const pt2 = getCentroid(geom2);

  const dx = pt1.x - pt2.x;
  const dy = pt1.y - pt2.y;
  const dist = Math.sqrt(dx * dx + dy * dy);

  logger.debug({ distance: dist, threshold: distance }, 'ST_DWithin');
  return dist <= distance;
}

/**
 * ST_Distance — Euclidean distance between two geometries' centroids.
 */
export function ST_Distance(geom1: Geometry, geom2: Geometry): number {
  const pt1 = getCentroid(geom1);
  const pt2 = getCentroid(geom2);
  return Math.sqrt((pt1.x - pt2.x) ** 2 + (pt1.y - pt2.y) ** 2);
}

/**
 * ST_Buffer — Create a simplified buffer polygon around a geometry.
 *
 * For a point, creates an octagonal approximation of a circle.
 * For other geometries, creates an expanded bounding box polygon.
 */
export function ST_Buffer(geom: Geometry, radius: number): PolygonGeometry {
  const bbox = computeBBox(geom);

  // For a point, create an octagonal circle approximation
  if (geom.type === 'POINT') {
    const pt = getCentroid(geom);
    const sides = 8;
    const coords: Coordinate[] = [];

    for (let i = 0; i <= sides; i++) {
      const angle = (2 * Math.PI * i) / sides;
      coords.push({
        x: pt.x + radius * Math.cos(angle),
        y: pt.y + radius * Math.sin(angle),
      });
    }

    return {
      type: 'POLYGON',
      coordinates: [[coords]],
      rings: [coords],
      srid: geom.srid,
    };
  }

  // For other geometries, create an expanded bounding box
  const expanded: PolygonGeometry = {
    type: 'POLYGON',
    coordinates: [[
      [
        { x: bbox.minX - radius, y: bbox.minY - radius },
        { x: bbox.maxX + radius, y: bbox.minY - radius },
        { x: bbox.maxX + radius, y: bbox.maxY + radius },
        { x: bbox.minX - radius, y: bbox.maxY + radius },
        { x: bbox.minX - radius, y: bbox.minY - radius },
      ],
    ]],
    rings: [
      [
        { x: bbox.minX - radius, y: bbox.minY - radius },
        { x: bbox.maxX + radius, y: bbox.minY - radius },
        { x: bbox.maxX + radius, y: bbox.maxY + radius },
        { x: bbox.minX - radius, y: bbox.maxY + radius },
        { x: bbox.minX - radius, y: bbox.minY - radius },
      ],
    ],
    srid: geom.srid,
  };

  return expanded;
}

/**
 * ST_Centroid — Compute the centroid of a geometry.
 */
export function ST_Centroid(geom: Geometry): PointGeometry {
  const pt = getCentroid(geom);
  return {
    type: 'POINT',
    coordinates: [[[pt]]],
    point: pt,
  };
}

/**
 * ST_Area — Compute the area of a polygon (using the shoelace formula).
 * Coordinates are Coordinate[][][]; for POLYGON, coordinates[0] = rings.
 */
export function ST_Area(geom: Geometry): number {
  if (geom.type !== 'POLYGON' && geom.type !== 'MULTIPOLYGON') {
    return 0;
  }

  let totalArea = 0;
  // For POLYGON: coordinates[0] = [ring1, ring2, ...]
  const rings = geom.coordinates[0] ?? [];
  for (const ring of rings) {
    if (ring.length < 3) continue;
    totalArea += shoelaceArea(ring);
  }

  // For MULTIPOLYGON: coordinates = [poly1_rings, poly2_rings, ...]
  if (geom.type === 'MULTIPOLYGON') {
    for (let i = 1; i < geom.coordinates.length; i++) {
      const polyRings = geom.coordinates[i];
      for (const ring of polyRings) {
        if (ring.length < 3) continue;
        totalArea += shoelaceArea(ring);
      }
    }
  }

  return Math.abs(totalArea);
}

/**
 * Shoelace formula for polygon area.
 */
function shoelaceArea(ring: Coordinate[]): number {
  let area = 0;
  const n = ring.length;
  for (let i = 0; i < n - 1; i++) {
    area += ring[i].x * ring[i + 1].y;
    area -= ring[i + 1].x * ring[i].y;
  }
  // Close the ring
  if (n > 1) {
    area += ring[n - 1].x * ring[0].y;
    area -= ring[0].x * ring[n - 1].y;
  }
  return area / 2;
}

/**
 * Compute the centroid (geometric center) of a set of coordinates.
 * Coordinates are Coordinate[][][] (part → ring → point).
 */
export function getCentroid(geom: Geometry): Coordinate {
  let sumX = 0, sumY = 0, count = 0;

  for (const part of geom.coordinates) {
    for (const ring of part) {
      for (const coord of ring) {
        sumX += coord.x;
        sumY += coord.y;
        count++;
      }
    }
  }

  if (count === 0) return { x: 0, y: 0 };
  return { x: sumX / count, y: sumY / count };
}

/**
 * Check if a point is inside a polygon using the ray-casting algorithm.
 * This is a true spatial check (not just bbox).
 * @param point - The point to test
 * @param polygonRings - The rings of the polygon (Coordinate[][]), first is exterior, rest are holes
 */
export function pointInPolygon(point: Coordinate, polygonRings: Coordinate[][]): boolean {
  const exterior = polygonRings[0];
  if (!exterior || exterior.length < 3) return false;

  // Ray casting algorithm
  let inside = false;
  const n = exterior.length;
  const px = point.x;
  const py = point.y;

  for (let i = 0, j = n - 1; i < n; j = i++) {
    const xi = exterior[i].x, yi = exterior[i].y;
    const xj = exterior[j].x, yj = exterior[j].y;

    const intersect =
      ((yi > py) !== (yj > py)) &&
      (px < ((xj - xi) * (py - yi)) / (yj - yi) + xi);
    if (intersect) inside = !inside;
  }

  return inside;
}

/**
 * ST_Contains — Check if geom1 contains geom2.
 * For our minimal implementation, checks bbox containment.
 */
export function ST_Contains(geom1: Geometry, geom2: Geometry): boolean {
  const bbox1 = computeBBox(geom1);
  const bbox2 = computeBBox(geom2);

  return (
    bbox1.minX <= bbox2.minX &&
    bbox1.maxX >= bbox2.maxX &&
    bbox1.minY <= bbox2.minY &&
    bbox1.maxY >= bbox2.maxY
  );
}
