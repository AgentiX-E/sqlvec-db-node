/**
 * FullTextSearch — PostgreSQL tsvector/tsquery full-text search engine
 * backed by SQLite FTS5.
 *
 * Maps PostgreSQL full-text search constructs to SQLite FTS5 equivalents:
 *
 * | PostgreSQL               | SQLite FTS5                    |
 * |--------------------------|--------------------------------|
 * | to_tsvector(config, txt) | FTS5 tokenize (internal)       |
 * | to_tsquery('a & b')      | 'a AND b'                      |
 * | plainto_tsquery('a b')   | 'a AND b'                      |
 * | ts_rank(vector, query)   | bm25() rank                    |
 * | ts_headline(...)         | Highlighted snippet            |
 * | column @@ tsquery        | column MATCH 'query'           |
 * | GIN index on tsvector    | FTS5 virtual table as index    |
 *
 * @module fts/FullTextSearch
 */

import Database from 'better-sqlite3';
import natural from 'natural';
import { PinoLogger } from '../monitoring/PinoLogger';

const logger = PinoLogger.forComponent('fulltext-search');
const porterStemmer = natural.PorterStemmer;

// ── Default stop words ───────────────────────────────────────────

const DEFAULT_STOP_WORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to',
  'for', 'of', 'by', 'with', 'from', 'is', 'it', 'as', 'be', 'are',
  'was', 'were', 'been', 'being', 'have', 'has', 'had', 'do', 'does',
  'did', 'will', 'would', 'could', 'should', 'may', 'might', 'shall',
  'can', 'not', 'no', 'nor', 'so', 'if', 'then', 'than', 'that',
  'this', 'these', 'those', 'which', 'who', 'whom', 'what', 'when',
  'where', 'why', 'how',
]);

// ── FTS5 index configuration ────────────────────────────────────

/**
 * Options for creating an FTS5 virtual table acting as a GIN-like index.
 */
export interface FTSIndexOptions {
  /** Tokenizer (default: 'unicode61') */
  tokenizer?: string;
  /** Whether to use content-sync mode (default: false) */
  contentSync?: boolean;
  /** Name of the content table for content-sync mode */
  contentTable?: string;
  /** Column names to index */
  columns: string[];
  /** Primary key column name (for content-sync) */
  pkColumn?: string;
}

// ── FullTextSearch ──────────────────────────────────────────────

/**
 * FullTextSearch — PG-to-FTS5 full-text search bridge.
 *
 * Supports:
 * - tsvector creation (PG-style lexeme-position format)
 * - tsquery / plainto_tsquery / phraseto_tsquery conversion
 * - @@ operator (tsquery MATCH)
 * - ts_rank scoring (bm25-based)
 * - ts_headline highlighting
 * - GIN-like index via FTS5 virtual tables
 * - Phrase search
 *
 * Usage:
 * ```typescript
 * const fts = new FullTextSearch(':memory:');
 * fts.createFTSIndex('docs_fts', { columns: ['title', 'body'] });
 * fts.insertDocument('docs_fts', { title: 'Hello', body: 'World' });
 * const results = fts.search('docs_fts', 'hello');
 * ```
 */
export class FullTextSearch {
  private readonly db: Database.Database;
  private readonly stopWords: Set<string>;
  private indexes: Map<string, { columns: string[]; pkColumn: string }> = new Map();

  /**
   * @param dbOrPath - Either a better-sqlite3 Database instance or a file path string. If ':memory:', creates an in-memory DB.
   * @param stopWords - Custom stop words set (optional).
   */
  constructor(
    dbOrPath: Database.Database | string = ':memory:',
    stopWords?: Set<string>,
  ) {
    this.stopWords = stopWords ?? DEFAULT_STOP_WORDS;

    if (typeof dbOrPath === 'string') {
      this.db = new Database(dbOrPath);
    } else {
      this.db = dbOrPath;
    }
  }

  /**
   * Close the underlying database connection.
   */
  close(): void {
    this.db.close();
  }

  /**
   * Get the underlying Database instance.
   */
  getDB(): Database.Database {
    return this.db;
  }

  // ── FTS Index Management (GIN-like) ───────────────────────────

  /**
   * Create an FTS5 virtual table acting as a GIN-like full-text index.
   *
   * PG equivalent: CREATE INDEX ... USING GIN (to_tsvector('english', col));
   *
   * @param indexName - Name for the FTS5 virtual table (e.g. 'docs_fts')
   * @param options - Index configuration
   */
  createFTSIndex(indexName: string, options: FTSIndexOptions): void {
    const tokenizer = options.tokenizer ?? 'unicode61';
    const columns = options.columns.map(c => `"${c}"`).join(', ');

    let sql: string;
    if (options.contentSync && options.contentTable) {
      const pkCol = options.pkColumn ?? 'rowid';
      sql = `CREATE VIRTUAL TABLE IF NOT EXISTS "${indexName}" USING fts5(
        ${columns},
        tokenize='${tokenizer}',
        content="${options.contentTable}",
        content_rowid="${pkCol}"
      )`;
    } else {
      sql = `CREATE VIRTUAL TABLE IF NOT EXISTS "${indexName}" USING fts5(
        ${columns},
        tokenize='${tokenizer}'
      )`;
    }

    this.db.exec(sql);
    this.indexes.set(indexName, {
      columns: options.columns,
      pkColumn: options.pkColumn ?? 'rowid',
    });

    logger.debug({ indexName, columns: options.columns }, 'FTS index created');
  }

  /**
   * Insert a document into an FTS5 index.
   *
   * @param indexName - Name of the FTS5 virtual table
   * @param doc - Document with column values
   */
  insertDocument(indexName: string, doc: Record<string, string | number>): void {
    const indexInfo = this.indexes.get(indexName);
    if (!indexInfo) {
      throw new Error(`FTS index '${indexName}' not found. Call createFTSIndex() first.`);
    }

    const cols = indexInfo.columns.map(c => `"${c}"`);
    const placeholders = cols.map(() => '?');
    const values = indexInfo.columns.map(c => String(doc[c] ?? ''));

    // Include pkColumn if specified
    if (doc[indexInfo.pkColumn] != null) {
      cols.unshift(`"${indexInfo.pkColumn}"`);
      placeholders.unshift('?');
      values.unshift(String(doc[indexInfo.pkColumn]));
    }

    const sql = `INSERT INTO "${indexName}" (${cols.join(', ')}) VALUES (${placeholders.join(', ')})`;
    this.db.prepare(sql).run(...values);
  }

  /**
   * Delete a document from an FTS5 index.
   *
   * @param indexName - Name of the FTS5 virtual table
   * @param docId - Document ID (rowid or pkColumn value)
   */
  deleteDocument(indexName: string, docId: number): void {
    const sql = `DELETE FROM "${indexName}" WHERE rowid = ?`;
    this.db.prepare(sql).run(docId);
  }

  /**
   * Drop an FTS5 virtual table.
   *
   * @param indexName - Name of the FTS5 virtual table
   */
  dropFTSIndex(indexName: string): void {
    this.db.exec(`DROP TABLE IF EXISTS "${indexName}"`);
    this.indexes.delete(indexName);
  }

  /**
   * Search an FTS5 index with a PG-compatible query.
   *
   * @param indexName - Name of the FTS5 virtual table
   * @param query - Query text (plaintext, will be AND-joined)
   * @param options - Search options (limit, rank ordering, etc.)
   * @returns Array of matching rows
   */
  search(
    indexName: string,
    query: string,
    options?: {
      limit?: number;
      orderBy?: 'ASC' | 'DESC';
      columns?: string[];
    },
  ): Array<Record<string, unknown>> {
    const indexInfo = this.indexes.get(indexName);
    if (!indexInfo) {
      throw new Error(`FTS index '${indexName}' not found`);
    }

    const fts5Query = this.toFTS5Query(query);
    if (!fts5Query) return [];

    const selectCols = options?.columns
      ? options.columns.map(c => `"${c}"`).join(', ')
      : '*';

    const orderDir = options?.orderBy ?? 'ASC';

    let sql =
      `SELECT ${selectCols}, bm25("${indexName}") AS rank ` +
      `FROM "${indexName}" WHERE "${indexName}" MATCH ? ` +
      `ORDER BY rank ${orderDir}`;

    if (options?.limit != null && options.limit > 0) {
      sql += ` LIMIT ${options.limit}`;
    }

    return this.db.prepare(sql).all(fts5Query) as Array<Record<string, unknown>>;
  }

  /**
   * Execute an arbitrary FTS5 MATCH query with raw FTS5 syntax.
   *
   * @param indexName - Name of the FTS5 virtual table
   * @param fts5Query - Raw FTS5 query string (e.g. 'hello AND world', '"hello world"')
   * @param options - Search options
   * @returns Array of matching rows
   */
  rawSearch(
    indexName: string,
    fts5Query: string,
    options?: {
      limit?: number;
      orderBy?: 'ASC' | 'DESC';
      columns?: string[];
    },
  ): Array<Record<string, unknown>> {
    const selectCols = options?.columns
      ? options.columns.map(c => `"${c}"`).join(', ')
      : '*';

    const orderDir = options?.orderBy ?? 'ASC';

    let sql =
      `SELECT ${selectCols}, bm25("${indexName}") AS rank ` +
      `FROM "${indexName}" WHERE "${indexName}" MATCH ? ` +
      `ORDER BY rank ${orderDir}`;

    if (options?.limit != null && options.limit > 0) {
      sql += ` LIMIT ${options.limit}`;
    }

    return this.db.prepare(sql).all(fts5Query) as Array<Record<string, unknown>>;
  }

  // ── PostgreSQL FTS Function Mapping ───────────────────────────

  /**
   * to_tsvector — Convert text to a PostgreSQL-style tsvector string.
   *
   * PG format: 'lexeme':position1 'lexeme':position2 ...
   * FTS5 tokenizes at index time, but we provide this for diagnostic use.
   *
   * @param _config - Text search configuration (e.g. 'english', 'simple')
   * @param text - Input text to tokenize
   * @returns A tsvector-like string
   */
  to_tsvector(_config: string, text: string): string {
    if (!text || text.trim().length === 0) return '';

    const tokens = this.tokenize(text, _config);
    if (tokens.length === 0) return '';

    // Build simplified tsvector: 'token1':1 'token2':2 ...
    const seen = new Map<string, number[]>();
    tokens.forEach((token, i) => {
      if (!seen.has(token)) seen.set(token, []);
      seen.get(token)!.push(i + 1);
    });

    const entries: string[] = [];
    for (const [token, positions] of seen) {
      entries.push(`'${this.escapeTsVector(token)}':${positions.join(',')}`);
    }

    return entries.join(' ');
  }

  /**
   * to_tsquery — Convert PostgreSQL tsquery string to FTS5 query syntax.
   *
   * Handles:
   *   & → AND | → OR ! → NOT <N> → space
   *   :* → * (prefix match)
   *
   * @param query - PG tsquery string (e.g. "'hello & world'")
   * @returns FTS5-compatible query string
   */
  to_tsquery(query: string): string {
    return this.convertTsquery(query);
  }

  /**
   * plainto_tsquery — Convert plain text to AND-joined FTS5 query.
   *
   * @param text - Plain text query
   * @returns FTS5 query with AND operators
   */
  plainto_tsquery(text: string): string {
    return this.convertPlaintoTsquery(text);
  }

  /**
   * ts_rank — Compute relevance rank between a tsvector and query.
   *
   * PG equivalent: ts_rank(vector, query [, normalization])
   * Returns a number between 0 and 1 (higher = more relevant).
   *
   * @param vector - tsvector string
   * @param query - Query string (tsquery or FTS5)
   * @returns Rank score (0 to 1)
   */
  ts_rank(vector: string, query: string): number {
    // Extract tokens from the tsvector (e.g. 'hello':1 'world':2 → ['hello', 'world'])
    const vectorTokens = new Set(
      vector
        .split(/'[\w]+':\d+(?:,\d+)*/g)
        .map(s => s.trim().replace(/'/g, ''))
        .filter(Boolean),
    );

    // If the vector is empty, try simpler extraction
    if (vectorTokens.size === 0) {
      const simplerTokens = vector.match(/'([^']+)':/g);
      if (simplerTokens) {
        simplerTokens.forEach(t => {
          const word = t.replace(/'/g, '').replace(/:$/, '');
          if (word) vectorTokens.add(word);
        });
      }
    }

    // Also try direct token extraction from 'word':N format
    if (vectorTokens.size === 0) {
      const parts = vector.split(/\s+/);
      for (const part of parts) {
        const match = part.match(/'([^']+)':\d+/);
        if (match) {
          vectorTokens.add(match[1]);
        }
      }
    }

    // Extract query terms
    const queryTerms = query
      .replace(/\b(AND|OR|NOT)\b/gi, '')
      .split(/\s+/)
      .map(s => s.replace(/\*/g, '').replace(/^["']|["']$/g, '').trim())
      .filter(Boolean);

    if (queryTerms.length === 0) return 0;

    const matches = queryTerms.filter(term => {
      const lower = term.toLowerCase();
      for (const vt of vectorTokens) {
        if (vt.toLowerCase() === lower) return true;
        // Stem matching
        if (porterStemmer.stem(vt.toLowerCase()) === porterStemmer.stem(lower)) return true;
      }
      return false;
    }).length;

    return matches / queryTerms.length;
  }

  /**
   * ts_headline — Generate a highlighted snippet from a document.
   *
   * PG equivalent: ts_headline(config, document, query [, options])
   *
   * @param _config - Text search configuration
   * @param document - Full document text
   * @param query - Search query
   * @param options - Headline formatting options
   * @returns Highlighted snippet string
   */
  ts_headline(
    _config: string,
    document: string,
    query: string,
    options?: {
      MaxWords?: number;
      MinWords?: number;
      StartSel?: string;
      EndSel?: string;
    },
  ): string {
    const maxWords = options?.MaxWords ?? 35;
    const minWords = options?.MinWords ?? 15;
    const startSel = options?.StartSel ?? '<b>';
    const endSel = options?.EndSel ?? '</b>';

    if (!document || document.trim().length === 0) return '';

    // Extract query terms
    const queryTerms = query
      .replace(/\b(AND|OR|NOT)\b/gi, '')
      .split(/\s+/)
      .map(t => t.replace(/[^a-zA-Z0-9]/g, '').toLowerCase())
      .filter(t => t.length > 0);

    if (queryTerms.length === 0) return document.substring(0, 200);

    const words = document.split(/\s+/);
    const lowerWords = words.map(w => w.toLowerCase().replace(/[^\w]/g, ''));

    // Find match positions
    const matchPositions: number[] = [];
    for (let i = 0; i < lowerWords.length; i++) {
      const stemmed = porterStemmer.stem(lowerWords[i]);
      for (const term of queryTerms) {
        if (
          lowerWords[i] === term ||
          stemmed === porterStemmer.stem(term)
        ) {
          matchPositions.push(i);
          break;
        }
      }
    }

    if (matchPositions.length === 0) {
      return words.slice(0, maxWords).join(' ');
    }

    // Find best snippet window
    const center = matchPositions[Math.floor(matchPositions.length / 2)];
    const start = Math.max(0, center - Math.floor(minWords / 2));
    const end = Math.min(words.length, start + maxWords);

    // Build snippet with highlights
    const snippetWords: string[] = [];
    for (let i = start; i < end; i++) {
      const lower = words[i].toLowerCase().replace(/[^\w]/g, '');
      const stemmed = porterStemmer.stem(lower);
      const isMatch = queryTerms.some(term => {
        return lower === term || stemmed === porterStemmer.stem(term);
      });

      snippetWords.push(isMatch ? `${startSel}${words[i]}${endSel}` : words[i]);
    }

    let snippet = snippetWords.join(' ');
    if (start > 0) snippet = '... ' + snippet;
    if (end < words.length) snippet += ' ...';

    return snippet;
  }

  /**
   * @@ operator — Check if a column matches a tsquery via FTS5 MATCH.
   *
   * @param indexName - FTS5 index name
   * @param query - PG tsquery string
   * @returns Whether any rows match
   */
  match(indexName: string, query: string): boolean {
    const fts5Query = this.toFTS5Query(query);
    if (!fts5Query) return false;

    const sql = `SELECT count(*) AS cnt FROM "${indexName}" WHERE "${indexName}" MATCH ?`;
    const result = this.db.prepare(sql).get(fts5Query) as { cnt: number } | undefined;
    return (result?.cnt ?? 0) > 0;
  }

  // ── Query Conversion ──────────────────────────────────────────

  /**
   * Convert a PG-compatible tsquery to FTS5 syntax.
   *
   * Supports:
   *   'hello & world' → 'hello AND world'
   *   'hello | world' → 'hello OR world'
   *   '!hello' → 'NOT hello'
   *   'hello <-> world' → 'hello world' (phrase)
   *   'hello:*' → 'hello*' (prefix)
   *   'hello <2> world' → 'hello world' (distance → phrase)
   */
  toFTS5Query(query: string): string {
    return this.convertTsquery(query);
  }

  /**
   * Internal tsquery to FTS5 conversion.
   */
  private convertTsquery(query: string): string {
    let q = query.trim();

    // Strip surrounding quotes
    if ((q.startsWith("'") && q.endsWith("'")) || (q.startsWith('"') && q.endsWith('"'))) {
      q = q.slice(1, -1);
    }

    if (q.length === 0) return '';

    let result = q
      // Phrase operators: <-> or <N> → space (FTS5 implicit phrase)
      .replace(/<[-\d]*>/g, ' ')
      // NOT operator
      .replace(/!/g, 'NOT ')
      // AND operator
      .replace(/&/g, 'AND')
      // OR operator
      .replace(/\|/g, 'OR')
      // Prefix match: :* → *
      .replace(/:(\*)?/g, '*')
      // FTS5 requires NOT as binary operator, not unary
      // 'x AND NOT y' → 'x NOT y'
      .replace(/\bAND\s+NOT\b/gi, 'NOT')
      .replace(/\bOR\s+NOT\b/gi, 'NOT')
      // Fix: leading NOT can't be unary; drop it
      .replace(/^NOT\s+/i, '')
      // Collapse spaces
      .replace(/\s+/g, ' ')
      .trim();

    return result;
  }

  /**
   * Convert plain text to AND-joined FTS5 query.
   */
  private convertPlaintoTsquery(text: string): string {
    let t = text.trim();
    if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"'))) {
      t = t.slice(1, -1);
    }

    const tokens = this.tokenize(t, 'simple').filter(tok => !this.stopWords.has(tok));
    if (tokens.length === 0) return '';

    return tokens.join(' AND ');
  }

  /**
   * Tokenize: unaccent → lowercase → split → stem.
   */
  private tokenize(text: string, _config: string): string[] {
    // Step 1: Unaccent — remove combining diacritical marks
    const unaccented = text.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');

    // Step 2: Lowercase
    let result = unaccented
      .toLowerCase()
      .replace(/[^\w\s'-]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 0);

    // Step 3: Apply Porter stemmer
    result = result.map(t => porterStemmer.stem(t));

    // Remove duplicate tokens (within same position window)
    return [...new Set(result)];
  }

  /**
   * Escape single quotes for tsvector format.
   */
  private escapeTsVector(token: string): string {
    return token.replace(/'/g, "''");
  }
}
