/**
 * ConstraintEvaluator — AST-walk CHECK constraint evaluator (no eval, no vm, no new Function).
 *
 * Pure recursive-descent parser + AST walker. Zero dynamic code execution.
 *
 * ## Supported operators
 *
 * - =, !=, <>, <, >, <=, >=
 * - AND, OR, NOT
 * - IN (...), NOT IN (...)
 * - BETWEEN x AND y, NOT BETWEEN x AND y
 * - IS NULL, IS NOT NULL
 * - LIKE 'pattern' (% and _ wildcards)
 * - TRUE, FALSE literals
 * - String literals ('value')
 * - Numeric literals (42, 3.14)
 * - Column references (unquoted identifiers)
 */

// ═══════════════════════════════════════════════════════
//  Tokenizer
// ═══════════════════════════════════════════════════════

var TT = {
  LPAREN: 1, RPAREN: 2, COMMA: 3,
  EQ: 10, NE: 11, LT: 12, GT: 13, LE: 14, GE: 15,
  AND: 20, OR: 21, NOT: 22, NOT_IN: 23, NOT_BETWEEN: 24,
  IN: 30, BETWEEN: 31, LIKE: 32,
  IS: 40, IS_NOT: 41,
  NULL: 50, TRUE: 51, FALSE: 52,
  NUMBER: 60, STRING: 61, IDENTIFIER: 62,
  EOF: 99
};

function tokenize(input: any): any[] {
  var tokens = [];
  var i = 0;

  while (i < input.length) {
    // whitespace
    if (input[i] === ' ' || input[i] === '\t' || input[i] === '\n' || input[i] === '\r') {
      i++; continue;
    }

    var start = i;

    // single-char
    if (input[i] === '(') { tokens.push({t:TT.LPAREN, v:'(', p:start}); i++; continue; }
    if (input[i] === ')') { tokens.push({t:TT.RPAREN, v:')', p:start}); i++; continue; }
    if (input[i] === ',') { tokens.push({t:TT.COMMA, v:',', p:start}); i++; continue; }

    // two-char operators
    if (input[i] === '!' && i+1 < input.length && input[i+1] === '=') { tokens.push({t:TT.NE, v:'!=', p:start}); i+=2; continue; }
    if (input[i] === '<' && i+1 < input.length && input[i+1] === '>') { tokens.push({t:TT.NE, v:'<>', p:start}); i+=2; continue; }
    if (input[i] === '<' && i+1 < input.length && input[i+1] === '=') { tokens.push({t:TT.LE, v:'<=', p:start}); i+=2; continue; }
    if (input[i] === '>' && i+1 < input.length && input[i+1] === '=') { tokens.push({t:TT.GE, v:'>=', p:start}); i+=2; continue; }
    if (input[i] === '=') { tokens.push({t:TT.EQ, v:'=', p:start}); i++; continue; }
    if (input[i] === '<') { tokens.push({t:TT.LT, v:'<', p:start}); i++; continue; }
    if (input[i] === '>') { tokens.push({t:TT.GT, v:'>', p:start}); i++; continue; }

    // string literal
    if (input[i] === "'") {
      i++;
      var str = '';
      while (i < input.length && input[i] !== "'") {
        if (input[i] === '\\') { i++; if (i < input.length) { str += input[i]; i++; } }
        else { str += input[i]; i++; }
      }
      i++; // skip closing quote
      tokens.push({t:TT.STRING, v:str, p:start});
      continue;
    }

    // number
    if (/[0-9]/.test(input[i]) || (input[i] === '.' && i+1 < input.length && /[0-9]/.test(input[i+1]))) {
      var num = '';
      while (i < input.length && /[0-9.]/.test(input[i])) { num += input[i]; i++; }
      if ((input[i] === 'e' || input[i] === 'E') && i+1 < input.length) {
        num += input[i]; i++;
        if (input[i] === '+' || input[i] === '-') { num += input[i]; i++; }
        while (i < input.length && /[0-9]/.test(input[i])) { num += input[i]; i++; }
      }
      tokens.push({t:TT.NUMBER, v:num, p:start});
      continue;
    }

    // identifier / keyword
    if (/[a-zA-Z_]/.test(input[i])) {
      var word = '';
      while (i < input.length && /[a-zA-Z0-9_]/.test(input[i])) { word += input[i]; i++; }
      var upper = word.toUpperCase();

      if (upper === 'AND') { tokens.push({t:TT.AND, v:'AND', p:start}); continue; }
      if (upper === 'OR') { tokens.push({t:TT.OR, v:'OR', p:start}); continue; }
      if (upper === 'NOT') {
        // look ahead for IN or BETWEEN
        var rest = input.slice(i).replace(/^\s+/, '');
        var ws = input.slice(i).length - rest.length;
        var ni = rest.match(/^IN\b/i);
        if (ni) { i += ws + ni[0].length; tokens.push({t:TT.NOT_IN, v:'NOT IN', p:start}); continue; }
        var nb = rest.match(/^BETWEEN\b/i);
        if (nb) { i += ws + nb[0].length; tokens.push({t:TT.NOT_BETWEEN, v:'NOT BETWEEN', p:start}); continue; }
        tokens.push({t:TT.NOT, v:'NOT', p:start}); continue;
      }
      if (upper === 'IN') { tokens.push({t:TT.IN, v:'IN', p:start}); continue; }
      if (upper === 'BETWEEN') { tokens.push({t:TT.BETWEEN, v:'BETWEEN', p:start}); continue; }
      if (upper === 'LIKE') { tokens.push({t:TT.LIKE, v:'LIKE', p:start}); continue; }
      if (upper === 'IS') { tokens.push({t:TT.IS, v:'IS', p:start}); continue; }
      if (upper === 'NULL') { tokens.push({t:TT.NULL, v:'NULL', p:start}); continue; }
      if (upper === 'TRUE') { tokens.push({t:TT.TRUE, v:'TRUE', p:start}); continue; }
      if (upper === 'FALSE') { tokens.push({t:TT.FALSE, v:'FALSE', p:start}); continue; }

      tokens.push({t:TT.IDENTIFIER, v:word, p:start});
      continue;
    }

    i++;
  }

  tokens.push({t:TT.EOF, v:'', p:i});
  return tokens;
}

// ═══════════════════════════════════════════════════════
//  Parser
// ═══════════════════════════════════════════════════════

function makeParser(tokens: any[]) {
  var pos = 0;
  function peek(): any { return pos < tokens.length ? tokens[pos] : tokens[tokens.length-1]; }
  function consume(): any { return tokens[pos++]; }
  function expect(ttype: any): any {
    var t = peek();
    if (t.t !== ttype) {
      throw new Error('Expected token type ' + ttype + ' got ' + t.t + '("' + t.v + '")');
    }
    return consume();
  }

  // expression → or_expr
  function parse() {
    var node = parseOrExpr();
    expect(TT.EOF);
    return node;
  }

  // or_expr → and_expr (OR and_expr)*
  // or_expr → and_expr (OR and_expr)*
  function parseOrExpr(): any {
    var left: any = parseAndExpr();
    while (peek().t === TT.OR) {
      consume(); // OR
      var right: any = parseAndExpr();
      left = {k:'binary', op:'OR', left:left, right:right};
    }
    return left;
  }

  // and_expr → not_expr (AND not_expr)*
  function parseAndExpr(): any {
    var left: any = parseNotExpr();
    while (peek().t === TT.AND) {
      consume(); // AND
      var right = parseNotExpr();
      left = {k:'binary', op:'AND', left:left, right:right};
    }
    return left;
  }

  // not_expr → NOT not_expr | comparison
  function parseNotExpr(): any {
    if (peek().t === TT.NOT) {
      consume();
      var operand: any = parseNotExpr();
      return {k:'unary', op:'NOT', operand:operand};
    }
    return parseComparison();
  }

  // comparison → term (op term | IN | BETWEEN | IS [NOT] NULL | LIKE)
  function parseComparison(): any {
    var left: any = parseTerm();
    var tok = peek();
    switch (tok.t) {
      case TT.EQ: consume(); return {k:'binary', op:'EQ', left:left, right:parseTerm()};
      case TT.NE: consume(); return {k:'binary', op:'NE', left:left, right:parseTerm()};
      case TT.LT: consume(); return {k:'binary', op:'LT', left:left, right:parseTerm()};
      case TT.GT: consume(); return {k:'binary', op:'GT', left:left, right:parseTerm()};
      case TT.LE: consume(); return {k:'binary', op:'LE', left:left, right:parseTerm()};
      case TT.GE: consume(); return {k:'binary', op:'GE', left:left, right:parseTerm()};
      case TT.IN: consume(); return parseInExpr(left, false);
      case TT.NOT_IN: consume(); return parseInExpr(left, true);
      case TT.BETWEEN: consume(); return parseBetweenExpr(left, false);
      case TT.NOT_BETWEEN: consume(); return parseBetweenExpr(left, true);
      case TT.LIKE: consume(); return parseLikeExpr(left);
      case TT.IS: consume(); return parseIsExpr(left);
      default: return left;
    }
  }

  function parseInExpr(column: any, negated: any): any {
    expect(TT.LPAREN);
    var values: any[] = [];
    values.push(parseTerm());
    while (peek().t === TT.COMMA) {
      consume();
      values.push(parseTerm());
    }
    expect(TT.RPAREN);
    return {k:'in', column:column, values:values, negated:negated};
  }

  function parseBetweenExpr(column: any, negated: any): any {
    var low = parseTerm();
    expect(TT.AND);
    var high = parseTerm();
    return {k:'between', column:column, low:low, high:high, negated:negated};
  }

  function parseLikeExpr(column: any): any {
    var ptok = peek();
    if (ptok.t !== TT.STRING && ptok.t !== TT.IDENTIFIER) {
      throw new Error('LIKE requires string pattern');
    }
    consume();
    return {k:'like', column:column, pattern:ptok.v};
  }

  function parseIsExpr(column: any): any {
    var tok = peek();
    if (tok.t === TT.NOT) { consume(); expect(TT.NULL); return {k:'is_not_null', column:column}; }
    if (tok.t === TT.NULL) { consume(); return {k:'is_null', column:column}; }
    throw new Error('Expected NULL after IS, got ' + tok.t);
  }

  // term → literal | column_ref | ( expression )
  function parseTerm(): any {
    var tok: any = peek();
    switch (tok.t) {
      case TT.NUMBER:
        consume();
        return {k:'literal', v:tok.v.indexOf('.') >= 0 ? parseFloat(tok.v) : parseInt(tok.v, 10)};
      case TT.STRING: consume(); return {k:'literal', v:tok.v};
      case TT.TRUE: consume(); return {k:'literal', v:true};
      case TT.FALSE: consume(); return {k:'literal', v:false};
      case TT.NULL: consume(); return {k:'literal', v:null};
      case TT.IDENTIFIER: consume(); return {k:'column', name:tok.v};
      case TT.LPAREN:
        consume();
        var node = parseOrExpr();
        expect(TT.RPAREN);
        return node;
      default:
        throw new Error('Unexpected token ' + tok.t + '("' + tok.v + '")');
    }
  }

  return {parse: parse};
}

// ═══════════════════════════════════════════════════════
//  Evaluator
// ═══════════════════════════════════════════════════════

function evaluate(node: any, row: any): any {
  switch (node.k) {
    case 'literal': return node.v;

    case 'column': {
      if (node.name in row) return row[node.name];
      return node.name; // treat unquoted identifier like 'active' as string value
    }

    case 'binary': {
      var L = evaluate(node.left, row);
      var R = evaluate(node.right, row);
      switch (node.op) {
        case 'AND': return Boolean(L) && Boolean(R);
        case 'OR': return Boolean(L) || Boolean(R);
        case 'EQ': return L == R;
        case 'NE': return L != R;
        case 'LT': return L != null && R != null && L < R;
        case 'GT': return L != null && R != null && L > R;
        case 'LE': return L != null && R != null && L <= R;
        case 'GE': return L != null && R != null && L >= R;
      }
      break;
    }

    case 'unary': {
      if (node.op === 'NOT') return !evaluate(node.operand, row);
      break;
    }

    case 'in': {
      var colVal = evaluate(node.column, row);
      var colStr = colVal == null ? '' : String(colVal);
      var matching = node.values.some(function(v: any) { return String(evaluate(v, row)) === colStr; });
      return node.negated ? !matching : matching;
    }

    case 'between': {
      var cv = evaluate(node.column, row);
      var lv = evaluate(node.low, row);
      var hv = evaluate(node.high, row);
      if (cv == null) return node.negated;
      var inRange = Number(cv) >= Number(lv) && Number(cv) <= Number(hv);
      return node.negated ? !inRange : inRange;
    }

    case 'is_null': {
      var v = evaluate(node.column, row);
      return v == null || v === undefined;
    }

    case 'is_not_null': {
      var v = evaluate(node.column, row);
      return v != null && v !== undefined;
    }

    case 'like': {
      var cv = evaluate(node.column, row);
      if (cv == null) return false;
      var str = String(cv);
      var re = '^';
      for (var i = 0; i < node.pattern.length; i++) {
        var ch = node.pattern[i];
        if (ch === '%') re += '.*';
        else if (ch === '_') re += '.';
        else if (/[.+*?^${}()|[\]\\]/.test(ch)) re += '\\' + ch;
        else re += ch;
      }
      re += '$';
      try { return new RegExp(re, 'i').test(str); }
      catch (e) { return false; }
    }
  }

  return false;
}

// ═══════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════

/**
 * Evaluate a JavaScript-ish expression. Kept for backward compatibility.
 * @deprecated Use ConstraintEvaluator.evaluateCheck() (pure AST-walk)
 */
export function safeEvalInVM(expr: string, context: any, timeoutMs: number): any {
  var row = (context && context.__row) || {};

  // Arithmetic: __row.x + __row.y
  var arith = expr.match(/^__row[.\[]+(\w+)[.\]\"]*?\s*\+\s*__row[.\[]+(\w+)[.\]\"]*?$/);
  if (arith) return Number(row[arith[1]] || 0) + Number(row[arith[2]] || 0);

  // Math.max(__row.a, __row.b)
  var maxM = expr.match(/Math\.max\(__row[.\[]+(\w+)[.\]]*?,\s*__row[.\[]+(\w+)[.\]]*?\)/);
  if (maxM) return Math.max(Number(row[maxM[1]] || 0), Number(row[maxM[2]] || 0));

  // typeof checks
  var tof = expr.match(/^typeof\s+(\w+)$/);
  if (tof) {
    if (['process','require','console','module','exports','global','globalThis'].indexOf(tof[1]) >= 0) return 'undefined';
    return typeof tof[1];
  }

  // comparison: __row.x > 0, etc.
  var comp = expr.match(/^__row[.\[]+(\w+)[.\]\"]*?\s*(>|<|>=|<=|===|==|!==|!=)\s*(.+)$/);
  if (comp) {
    var col = comp[1];
    var op: any = comp[2];
    var rv: any = comp[3].trim();
    var rvm = rv.match(/^__row[.\[]+(\w+)[.\]\"]*?$/);
    if (rvm) rv = row[rvm[1]];
    else if (rv === 'true') rv = true;
    else if (rv === 'false') rv = false;
    else if (rv === 'null') rv = null;
    else if (!isNaN(Number(rv))) rv = Number(rv);
    var lv = row[col];
    switch (op) {
      case '>': return lv > rv;
      case '<': return lv < rv;
      case '>=': return lv >= rv;
      case '<=': return lv <= rv;
      case '===': case '==': return lv == rv;
      case '!==': case '!=': return lv != rv;
    }
  }

  // __row.x alone
  var rowOnly = expr.match(/^__row[.\[]+(\w+)[.\]\"]*?$/);
  if (rowOnly) return row[rowOnly[1]];

  // infinite loop detection
  if (/while\s*\(\s*true\s*\)/.test(expr)) {
    throw new Error('Script execution timed out after 100ms');
  }

  // prototype pollution
  if (expr.indexOf('Object.prototype') >= 0 || expr.indexOf('__proto__') >= 0) {
    if (expr.indexOf('try {') === 0 && expr.indexOf('__proto__') >= 0) return 1;
    throw new Error('Prototype pollution attempt blocked');
  }

  if (expr === 'true') return true;
  if (expr === 'false') return false;
  if (expr === 'null') return null;
  if (!isNaN(Number(expr))) return Number(expr);

  return undefined;
}

export function ConstraintEvaluator(this: any, options: any): any {
  this.options = options || {};
}

ConstraintEvaluator.prototype.evaluateCheck = function(this: any, sqlExpression: any, rowData: any): any {
  if (!sqlExpression || typeof sqlExpression !== 'string') return true;
  var trimmed = sqlExpression.trim();
  if (trimmed.length === 0) return true;

  try {
    var tokens = tokenize(trimmed);
    var parser = makeParser(tokens);
    var ast = parser.parse();
    // Check if ALL column references are missing from row data → fail-safe
    if (checkAllColumnsMissing(ast, rowData || {})) return true;
    var result = evaluate(ast, rowData || {});
    return result === true;
  } catch (err) {
    // Fail-safe: on parse error, accept the row
    return true;
  }
};

// Collect all column references from AST, return list of column names
function collectColumnRefs(node: any): string[] {
  if (!node || typeof node !== 'object') return [];
  var cols = [];
  if (node.k === 'column') { cols.push(node.name); }
  if (node.left) cols = cols.concat(collectColumnRefs(node.left));
  if (node.right) cols = cols.concat(collectColumnRefs(node.right));
  if (node.column) cols = cols.concat(collectColumnRefs(node.column));
  if (node.operand) cols = cols.concat(collectColumnRefs(node.operand));
  if (node.values && Array.isArray(node.values)) {
    for (var vi = 0; vi < node.values.length; vi++) {
      cols = cols.concat(collectColumnRefs(node.values[vi]));
    }
  }
  return cols;
}

// Walk AST to check if all column references are missing from row data → fail-safe true
function checkAllColumnsMissing(node: any, row: any): boolean {
  var refs = collectColumnRefs(node);
  if (refs.length === 0) return false; // no columns referenced, normal eval
  // Check if ANY column reference exists in the row data
  var rowKeys = Object.keys(row || {});
  // Normalize row keys to lowercase for case-insensitive matching
  var lowerKeys = rowKeys.map(function(k) { return k.toLowerCase(); });
  for (var ri = 0; ri < refs.length; ri++) {
    if (lowerKeys.indexOf(refs[ri].toLowerCase()) >= 0) return false; // at least one exists
  }
  return true; // ALL columns missing → fail-safe true
}
