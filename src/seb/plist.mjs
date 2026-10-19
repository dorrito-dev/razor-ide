// Minimal Apple plist writer/parser for SEB configuration files.
//
// Scope note: this is deliberately *not* a general plist library. It covers
// exactly the value types SEB uses -- dict, array, string, integer, real,
// boolean, data, date -- because the SEB Config Key algorithm has
// type-specific canonicalisation rules and guessing them would silently
// produce wrong hashes.
//
// The parser is only used for round-trip tests and for reading a plist the
// operator produced with SEB Config Tool, so it stays strict and small.

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };

export const escapeXml = (s) => String(s).replace(/[&<>"]/g, (c) => ESCAPES[c]);

const unescapeXml = (s) =>
  s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');

const INDENT = '\t';

/**
 * Serialise a JS value to plist XML.
 *
 * Ambiguity rule: `{ __type: 'real', value: 0.1 }` forces `<real>` because a
 * JS number cannot otherwise be distinguished between `<integer>` and
 * `<real>`. `{ __type: 'data' | 'date', value }` likewise. This matters
 * because SEB's Config Key canonicalisation treats each type differently.
 */
export function toPlistXml(value, options = {}) {
  const indent = Number(options.indent ?? 0);
  const pad = INDENT.repeat(indent);
  const inner = (v, depth) => toPlistXml(v, { indent: depth });

  if (value === null || value === undefined) return `${pad}<string></string>`;

  if (typeof value === 'boolean') return `${pad}<${value ? 'true' : 'false'}/>`;

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`non-finite number: ${value}`);
    const tag = Number.isInteger(value) ? 'integer' : 'real';
    return `${pad}<${tag}>${value}</${tag}>`;
  }

  if (typeof value === 'string') return `${pad}<string>${escapeXml(value)}</string>`;

  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}<array/>`;
    const body = value.map((item) => inner(item, indent + 1)).join('\n');
    return `${pad}<array>\n${body}\n${pad}</array>`;
  }

  if (typeof value === 'object') {
    if (value.__type === 'real') return `${pad}<real>${roundReal(value.value)}</real>`;
    if (value.__type === 'data') return `${pad}<data>${value.value}</data>`;
    if (value.__type === 'date') return `${pad}<date>${value.value}</date>`;

    const keys = Object.keys(value).sort((a, b) => a.localeCompare(b));
    if (keys.length === 0) return `${pad}<dict/>`;
    const body = keys
      .map(
        (k) =>
          `${INDENT.repeat(indent + 1)}<key>${escapeXml(k)}</key>\n${inner(value[k], indent + 1)}`,
      )
      .join('\n');
    return `${pad}<dict>\n${body}\n${pad}</dict>`;
  }

  throw new TypeError(`unsupported plist value: ${typeof value}`);
}

/**
 * Round a float the way SEB's Config Key canonicalisation does: strip the
 * spurious precision that IEEE-754 round-tripping introduces, so
 * 0.10000000000000001 and 0.1 hash identically.
 */
export function roundReal(value) {
  const n = Number(value);
  if (Number.isInteger(n)) return String(n);
  const rounded = Number.parseFloat(n.toPrecision(12));
  return String(rounded);
}

export function buildDocument(rootDict) {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    toPlistXml(rootDict, { indent: 0 }),
    '</plist>',
    '',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Parser (tests + reading Config-Tool output)
// ---------------------------------------------------------------------------

export function parsePlistXml(xml) {
  const tokens = tokenize(xml);
  let i = 0;

  const peek = () => tokens[i];
  const next = () => tokens[i++];

  // Skip the prolog / doctype.
  while (i < tokens.length && tokens[i].type !== 'open') i++;
  if (tokens[i]?.name !== 'plist') throw new SyntaxError('expected <plist>');
  i++;

  const value = parseValue();
  return value;

  function parseValue() {
    const token = next();
    if (!token) throw new SyntaxError('unexpected end of document');
    if (token.type !== 'open') throw new SyntaxError(`expected an element, got ${token.type}`);

    switch (token.name) {
      case 'dict':
        return parseDict();
      case 'array':
        return parseArray();
      case 'true':
        expectClose('true');
        return true;
      case 'false':
        expectClose('false');
        return false;
      case 'integer':
        return Number(readText('integer'));
      case 'real':
        return { __type: 'real', value: Number(readText('real')) };
      case 'string':
        return readText('string');
      case 'data':
        return { __type: 'data', value: readText('data').replace(/\s+/g, '') };
      case 'date':
        return { __type: 'date', value: readText('date') };
      default:
        throw new SyntaxError(`unsupported element <${token.name}>`);
    }
  }

  function parseDict() {
    if (peek()?.type === 'close') {
      next();
      return {};
    }
    const out = {};
    while (peek() && peek().type === 'open' && peek().name === 'key') {
      next();
      const key = readText('key');
      out[key] = parseValue();
    }
    expectClose('dict');
    return out;
  }

  function parseArray() {
    if (peek()?.type === 'close') {
      next();
      return [];
    }
    const out = [];
    while (peek() && !(peek().type === 'close' && peek().name === 'array')) {
      out.push(parseValue());
    }
    expectClose('array');
    return out;
  }

  function readText(name) {
    const token = next();
    if (!token || token.type !== 'text') throw new SyntaxError(`<${name}> has no text`);
    expectClose(name);
    return unescapeXml(token.value);
  }

  function expectClose(name) {
    const token = next();
    if (!token || token.type !== 'close' || token.name !== name) {
      throw new SyntaxError(`expected </${name}>, got ${token ? token.type + ':' + token.name : 'EOF'}`);
    }
  }
}

function tokenize(xml) {
  const out = [];
  const re = /<([!?][^>]*?)>|<!--[\s\S]*?-->|<\/([A-Za-z0-9_]+)\s*>|<([A-Za-z0-9_]+)((?:\s[^>]*?)?)(\/?)>|([^<]+)/g;
  let match;
  while ((match = re.exec(xml)) !== null) {
    const [, misc, closeName, openName, , selfClose, text] = match;
    if (misc !== undefined) continue;
    if (closeName) out.push({ type: 'close', name: closeName });
    else if (openName) {
      if (selfClose === '/') {
        out.push({ type: 'open', name: openName });
        out.push({ type: 'close', name: openName });
      } else {
        out.push({ type: 'open', name: openName });
      }
    } else if (text !== undefined) {
      if (text.trim() !== '') out.push({ type: 'text', value: text });
    }
  }
  return out;
}
