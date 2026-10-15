// src/config.js
var DEFAULT = {
  path: "/html/static",
  domesticPrimary: "https://1.1.1.1/dns-query",
  domesticFallback: "https://1.1.1.1/dns-query",
  globalPrimary: "https://1.1.1.1/dns-query",
  globalFallback: "https://1.1.1.1/dns-query",
  ecsV4Prefix: 24,
  ecsV6Prefix: 56,
  upstreamTimeoutMs: 3e3,
  maxQueryBytes: 4096,
  maxResponseBytes: 65535,
  maxTtlSeconds: 3600,
  cacheTtlSeconds: 300,
  rulesUrl: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
  rulesCacheMin: 15,
  dnssec: true,
  // 感知/透传 DNSSEC（上游置 AD 且客户端请求过 DO 才回 AD 位）
  blockAction: "nxdomain",
  // 过滤命中响应: nxdomain|zero(null 0.0.0.0/::)|passthrough
  jsonPath: "/json"
  // 兼容 Google 风格的 DoH JSON API（GET ?name=&type=）
};
function asSingle(s, fallback) {
  if (!s) return fallback;
  const v = String(s).trim();
  return v ? v : fallback;
}
function parseUint(val, fallback, min = 0, max = Infinity) {
  const n = Number(val);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}
function readConfig(env) {
  const path = asSingle(env.DOH_PATH, DEFAULT.path);
  const config = {
    path: path.startsWith("/") ? path : `/${path}`,
    domesticUrls: [
      asSingle(env.DOMESTIC_DOH_URL, DEFAULT.domesticPrimary),
      asSingle(env.DOMESTIC_FALLBACK_DOH_URL, DEFAULT.domesticFallback)
    ],
    globalUrls: [
      asSingle(env.GLOBAL_DOH_URL, DEFAULT.globalPrimary),
      asSingle(env.GLOBAL_FALLBACK_DOH_URL, DEFAULT.globalFallback)
    ],
    ecsV4Prefix: parseUint(env.ECS_IPV4_PREFIX, DEFAULT.ecsV4Prefix, 8, 32),
    ecsV6Prefix: parseUint(env.ECS_IPV6_PREFIX, DEFAULT.ecsV6Prefix, 8, 128),
    upstreamTimeoutMs: parseUint(env.UPSTREAM_TIMEOUT_MS, DEFAULT.upstreamTimeoutMs, 500, 1e4),
    maxQueryBytes: parseUint(env.MAX_QUERY_BYTES, DEFAULT.maxQueryBytes, 512, 8192),
    maxResponseBytes: parseUint(env.MAX_RESPONSE_BYTES, DEFAULT.maxResponseBytes, 512, 65535),
    maxTtlSeconds: parseUint(env.MAX_TTL_SECONDS, DEFAULT.maxTtlSeconds, 0, 86400),
    cacheTtlSeconds: parseUint(env.CACHE_TTL_SECONDS, DEFAULT.cacheTtlSeconds, 0, 86400),
    rulesUrl: asSingle(env.RULES_URL, DEFAULT.rulesUrl),
    rulesCacheMin: parseUint(env.RULES_CACHE_MIN, DEFAULT.rulesCacheMin, 1, 1440),
    token: asSingle(env.DOH_TOKEN, ""),
    rulesSyncSecret: asSingle(env.RULES_SYNC_SECRET, ""),
    pageUrl: asSingle(env.PAGE_URL, ""),
    dnssec: String(env.DNSSEC ?? "").trim() === "" ? DEFAULT.dnssec : String(env.DNSSEC).trim() !== "0" && String(env.DNSSEC).trim().toLowerCase() !== "false",
    blockAction: (() => {
      const v = asSingle(env.BLOCK_ACTION, DEFAULT.blockAction).toLowerCase();
      return ["nxdomain", "zero", "passthrough"].includes(v) ? v : DEFAULT.blockAction;
    })(),
    jsonPath: (() => {
      const p = asSingle(env.JSON_PATH, DEFAULT.jsonPath);
      return p.startsWith("/") ? p : `/${p}`;
    })()
  };
  return config;
}

// src/dns.js
var DNS_CONTENT_TYPE = "application/dns-message";
var OPCODE_QUERY = 0;
var HDR_ID = 0;
var HDR_FLAGS = 2;
var HDR_QDCOUNT = 4;
var HDR_ARCOUNT = 10;
var HEADER_LEN = 12;
var DnsFormatError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "DnsFormatError";
  }
};
function readU16(buf, off) {
  return buf[off] << 8 | buf[off + 1];
}
function writeU16(buf, off, value) {
  buf[off] = value >> 8 & 255;
  buf[off + 1] = value & 255;
}
function decodeName(buf, start) {
  let off = start;
  let name = "";
  let jumps = 0;
  while (true) {
    const len = buf[off];
    if (len === void 0) throw new DnsFormatError("name_truncated");
    if (len === 0) {
      off += 1;
      return { name, end: off };
    }
    if ((len & 192) === 192) {
      if (off + 1 >= buf.length) throw new DnsFormatError("name_pointer_truncated");
      off += 2;
      if (jumps++ > 4) throw new DnsFormatError("name_too_many_ptrs");
      return { name, end: off };
    }
    if ((len & 192) !== 0) throw new DnsFormatError("name_bad_label");
    if (off + 1 + len > buf.length) throw new DnsFormatError("name_label_truncated");
    let label = "";
    for (let i = 0; i < len; i += 1) {
      const c = buf[off + 1 + i] & 255;
      label += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : String.fromCharCode(c);
    }
    if (name !== "") name += ".";
    name += label;
    off += 1 + len;
  }
}
function parseDnsMessage(buf) {
  if (buf.length < HEADER_LEN) throw new DnsFormatError("too_short");
  const id = readU16(buf, HDR_ID);
  const flags = readU16(buf, HDR_FLAGS);
  const qdcount = readU16(buf, HDR_QDCOUNT);
  const arcount = readU16(buf, HDR_ARCOUNT);
  if (qdcount !== 1) {
    throw new DnsFormatError("qdcount_not_one");
  }
  if ((flags & 30720) !== OPCODE_QUERY << 11) {
    throw new DnsFormatError("not_a_query");
  }
  let off = HEADER_LEN;
  const nameStart = off;
  const { name, end } = decodeName(buf, off);
  const questionStart = nameStart;
  off = end;
  if (off + 4 > buf.length) throw new DnsFormatError("question_truncated");
  const qtype = readU16(buf, off);
  const qclass = readU16(buf, off + 2);
  const questionEnd = off + 4;
  off = questionEnd;
  const question = {
    name,
    // lower-cased qname, e.g. "github.com"
    qtype,
    qclass,
    nameOffset: nameStart,
    nameEnd: end,
    questionStart,
    questionEnd
  };
  const ancount = readU16(buf, 6);
  const nscount = readU16(buf, 8);
  const skipRRs = (start, count) => {
    let cursor2 = start;
    for (let i = 0; i < count; i += 1) {
      const { end: nEnd } = decodeName(buf, cursor2);
      cursor2 = nEnd;
      if (cursor2 + 10 > buf.length) throw new DnsFormatError("rr_truncated");
      const rdlength = readU16(buf, cursor2 + 8);
      cursor2 += 10 + rdlength;
      if (cursor2 > buf.length) throw new DnsFormatError("rr_rdata_truncated");
    }
    return cursor2;
  };
  let cursor = questionEnd;
  cursor = skipRRs(cursor, ancount);
  cursor = skipRRs(cursor, nscount);
  let opt = null;
  if (arcount >= 1) {
    let last = cursor;
    for (let i = 0; i < arcount - 1; i += 1) {
      const { end: nEnd } = decodeName(buf, last);
      last = nEnd;
      if (last + 10 > buf.length) throw new DnsFormatError("add_rr_truncated");
      last += 10 + readU16(buf, last + 8);
    }
    const { end: lastNameEnd } = decodeName(buf, last);
    const addStart = lastNameEnd;
    if (addStart + 10 <= buf.length) {
      const type = readU16(buf, addStart);
      const rdataLenOff = addStart + 8;
      const rdlength = readU16(buf, rdataLenOff);
      const rdataStart = addStart + 10;
      const rdataEnd = rdataStart + rdlength;
      if (rdataEnd <= buf.length && type === 41) {
        opt = {
          additionalIndex: arcount - 1,
          // 0-based index of last
          rdataStart,
          rdataEnd,
          rdataLenOff
        };
      }
    }
  }
  return { id, flags, question, opt, additionalCount: arcount };
}
function buildErrorResponse(fromBuf, rcode, question) {
  const out = new Uint8Array(HEADER_LEN);
  const id = readU16(fromBuf, HDR_ID);
  const reqFlags = readU16(fromBuf, HDR_FLAGS);
  writeU16(out, HDR_ID, id);
  const rd = reqFlags & 256;
  const flags = 32768 | reqFlags & 30720 | rd | 128 | rcode & 15;
  writeU16(out, HDR_FLAGS, flags);
  writeU16(out, HDR_QDCOUNT, question ? 1 : 0);
  writeU16(out, 6, 0);
  writeU16(out, 8, 0);
  writeU16(out, HDR_ARCOUNT, 0);
  if (question) {
    const q = question.questionEnd - question.questionStart;
    const full = new Uint8Array(HEADER_LEN + q);
    full.set(out, 0);
    full.set(fromBuf.subarray(question.questionStart, question.questionEnd), HEADER_LEN);
    return full;
  }
  return out;
}
function writeU32(buf, off, value) {
  buf[off] = value >>> 24 & 255;
  buf[off + 1] = value >>> 16 & 255;
  buf[off + 2] = value >>> 8 & 255;
  buf[off + 3] = value & 255;
}
function validateUpstreamResponse(answerBuf, originalInfo) {
  if (answerBuf.length < 12) throw new DnsFormatError("answer_too_short");
  const answerId = answerBuf[0] << 8 | answerBuf[1];
  if (originalInfo && answerId !== originalInfo.id) {
    throw new DnsFormatError("id_mismatch");
  }
  const flags = answerBuf[2] << 8 | answerBuf[3];
  if ((flags & 32768) === 0) throw new DnsFormatError("not_response");
  if ((flags & 512) !== 0) throw new DnsFormatError("truncated");
  return flags;
}
var TYPE_A = 1;
var TYPE_AAAA = 28;
function buildZeroResponse(fromBuf, parsed) {
  const q = parsed.question;
  const qtype = q.qtype;
  const isAaaa = qtype === TYPE_AAAA;
  const keep = isAaaa ? TYPE_AAAA : TYPE_A;
  const addr = isAaaa ? new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) : new Uint8Array([0, 0, 0, 0]);
  const questionLen = q.questionEnd - q.questionStart;
  const ansNameLen = 2;
  const outLen = HEADER_LEN + questionLen + (2 + 10 + addr.length);
  const out = new Uint8Array(outLen);
  const id = readU16(fromBuf, HDR_ID);
  const reqFlags = readU16(fromBuf, HDR_FLAGS);
  const rd = reqFlags & 256;
  const flags = 32768 | reqFlags & 30720 | rd | 128;
  writeU16(out, HDR_ID, id);
  writeU16(out, HDR_FLAGS, flags);
  writeU16(out, HDR_QDCOUNT, 1);
  writeU16(out, 6, 1);
  writeU16(out, 8, 0);
  writeU16(out, HDR_ARCOUNT, 0);
  out.set(fromBuf.subarray(q.questionStart, q.questionEnd), HEADER_LEN);
  let o = HEADER_LEN + questionLen;
  out[o] = 192;
  out[o + 1] = 12;
  o += 2;
  writeU16(out, o, keep);
  writeU16(out, o + 2, 1);
  writeU32(out, o + 4, 60);
  writeU16(out, o + 8, addr.length);
  out.set(addr, o + 10);
  return out;
}
var FLAG_AD = 32;
function applyRelayedDnssec(answerBuf, clientRequestedDnssec2) {
  const cur = readU16(answerBuf, 2);
  let next = cur;
  if (!clientRequestedDnssec2) {
    next &= ~FLAG_AD;
  }
  writeU16(answerBuf, 2, next);
  return next;
}
function clientRequestedDnssec(parsed) {
  return Boolean(parsed && parsed.opt);
}
function answerTtlSeconds(buf, info) {
  const toU32At = (o) => o + 3 < buf.length ? (buf[o] & 255) << 24 | (buf[o + 1] & 255) << 16 | (buf[o + 2] & 255) << 8 | buf[o + 3] & 255 : 0;
  const skipRr = (start) => {
    const { end } = decodeName(buf, start);
    if (end + 10 > buf.length) return { next: buf.length, type: 0, ttl: 0, rdataOff: 0 };
    const type = readU16(buf, end);
    const ttl = toU32At(end + 4);
    const rdlen = readU16(buf, end + 8);
    const rdataOff = end + 10;
    return { next: rdataOff + rdlen, type, ttl, rdataOff };
  };
  const ancount = readU16(buf, 6);
  const nscount = readU16(buf, 8);
  let cursor = info.question.questionEnd;
  let minTtl = Infinity;
  let sawRecord = false;
  for (let s = 0; s < ancount + nscount; s += 1) {
    const { next, type, ttl, rdataOff } = skipRr(cursor);
    sawRecord = true;
    if (ttl < minTtl) minTtl = ttl;
    if (type === 6) {
      try {
        const { end: mnameEnd } = decodeName(buf, rdataOff);
        const { end: rnameEnd } = decodeName(buf, mnameEnd);
        const minFieldOff = rnameEnd + 16;
        if (minFieldOff + 4 <= buf.length) {
          const minimum = toU32At(minFieldOff);
          if (minimum < minTtl) minTtl = minimum;
        }
      } catch {
      }
    }
    cursor = next;
    if (cursor > buf.length) break;
  }
  if (!sawRecord) return 0;
  return minTtl === Infinity ? 0 : minTtl;
}

// src/matcher.js
function parseRuleText(text) {
  const plain = [];
  const plainSet = /* @__PURE__ */ new Set();
  const full = /* @__PURE__ */ new Set();
  const regexp = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    if (line.startsWith("full:")) {
      const d = line.slice(5).trim().toLowerCase();
      if (d) full.add(d);
    } else if (line.startsWith("regexp:")) {
      const d = line.slice(7).trim();
      if (d) regexp.push(new RegExp(d, "i"));
    } else {
      const d = line.toLowerCase();
      plain.push(d);
      plainSet.add(d);
    }
  }
  plain.sort();
  return { plain, plainSet, full, regexp, version: text.length };
}
function matchesRule(qname, rule) {
  const q = qname.toLowerCase();
  if (!rule) return false;
  if (rule.full && rule.full.has(q)) return true;
  if (rule.plainSet) {
    if (rule.plainSet.has(q)) return true;
    let dotIdx = q.indexOf(".");
    while (dotIdx !== -1) {
      const parent = q.slice(dotIdx + 1);
      if (rule.plainSet.has(parent)) return true;
      dotIdx = q.indexOf(".", dotIdx + 1);
    }
  } else if (rule.plain) {
    for (let i = 0; i < rule.plain.length; i += 1) {
      const p = rule.plain[i];
      if (q === p || q.endsWith(`.${p}`)) return true;
    }
  }
  if (rule.regexp) {
    for (let i = 0; i < rule.regexp.length; i += 1) {
      if (rule.regexp[i].test(q)) return true;
    }
  }
  return false;
}

// src/rules.js
var DEC = new TextDecoder("latin1");
var ENC = new TextEncoder();
var DEFAULT_RULES_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt";
var BUILTIN_OVERRIDE = [
  "linux.do",
  // 主论坛及子域
  "github.com",
  "githubusercontent.com",
  "githubassets.com"
];
var KV_KEY = "rules:data";
var KV_MAX_BYTES = 8 * 1024 * 1024;
var FAIL_COOLDOWN_MS = 3e4;
var failUntil = 0;
var live = null;
var coldInflight = null;
function noteFailure() {
  failUntil = Date.now() + FAIL_COOLDOWN_MS;
}
function inFailureWindow() {
  return Date.now() < failUntil;
}
function matchesRules(qname, rules) {
  const q = qname.toLowerCase();
  if (matchesBuiltin(q)) return true;
  return matchesRule(qname, rules);
}
var BUILTIN = new Set(BUILTIN_OVERRIDE.map((d) => d.toLowerCase()));
function matchesBuiltin(q) {
  if (BUILTIN.has(q)) return true;
  let dotIdx = q.indexOf(".");
  while (dotIdx !== -1) {
    const parent = q.slice(dotIdx + 1);
    if (BUILTIN.has(parent)) return true;
    dotIdx = q.indexOf(".", dotIdx + 1);
  }
  return false;
}
function isDomestic(qname, rules) {
  return matchesRules(qname, rules);
}
async function ensureFromKv(kv) {
  try {
    const raw = await kv.get(KV_KEY);
    if (!raw) return null;
    const bytes = typeof raw === "string" ? ENC.encode(raw) : raw;
    if (bytes.byteLength === 0) return null;
    const text = DEC.decode(bytes);
    const parsed = parseRuleText(text);
    const rule = { ...parsed, data: text };
    live = rule;
    return rule;
  } catch {
    return null;
  }
}
async function fetchAndAdopt(rulesUrl, fetcher) {
  const resp = await fetcher(rulesUrl, { method: "GET", redirect: "manual" });
  if (!resp.ok) throw new Error(`rules_http_${resp.status}`);
  const ct = (resp.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("text/html")) throw new Error("rules_html_response");
  const buf = await resp.arrayBuffer();
  if (buf.byteLength > KV_MAX_BYTES) throw new Error("rules_too_large");
  const text = DEC.decode(buf);
  const parsed = parseRuleText(text);
  return { rule: { ...parsed, data: text }, bytes: new Uint8Array(buf) };
}
async function ensureRules(env, fetcher = fetch) {
  if (live) return live;
  if (env.RULES_KV) {
    const fromKv = await ensureFromKv(env.RULES_KV);
    if (fromKv) return fromKv;
  }
  if (inFailureWindow()) return null;
  if (!coldInflight) {
    const rulesUrl = env.RULES_URL || DEFAULT_RULES_URL;
    coldInflight = (async () => {
      try {
        const { rule, bytes } = await fetchAndAdopt(rulesUrl, fetcher);
        live = rule;
        if (env.RULES_KV) {
          try {
            await env.RULES_KV.put(KV_KEY, bytes);
          } catch {
          }
        }
        return live;
      } catch {
        noteFailure();
        return null;
      }
    })().finally(() => {
      coldInflight = null;
    });
  }
  return coldInflight;
}
async function refreshRules(env, fetcher = fetch) {
  const rulesUrl = env.RULES_URL || DEFAULT_RULES_URL;
  try {
    const { rule, bytes } = await fetchAndAdopt(rulesUrl, fetcher);
    live = rule;
    if (env.RULES_KV) {
      try {
        await env.RULES_KV.put(KV_KEY, bytes);
      } catch {
      }
    }
    return true;
  } catch {
    noteFailure();
    return false;
  }
}
async function adoptRawRules(text, env) {
  if (typeof text !== "string" || text.trim().length === 0) {
    throw new Error("rules_empty");
  }
  if (text.toLowerCase().includes("<html")) {
    throw new Error("rules_html_response");
  }
  const bytes = ENC.encode(text);
  if (bytes.byteLength > KV_MAX_BYTES) {
    throw new Error("rules_too_large");
  }
  const parsed = parseRuleText(text);
  const rule = { ...parsed, data: text };
  live = rule;
  failUntil = 0;
  if (env && env.RULES_KV) {
    await env.RULES_KV.put(KV_KEY, bytes);
  }
  return {
    ruleCount: parsed.plain.length + parsed.full.size + parsed.regexp.length,
    bytes: bytes.byteLength
  };
}

// src/filter.js
var DEC2 = new TextDecoder("latin1");
var ENC2 = new TextEncoder();
var KV_KEY2 = "block:data";
var live2 = null;
var coldInflight2 = null;
function isBlocked(qname, rule) {
  return matchesRule(qname, rule);
}
var disabled = false;
async function ensureBlock(env, fetcher = fetch) {
  if (live2) return live2;
  if (!env.BLOCK_URL && disabled) return null;
  if (env.BLOCK_KV) {
    try {
      const raw = await env.BLOCK_KV.get(KV_KEY2);
      if (raw) {
        const bytes = typeof raw === "string" ? ENC2.encode(raw) : raw;
        const text = DEC2.decode(bytes);
        live2 = { ...parseRuleText(text), data: text };
        return live2;
      }
    } catch {
    }
  }
  const url = env.BLOCK_URL || "";
  if (!url) {
    disabled = true;
    return null;
  }
  if (!coldInflight2) {
    coldInflight2 = (async () => {
      try {
        const resp = await fetcher(url, { method: "GET", redirect: "manual" });
        if (!resp.ok) return null;
        const ct = (resp.headers.get("content-type") || "").toLowerCase();
        if (ct.includes("text/html")) return null;
        const buf = await resp.arrayBuffer();
        const text = DEC2.decode(buf);
        const rule = parseRuleText(text);
        live2 = { ...rule, data: text };
        if (env.BLOCK_KV) {
          try {
            await env.BLOCK_KV.put(KV_KEY2, new Uint8Array(buf));
          } catch {
          }
        }
        return live2;
      } catch {
        return null;
      }
    })().finally(() => {
      coldInflight2 = null;
    });
  }
  return coldInflight2;
}
function resetBlock() {
  live2 = null;
  coldInflight2 = null;
  disabled = false;
}
async function refreshBlock(env, fetcher = fetch) {
  const url = env.BLOCK_URL || "";
  if (!url) return false;
  try {
    const resp = await fetcher(url, { method: "GET", redirect: "manual" });
    if (!resp.ok) return false;
    const ct = (resp.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("text/html")) return false;
    const buf = await resp.arrayBuffer();
    const text = DEC2.decode(buf);
    live2 = { ...parseRuleText(text), data: text };
    if (env.BLOCK_KV) {
      try {
        await env.BLOCK_KV.put(KV_KEY2, new Uint8Array(buf));
      } catch {
      }
    }
    return true;
  } catch {
    return false;
  }
}

// src/jsonapi.js
var DECODE = new TextDecoder("latin1");
var TYPE_STR = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  65: "HTTPS"
};
function readU162(b, o) {
  return b[o] << 8 | b[o + 1];
}
function toU32(b, o) {
  return (b[o] & 255) << 24 | (b[o + 1] & 255) << 16 | (b[o + 2] & 255) << 8 | b[o + 3] & 255;
}
function readName(b, o) {
  let out = "";
  let p = o;
  let jumped = false;
  let jumpTo = 0;
  while (true) {
    if (p >= b.length) break;
    const len = b[p];
    if (len === 0) {
      p += 1;
      break;
    }
    if ((len & 192) === 192) {
      if (!jumped) {
        jumpTo = p + 2;
        jumped = true;
      }
      p = (len & 63) << 8 | b[p + 1];
      continue;
    }
    if (out) out += ".";
    for (let i = 1; i <= len; i++) out += String.fromCharCode(b[p + i] & 255);
    p += len + 1;
  }
  return { name: out, end: jumped ? jumpTo : p };
}
function rdataString(type, wire, off, len) {
  switch (type) {
    case 1: {
      if (len < 4 || off + 4 > wire.length) return "";
      return `${wire[off]}.${wire[off + 1]}.${wire[off + 2]}.${wire[off + 3]}`;
    }
    case 28: {
      if (len < 16 || off + 16 > wire.length) return "";
      const h = [];
      for (let i = 0; i < 8; i++) {
        const idx = off + i * 2;
        h.push((wire[idx] << 8 | wire[idx + 1]).toString(16));
      }
      return h.join(":");
    }
    case 5:
    case 2:
    case 12: {
      const r = readName(wire, off);
      return r.name;
    }
    case 16: {
      if (len === 0 || off + len > wire.length) return "";
      let p = off;
      const end = off + len;
      const parts = [];
      while (p < end) {
        const slen = wire[p];
        p += 1;
        if (p + slen > end) {
          parts.push(DECODE.decode(wire.subarray(p, end)));
          break;
        }
        parts.push(DECODE.decode(wire.subarray(p, p + slen)));
        p += slen;
      }
      return JSON.stringify(parts.join(""));
    }
    case 15: {
      if (len < 2 || off + 2 > wire.length) return "";
      const pref = readU162(wire, off);
      const r = readName(wire, off + 2);
      return `${pref} ${r.name}`;
    }
    case 6: {
      if (len < 22 || off + len > wire.length) return "";
      const mname = readName(wire, off);
      const rname = readName(wire, mname.end);
      let p = rname.end;
      if (p + 20 > off + len) return `${mname.name} ${rname.name}`;
      const ser = toU32(wire, p);
      const refresh = toU32(wire, p + 4);
      const retry2 = toU32(wire, p + 8);
      const expire = toU32(wire, p + 12);
      const mini = toU32(wire, p + 16);
      return `${mname.name} ${rname.name} ${ser} ${refresh} ${retry2} ${expire} ${mini}`;
    }
    default:
      return Array.from(wire.subarray(off, Math.min(off + len, off + 64))).map((x) => x.toString(16).padStart(2, "0")).join("");
  }
}
function toJsonResponse(wire, qname, qtypeName) {
  if (!wire || wire.length < 12) {
    return { Status: 2, RA: false, Question: [{ name: qname, type: qtypeName }] };
  }
  const flags = readU162(wire, 2);
  const qd = readU162(wire, 4);
  const an = readU162(wire, 6);
  const ns = readU162(wire, 8);
  const ar = readU162(wire, 10);
  const rc = flags & 15;
  const rd = !!(flags & 256);
  const ra = !!(flags & 128);
  const ad = !!(flags & 32);
  const tc = !!(flags & 512);
  const cd = !!(flags & 16);
  const questions = [];
  let p = 12;
  for (let i = 0; i < qd; i++) {
    const { name, end } = readName(wire, p);
    const t = readU162(wire, end);
    questions.push({ name, type: TYPE_STR[t] || `TYPE${t}` });
    p = end + 4;
  }
  const collect = (count) => {
    const arr = [];
    for (let i = 0; i < count; i++) {
      if (p >= wire.length) break;
      const { name, end } = readName(wire, p);
      p = end;
      if (p + 10 > wire.length) break;
      const t = readU162(wire, p);
      const cl = readU162(wire, p + 2);
      const ttl = toU32(wire, p + 4);
      const len = readU162(wire, p + 8);
      p += 10;
      if (p + len > wire.length) break;
      const rdataOffset = p;
      p += len;
      const typeName = TYPE_STR[t] || `TYPE${t}`;
      arr.push({
        name,
        type: typeName,
        TTL: ttl,
        data: rdataString(t, wire, rdataOffset, len)
      });
    }
    return arr;
  };
  const answers = collect(an);
  const authority = collect(ns);
  const additional = collect(ar);
  return {
    Status: rc,
    TC: tc,
    RD: rd,
    RA: ra,
    AD: ad,
    CD: cd,
    Question: questions.length ? questions : [{ name: qname, type: qtypeName }],
    Answer: answers,
    Authority: authority,
    Additional: additional
  };
}
function jsonResponse(obj, minTtlSeconds = 0) {
  const cc = minTtlSeconds > 0 ? `max-age=${minTtlSeconds}` : "no-store";
  return new Response(JSON.stringify(obj), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": cc,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

// src/resolver.js
async function queryUpstream(url, query, { timeoutMs, maxResponseBytes, signal }) {
  const controller = new AbortController();
  const onParentAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", onParentAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = performance.now();
  try {
    const resp = await fetch(url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: DNS_CONTENT_TYPE,
        "Content-Type": DNS_CONTENT_TYPE
      },
      body: query
    });
    const durationMs = Math.round((performance.now() - start) * 10) / 10;
    if (!resp.ok) return { ok: false, reason: `http_${resp.status}`, durationMs };
    const ct = (resp.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
    if (ct !== DNS_CONTENT_TYPE) return { ok: false, reason: "bad_content_type", durationMs };
    const buf = await resp.arrayBuffer();
    if (buf.byteLength < 12 || buf.byteLength > maxResponseBytes) {
      return { ok: false, reason: "bad_size", durationMs };
    }
    return { ok: true, body: new Uint8Array(buf), durationMs };
  } catch {
    const durationMs = Math.round((performance.now() - start) * 10) / 10;
    return { ok: false, reason: controller.signal.aborted ? "timeout" : "network", durationMs };
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener("abort", onParentAbort);
  }
}
function classify(r) {
  if (r.ok) {
    try {
      const flags = validateUpstreamResponse(r.body, null);
      return (flags & 15) === 2 ? "servfail" : "ok";
    } catch {
      return "bad_response";
    }
  }
  return r.reason === "timeout" ? "timeout" : "error";
}
async function raceGroup(urls, query, parsedInfo, { timeoutMs, maxResponseBytes, on }) {
  const groupController = new AbortController();
  const settle = (r) => {
    if (on) on({ kind: classify(r), url: r.url, durationMs: r.durationMs ?? 0 });
  };
  const pending = urls.map(async (url) => {
    const res = await queryUpstream(url, query, { timeoutMs, maxResponseBytes, signal: groupController.signal });
    return { url, ...res };
  });
  const results = new Array(pending.length);
  let settled = 0;
  return new Promise((resolve) => {
    for (let i = 0; i < pending.length; i += 1) {
      pending[i].then(
        (r) => {
          settled += 1;
          results[i] = r;
          settle(r);
          if (r.ok) {
            try {
              const flags = validateUpstreamResponse(r.body, parsedInfo ?? null);
              if ((flags & 15) !== 2) {
                groupController.abort();
                resolve({ answer: r.body, from: r.url, durationMs: r.durationMs ?? 0 });
                return;
              }
            } catch {
            }
          }
          if (settled === pending.length) resolve(null);
        },
        (err) => {
          settled += 1;
          settle({ ok: false, reason: "error", url: urls[i], durationMs: 0 });
          if (settled === pending.length) resolve(null);
        }
      );
    }
    if (pending.length === 0) resolve(null);
  });
}
function serverFailure(fromQuery, question) {
  return buildErrorResponse(fromQuery, 2, question ?? null);
}

// src/metrics.js
var COUNTERS = {
  requests: 0,
  get: 0,
  post: 0,
  ok: 0,
  formerr: 0,
  servfail: 0,
  upstream_timeouts: 0,
  upstream_errors: 0,
  upstream_ok: 0,
  upstream_servfail: 0,
  cache_hit: 0,
  cache_miss: 0,
  rules_fetch: 0,
  rules_unchanged: 0,
  rules_fetch_fail: 0,
  filter_blocked: 0,
  // DoT entry point (src/dot.js) — declared up front so /health always lists them.
  dot_connections: 0,
  dot_rejected: 0,
  dot_tls_errors: 0,
  dot_idle_timeouts: 0,
  dot_answer_errors: 0,
  dot_write_errors: 0,
  dot_frame_dropped: 0,
  dot_socket_errors: 0,
  dot_rate_limited: 0
};
var startedAt = Date.now();
var KNOWN = new Set(Object.keys(COUNTERS));
var UNKNOWN_WARNED = /* @__PURE__ */ new Set();
var UPSTREAM_WINS = {};
var MAX_SAMPLES = 300;
var LATENCY_SAMPLES = {
  domestic: [],
  global: []
};
function inc(name, n = 1) {
  if (!Object.hasOwn(COUNTERS, name)) {
    if (!UNKNOWN_WARNED.has(name)) {
      UNKNOWN_WARNED.add(name);
      console.warn(`[metrics] unknown counter incremented: ${name}`);
    }
    COUNTERS[name] = 0;
  }
  COUNTERS[name] += n;
}
function snapshot() {
  return { ...COUNTERS };
}
function recordUpstreamRace(group, winnerUrl, durationMs) {
  let host = "unknown";
  if (winnerUrl) {
    try {
      host = new URL(winnerUrl).hostname;
    } catch {
      host = String(winnerUrl);
    }
  }
  UPSTREAM_WINS[host] = (UPSTREAM_WINS[host] || 0) + 1;
  const key = group === "domestic" ? "domestic" : "global";
  if (typeof durationMs === "number" && durationMs >= 0) {
    const arr = LATENCY_SAMPLES[key];
    if (arr.length >= MAX_SAMPLES) arr.shift();
    arr.push(Math.round(durationMs * 10) / 10);
  }
}
function recordAnalyticsPoint(env, { group, winnerUrl, durationMs, qtype, rcode, cacheStatus }) {
  if (env && env.DOH_ANALYTICS && typeof env.DOH_ANALYTICS.writeDataPoint === "function") {
    let host = "cache";
    if (winnerUrl && winnerUrl !== "cache") {
      try {
        host = new URL(winnerUrl).hostname;
      } catch {
        host = String(winnerUrl);
      }
    }
    try {
      env.DOH_ANALYTICS.writeDataPoint({
        blobs: [
          host,
          group || "unknown",
          qtype ? String(qtype) : "A",
          rcode ? String(rcode) : "NOERROR",
          cacheStatus || "miss"
        ],
        doubles: [typeof durationMs === "number" ? durationMs : 0],
        indexes: [host]
      });
    } catch {
    }
  }
}
function computePercentiles(samples) {
  if (!samples || samples.length === 0) {
    return { count: 0, avgMs: 0, p50Ms: 0, p90Ms: 0, p95Ms: 0, minMs: 0, maxMs: 0 };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = samples.reduce((acc, v) => acc + v, 0);
  return {
    count: samples.length,
    avgMs: Math.round(sum / samples.length * 10) / 10,
    p50Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.5))],
    p90Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.9))],
    p95Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))],
    minMs: sorted[0],
    maxMs: sorted[sorted.length - 1]
  };
}
function statsSnapshot(config = {}) {
  const domesticUrls = config.domesticUrls || [
    config.domesticUrl || "https://dns.alidns.com/dns-query",
    config.domesticFallbackUrl || "https://doh.pub/dns-query"
  ];
  const globalUrls = config.globalUrls || [
    config.globalUrl || "https://dns.google/dns-query",
    config.globalFallbackUrl || "https://cloudflare-dns.com/dns-query"
  ];
  function buildGroupStats(urls) {
    const list = urls.map((u) => {
      let host = u;
      try {
        host = new URL(u).hostname;
      } catch {
      }
      return { url: u, host, wins: UPSTREAM_WINS[host] || 0 };
    });
    const totalWins = list.reduce((acc, item) => acc + item.wins, 0);
    const result = {};
    for (const item of list) {
      result[item.host] = {
        wins: item.wins,
        winRate: totalWins > 0 ? `${(item.wins / totalWins * 100).toFixed(1)}%` : "0.0%"
      };
    }
    return { upstreams: result, totalWins };
  }
  const domesticStats = buildGroupStats(domesticUrls);
  const globalStats = buildGroupStats(globalUrls);
  const totalCacheRequests = COUNTERS.cache_hit + COUNTERS.cache_miss;
  const cacheHitRate = totalCacheRequests > 0 ? `${(COUNTERS.cache_hit / totalCacheRequests * 100).toFixed(1)}%` : "0.0%";
  return {
    service: "cf-doh",
    version: "1.2.0",
    uptimeSec: Math.round((Date.now() - startedAt) / 1e3),
    totalRequests: COUNTERS.requests,
    cache: {
      hits: COUNTERS.cache_hit,
      misses: COUNTERS.cache_miss,
      hitRate: cacheHitRate
    },
    latency: {
      domestic: computePercentiles(LATENCY_SAMPLES.domestic),
      global: computePercentiles(LATENCY_SAMPLES.global)
    },
    upstreams: {
      domestic: domesticStats,
      global: globalStats
    },
    rawWins: { ...UPSTREAM_WINS }
  };
}
function statsResponse(config) {
  const body = JSON.stringify(statsSnapshot(config), null, 2);
  return new Response(body, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
function parseAnalyticsRows(rows, config = {}, dataset = "cf_doh_metrics") {
  const domesticUrls = config.domesticUrls || [
    config.domesticUrl || "https://dns.alidns.com/dns-query",
    config.domesticFallbackUrl || "https://doh.pub/dns-query"
  ];
  const globalUrls = config.globalUrls || [
    config.globalUrl || "https://dns.google/dns-query",
    config.globalFallbackUrl || "https://cloudflare-dns.com/dns-query"
  ];
  let totalRequests = 0;
  let cacheHits = 0;
  let cacheMisses = 0;
  const winCounts = {};
  const domesticLatencies = [];
  const globalLatencies = [];
  for (const row of rows || []) {
    const host = String(row.host || "unknown");
    const group = String(row.group_name || "unknown");
    const cacheStatus = String(row.cache_status || "miss");
    const count = Number(row.total_count || row.count || 0);
    const avg = Number(row.avg_duration || 0);
    const p50 = Number(row.p50 || 0);
    const p90 = Number(row.p90 || 0);
    const p95 = Number(row.p95 || 0);
    const min = Number(row.min_duration || 0);
    const max = Number(row.max_duration || 0);
    totalRequests += count;
    if (cacheStatus === "hit") {
      cacheHits += count;
    } else {
      cacheMisses += count;
      if (host !== "cache" && host !== "unknown") {
        winCounts[host] = (winCounts[host] || 0) + count;
      }
      if (group === "domestic") {
        domesticLatencies.push({ count, avg, p50, p90, p95, min, max });
      } else if (group === "global") {
        globalLatencies.push({ count, avg, p50, p90, p95, min, max });
      }
    }
  }
  function buildGroupStats(urls) {
    const list = urls.map((u) => {
      let host = u;
      try {
        host = new URL(u).hostname;
      } catch {
      }
      return { url: u, host, wins: winCounts[host] || 0 };
    });
    const totalWins = list.reduce((acc, item) => acc + item.wins, 0);
    const res = {};
    for (const item of list) {
      res[item.host] = {
        wins: item.wins,
        winRate: totalWins > 0 ? `${(item.wins / totalWins * 100).toFixed(1)}%` : "0.0%"
      };
    }
    return { upstreams: res, totalWins };
  }
  function aggregateLatency(list) {
    const total = list.reduce((sum, item) => sum + item.count, 0);
    if (total === 0) {
      return { count: 0, avgMs: 0, p50Ms: 0, p90Ms: 0, p95Ms: 0, minMs: 0, maxMs: 0 };
    }
    const weightedAvg = list.reduce((sum, item) => sum + item.avg * item.count, 0) / total;
    const weightedP50 = list.reduce((sum, item) => sum + item.p50 * item.count, 0) / total;
    const maxP90 = Math.max(...list.map((item) => item.p90));
    const maxP95 = Math.max(...list.map((item) => item.p95));
    const minVal = Math.min(...list.map((item) => item.min));
    const maxVal = Math.max(...list.map((item) => item.max));
    return {
      count: total,
      avgMs: Math.round(weightedAvg * 10) / 10,
      p50Ms: Math.round(weightedP50 * 10) / 10,
      p90Ms: Math.round(maxP90 * 10) / 10,
      p95Ms: Math.round(maxP95 * 10) / 10,
      minMs: Math.round(minVal * 10) / 10,
      maxMs: Math.round(maxVal * 10) / 10
    };
  }
  const cacheTotal = cacheHits + cacheMisses;
  const cacheHitRate = cacheTotal > 0 ? `${(cacheHits / cacheTotal * 100).toFixed(1)}%` : "0.0%";
  return {
    scope: "global",
    available: true,
    dataset,
    timespan: "24h",
    totalRequests,
    cache: {
      hits: cacheHits,
      misses: cacheMisses,
      hitRate: cacheHitRate
    },
    latency: {
      domestic: aggregateLatency(domesticLatencies),
      global: aggregateLatency(globalLatencies)
    },
    upstreams: {
      domestic: buildGroupStats(domesticUrls),
      global: buildGroupStats(globalUrls)
    },
    rawWins: { ...winCounts }
  };
}
async function queryGlobalStats(env = {}, config = {}, { interval = "1 DAY" } = {}) {
  const accountId = env.CF_ACCOUNT_ID || env.ACCOUNT_ID;
  const token = env.CF_ANALYTICS_READ_TOKEN || env.CLOUDFLARE_API_TOKEN;
  const dataset = env.ANALYTICS_DATASET || "cf_doh_metrics";
  if (!accountId || !token) {
    return {
      scope: "global",
      available: false,
      reason: "missing_credentials",
      message: "Global multi-PoP aggregation requires CF_ACCOUNT_ID and CF_ANALYTICS_READ_TOKEN (or CLOUDFLARE_API_TOKEN) environment variables.",
      fallback: statsSnapshot(config)
    };
  }
  const ALLOWED_INTERVALS = /* @__PURE__ */ new Set([
    "1 HOUR",
    "6 HOUR",
    "12 HOUR",
    "1 DAY",
    "2 DAY",
    "3 DAY",
    "7 DAY",
    "14 DAY",
    "30 DAY"
  ]);
  const cleanedInterval = String(interval || "").trim().toUpperCase();
  const safeInterval = ALLOWED_INTERVALS.has(cleanedInterval) ? cleanedInterval : "1 DAY";
  const sql = `
SELECT
  blob1 AS host,
  blob2 AS group_name,
  blob5 AS cache_status,
  count() AS total_count,
  avg(double1) AS avg_duration,
  quantile(0.5)(double1) AS p50,
  quantile(0.9)(double1) AS p90,
  quantile(0.95)(double1) AS p95,
  min(double1) AS min_duration,
  max(double1) AS max_duration
FROM ${dataset}
WHERE timestamp >= NOW() - INTERVAL '${safeInterval}'
GROUP BY host, group_name, cache_status
FORMAT JSON
  `.trim();
  const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/analytics_engine/sql`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/sql"
      },
      body: sql
    });
    if (!resp.ok) {
      const errText = await resp.text();
      return {
        scope: "global",
        available: false,
        reason: `http_${resp.status}`,
        message: `Analytics Engine SQL API error (${resp.status}): ${errText.slice(0, 200)}`,
        fallback: statsSnapshot(config)
      };
    }
    const result = await resp.json();
    const rows = Array.isArray(result?.data) ? result.data : [];
    return parseAnalyticsRows(rows, config, dataset);
  } catch (err) {
    return {
      scope: "global",
      available: false,
      reason: "network_error",
      message: String(err?.message || err),
      fallback: statsSnapshot(config)
    };
  }
}
async function globalStatsResponse(config, env, options) {
  const stats = await queryGlobalStats(env, config, options);
  return new Response(JSON.stringify(stats, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
function healthResponse(config) {
  const body = JSON.stringify(
    {
      status: "ok",
      service: "cf-doh",
      version: "1.2.0",
      uptimeSec: Math.round((Date.now() - startedAt) / 1e3),
      counters: snapshot(),
      stats: statsSnapshot(config),
      config: {
        path: config.path,
        upstreams: { domestic: config.domesticUrls, global: config.globalUrls },
        ecs: { v4: config.ecsV4Prefix, v6: config.ecsV6Prefix }
      }
    },
    null,
    2
  );
  return new Response(body, {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}
function resetMetrics() {
  for (const k of Object.keys(COUNTERS)) {
    if (KNOWN.has(k)) COUNTERS[k] = 0;
    else delete COUNTERS[k];
  }
  for (const k of Object.keys(UPSTREAM_WINS)) delete UPSTREAM_WINS[k];
  LATENCY_SAMPLES.domestic.length = 0;
  LATENCY_SAMPLES.global.length = 0;
  UNKNOWN_WARNED.clear();
  startedAt = Date.now();
}
var metrics = {
  inc,
  snapshot,
  recordUpstreamRace,
  recordAnalyticsPoint,
  statsSnapshot,
  statsResponse,
  parseAnalyticsRows,
  queryGlobalStats,
  globalStatsResponse,
  healthResponse,
  resetMetrics
};

// src/landing.js
function renderLandingHtml(origin, config) {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-theme="auto">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>cf-doh \u2014 \u9AD8\u6027\u80FD\u81EA\u7814 Cloudflare Workers DoH/DoT \u89E3\u6790\u7F51\u5173</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22 fill=%22none%22 stroke=%22%233b82f6%22 stroke-width=%222%22 stroke-linecap=%22round%22 stroke-linejoin=%22round%22><polygon points=%2213 2 3 14 12 14 11 22 21 10 12 10 13 2%22/></svg>">
  <script>
    (function() {
      try {
        var mode = localStorage.getItem('cf-doh-theme') || 'auto';
        var resolved = mode;
        if (mode === 'auto') {
          var isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          resolved = isDark ? 'dark' : 'light';
        }
        document.documentElement.dataset.theme = mode;
        document.documentElement.dataset.resolvedTheme = resolved;
        if (resolved === 'dark') {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
      } catch (e) {}
    })();
  <\/script>
  <style>
    :root {
      --bg: #101418;
      --bg-subtle: #171d22;
      --card-bg: #171d22;
      --card-border: #2a333a;
      --card-hover-border: #48616a;
      --text: #e8edf0;
      --text-muted: #a0adb4;
      --text-faint: #78878f;
      --primary: #70c7bd;
      --primary-hover: #8bd8ce;
      --primary-glow: rgba(112, 199, 189, 0.12);
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #ef4444;
      --accent-purple: #8b5cf6;
      --accent-orange: #f97316;
      --code-bg: #11171b;
      --chip-bg: #1b2328;
      --chip-border: #303b42;
      --nav-bg: rgba(16, 20, 24, 0.94);
    }
    html:not(.dark) {
      --bg: #f3f6f6;
      --bg-subtle: #e9eeee;
      --card-bg: #ffffff;
      --card-border: #dce4e5;
      --card-hover-border: #9abbb7;
      --text: #192326;
      --text-muted: #58686d;
      --text-faint: #829094;
      --primary: #187d73;
      --primary-hover: #12675f;
      --primary-glow: rgba(24, 125, 115, 0.1);
      --accent-emerald: #059669;
      --accent-amber: #d97706;
      --accent-rose: #dc2626;
      --accent-purple: #7c3aed;
      --accent-orange: #ea580c;
      --code-bg: #f5f8f8;
      --chip-bg: #f6f8f8;
      --chip-border: #dce4e5;
      --nav-bg: rgba(243, 246, 246, 0.94);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.55;
      overflow-x: hidden;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      transition: background-color 0.25s ease, color 0.25s ease;
    }
    a { color: var(--primary); text-decoration: none; transition: color 0.2s; }
    a:hover { color: var(--primary-hover); text-decoration: underline; }
    
    /* Navigation Bar */
    .nav-bar {
      position: sticky;
      top: 0;
      z-index: 50;
      background: var(--nav-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--card-border);
      padding: 10px 28px;
    }
    .nav-inner {
      max-width: 1220px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 9px;
      font-weight: 700;
      font-size: 1rem;
      letter-spacing: -0.01em;
      color: var(--text);
    }
    .brand-icon {
      width: 30px;
      height: 30px;
      border-radius: 7px;
      background: linear-gradient(135deg, var(--primary) 0%, #187d73 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
    }
    .version-tag {
      font-size: 0.68rem;
      font-weight: 600;
      padding: 2px 7px;
      border-radius: 5px;
      background: var(--primary-glow);
      color: var(--primary);
      border: 1px solid var(--card-border);
    }
    .nav-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    /* Layout Container */
    .container {
      max-width: 1220px;
      margin: 0 auto;
      padding: 34px 24px 64px;
      width: 100%;
      flex: 1;
    }
    
    /* Hero Header */
    .hero {
      text-align: left;
      margin: 0 0 28px;
      padding: 8px 0 24px;
      border-bottom: 1px solid var(--card-border);
    }
    .hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 4px 9px;
      border-radius: 5px;
      font-size: 0.76rem;
      font-weight: 500;
      background: var(--primary-glow);
      color: var(--primary);
      border: 1px solid var(--card-border);
      margin-bottom: 12px;
    }
    .hero h1 {
      font-size: 2rem;
      font-weight: 700;
      letter-spacing: 0;
      margin-bottom: 8px;
      color: var(--text);
    }
    .hero-desc {
      font-size: 0.96rem;
      color: var(--text-muted);
      max-width: 780px;
      margin: 0;
    }
    .feature-tags {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-start;
      gap: 7px;
      margin-top: 17px;
    }
    .feature-tag {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--chip-bg);
      border: 1px solid var(--chip-border);
      padding: 4px 9px;
      border-radius: 5px;
      font-size: 0.76rem;
      font-weight: 500;
      color: var(--text-muted);
    }
    .feature-tag svg {
      color: var(--primary);
    }
    
    /* Grid system */
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
      margin-bottom: 22px;
    }
    @media (min-width: 840px) {
      .grid-2 { grid-template-columns: minmax(0, 1.15fr) minmax(360px, 0.85fr); }
    }
    @media (min-width: 1024px) {
      .grid-3 { grid-template-columns: repeat(3, 1fr); }
      .grid-4 { grid-template-columns: repeat(4, 1fr); }
    }
    
    /* Modern Card */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08);
      transition: border-color 0.2s;
    }
    .card:hover {
      border-color: var(--card-hover-border);
    }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--card-border);
    }
    .card-title {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 1rem;
      font-weight: 600;
      letter-spacing: 0;
    }
    .card-title-icon {
      width: 20px;
      height: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary);
    }
    .card-title-icon svg {
      width: 18px;
      height: 18px;
    }
    
    /* Inputs & Form Elements */
    .input-group {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    @media (min-width: 540px) {
      .input-group { flex-wrap: nowrap; }
    }
    input[type="text"] {
      flex: 1;
      min-width: 180px;
      min-height: 40px;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="text"]:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px var(--primary-glow);
    }
    select {
      min-height: 40px;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      cursor: pointer;
      transition: border-color 0.2s;
    }
    select:focus {
      border-color: var(--primary);
    }
    button.btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      min-height: 40px;
      padding: 8px 16px;
      background: var(--primary);
      color: #101418;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.9rem;
      cursor: pointer;
      transition: background-color 0.15s;
      white-space: nowrap;
    }
    html.dark button.btn {
      color: #101418;
    }
    html:not(.dark) button.btn {
      color: #ffffff;
    }
    button.btn:hover {
      background: var(--primary-hover);
    }
    button.btn-secondary {
      background: var(--chip-bg);
      color: var(--text);
      border: 1px solid var(--card-border);
    }
    button.btn-secondary:hover {
      background: var(--primary-glow);
      color: var(--primary);
      border-color: var(--primary);
    }
    button:focus-visible, a:focus-visible, input:focus-visible, select:focus-visible {
      outline: 2px solid var(--primary);
      outline-offset: 2px;
    }
    
    /* Quick Domain Chips */
    .chips-group {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      margin-bottom: 16px;
    }
    .chips-label {
      font-size: 0.78rem;
      color: var(--text-faint);
      margin-right: 4px;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: var(--chip-bg);
      border: 1px solid var(--chip-border);
      padding: 4px 10px;
      border-radius: 5px;
      font-size: 0.8rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.18s;
      user-select: none;
    }
    .chip:hover {
      color: var(--primary);
      border-color: var(--primary);
      background: var(--primary-glow);
    }
    
    /* Code & Output Blocks */
    .code-block {
      position: relative;
      background: var(--code-bg);
      border-radius: 6px;
      padding: 12px 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      border: 1px solid var(--card-border);
      overflow-x: auto;
      margin-bottom: 12px;
    }
    .code-block code {
      color: var(--text);
      word-break: break-all;
    }
    .copy-btn {
      position: absolute;
      top: 8px;
      right: 8px;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: var(--text-muted);
      border-radius: 5px;
      padding: 4px 9px;
      font-size: 0.75rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.18s;
    }
    html:not(.dark) .copy-btn {
      background: rgba(0, 0, 0, 0.05);
      border-color: rgba(0, 0, 0, 0.1);
      color: var(--text-muted);
    }
    .copy-btn:hover {
      background: var(--primary);
      color: #101418;
      border-color: var(--primary);
    }
    html:not(.dark) .copy-btn:hover {
      color: #ffffff;
    }
    
    /* Result Playground Box */
    .playground-result {
      background: var(--code-bg);
      border-radius: 6px;
      padding: 16px;
      border: 1px solid var(--card-border);
      min-height: 120px;
    }
    .meta-badges {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 14px;
      padding-bottom: 12px;
      border-bottom: 1px dashed var(--card-border);
    }
    .meta-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 9px;
      border-radius: 5px;
      font-size: 0.78rem;
      font-weight: 600;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
    }
    .meta-badge.success {
      background: rgba(16, 185, 129, 0.12);
      color: var(--accent-emerald);
      border-color: rgba(16, 185, 129, 0.25);
    }
    .meta-badge.warn {
      background: rgba(245, 158, 11, 0.12);
      color: var(--accent-amber);
      border-color: rgba(245, 158, 11, 0.25);
    }
    .meta-badge.error {
      background: rgba(239, 68, 68, 0.12);
      color: var(--accent-rose);
      border-color: rgba(239, 68, 68, 0.25);
    }
    .meta-badge.info {
      background: var(--primary-glow);
      color: var(--primary);
      border-color: rgba(112, 199, 189, 0.25);
    }
    
    /* Record Table */
    .record-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin-top: 8px;
      table-layout: fixed;
    }
    .record-table th {
      text-align: left;
      padding: 8px;
      color: var(--text-faint);
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .record-table td {
      padding: 8px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      word-break: break-all;
    }
    html:not(.dark) .record-table td {
      border-bottom-color: rgba(0, 0, 0, 0.04);
    }
    .record-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }
    .record-type-pill {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      background: var(--primary-glow);
      color: var(--primary);
    }
    
    /* View Switcher */
    .view-switcher {
      display: inline-flex;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 2px;
      gap: 2px;
      margin-left: auto;
    }
    html:not(.dark) .view-switcher {
      background: rgba(0, 0, 0, 0.04);
    }
    .view-btn {
      min-height: 30px;
      padding: 4px 10px;
      font-size: 0.75rem;
      border-radius: 4px;
      border: none;
      background: transparent;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 500;
      transition: all 0.15s;
    }
    .view-btn.active {
      background: var(--primary);
      color: #101418;
      font-weight: 600;
    }
    html:not(.dark) .view-btn.active {
      color: #ffffff;
    }
    
    /* Racing Telemetry Cards */
    .metric-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      font-size: 0.9rem;
      font-weight: 600;
    }
    .progress-bar-container {
      display: flex;
      height: 8px;
      border-radius: 9999px;
      overflow: hidden;
      background: rgba(255, 255, 255, 0.08);
      margin-bottom: 10px;
    }
    html:not(.dark) .progress-bar-container {
      background: rgba(0, 0, 0, 0.08);
    }
    .progress-bar-fill {
      height: 100%;
      transition: width 0.45s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .latency-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-top: 12px;
      padding-top: 10px;
      border-top: 1px dashed var(--card-border);
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
    .latency-grid b {
      display: block;
      color: var(--text);
      font-size: 0.92rem;
      margin-top: 2px;
    }
    
    /* Tabs for Client Configuration */
    .tabs-header {
      display: flex;
      gap: 3px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 16px;
      overflow-x: auto;
      padding-bottom: 8px;
      scrollbar-width: thin;
    }
    .tab-btn {
      padding: 6px 10px;
      border-radius: 5px;
      font-size: 0.86rem;
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 500;
      white-space: nowrap;
      transition: all 0.18s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .tab-btn:hover {
      color: var(--text);
      background: var(--chip-bg);
    }
    .tab-btn.active {
      background: var(--primary-glow);
      color: var(--primary);
      border-color: transparent;
      box-shadow: inset 0 -2px var(--primary);
      font-weight: 600;
    }
    
    /* Feature Matrix List */
    .feature-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 7px;
      padding: 16px;
      display: flex;
      gap: 12px;
      align-items: flex-start;
      transition: border-color 0.2s;
    }
    .feature-card:hover {
      border-color: var(--card-hover-border);
    }
    .feature-icon-wrapper {
      width: 34px;
      height: 34px;
      border-radius: 7px;
      background: var(--primary-glow);
      color: var(--primary);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    
    /* Footer */
    footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 0.88rem;
      padding: 24px 20px;
      border-top: 1px solid var(--card-border);
      background: transparent;
    }
    .footer-links {
      display: flex;
      justify-content: center;
      gap: 18px;
      margin-bottom: 10px;
      flex-wrap: wrap;
    }
    
    /* Notification Toast */
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--primary);
      color: #101418;
      padding: 10px 18px;
      border-radius: 6px;
      font-size: 0.88rem;
      font-weight: 600;
      box-shadow: 0 10px 25px rgba(0,0,0,0.3);
      display: flex;
      align-items: center;
      gap: 8px;
      z-index: 100;
      opacity: 0;
      transform: translateY(12px);
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      pointer-events: none;
    }
    html:not(.dark) .toast {
      color: #ffffff;
    }
    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }

    /* Status indicator label targeting */
    .status-indicator-label {
      display: inline-block;
    }

    /* Mobile Responsive Breakpoints */
    @media (max-width: 700px) {
      .nav-bar { padding: 9px 14px; }
      .nav-actions { gap: 6px; }
      #globalGatewayStatus > div { max-width: 118px; padding: 3px 7px !important; }
      #globalGatewayStatus .status-indicator-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      theme-toggle button span { display: none; }
      theme-toggle button { padding: 5px 7px !important; }
      .container { padding: 24px 14px 42px; }
      .hero { padding-bottom: 18px; margin-bottom: 18px; }
      .hero h1 { font-size: 1.65rem; }
      .hero-desc { font-size: 0.9rem; }
      .feature-tags { gap: 6px; }
      .feature-tag { font-size: 0.71rem; }
      .card { padding: 15px; }
      .card-header { align-items: flex-start; flex-wrap: wrap; }
      .card-header > .view-switcher { margin-left: 0; }
      .card-header > div:last-child { max-width: 100%; }
      .input-group { flex-wrap: wrap; }
      .input-group input[type="text"] { flex-basis: 100%; }
      .input-group select { flex: 1; }
      .view-switcher { margin-left: 0; }
      .record-table { font-size: 0.76rem; }
      .record-table th, .record-table td { padding: 6px 4px; }
      .record-table th:nth-child(1), .record-table td:nth-child(1) { display: none; }
      .record-table th:nth-child(5), .record-table td:nth-child(5) { width: 56px; }
      .record-table .btn { white-space: normal; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        scroll-behavior: auto !important;
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>
  <!-- Top Navigation -->
  <header class="nav-bar">
    <div class="nav-inner">
      <div class="nav-brand">
        <div class="brand-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        </div>
        <span>cf-doh</span>
        <span class="version-tag">v1.2.0</span>
      </div>
      <div class="nav-actions">
        <status-indicator id="globalGatewayStatus" status="online" label="\u8FB9\u7F18\u63A2\u6D4B\u4E2D..." show-dot="true"></status-indicator>
        <theme-toggle storage-key="cf-doh-theme"></theme-toggle>
      </div>
    </div>
  </header>

  <main class="container">
    <!-- Hero Section -->
    <section class="hero">
      <div class="hero-badge">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.2 4.8L6 9l4.8 1.2L12 15l1.2-4.8L18 9l-4.8-1.2L12 3Z"/></svg>
        <span>Cloudflare Workers \u2022 RFC 8484 / RFC 7858 \u2022 \u53CC\u6808\u89E3\u6790</span>
      </div>
      <h1>cf-doh \u89E3\u6790\u7F51\u5173</h1>
      <p class="hero-desc">
        \u4E13\u4E3A\u56FD\u5185\u7F51\u7EDC\u73AF\u5883\u6DF1\u5EA6\u4F18\u5316\u7684\u81EA\u7814\u9AD8\u6027\u80FD DoH / DoT \u89E3\u6790\u670D\u52A1\u3002\u5185\u7F6E\u56FD\u5185\u5916\u667A\u80FD\u5206\u6D41\u3001\u771F\u5B9E\u53EF\u4FE1\u51FA\u53E3 ECS \u6CE8\u5165\u3001\u4E0A\u6E38\u5E76\u53D1\u5168\u901F\u7ADE\u4EF7\u4E0E Android \u79C1\u4EBA DNS \u539F\u751F\u652F\u6301\u3002
      </p>
      <div class="feature-tags">
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          <span>\u5E76\u53D1\u5168\u901F\u7ADE\u4EF7 (Zero Penalty)</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/></svg>
          <span>\u53EF\u4FE1\u771F\u5B9E ECS \u6CE8\u5165</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="8" rx="2"/><rect x="3" y="12" width="18" height="8" rx="2"/><line x1="7" y1="8" x2="7.01" y2="8"/><line x1="7" y1="16" x2="7.01" y2="16"/></svg>
          <span>\u963F\u91CC / \u817E\u8BAF \u76F4\u8FDE\u5206\u6D41</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>
          <span>Google / CF \u5168\u7403\u515C\u5E95</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
          <span>DNSSEC \u771F\u5B9E AD \u900F\u4F20</span>
        </div>
        <div class="feature-tag">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="4" width="10" height="16" rx="2"/><line x1="11" y1="17" x2="13" y2="17"/></svg>
          <span>Android \u79C1\u4EBA DNS (DoT 853)</span>
        </div>
      </div>
    </section>

    <!-- Two-column Main Section: Playground & Endpoints -->
    <div class="grid grid-2">
      <!-- \u5728\u7EBF\u89E3\u6790\u6D4B\u8BD5\u53F0 -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <span class="card-title-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><polygon points="12 6 12 12 16 14"/></svg>
            </span>
            <span>\u5728\u7EBF\u89E3\u6790\u6D4B\u8BD5\u53F0 (Live Playground)</span>
          </div>
          <div class="view-switcher">
            <button id="viewFormattedBtn" class="view-btn active" onclick="switchResultView('formatted')">\u7ED3\u6784\u5316\u5361\u7247</button>
            <button id="viewRawBtn" class="view-btn" onclick="switchResultView('raw')">Raw JSON</button>
          </div>
        </div>

        <p style="font-size:0.86rem; color:var(--text-muted); margin-bottom:12px;">
          \u76F4\u63A5\u5728\u6D4F\u89C8\u5668\u5185\u5411\u7F51\u5173\u53D1\u9001\u89E3\u6790\u8BF7\u6C42\uFF0C\u5B9E\u65F6\u89C2\u6D4B\u5206\u6D41\u51B3\u7B56\u3001\u54CD\u5E94\u8BB0\u5F55\u4E0E\u5B9E\u6D4B\u94FE\u8DEF\u65F6\u5EF6\uFF1A
        </p>

        <!-- \u5FEB\u6377\u6D4B\u8BD5\u6807\u7B7E -->
        <div class="chips-group">
          <span class="chips-label">\u9884\u8BBE:</span>
          <span class="chip" onclick="setQuery('linux.do', 'A')">linux.do (\u56FD\u5185\u7EC4)</span>
          <span class="chip" onclick="setQuery('github.com', 'A')">github.com (\u56FD\u5185\u76F4\u8FDE)</span>
          <span class="chip" onclick="setQuery('bilibili.com', 'A')">bilibili.com (CDN\u8282\u70B9)</span>
          <span class="chip" onclick="setQuery('google.com', 'A')">google.com (\u5168\u7403\u7EC4)</span>
          <span class="chip" onclick="setQuery('cloudflare.com', 'A')">cloudflare.com (DNSSEC)</span>
          <span class="chip" onclick="setQuery('apple.com', 'HTTPS')">apple.com (HTTPS)</span>
        </div>

        <!-- \u67E5\u8BE2\u8F93\u5165\u533A -->
        <div class="input-group">
          <input type="text" id="domainInput" placeholder="\u8F93\u5165\u5F85\u89E3\u6790\u57DF\u540D (\u5982 linux.do)" value="linux.do" onkeydown="if(event.key==='Enter') runQuery();">
          <select id="typeSelect">
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
            <option value="CNAME">CNAME</option>
            <option value="TXT">TXT</option>
            <option value="HTTPS">HTTPS (Type 65)</option>
            <option value="MX">MX</option>
            <option value="NS">NS</option>
            <option value="SOA">SOA</option>
          </select>
          <button class="btn" id="queryBtn" onclick="runQuery()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="7"/><line x1="21" y1="21" x2="15" y2="15"/></svg>
            <span>\u67E5\u8BE2</span>
          </button>
        </div>

        <!-- \u7ED3\u679C\u5C55\u793A\u9762\u677F -->
        <div class="playground-result" id="playgroundResult">
          <div style="color:var(--text-faint); font-size:0.85rem; padding: 20px 0; text-align: center;">
            \u70B9\u51FB\u4E0A\u65B9\u300C\u67E5\u8BE2\u300D\u6216\u5FEB\u6377\u57DF\u540D\u6807\u7B7E\uFF0C\u5F00\u59CB\u5B9E\u65F6\u6D4B\u8BD5...
          </div>
        </div>
      </div>

      <!-- \u6838\u5FC3\u7AEF\u70B9\u670D\u52A1\u77E9\u9635 -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">
            <span class="card-title-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>
            </span>
            <span>\u670D\u52A1\u63A5\u5165\u7AEF\u70B9\u77E9\u9635</span>
          </div>
          <span style="font-size:0.78rem; color:var(--text-muted);">\u751F\u4EA7\u5C31\u7EEA</span>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>RFC 8484 \u6807\u51C6 DoH URL</span>
            <span style="color:var(--primary); font-weight:600;">HTTPS 443</span>
          </div>
          <div class="code-block">
            <code>${origin}${config.path}</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.path}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>
              <span>\u590D\u5236</span>
            </button>
          </div>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>RFC 7858 DoT (Android \u79C1\u4EBA DNS)</span>
            <span style="color:var(--accent-emerald); font-weight:600;">TLS 853</span>
          </div>
          <div class="code-block">
            <code>2fa.mangoqwq.com</code>
            <button class="copy-btn" onclick="copyText('2fa.mangoqwq.com')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>
              <span>\u590D\u5236\u4E3B\u673A\u540D</span>
            </button>
          </div>
        </div>

        <div style="margin-bottom: 14px;">
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>Google \u98CE\u683C DoH JSON API</span>
            <span style="color:var(--text-faint);">RFC 8427 \u517C\u5BB9</span>
          </div>
          <div class="code-block">
            <code>${origin}${config.jsonPath}?name=linux.do&type=A</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.jsonPath}?name=linux.do&type=A')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>
              <span>\u590D\u5236</span>
            </button>
          </div>
        </div>

        <div>
          <div style="display:flex; justify-content:space-between; font-size: 0.82rem; color: var(--text-muted); margin-bottom: 5px;">
            <span>\u76D1\u63A7\u4E0E\u5EA6\u91CF\u7AEF\u70B9</span>
            <span style="color:var(--text-faint);">Prometheus / JSON</span>
          </div>
          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
            <div class="code-block" style="margin-bottom:0;">
              <code>/healthz</code>
              <button class="copy-btn" onclick="copyText('${origin}/healthz')">\u590D\u5236</button>
            </div>
            <div class="code-block" style="margin-bottom:0;">
              <code>/api/stats</code>
              <button class="copy-btn" onclick="copyText('${origin}/api/stats')">\u590D\u5236</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- \u4E0A\u6E38\u5E76\u53D1\u7ADE\u901F\u4E0E\u5EF6\u8FDF\u76D1\u63A7\u5927\u5C4F -->
    <section class="card" style="margin-bottom: 32px;">
      <div class="card-header">
        <div class="card-title">
          <span class="card-title-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </span>
          <span>\u4E0A\u6E38\u5E76\u53D1\u7ADE\u901F\u4E0E\u5EF6\u8FDF\u76D1\u63A7 (Racing & P95 Telemetry)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
          <div class="view-switcher" style="margin-left:0;">
            <button id="scopeLocalBtn" class="view-btn active" onclick="setStatsScope('local')">
              <span>\u672C\u5730 PoP \u8FB9\u7F18</span>
            </button>
            <button id="scopeGlobalBtn" class="view-btn" onclick="setStatsScope('global')">
              <span>\u5168\u7403\u591A\u5730\u57DF\u805A\u5408</span>
            </button>
          </div>
          <label style="display:inline-flex; align-items:center; gap:6px; font-size:0.8rem; color:var(--text-muted); cursor:pointer;">
            <input type="checkbox" id="autoRefreshCheckbox" onchange="toggleAutoRefresh(this.checked)" checked>
            <span>\u81EA\u52A8\u5237\u65B0 (10s)</span>
          </label>
          <button class="btn btn-secondary" style="padding: 5px 12px; font-size: 0.8rem;" id="refreshStatsBtn" onclick="loadStats()">
            <svg id="refreshIcon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 0 0-14.5-4L3 10m0-5v5h5M4 13a8 8 0 0 0 14.5 4L21 14m0 5v-5h-5"/></svg>
            <span>\u5237\u65B0\u6307\u6807</span>
          </button>
        </div>
      </div>

      <div id="scopeNotice" style="font-size:0.82rem; color:var(--text-muted); margin-bottom:16px; padding:8px 14px; background:rgba(255,255,255,0.03); border-radius:8px; border-left:3px solid var(--primary);">
        \u7EDF\u8BA1\u8303\u56F4\uFF1A\u5F53\u524D Cloudflare \u8FB9\u7F18\u8282\u70B9\u5185\u5B58\u5B9E\u65F6\u91C7\u6837 (\u5355\u5B9E\u4F8B)
      </div>

      <div class="grid grid-2" style="margin-bottom: 20px;">
        <!-- \u56FD\u5185\u7EC4\u7ADE\u901F\u770B\u677F -->
        <div style="background:var(--code-bg); padding:18px; border-radius:12px; border:1px solid var(--card-border);">
          <div class="metric-row">
            <span style="display:flex; align-items:center; gap:6px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="8" rx="2"/><rect x="3" y="12" width="18" height="8" rx="2"/><line x1="7" y1="8" x2="7.01" y2="8"/><line x1="7" y1="16" x2="7.01" y2="16"/></svg>
              <span>\u56FD\u5185\u7EC4\u7ADE\u901F (AliDNS vs DNSPod)</span>
            </span>
            <span id="domesticTotalWins" style="color:var(--text-muted); font-size:0.82rem; font-weight:normal;">0 \u6B21\u80DC\u51FA</span>
          </div>
          <div class="progress-bar-container">
            <div id="barAlidns" class="progress-bar-fill" style="width:50%; background:#3b82f6;"></div>
            <div id="barDohpub" class="progress-bar-fill" style="width:50%; background:#10b981;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.82rem; color:var(--text-muted);">
            <span><span style="color:#3b82f6;">\u25CF</span> \u963F\u91CC DNS: <b id="winAlidns" style="color:var(--text);">0 (0.0%)</b></span>
            <span><span style="color:#10b981;">\u25CF</span> \u817E\u8BAF DNSPod: <b id="winDohpub" style="color:var(--text);">0 (0.0%)</b></span>
          </div>
          <div class="latency-grid">
            <div>P50 \u65F6\u5EF6<b id="p50Domestic">- ms</b></div>
            <div>P95 \u65F6\u5EF6<b id="p95Domestic" style="color:#f59e0b;">- ms</b></div>
            <div>\u5E73\u5747\u65F6\u5EF6<b id="avgDomestic">- ms</b></div>
          </div>
        </div>

        <!-- \u5168\u7403\u7EC4\u7ADE\u901F\u770B\u677F -->
        <div style="background:var(--code-bg); padding:18px; border-radius:12px; border:1px solid var(--card-border);">
          <div class="metric-row">
            <span style="display:flex; align-items:center; gap:6px;">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>
              <span>\u5168\u7403\u7EC4\u7ADE\u901F (Google vs Cloudflare)</span>
            </span>
            <span id="globalTotalWins" style="color:var(--text-muted); font-size:0.82rem; font-weight:normal;">0 \u6B21\u80DC\u51FA</span>
          </div>
          <div class="progress-bar-container">
            <div id="barGoogle" class="progress-bar-fill" style="width:50%; background:#8b5cf6;"></div>
            <div id="barCf" class="progress-bar-fill" style="width:50%; background:#f97316;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.82rem; color:var(--text-muted);">
            <span><span style="color:#8b5cf6;">\u25CF</span> Google DNS: <b id="winGoogle" style="color:var(--text);">0 (0.0%)</b></span>
            <span><span style="color:#f97316;">\u25CF</span> Cloudflare: <b id="winCf" style="color:var(--text);">0 (0.0%)</b></span>
          </div>
          <div class="latency-grid">
            <div>P50 \u65F6\u5EF6<b id="p50Global">- ms</b></div>
            <div>P95 \u65F6\u5EF6<b id="p95Global" style="color:#f59e0b;">- ms</b></div>
            <div>\u5E73\u5747\u65F6\u5EF6<b id="avgGlobal">- ms</b></div>
          </div>
        </div>
      </div>

      <!-- \u6982\u89C8\u6307\u6807\u884C -->
      <div style="display:flex; flex-wrap:wrap; gap:20px; font-size:0.85rem; color:var(--text-muted); padding-top:4px;">
        <span style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v3m0 12v3M3 12h3m12 0h3"/></svg>
          <span>\u8FB9\u7F18 LRU \u7F13\u5B58\u547D\u4E2D\u7387:</span> <b id="cacheHitRate" style="color:var(--accent-emerald);">0.0%</b>
        </span>
        <span style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          <span>\u7D2F\u8BA1\u89E3\u6790\u670D\u52A1\u6570:</span> <b id="totalRequests" style="color:var(--text);">0</b>
        </span>
        <span id="uptimeWrap" style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>\u5B9E\u4F8B\u8FD0\u884C\u65F6\u95F4:</span> <b id="nodeUptime" style="color:var(--text);">0s</b>
        </span>
        <span style="display:inline-flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/></svg>
          <span>Analytics Engine:</span> <b id="analyticsStatus" style="color:var(--primary);">\u5DF2\u63A5\u5165 (Worker \u70B9\u4F4D\u5199\u5165)</b>
        </span>
      </div>
    </section>

    <!-- \u5168\u5E73\u53F0\u5BA2\u6237\u7AEF\u63A5\u5165\u6307\u5357 -->
    <section class="card" style="margin-bottom: 32px;">
      <div class="card-header">
        <div class="card-title">
          <span class="card-title-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>
          </span>
          <span>\u5168\u5E73\u53F0\u5BA2\u6237\u7AEF\u63A5\u5165\u6307\u5357</span>
        </div>
        <span style="font-size:0.8rem; color:var(--text-muted);">\u4E00\u952E\u590D\u5236\u914D\u7F6E</span>
      </div>

      <div class="tabs-header">
        <button class="tab-btn active" onclick="switchClientTab('mihomo')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9" r="1.5"/></svg>
          <span>Clash / Mihomo</span>
        </button>
        <button class="tab-btn" onclick="switchClientTab('surge')">Surge</button>
        <button class="tab-btn" onclick="switchClientTab('singbox')">Sing-box</button>
        <button class="tab-btn" onclick="switchClientTab('shadowrocket')">Shadowrocket</button>
        <button class="tab-btn" onclick="switchClientTab('android')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="4" width="10" height="16" rx="2"/><line x1="11" y1="17" x2="13" y2="17"/></svg>
          <span>Android (\u79C1\u4EBA DNS)</span>
        </button>
        <button class="tab-btn" onclick="switchClientTab('windows')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></svg>
          <span>Windows 11 / dnscrypt</span>
        </button>
        <button class="tab-btn" onclick="switchClientTab('apple')">iOS / macOS</button>
        <button class="tab-btn" onclick="switchClientTab('linux')">Linux (resolved)</button>
        <button class="tab-btn" onclick="switchClientTab('cli')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          <span>cURL / dig \u8C03\u8BD5</span>
        </button>
      </div>

      <!-- Tab Mihomo / Clash -->
      <div id="tab-mihomo" class="client-tab-content">
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:10px;">
          \u9002\u7528\u4E8E Mihomo (Clash Verge Rev / Mihomo Party / ShellCrash)\u3002\u6CE8\u610F <code>default-nameserver</code> \u5FC5\u987B\u4E3A\u7EAF IP \u4EE5\u9632\u6B7B\u5FAA\u73AF\u3002
        </div>
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-mihomo')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-mihomo"><code>dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  nameserver:
    - "${origin}${config.path}"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  proxy-server-nameserver:
    - 223.5.5.5
  nameserver-policy:
    "doh.mangoqwq.com":
      - 223.5.5.5</code></pre>
        </div>
      </div>

      <!-- Tab Surge -->
      <div id="tab-surge" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-surge')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-surge"><code>[General]
dns-server = 223.5.5.5, 119.29.29.29
doh-server = ${origin}${config.path}
doh-format = wire</code></pre>
        </div>
      </div>

      <!-- Tab Sing-box -->
      <div id="tab-singbox" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-singbox')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-singbox"><code>{
  "dns": {
    "servers": [
      {
        "tag": "cf-doh",
        "address": "${origin}${config.path}",
        "detour": "direct"
      },
      {
        "tag": "local-bootstrap",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "domain": ["doh.mangoqwq.com"],
        "server": "local-bootstrap"
      }
    ],
    "strategy": "prefer_ipv4"
  }
}</code></pre>
        </div>
      </div>

      <!-- Tab Shadowrocket -->
      <div id="tab-shadowrocket" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-shadowrocket')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-shadowrocket"><code># 1. \u6253\u5F00 Shadowrocket -> \u8BBE\u7F6E -> DNS
# 2. \u542F\u7528\u300CDNS-over-HTTPS\u300D
# 3. \u5728 DNS \u670D\u52A1\u5668 URL \u586B\u5165\uFF1A
${origin}${config.path}</code></pre>
        </div>
      </div>

      <!-- Tab Android -->
      <div id="tab-android" class="client-tab-content" style="display:none;">
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:10px;">
          \u63A8\u8350\u65B9\u5F0F\u4E00\uFF08RFC 7858 DoT\uFF09\uFF1A\u7CFB\u7EDF\u5E95\u5C42\u5168\u5C40\u751F\u6548\u3001\u96F6\u8017\u7535\u3001\u9632\u6C61\u67D3\u3002
        </div>
        <div class="code-block">
          <button class="copy-btn" onclick="copyText('2fa.mangoqwq.com')">\u590D\u5236\u4E3B\u673A\u540D</button>
          <pre><code># \u65B9\u5F0F\u4E00\uFF1A\u7CFB\u7EDF\u7EA7\u79C1\u4EBA DNS (Android 9+ / \u63A8\u8350)
\u8BBE\u7F6E -> \u8FDE\u63A5\u4E0E\u5171\u4EAB / \u7F51\u7EDC\u548C\u4E92\u8054\u7F51 -> \u79C1\u4EBA DNS (Private DNS) -> \u9009\u62E9\u300C\u6307\u5B9A\u4E3B\u673A\u540D\u300D\uFF1A
2fa.mangoqwq.com

# \u65B9\u5F0F\u4E8C\uFF1AChrome / Edge \u7B49\u6D4F\u89C8\u5668\u7AEF\u5B89\u5168 DNS (DoH)
\u8BBE\u7F6E -> \u9690\u79C1\u548C\u5B89\u5168\u6027 -> \u4F7F\u7528\u5B89\u5168 DNS -> \u9009\u62E9\u63D0\u4F9B\u5546 -> \u81EA\u5B9A\u4E49\uFF1A
${origin}${config.path}</code></pre>
        </div>
      </div>

      <!-- Tab Windows -->
      <div id="tab-windows" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-win')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-win"><code># \u65B9\u6848 A\uFF1AWindows 11 \u539F\u751F\u5B89\u5168 DNS (\u52A0\u5BC6\u901A\u8FC7 HTTPS)
# \u8BBE\u7F6E -> \u7F51\u7EDC\u548C Internet -> \u5C5E\u6027 -> DNS \u670D\u52A1\u5668\u5206\u914D (\u624B\u52A8) -> \u542F\u7528\u300C\u4EC5\u52A0\u5BC6\u300D
DoH \u6A21\u677F URL:
${origin}${config.path}

# \u65B9\u6848 B\uFF1Adnscrypt-proxy (\u81EA\u5EFA\u65E0\u7F1D\u5B88\u62A4)
# Stamp (sdns):
sdns://AgEAAAAAAAAAAAAQZG9oLm1hbmdvcXdxLmNvbQQvZG9o</code></pre>
        </div>
      </div>

      <!-- Tab Apple -->
      <div id="tab-apple" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-apple')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-apple"><code># iOS 14+ / macOS 11+ \u539F\u751F\u652F\u6301 DoH \u63CF\u8FF0\u6587\u4EF6 (.mobileconfig)
# \u5BF9\u5E94 DoH \u670D\u52A1\u5668\u5730\u5740:
${origin}${config.path}

# \u4EA6\u53EF\u5728 Safari / \u6D4F\u89C8\u5668\u4E2D\u4F5C\u4E3A\u5B89\u5168 DNS \u63D0\u4F9B\u5546\u914D\u7F6E\u3002</code></pre>
        </div>
      </div>

      <!-- Tab Linux -->
      <div id="tab-linux" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-linux')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-linux"><code># Linux \u751F\u4EA7\u63A5\u5165\u6700\u4F73\u5B9E\u8DF5 (dnscrypt-proxy \u672C\u5730\u73AF\u56DE + systemd-resolved)
# /etc/systemd/resolved.conf.d/doh.conf:
[Resolve]
DNS=127.0.0.1:5053
Domains=~.

# dnscrypt-proxy \u76D1\u542C 127.0.0.1:5053 \u5E76\u4F7F\u7528 Stamp\uFF1A
sdns://AgEAAAAAAAAAAAAQZG9oLm1hbmdvcXdxLmNvbQQvZG9o</code></pre>
        </div>
      </div>

      <!-- Tab CLI -->
      <div id="tab-cli" class="client-tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-cli')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-cli"><code># 1. \u670D\u52A1\u5065\u5EB7\u63A2\u6D4B\u4E0E\u5F53\u524D\u7248\u672C
curl -s "${origin}/healthz"

# 2. \u901A\u8FC7 JSON API \u5FEB\u901F\u89E3\u6790 A \u8BB0\u5F55
curl -s "${origin}${config.jsonPath}?name=linux.do&type=A"

# 3. kdig (knot-dnsutils) \u6807\u51C6 RFC 8484 \u67E5\u8BE2
kdig -d @${new URL(origin).hostname} +https=${config.path} linux.do A

# 4. doggo \u547D\u4EE4\u884C\u5DE5\u5177\u6D4B\u8BD5
doggo linux.do @${origin}${config.path} --doh</code></pre>
        </div>
      </div>
    </section>

    <!-- \u67B6\u6784\u4E0E\u6838\u5FC3\u4F18\u52BF\u7F51\u683C -->
    <section class="card">
      <div class="card-header">
        <div class="card-title">
          <span class="card-title-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/></svg>
          </span>
          <span>\u6838\u5FC3\u67B6\u6784\u4E0E\u6280\u672F\u4FDD\u969C</span>
        </div>
        <span style="font-size:0.8rem; color:var(--text-muted);">\u4E3A\u4EC0\u4E48\u9009\u62E9 cf-doh\uFF1F</span>
      </div>

      <div class="grid grid-2" style="margin-bottom:0;">
        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">\u5168\u5E76\u53D1\u7ADE\u4EF7 (Zero Wait Racing)</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u56FD\u5185\u7EC4\u4E0E\u5168\u7403\u7EC4\u540C\u7EC4\u6240\u6709\u4E0A\u6E38\u5E76\u53D1 fan-out \u53D1\u8D77\u67E5\u8BE2\uFF0C\u54CD\u5E94\u65F6\u95F4\u53D6\u6700\u5FEB\u4E0A\u6E38\u9996\u5305\uFF0C\u6162\u4E0A\u6E38\u81EA\u52A8 Abort\uFF0C\u5F7B\u5E95\u544A\u522B\u5355\u70B9\u8D85\u65F6\u5361\u987F\u3002
            </p>
          </div>
        </div>

        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">\u53EF\u4FE1\u771F\u5B9E ECS \u6CE8\u5165</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u4E25\u683C\u57FA\u4E8E Cloudflare \u8FB9\u7F18\u53EF\u4FE1\u62A5\u5934\u6CE8\u5165 IPv4 /24 \u4E0E IPv6 /56 \u5BA2\u6237\u7AEF\u5B50\u7F51\uFF0C\u675C\u7EDD\u4F2A\u9020 XFF \u6B3A\u9A97\uFF0C\u5F15\u5BFC\u6743\u5A01 CDN \u7CBE\u51C6\u5C31\u8FD1\u8C03\u5EA6\u3002
            </p>
          </div>
        </div>

        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9" r="1.5"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">\u9632\u6C61\u67D3\u786C\u9694\u79BB\u4E0E\u89C4\u5219\u81EA\u6108</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u5185\u7F6E linux.do \u4E0E github.com \u76F4\u8FDE\u786C\u7F16\u7801\u4FDD\u62A4\u3002\u5916\u90E8\u89C4\u5219\u96C6\u89E3\u6790\u5F02\u5E38\u6216\u7F51\u7EDC\u4E2D\u65AD\u65F6\u81EA\u52A8\u51B7\u5374\u964D\u7EA7\uFF0C\u786E\u4FDD\u6838\u5FC3\u57FA\u7840\u670D\u52A1\u6C38\u4E0D\u6389\u7EBF\u3002
            </p>
          </div>
        </div>

        <div class="feature-card">
          <div class="feature-icon-wrapper">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m14 5h5v5M19 5l-8 8M19 14v3a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h3"/></svg>
          </div>
          <div>
            <strong style="font-size:0.96rem; display:block; margin-bottom:4px;">\u96F6\u5916\u90E8\u4F9D\u8D56 & \u6BEB\u79D2\u7EA7\u51B7\u542F</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u7EAF\u539F\u751F JavaScript ESM \u5B9E\u73B0\uFF0C\u96F6\u91CD\u91CF\u7EA7\u6846\u67B6\u4FB5\u5165\uFF0C\u65E0\u8BBA\u662F\u514D\u8D39\u7248\u8FD8\u662F\u4F01\u4E1A\u7248 Cloudflare Workers\uFF0C\u5355\u6587\u4EF6 bundle \u5747\u53EF\u79D2\u7EA7\u542F\u52A8\u3002
            </p>
          </div>
        </div>
      </div>
    </section>
  </main>

  <!-- Footer -->
  <footer>
    <div class="footer-links">
      <a href="https://github.com/dengyie/cf-doh" target="_blank" rel="noopener">
        <span>GitHub \u6E90\u7801\u4ED3\u5E93</span>
      </a>
      <span>\u2022</span>
      <a href="${origin}/healthz" target="_blank" rel="noopener">\u670D\u52A1\u5065\u5EB7\u63A2\u9488 (/healthz)</a>
      <span>\u2022</span>
      <a href="${origin}/api/stats" target="_blank" rel="noopener">\u5B9E\u65F6\u5EA6\u91CF API (/api/stats)</a>
    </div>
    <p style="font-size:0.82rem; color:var(--text-faint);">
      cf-doh \u2022 \u57FA\u4E8E MIT License \u5F00\u6E90 \u2022 Powered by Cloudflare Workers & Serverless Edge Computing
    </p>
  </footer>

  <!-- Toast Element -->
  <div id="toast" class="toast">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 4 4L19 6"/></svg>
    <span id="toastMsg">\u5DF2\u590D\u5236</span>
  </div>

  <!-- Client-side Logic & Web Components -->
  <script>
    // ---- Web Component: <theme-toggle> --------------------------------------
    class ThemeToggle extends HTMLElement {
      connectedCallback() {
        this.storageKey = this.getAttribute('storage-key') || 'cf-doh-theme';
        this.mode = localStorage.getItem(this.storageKey) || 'auto';
        this.render();
        this.applyTheme(this.mode, false);
        this.bindEvents();
      }
      resolveTheme(m) {
        if (m === 'light' || m === 'dark') return m;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      }
      applyTheme(nextMode, notify = true) {
        this.mode = nextMode;
        var resolved = this.resolveTheme(nextMode);
        document.documentElement.dataset.theme = nextMode;
        document.documentElement.dataset.resolvedTheme = resolved;
        if (resolved === 'dark') {
          document.documentElement.classList.add('dark');
        } else {
          document.documentElement.classList.remove('dark');
        }
        localStorage.setItem(this.storageKey, nextMode);
        this.updateActiveButtons();
      }
      updateActiveButtons() {
        var btns = this.querySelectorAll('[data-mode]');
        for (var i = 0; i < btns.length; i++) {
          var btn = btns[i];
          if (btn.dataset.mode === this.mode) {
            btn.style.background = 'var(--card-bg)';
            btn.style.color = 'var(--primary)';
            btn.style.fontWeight = '600';
            btn.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
          } else {
            btn.style.background = 'transparent';
            btn.style.color = 'var(--text-muted)';
            btn.style.fontWeight = 'normal';
            btn.style.boxShadow = 'none';
          }
        }
      }
      render() {
        this.innerHTML =
          '<div style="display:inline-flex; align-items:center; padding:2px; border-radius:10px; background:var(--code-bg); border:1px solid var(--card-border); font-size:0.78rem;">' +
            '<button type="button" data-mode="auto" title="\u8DDF\u968F\u7CFB\u7EDF" aria-label="\u8DDF\u968F\u7CFB\u7EDF" style="display:inline-flex; align-items:center; gap:4px; padding:4px 8px; border-radius:7px; border:none; cursor:pointer; transition:all 0.15s;">' +
              '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/></svg>' +
              '<span>Auto</span>' +
            '</button>' +
            '<button type="button" data-mode="light" title="\u4EAE\u8272\u6A21\u5F0F" aria-label="\u4EAE\u8272\u6A21\u5F0F" style="display:inline-flex; align-items:center; gap:4px; padding:4px 8px; border-radius:7px; border:none; cursor:pointer; transition:all 0.15s;">' +
              '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2"/></svg>' +
              '<span>Light</span>' +
            '</button>' +
            '<button type="button" data-mode="dark" title="\u6697\u8272\u6A21\u5F0F" aria-label="\u6697\u8272\u6A21\u5F0F" style="display:inline-flex; align-items:center; gap:4px; padding:4px 8px; border-radius:7px; border:none; cursor:pointer; transition:all 0.15s;">' +
              '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 15.5A8 8 0 0 1 8.5 4 8 8 0 0 0 20 15.5Z"/></svg>' +
              '<span>Dark</span>' +
            '</button>' +
          '</div>';
      }
      bindEvents() {
        var self = this;
        this.addEventListener('click', function(e) {
          var btn = e.target.closest('[data-mode]');
          if (btn) {
            self.applyTheme(btn.dataset.mode);
          }
        });
      }
    }
    if (!customElements.get('theme-toggle')) {
      customElements.define('theme-toggle', ThemeToggle);
    }

    // ---- Web Component: <status-indicator> -----------------------------------
    class StatusIndicator extends HTMLElement {
      static get observedAttributes() { return ['status', 'label', 'ping-ms', 'show-dot']; }
      connectedCallback() { this.render(); }
      attributeChangedCallback() { this.render(); }
      render() {
        var status = this.getAttribute('status') || 'online';
        var label = this.getAttribute('label') || '\u5728\u7EBF';
        var pingMs = this.getAttribute('ping-ms');
        var showDot = this.getAttribute('show-dot') !== 'false';

        var dotColor = '#10b981', bg = 'rgba(16, 185, 129, 0.12)', text = '#10b981', border = 'rgba(16, 185, 129, 0.25)';
        if (status === 'connecting' || status === 'busy') {
          dotColor = '#f59e0b'; bg = 'rgba(245, 158, 11, 0.12)'; text = '#f59e0b'; border = 'rgba(245, 158, 11, 0.25)';
        } else if (status === 'error' || status === 'offline') {
          dotColor = '#ef4444'; bg = 'rgba(239, 68, 68, 0.12)'; text = '#ef4444'; border = 'rgba(239, 68, 68, 0.25)';
        }

        var dotHtml = '';
        if (showDot) {
          var pingPulse = status === 'online' ? '<span style="position:absolute; width:100%; height:100%; border-radius:50%; background:' + dotColor + '; opacity:0.6; animation:ping 1.4s cubic-bezier(0, 0, 0.2, 1) infinite;"></span>' : '';
          dotHtml = '<span style="position:relative; display:inline-flex; width:7px; height:7px;">' +
            pingPulse +
            '<span style="position:relative; width:7px; height:7px; border-radius:50%; background:' + dotColor + ';"></span>' +
          '</span>';
        }

        var pingText = (pingMs !== null && pingMs !== undefined && pingMs !== '') ? '<span style="opacity:0.8; font-family:monospace; font-size:0.72rem;">(' + pingMs + 'ms)</span>' : '';

        this.innerHTML =
          '<div style="display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:9999px; background:' + bg + '; border:1px solid ' + border + '; color:' + text + '; font-size:0.76rem; font-weight:600;">' +
            dotHtml +
            '<span class="status-indicator-label">' + label + '</span>' +
            pingText +
          '</div>';
      }
    }
    if (!customElements.get('status-indicator')) {
      customElements.define('status-indicator', StatusIndicator);
    }

    // Ping animation keyframe
    var styleSheet = document.createElement("style");
    styleSheet.innerText = "@keyframes ping { 75%, 100% { transform: scale(2.2); opacity: 0; } }";
    document.head.appendChild(styleSheet);

    // ---- Utilities & State --------------------------------------------------
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/[&<>"']/g, function(m) {
        switch (m) {
          case '&': return '&amp;';
          case '<': return '&lt;';
          case '>': return '&gt;';
          case '"': return '&quot;';
          case "'": return '&#39;';
          default: return m;
        }
      });
    }

    function showToast(msg) {
      var toast = document.getElementById('toast');
      var toastMsg = document.getElementById('toastMsg');
      toastMsg.innerText = msg;
      toast.classList.add('show');
      setTimeout(function() { toast.classList.remove('show'); }, 2200);
    }

    function copyText(txt) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(function() {
          showToast('\u5DF2\u590D\u5236\u5230\u526A\u8D34\u677F');
        }).catch(function() {
          legacyCopy(txt);
        });
      } else {
        legacyCopy(txt);
      }
    }

    function legacyCopy(txt) {
      var input = document.createElement('textarea');
      input.value = txt;
      document.body.appendChild(input);
      input.select();
      document.execCommand('copy');
      document.body.removeChild(input);
      showToast('\u5DF2\u590D\u5236\u5230\u526A\u8D34\u677F');
    }

    function copyElement(id) {
      var el = document.getElementById(id);
      if (el) copyText(el.innerText);
    }

    // ---- Playground Query ---------------------------------------------------
    var lastQueryResult = null;
    var currentResultView = 'formatted';

    function setQuery(domain, type) {
      document.getElementById('domainInput').value = domain;
      if (type) document.getElementById('typeSelect').value = type;
      runQuery();
    }

    function switchResultView(view) {
      currentResultView = view;
      var fmtBtn = document.getElementById('viewFormattedBtn');
      var rawBtn = document.getElementById('viewRawBtn');
      if (view === 'formatted') {
        fmtBtn.classList.add('active');
        rawBtn.classList.remove('active');
      } else {
        rawBtn.classList.add('active');
        fmtBtn.classList.remove('active');
      }
      renderQueryResult();
    }

    async function runQuery() {
      var domain = document.getElementById('domainInput').value.trim();
      var type = document.getElementById('typeSelect').value;
      var box = document.getElementById('playgroundResult');
      var btn = document.getElementById('queryBtn');
      if (!domain) return;

      btn.disabled = true;
      btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>\u67E5\u8BE2\u4E2D...</span>';

      var start = performance.now();
      try {
        var resp = await fetch('${config.jsonPath}?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type));
        var data = await resp.json();
        var duration = Math.round(performance.now() - start);

        lastQueryResult = {
          domain: domain,
          type: type,
          data: data,
          duration: duration,
          status: resp.status
        };
        renderQueryResult();
        loadStats();
      } catch (err) {
        box.innerHTML = '<div style="color:var(--accent-rose); font-size:0.88rem; padding:12px;">' +
          '<strong>\u67E5\u8BE2\u5931\u8D25\uFF1A</strong> ' + escapeHtml(err.message) +
          '</div>';
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="7"/><line x1="21" y1="21" x2="15" y2="15"/></svg><span>\u67E5\u8BE2</span>';
      }
    }

    function renderQueryResult() {
      var box = document.getElementById('playgroundResult');
      if (!lastQueryResult) return;
      var q = lastQueryResult;
      var data = q.data;

      if (currentResultView === 'raw') {
        box.innerHTML = '<div style="position:relative;">' +
          '<button class="copy-btn" onclick="copyText(document.getElementById(\\'rawJsonBlock\\').innerText)">\u590D\u5236 JSON</button>' +
          '<pre id="rawJsonBlock" style="margin:0; font-family:ui-monospace, monospace; font-size:0.82rem; color:var(--text); max-height:360px; overflow-y:auto;">' +
          escapeHtml(JSON.stringify(data, null, 2)) +
          '</pre></div>';
        return;
      }

      var statusNum = Number(data.Status);
      var statusBadge = '';
      if (statusNum === 0) {
        statusBadge = '<span class="meta-badge success">\u25CF NOERROR (\u6210\u529F)</span>';
      } else if (statusNum === 3) {
        statusBadge = '<span class="meta-badge warn">\u25CF NXDOMAIN (\u57DF\u540D\u4E0D\u5B58\u5728)</span>';
      } else {
        statusBadge = '<span class="meta-badge error">\u25CF Status ' + statusNum + '</span>';
      }

      var dnssecBadge = data.AD
        ? '<span class="meta-badge info"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg> DNSSEC \u5DF2\u9A8C\u8BC1 (AD=1)</span>'
        : '<span class="meta-badge" style="color:var(--text-faint);">DNSSEC \u672A\u7B7E\u540D (AD=0)</span>';

      var isDomestic = (q.domain.endsWith('linux.do') || q.domain.endsWith('github.com') || q.domain.endsWith('.cn') || q.domain.includes('bilibili') || q.domain.includes('ali') || q.domain.includes('tencent'));
      var routeGroupBadge = isDomestic
        ? '<span class="meta-badge info">\u5206\u6D41\uFF1A\u56FD\u5185\u76F4\u8FDE\u7EC4</span>'
        : '<span class="meta-badge" style="color:var(--accent-purple); background:rgba(139,92,246,0.12); border-color:rgba(139,92,246,0.25);">\u5206\u6D41\uFF1A\u5168\u7403\u515C\u5E95\u7EC4</span>';

      var html = '<div class="meta-badges">' +
        statusBadge +
        '<span class="meta-badge">\u94FE\u8DEF\u8017\u65F6: <b style="color:var(--primary); margin-left:3px;">' + q.duration + ' ms</b></span>' +
        dnssecBadge +
        routeGroupBadge +
        '</div>';

      if (Array.isArray(data.Answer) && data.Answer.length > 0) {
        html += '<div style="font-size:0.82rem; font-weight:600; color:var(--text-muted); margin-bottom:6px;">\u5E94\u7B54\u89E3\u6790\u8BB0\u5F55 (Answers):</div>';
        html += '<table class="record-table"><thead><tr>' +
          '<th>Name</th><th>Type</th><th>TTL</th><th>Data (Resolved)</th><th></th>' +
          '</tr></thead><tbody>';
        data.Answer.forEach(function(ans, idx) {
          var safeName = escapeHtml(ans.name);
          var safeType = escapeHtml(ans.type);
          var safeData = escapeHtml(ans.data);
          var safeTtl = Number(ans.TTL) || 0;
          html += '<tr>' +
            '<td>' + safeName + '</td>' +
            '<td><span class="record-type-pill">' + safeType + '</span></td>' +
            '<td style="color:var(--text-faint);">' + safeTtl + 's</td>' +
            '<td style="font-weight:600; color:var(--text);">' + safeData + '</td>' +
            '<td style="text-align:right;"><button class="btn btn-secondary" style="padding:2px 8px; font-size:0.75rem;" onclick="copyText(\\'' + safeData.replace(/'/g, "\\\\'") + '\\')">\u590D\u5236\u503C</button></td>' +
            '</tr>';
        });
        html += '</tbody></table>';
      } else {
        html += '<div style="color:var(--text-muted); font-size:0.85rem; padding:8px 0;">\u672A\u67E5\u8BE2\u5230\u5BF9\u5E94\u5E94\u7B54\u8BB0\u5F55 (ANCOUNT=0)\u3002</div>';
      }

      if (Array.isArray(data.Authority) && data.Authority.length > 0) {
        html += '<details style="margin-top:12px; font-size:0.82rem; color:var(--text-muted);">' +
          '<summary style="cursor:pointer; font-weight:600; padding:4px 0;">\u67E5\u770B\u6743\u5A01\u8BB0\u5F55 (Authority: ' + data.Authority.length + ' \u6761)</summary>' +
          '<div style="margin-top:6px; background:rgba(0,0,0,0.15); padding:8px; border-radius:6px; font-family:ui-monospace, monospace;">';
        data.Authority.forEach(function(auth) {
          html += '<div>' + escapeHtml(auth.name) + ' ' + escapeHtml(auth.type) + ' ' + escapeHtml(auth.data) + '</div>';
        });
        html += '</div></details>';
      }

      box.innerHTML = html;
    }

    // ---- Racing Telemetry & Stats -------------------------------------------
    var currentScope = 'local';
    var autoRefreshTimer = null;

    function setStatsScope(scope) {
      currentScope = scope;
      var localBtn = document.getElementById('scopeLocalBtn');
      var globalBtn = document.getElementById('scopeGlobalBtn');
      if (scope === 'global') {
        localBtn.classList.remove('active');
        globalBtn.classList.add('active');
      } else {
        globalBtn.classList.remove('active');
        localBtn.classList.add('active');
      }
      loadStats(scope);
    }

    function toggleAutoRefresh(enable) {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      if (enable) {
        autoRefreshTimer = setInterval(function() {
          loadStats(currentScope);
        }, 10000);
      }
    }

    async function loadStats(scope = currentScope) {
      var icon = document.getElementById('refreshIcon');
      if (icon) icon.style.animation = 'spin 1s linear infinite';
      try {
        var url = scope === 'global' ? '/api/stats?scope=global' : '/api/stats';
        var resp = await fetch(url);
        if (!resp.ok) return;
        var rawData = await resp.json();
        var isGlobal = scope === 'global';
        var noticeEl = document.getElementById('scopeNotice');

        var data = rawData;
        if (isGlobal) {
          if (rawData.available) {
            noticeEl.innerHTML = '<b>\u5168\u7403\u591A\u5730\u57DF\u805A\u5408\u6570\u636E (Cloudflare Analytics Engine)</b> \xB7 \u6700\u8FD1 24 \u5C0F\u65F6\u8DE8\u6240\u6709 PoP \u8FB9\u7F18\u8282\u70B9\u603B\u8BA1';
            noticeEl.style.borderLeftColor = 'var(--accent-emerald)';
            document.getElementById('analyticsStatus').innerText = '\u5168\u5C40 SQL \u67E5\u8BE2\u5DF2\u6FC0\u6D3B';
            document.getElementById('analyticsStatus').style.color = 'var(--accent-emerald)';
            document.getElementById('uptimeWrap').style.display = 'none';
          } else {
            noticeEl.innerHTML = '<b>\u5168\u7403\u805A\u5408\u672A\u5F00\u542F\u6216\u672A\u914D\u7F6E\u8BFB\u53D6\u51ED\u636E</b>\uFF1A' + escapeHtml(rawData.message || '\u56DE\u9000\u5C55\u793A\u5F53\u524D\u672C\u5730 PoP \u6570\u636E') + '\u3002\u53EF\u81F3 Cloudflare \u63A7\u5236\u53F0\u6FC0\u6D3B Analytics Engine\u3002';
            noticeEl.style.borderLeftColor = 'var(--accent-amber)';
            document.getElementById('analyticsStatus').innerText = '\u672A\u6FC0\u6D3B\u5168\u5C40\u8BFB\u53D6 (\u5C55\u793A\u672C\u5730)';
            document.getElementById('analyticsStatus').style.color = 'var(--accent-amber)';
            document.getElementById('uptimeWrap').style.display = 'inline-flex';
            if (rawData.fallback) data = rawData.fallback;
          }
        } else {
          noticeEl.innerHTML = '\u7EDF\u8BA1\u8303\u56F4\uFF1A\u5F53\u524D Cloudflare \u8FB9\u7F18\u8282\u70B9\u5185\u5B58\u5B9E\u65F6\u91C7\u6837 (\u5355\u5B9E\u4F8B)';
          noticeEl.style.borderLeftColor = 'var(--primary)';
          document.getElementById('analyticsStatus').innerText = '\u5DF2\u63A5\u5165 (Worker \u70B9\u4F4D\u5199\u5165)';
          document.getElementById('analyticsStatus').style.color = 'var(--primary)';
          document.getElementById('uptimeWrap').style.display = 'inline-flex';
        }

        // Domestic
        var dom = (data.upstreams && data.upstreams.domestic) ? data.upstreams.domestic : { upstreams: {}, totalWins: 0 };
        var ali = dom.upstreams['dns.alidns.com'] || { wins: 0, winRate: '0.0%' };
        var pod = dom.upstreams['doh.pub'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('domesticTotalWins').innerText = dom.totalWins + ' \u6B21\u80DC\u51FA';
        document.getElementById('winAlidns').innerText = ali.wins + ' (' + ali.winRate + ')';
        document.getElementById('winDohpub').innerText = pod.wins + ' (' + pod.winRate + ')';
        var domTotal = ali.wins + pod.wins;
        var aliPct = domTotal > 0 ? (ali.wins / domTotal) * 100 : 50;
        document.getElementById('barAlidns').style.width = aliPct + '%';
        document.getElementById('barDohpub').style.width = (100 - aliPct) + '%';

        if (data.latency && data.latency.domestic) {
          document.getElementById('p50Domestic').innerText = (data.latency.domestic.p50Ms || 0) + ' ms';
          document.getElementById('p95Domestic').innerText = (data.latency.domestic.p95Ms || 0) + ' ms';
          document.getElementById('avgDomestic').innerText = (data.latency.domestic.avgMs || 0) + ' ms';
        }

        // Global
        var glob = (data.upstreams && data.upstreams.global) ? data.upstreams.global : { upstreams: {}, totalWins: 0 };
        var ggl = glob.upstreams['dns.google'] || { wins: 0, winRate: '0.0%' };
        var cf = glob.upstreams['cloudflare-dns.com'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('globalTotalWins').innerText = glob.totalWins + ' \u6B21\u80DC\u51FA';
        document.getElementById('winGoogle').innerText = ggl.wins + ' (' + ggl.winRate + ')';
        document.getElementById('winCf').innerText = cf.wins + ' (' + cf.winRate + ')';
        var globTotal = ggl.wins + cf.wins;
        var gglPct = globTotal > 0 ? (ggl.wins / globTotal) * 100 : 50;
        document.getElementById('barGoogle').style.width = gglPct + '%';
        document.getElementById('barCf').style.width = (100 - gglPct) + '%';

        if (data.latency && data.latency.global) {
          document.getElementById('p50Global').innerText = (data.latency.global.p50Ms || 0) + ' ms';
          document.getElementById('p95Global').innerText = (data.latency.global.p95Ms || 0) + ' ms';
          document.getElementById('avgGlobal').innerText = (data.latency.global.avgMs || 0) + ' ms';
        }

        if (data.cache) {
          document.getElementById('cacheHitRate').innerText = data.cache.hitRate || '0.0%';
        }
        if (typeof data.totalRequests !== 'undefined') {
          document.getElementById('totalRequests').innerText = data.totalRequests;
        }
        if (typeof data.uptimeSec !== 'undefined') {
          document.getElementById('nodeUptime').innerText = formatUptime(data.uptimeSec);
        }
      } catch (err) {
        console.warn('Failed to load stats:', err);
      } finally {
        if (icon) setTimeout(function() { icon.style.animation = ''; }, 300);
      }
    }

    function formatUptime(sec) {
      if (!sec || sec < 0) return '0s';
      if (sec < 60) return sec + 's';
      if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
      var h = Math.floor(sec / 3600);
      var m = Math.floor((sec % 3600) / 60);
      return h + 'h ' + m + 'm';
    }

    // Gateway Live Probe (/healthz)
    async function probeGateway() {
      var indicator = document.getElementById('globalGatewayStatus');
      var start = performance.now();
      try {
        var resp = await fetch('/healthz');
        var duration = Math.round(performance.now() - start);
        if (resp.ok) {
          var data = await resp.json();
          indicator.setAttribute('status', 'online');
          indicator.setAttribute('label', '\u8FB9\u7F18\u5728\u7EBF (' + (data.version || 'v1.2.0') + ')');
          indicator.setAttribute('ping-ms', duration);
        } else {
          indicator.setAttribute('status', 'error');
          indicator.setAttribute('label', '\u72B6\u6001\u5F02\u5E38');
        }
      } catch (e) {
        indicator.setAttribute('status', 'offline');
        indicator.setAttribute('label', '\u63A2\u6D4B\u79BB\u7EBF');
      }
    }

    // Client Config Tabs
    function switchClientTab(name) {
      var contents = document.querySelectorAll('.client-tab-content');
      for (var i = 0; i < contents.length; i++) contents[i].style.display = 'none';
      var btns = document.querySelectorAll('.tabs-header .tab-btn');
      for (var j = 0; j < btns.length; j++) btns[j].classList.remove('active');

      var target = document.getElementById('tab-' + name);
      if (target) target.style.display = 'block';
      if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
      }
    }

    // Init
    window.addEventListener('DOMContentLoaded', function() {
      loadStats();
      probeGateway();
      toggleAutoRefresh(true);
      setInterval(probeGateway, 30000);
    });
  <\/script>
</body>
</html>`;
}

// src/ecs.js
var ECS_OPTION_CODE = 8;
function encodeEcsRdata(family, networkBytes, prefixLength) {
  const addrLen = Math.ceil(prefixLength / 8);
  const rdata = new Uint8Array(4 + addrLen);
  rdata[0] = family >> 8 & 255;
  rdata[1] = family & 255;
  rdata[2] = prefixLength;
  rdata[3] = 0;
  rdata.set(networkBytes.subarray(0, addrLen), 4);
  return rdata;
}
function wrapEcsOption(rdata) {
  const out = new Uint8Array(2 + 2 + rdata.length);
  out[0] = ECS_OPTION_CODE >> 8 & 255;
  out[1] = ECS_OPTION_CODE & 255;
  out[2] = rdata.length >> 8 & 255;
  out[3] = rdata.length & 255;
  out.set(rdata, 4);
  return out;
}

// src/ip.js
function isIpv4GlobalUnicast(b) {
  const a = b[0];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  const second = b[1];
  if (a === 100 && second >= 64 && second <= 127) return false;
  if (a === 169 && second === 254) return false;
  if (a === 172 && second >= 16 && second <= 31) return false;
  if (a === 192 && second === 168) return false;
  if (a === 192 && second === 0 && b[2] === 0) return false;
  if (a === 192 && second === 0 && b[2] === 2) return false;
  if (a === 192 && b[1] === 88 && b[2] === 99) return false;
  if (a === 198 && (second === 18 || second === 19)) return false;
  if (a === 198 && second === 51 && b[2] === 100) return false;
  if (a === 203 && second === 0 && b[2] === 113) return false;
  return true;
}
function isV6GlobalUnicast(b) {
  if ((b[0] & 224) !== 32) return false;
  if (b[0] === 32 && b[1] === 1 && b[2] === 13 && b[3] === 184) return false;
  return true;
}
function parseIpString(value) {
  const s = String(value || "").trim();
  if (s.includes(":")) {
    return parseIpv6(s);
  }
  return parseIpv4(s);
}
function parseIpv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    const p = parts[i];
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    bytes[i] = n;
  }
  return { family: 1, bytes };
}
function parseIpv6(s) {
  if (s.length === 0 || s.includes("%")) return null;
  let address = s;
  const lastColon = address.lastIndexOf(":");
  const lastPart = lastColon >= 0 ? address.slice(lastColon + 1) : address;
  let ipv4Tail = null;
  let hasIpv4Tail = false;
  if (lastPart.includes(".")) {
    const v4 = parseIpv4(lastPart);
    if (v4 === null) return null;
    ipv4Tail = v4.bytes;
    hasIpv4Tail = true;
    address = `${address.slice(0, lastColon)}:v4`;
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const leftParts = halves[0] === "" ? [] : halves[0].split(":");
  const rightParts = halves.length === 1 || halves[1] === "" ? [] : halves[1].split(":");
  const parseParts = (arr) => {
    const out = [];
    for (const part of arr) {
      if (part === "v4") {
        if (!hasIpv4Tail) return null;
        out.push(ipv4Tail[0] << 8 | ipv4Tail[1], ipv4Tail[2] << 8 | ipv4Tail[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
        out.push(parseInt(part, 16));
      }
    }
    return out;
  };
  const left = parseParts(leftParts);
  const right = parseParts(rightParts);
  if (left === null || right === null) return null;
  const hasCompression = halves.length === 2;
  const missing = 8 - left.length - right.length;
  if (!hasCompression && missing !== 0 || hasCompression && missing < 1) return null;
  const words = [...left, ...new Array(missing).fill(0), ...right];
  if (words.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i += 1) {
    bytes[i * 2] = words[i] >>> 8 & 255;
    bytes[i * 2 + 1] = words[i] & 255;
  }
  let mapped = true;
  for (let i = 0; i < 10; i += 1) if (bytes[i] !== 0) mapped = false;
  if (mapped && bytes[10] === 255 && bytes[11] === 255) {
    return { family: 1, bytes: bytes.slice(12) };
  }
  return { family: 2, bytes };
}
function isGlobalUnicast(ip) {
  return ip ? ip.family === 1 ? isIpv4GlobalUnicast(ip.bytes) : isV6GlobalUnicast(ip.bytes) : false;
}
function subnetForEcs(cfConnectingIp, ipv4Prefix, ipv6Prefix) {
  if (!cfConnectingIp) return null;
  const ip = parseIpString(cfConnectingIp);
  if (ip === null || !isGlobalUnicast(ip)) return null;
  const prefixLength = ip.family === 1 ? ipv4Prefix : ipv6Prefix;
  const network = ip.bytes.slice();
  const whole = Math.floor(prefixLength / 8);
  const rem = prefixLength % 8;
  if (rem !== 0) network[whole] = network[whole] & 255 << 8 - rem;
  network.fill(0, whole + (rem === 0 ? 0 : 1));
  return { family: ip.family, bytes: ip.bytes, network, prefixLength };
}

// src/cache.js
var DEFAULT_SIZE = 1024;
function createCache({ size = DEFAULT_SIZE, now = Date.now } = {}) {
  const map = /* @__PURE__ */ new Map();
  const key = (qname, qtype, ecs) => `${qname.toLowerCase()}|${qtype}|${ecs}`;
  return {
    /** Look up; returns answer bytes on fresh hit, else null. */
    get(qname, qtype, ecs, ts = now()) {
      const k = key(qname, qtype, ecs);
      const e = map.get(k);
      if (!e) return null;
      if (e.expiresAt <= ts) {
        map.delete(k);
        return null;
      }
      return e.value;
    },
    /** Store an answer for `ttl` seconds. ttl <= 0 skips caching. */
    set(qname, qtype, ecs, value, ttl, ts = now()) {
      if (ttl <= 0) return;
      const k = key(qname, qtype, ecs);
      map.delete(k);
      map.set(k, { value, expiresAt: ts + ttl * 1e3 });
      while (map.size > size) {
        const oldest = map.keys().next().value;
        if (oldest === void 0) break;
        map.delete(oldest);
      }
    },
    /** Number of live entries (metrics). */
    size() {
      return map.size;
    }
  };
}

// src/core.js
function appendEcsOpt(query, subnet) {
  const rdata = encodeEcsRdata(subnet.family, subnet.network, subnet.prefixLength);
  const option = wrapEcsOption(rdata);
  const opt = new Uint8Array(1 + 2 + 2 + 4 + 2 + option.length);
  opt[0] = 0;
  opt[1] = 0;
  opt[2] = 41;
  opt[3] = 4;
  opt[4] = 208;
  opt[5] = 0;
  opt[6] = 0;
  opt[7] = 0;
  opt[8] = 0;
  opt[9] = option.length >> 8 & 255;
  opt[10] = option.length & 255;
  opt.set(option, 11);
  const out = new Uint8Array(query.length + opt.length);
  out.set(query, 0);
  out.set(opt, query.length);
  const oldAr = (query[10] << 8 | query[11]) & 65535;
  const newAr = oldAr + 1;
  out[10] = newAr >> 8 & 255;
  out[11] = newAr & 255;
  return out;
}
var dnsCache = createCache();
async function resolveQuery(wireQuery, parsed, { clientIp, env, config }) {
  const qname = parsed.question.name;
  let rules = null;
  try {
    rules = await ensureRules(env);
  } catch {
    rules = null;
  }
  const domestic = isDomestic(qname, rules);
  if (env.BLOCK_URL || env.BLOCK_KV) {
    const blockRule = await ensureBlock(env);
    if (isBlocked(qname, blockRule)) {
      metrics.inc("filter_blocked");
      const action = config.blockAction;
      const meta = { "X-DoH-Filter": "blocked" };
      if (action === "nxdomain") {
        return { ok: true, answer: buildErrorResponse(wireQuery, 3, parsed.question), meta };
      }
      if (action === "zero") {
        return { ok: true, answer: buildZeroResponse(wireQuery, parsed), meta };
      }
    }
  }
  const subnet = subnetForEcs(clientIp, config.ecsV4Prefix, config.ecsV6Prefix);
  const ecsKey = subnet ? `${subnet.family}:${subnet.network.join(".")}` : "none";
  const result = await resolveWithCache(parsed, wireQuery, subnet, ecsKey, domestic, config, env);
  if (!result) return { ok: false };
  let answer = result.answer;
  if (result.cached) {
    answer = answer.slice();
    answer[0] = parsed.id >> 8 & 255;
    answer[1] = parsed.id & 255;
  } else if (config.dnssec) {
    answer = answer.slice();
  }
  if (config.dnssec) {
    applyRelayedDnssec(answer, clientRequestedDnssec(parsed));
  }
  return { ok: true, answer, meta: result.meta };
}
async function resolveWithCache(parsed, query, subnet, ecsKey, domestic, config, env) {
  const qname = parsed.question.name;
  const qtype = parsed.question.qtype;
  if (config.cacheTtlSeconds > 0) {
    const cached = dnsCache.get(qname, qtype, ecsKey);
    if (cached) {
      metrics.inc("cache_hit");
      metrics.recordAnalyticsPoint(env, {
        group: domestic ? "domestic" : "global",
        winnerUrl: "cache",
        durationMs: 0,
        qtype,
        rcode: "NOERROR",
        cacheStatus: "hit"
      });
      return { answer: cached, from: "cache", durationMs: 0, cached: true };
    }
    metrics.inc("cache_miss");
  }
  const forwarded = subnet ? appendEcsOpt(query, subnet) : query;
  const urls = domestic ? config.domesticUrls : config.globalUrls;
  const result = await raceGroup(urls, forwarded, parsed, {
    timeoutMs: config.upstreamTimeoutMs,
    maxResponseBytes: config.maxResponseBytes,
    on: ({ kind }) => {
      if (kind === "ok") metrics.inc("upstream_ok");
      else if (kind === "timeout") metrics.inc("upstream_timeouts");
      else if (kind === "servfail") metrics.inc("upstream_servfail");
      else metrics.inc("upstream_errors");
    }
  });
  if (!result) return null;
  metrics.recordUpstreamRace(domestic ? "domestic" : "global", result.from, result.durationMs);
  metrics.recordAnalyticsPoint(env, {
    group: domestic ? "domestic" : "global",
    winnerUrl: result.from,
    durationMs: result.durationMs,
    qtype,
    rcode: "NOERROR",
    cacheStatus: "miss"
  });
  if (config.cacheTtlSeconds > 0) {
    let ttl = answerTtlSeconds(result.answer, parsed);
    const flags = result.answer[2] << 8 | result.answer[3];
    const rcode = flags & 15;
    const ancount = result.answer[6] << 8 | result.answer[7];
    if (rcode === 3 || ancount === 0) {
      const maxNegTtl = Math.min(config.cacheTtlSeconds, 30);
      ttl = ttl <= 0 ? maxNegTtl : Math.min(ttl, maxNegTtl);
    } else if (ttl <= 0) {
      ttl = config.cacheTtlSeconds;
    }
    dnsCache.set(qname, qtype, ecsKey, result.answer, Math.min(ttl, config.cacheTtlSeconds));
  }
  return result;
}

// src/worker.js
var QTYPE_STR = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  HTTPS: 65
};
function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) return null;
  let v = value.replace(/-/g, "+").replace(/_/g, "/");
  while (v.length % 4 !== 0) v += "=";
  try {
    const bin = atob(v);
    if (bin.length === 0) return null;
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}
function dnsResponse(body, extraHeaders) {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": DNS_CONTENT_TYPE,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept, X-DoH-Token",
      ...extraHeaders || {}
    }
  });
}
function isValidQname(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 253) return false;
  if (name.endsWith(".")) return false;
  const labels = name.split(".");
  if (labels.some((l) => l.length === 0 || l.length > 63)) return false;
  return /^[a-zA-Z0-9_.-]+$/.test(name) && !name.includes("..");
}
function buildWireQuery(name, type) {
  const qname = name.toLowerCase();
  const labels = qname.split(".").filter((l) => l.length > 0).map((l) => new TextEncoder().encode(l));
  const qnameLen = labels.reduce((n, b) => n + 1 + b.length, 0) + 1;
  const out = new Uint8Array(12 + qnameLen + 4);
  out[2] = 1;
  out[5] = 1;
  let o = 12;
  for (const bytes of labels) {
    out[o] = bytes.length;
    out.set(bytes, o + 1);
    o += 1 + bytes.length;
  }
  out[o] = 0;
  o += 1;
  out[o] = type >> 8 & 255;
  out[o + 1] = type & 255;
  out[o + 2] = 0;
  out[o + 3] = 1;
  return out;
}
async function readDnsQuery(request, config) {
  const url = new URL(request.url);
  if (url.pathname !== config.path) return { error: "not_found" };
  if (request.method === "GET") {
    const values = url.searchParams.getAll("dns");
    if (values.length !== 1) return { error: "bad_get" };
    const decoded = decodeBase64Url(values[0]);
    if (!decoded || decoded.byteLength === 0) return { error: "bad_get" };
    if (decoded.byteLength > config.maxQueryBytes) return { error: "too_large" };
    return { query: decoded };
  }
  if (request.method === "POST") {
    const type = (request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
    if (type !== DNS_CONTENT_TYPE) return { error: "unsupported_media" };
    const body = await request.arrayBuffer();
    if (body.byteLength === 0) return { error: "empty" };
    if (body.byteLength > config.maxQueryBytes) return { error: "too_large" };
    return { query: new Uint8Array(body) };
  }
  return { error: "method_not_allowed" };
}
async function handleRequest(request, env) {
  const config = readConfig(env);
  metrics.inc("requests");
  const url = new URL(request.url);
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept, X-DoH-Token, Authorization, X-Rules-Secret",
        "Access-Control-Max-Age": "86400"
      }
    });
  }
  if (url.pathname === "/healthz" || url.pathname === "/metrics") {
    return metrics.healthResponse(config);
  }
  if (url.pathname === "/api/stats" || url.pathname === "/stats" || url.pathname === "/api/stats/global" || url.pathname === "/stats/global") {
    const scope = url.searchParams.get("scope") || (url.pathname.endsWith("/global") ? "global" : "local");
    if (scope === "global") {
      const interval = url.searchParams.get("interval") || "1 DAY";
      return metrics.globalStatsResponse(config, env, { interval });
    }
    return metrics.statsResponse(config);
  }
  if (url.pathname === "/api/rules/sync" || url.pathname === "/rules/sync") {
    return handleRulesSync(request, url, env, config);
  }
  if (url.pathname === "/" && request.method === "GET") {
    const accept = (request.headers.get("accept") || "").toLowerCase();
    if (accept.includes("text/html") || accept.includes("*/*") || !accept) {
      return new Response(renderLandingHtml(url.origin, config), {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    }
    return new Response(
      `cf-doh \u2014 Self-hosted DNS-over-HTTPS Resolver

Endpoints:
  \u2022 RFC 8484 DoH Query : ${url.origin}${config.path}
  \u2022 DoH JSON API       : ${url.origin}${config.jsonPath}?name=example.com&type=A
  \u2022 Health Check       : ${url.origin}/healthz
  \u2022 Web Console        : ${url.origin}/

GitHub: https://github.com/dengyie/cf-doh
`,
      { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } }
    );
  }
  if (config.token) {
    const submitted = url.searchParams.get("token") || request.headers.get("x-doh-token") || "";
    if (submitted !== config.token) return new Response("Forbidden", { status: 403 });
  }
  if (url.pathname === config.jsonPath) {
    return handleJsonQuery(request, url, env, config);
  }
  const read = await readDnsQuery(request, config);
  if (read.error) {
    metrics.inc("formerr");
    const code = read.error === "not_found" ? 404 : read.error === "method_not_allowed" ? 405 : read.error === "too_large" ? 413 : read.error === "unsupported_media" ? 415 : 400;
    return new Response(code === 400 ? "Bad Request" : "", { status: code });
  }
  metrics.inc(request.method === "GET" ? "get" : "post");
  let parsed;
  try {
    parsed = parseDnsMessage(read.query);
  } catch {
    metrics.inc("formerr");
    return dnsResponse(buildErrorResponse(read.query, 1, null));
  }
  const outcome = await resolveQuery(read.query, parsed, {
    clientIp: request.headers.get("cf-connecting-ip"),
    env,
    config
  });
  if (!outcome.ok) {
    metrics.inc("servfail");
    return dnsResponse(serverFailure(read.query, parsed.question));
  }
  metrics.inc("ok");
  return dnsResponse(outcome.answer, outcome.meta);
}
async function handleJsonQuery(request, url, env, config) {
  if (request.method !== "GET" && request.method !== "OPTIONS") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const qname = url.searchParams.get("name");
  const typeName = (url.searchParams.get("type") || "A").toUpperCase();
  const qtype = QTYPE_STR[typeName] ?? 1;
  if (!qname || !isValidQname(qname)) {
    return jsonResponse({ Status: 2, Question: [{ name: qname || "", type: typeName }] });
  }
  const wireQuery = buildWireQuery(qname, qtype);
  let parsed;
  try {
    parsed = parseDnsMessage(wireQuery);
  } catch {
    return jsonResponse({ Status: 2, Question: [{ name: qname, type: typeName }] });
  }
  const outcome = await resolveQuery(wireQuery, parsed, {
    clientIp: request.headers.get("cf-connecting-ip"),
    env,
    config
  });
  if (!outcome.ok) {
    return jsonResponse({ Status: 2, Question: [{ name: qname, type: typeName }] });
  }
  let minTtl = 0;
  try {
    minTtl = answerTtlSeconds(outcome.answer, parsed);
  } catch {
    minTtl = 0;
  }
  const json = toJsonResponse(outcome.answer, qname, typeName);
  const resp = jsonResponse(json, minTtl);
  if (outcome.meta) {
    for (const [k, v] of Object.entries(outcome.meta)) resp.headers.set(k, v);
  }
  return resp;
}
async function handleRulesSync(request, url, env, config) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" }
    });
  }
  const secret = config.rulesSyncSecret || env.RULES_SYNC_SECRET;
  if (!secret) {
    return new Response(
      JSON.stringify({ error: "RULES_SYNC_SECRET is not configured on server" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  const authHeader = request.headers.get("Authorization") || "";
  const bearerMatch = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
  const xSecret = request.headers.get("X-Rules-Secret");
  const querySecret = url.searchParams.get("secret");
  const tokenMatch = bearerMatch || xSecret || querySecret;
  if (tokenMatch !== secret) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  const text = await request.text();
  let ruleText = text;
  if (ct.includes("application/json") && text.trim().length > 0) {
    try {
      const json = JSON.parse(text);
      if (typeof json.rules === "string") {
        ruleText = json.rules;
      }
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON payload" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
  }
  if (ruleText && ruleText.trim().length > 0) {
    try {
      const adopted = await adoptRawRules(ruleText, env);
      return new Response(
        JSON.stringify({
          ok: true,
          mode: "push",
          rulesCount: adopted.ruleCount,
          bytes: adopted.bytes,
          updatedAt: (/* @__PURE__ */ new Date()).toISOString()
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        }
      );
    } catch (err) {
      return new Response(
        JSON.stringify({ error: err.message || "Failed to adopt rules" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  } else {
    const updated = await refreshRules(env);
    return new Response(
      JSON.stringify({
        ok: updated,
        mode: "pull",
        updatedAt: (/* @__PURE__ */ new Date()).toISOString()
      }),
      {
        status: updated ? 200 : 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      }
    );
  }
}
var worker_default = {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
  async scheduled(_ctrl, env) {
    try {
      const updated = await refreshRules(env);
      metrics.inc(updated ? "rules_fetch" : "rules_unchanged");
    } catch {
      metrics.inc("rules_fetch_fail");
    }
    try {
      const updated = await refreshBlock(env);
      metrics.inc(updated ? "block_fetch" : "block_unchanged");
    } catch {
      metrics.inc("block_fetch_fail");
    }
  }
};
export {
  worker_default as default,
  handleRequest,
  resetBlock
};
