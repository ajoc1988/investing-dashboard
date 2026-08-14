'use strict';
/*
 * Investing Command Centre — secure data + AI proxy
 * --------------------------------------------------
 * Holds all API keys server-side. The frontend calls these endpoints and
 * never sees a key. Every adapter fails soft: a missing key or a dead
 * upstream returns null for that field instead of crashing the response.
 *
 * Endpoints
 *   GET  /api/health          -> ok, version (build id), key/seat availability
 *   GET  /api/prices?symbols=VOO,QQQ,NVDA,MSFT,VXUS,SCHD
 *   GET  /api/market          -> spx, ndx, vix, y2, y10, dxy
 *   GET  /api/macro           -> cpi, cpiPrev, fedRate, cutProb, fg, breadth
 *   GET  /api/events          -> upcoming CPI/PPI/Jobs/Fed + NVDA/MSFT earnings
 *   GET  /api/news            -> market headlines
 *   POST /api/deep-triggers   -> { packet, cashContext, fresh? } => AI consensus, verdict, risk
 *                                (25-minute result cache; see DEEP_CACHE below)
 */

try { require('dotenv').config(); } catch (_) { /* dotenv optional: hosted platforms inject env vars directly */ }
const express = require('express');
const cors = require('cors');
const { resolve: resolveCommitteeAction } = require('./committee-resolver');

/* ── BUILD IDENTIFICATION (V2 §3.1) ────────────────────────────────────────────
 * Explicit constant, deliberately NOT derived from package.json (Ruling 6). Bump this
 * by hand whenever the backend is deployed. Surfaced via /api/health so the frontend
 * can compare it against its own constant and flag frontend/backend deployment drift.
 * The frontend expects API_VERSION to match its EXPECTED_API constant.               */
const API_VERSION = '2.7.0';

const app = express();
app.use(express.json({ limit: '128kb' }));
/* CORS (step 6). Now accepts a comma-separated list, e.g.
 *   CORS_ORIGIN=https://ajoc1988.github.io
 * DEFAULT IS STILL '*' AND THAT IS DELIBERATE — see the deployment notes. Restricting it
 * would break opening the dashboard as a local file (file:// sends `Origin: null`), which
 * the owner does when testing. CORS constrains browsers only and does nothing against a
 * script or curl, so this is tidiness rather than a control; authentication is what
 * actually protects these routes. Owner's call, not a silent default change. */
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
app.use(cors({ origin: CORS_ORIGIN === '*' ? '*' : CORS_ORIGIN.split(',').map(x => x.trim()).filter(Boolean) }));

const PORT = process.env.PORT || 8787;
const FINNHUB = process.env.FINNHUB_API_KEY || '';
const FRED = process.env.FRED_API_KEY || '';
// eToro read-only. We never request or send trade/order/leverage scopes.
const ETORO_KEY = process.env.ETORO_API_KEY || '';          // x-api-key (Public Key)
const ETORO_USER_KEY = process.env.ETORO_USER_KEY || '';    // x-user-key (the eyJ… User Key)
const ETORO_ENV = (process.env.ETORO_ENV || 'real').toLowerCase() === 'demo' ? 'demo' : 'real';
const ETORO_BASE = (process.env.ETORO_API_URL || 'https://public-api.etoro.com').replace(/\/+$/, '');
const ETORO_ON = !!(ETORO_KEY && ETORO_USER_KEY);
// Grok (xAI) — optional Geopolitical Risk Officer. NOT a voting seat. Off until GROK_API_KEY is set.
// Never receives portfolio holdings or history. Live/web search is a paid tool, OFF unless GROK_LIVE_SEARCH=on.
const GROK_KEY = process.env.GROK_API_KEY || process.env.XAI_API_KEY || '';
const GROK_MODEL = process.env.GROK_MODEL || 'grok-4.3';
const GROK_LIVE_SEARCH = String(process.env.GROK_LIVE_SEARCH || '').toLowerCase() === 'on';
const GROK_ON = !!GROK_KEY;

/* ───────── tiny utilities ───────── */
async function getJson(url, opts = {}, ms = 9000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal });
    if (!r.ok) { let b = ''; try { b = (await r.text()).slice(0, 200); } catch (_) {} throw new Error('HTTP ' + r.status + (b ? ' ' + b : '')); }
    return await r.json();
  } finally { clearTimeout(timer); }
}
const num = (v) => (v == null || v === '' || v === '.' || isNaN(+v)) ? null : +v;

// in-memory cache so we don't burn free-tier quotas on rapid refreshes
const cache = new Map();
async function cached(key, ttlMs, fn) {
  const hit = cache.get(key);
  if (hit && hit.exp > Date.now()) return hit.data;
  const data = await fn();
  cache.set(key, { data, exp: Date.now() + ttlMs });
  // Nothing ever evicted from this Map before (step 5). Sweep expired entries once it grows.
  if (cache.size > 400) { const now = Date.now(); for (const [k, v] of cache) if (v.exp < now) cache.delete(k); }
  return data;
}

/* ── Client IP behind Render's proxy (step 4) ───────────────────────────────────
 * Express defaults to trust proxy = false, which made req.ip the address of Render's
 * edge proxy rather than the visitor — meaning every client on earth shared ONE rate
 * limit bucket, so an attacker draining the API would also lock the owner out.
 * Render puts exactly one proxy in front of the service, hence 1.
 * Set TRUST_PROXY=0 to disable if that ever changes. Verify with the authenticated
 * /api/health payload, which reports the observed ip and X-Forwarded-For chain —
 * deliberately NOT a public debug endpoint. */
app.set('trust proxy', process.env.TRUST_PROXY != null ? (isNaN(+process.env.TRUST_PROXY) ? process.env.TRUST_PROXY : +process.env.TRUST_PROXY) : 1);

/* Opportunistic per-IP limit. Lowered from 120/min: at 120 an attacker was allowed
 * 172,800 committee runs a day, each costing 10-29 upstream AI calls. This is now a
 * backstop against a runaway client, NOT the quota protection — authentication is
 * what stops quota drain, and the durable daily cap below is what bounds the cost of
 * a stolen token. Entries are pruned; the original Map grew without limit. */
const hits = new Map();
const RATE_MAX = Math.max(10, +process.env.RATE_MAX || 40);
app.use((req, res, next) => {
  const ip = req.ip || 'x';
  const now = Date.now();
  if (hits.size > 5000) { for (const [k, v] of hits) if (v.exp < now) hits.delete(k); }
  const w = hits.get(ip) || { n: 0, exp: now + 60000 };
  if (w.exp < now) { w.n = 0; w.exp = now + 60000; }
  w.n++; hits.set(ip, w);
  if (w.n > RATE_MAX) return res.status(429).json({ error: 'rate_limited' });
  next();
});


/* ═══════════════════ AUTHENTICATION (step 2) ═══════════════════════════════════
 * One owner, static GitHub Pages frontend, Render free backend.
 *
 * Signed STATELESS tokens, not server-held sessions. This is not a preference:
 * DEEP_CACHE, `cache` and `hits` are all in-memory Maps and every one of them is
 * emptied by a Render cold start (see the DEEP_CACHE note below). A session store
 * would be a fourth such Map, so every sleep would force a re-login. A signed token
 * stores nothing here, so a restart cannot lose it — the secret is revalidated from
 * the environment on every request.
 *
 * FAILS CLOSED. If OWNER_PASSWORD or TOKEN_SECRET is missing, every protected route
 * AND /api/login return 503. There is deliberately no "skip the check if unconfigured"
 * path: the rest of this file degrades gracefully when a key is absent (sbOn,
 * providerHasKey, loadPrompt) which is right for a data feed and catastrophic here.  */
const crypto = require('crypto');

const OWNER_PASSWORD = process.env.OWNER_PASSWORD || '';
const TOKEN_SECRET   = process.env.TOKEN_SECRET || '';
const AUTH_READY     = !!(OWNER_PASSWORD && TOKEN_SECRET);
const TOKEN_TTL_MS       = 12 * 60 * 60 * 1000;   // absolute lifetime
const TOKEN_REFRESH_MS   =      60 * 60 * 1000;   // re-issue once a token is older than this

const b64u = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uDec = (s) => { const t = String(s).replace(/-/g, '+').replace(/_/g, '/'); return Buffer.from(t + '='.repeat((4 - t.length % 4) % 4), 'base64'); };

function issueToken() {
  const now = Date.now();
  const p = b64u(JSON.stringify({ iat: now, exp: now + TOKEN_TTL_MS }));
  return p + '.' + b64u(crypto.createHmac('sha256', TOKEN_SECRET).update(p).digest());
}
function verifyToken(tok) {
  if (!AUTH_READY || typeof tok !== 'string') return null;
  const i = tok.indexOf('.');
  if (i <= 0) return null;
  const p = tok.slice(0, i), sig = tok.slice(i + 1);
  const expect = b64u(crypto.createHmac('sha256', TOKEN_SECRET).update(p).digest());
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length) return null;                 // timingSafeEqual throws on length mismatch
  if (!crypto.timingSafeEqual(a, b)) return null;
  let payload = null;
  try { payload = JSON.parse(b64uDec(p).toString('utf8')); } catch (_) { return null; }
  if (!payload || typeof payload.exp !== 'number' || typeof payload.iat !== 'number') return null;
  if (Date.now() >= payload.exp) return null;
  return payload;
}

/* Password check. The password is stored in the environment in plaintext, alongside every
 * other secret this service holds, so hashing it AT REST would buy nothing. The ONE thing
 * scrypt buys here is a deliberate ~100ms cost per attempt, which is what makes online
 * guessing expensive. Do not "optimise" it away — the slowness IS the feature.
 * Async form only: scryptSync would block Node's single thread and freeze every other
 * request for the duration of each login attempt. */
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };
const SCRYPT_SALT = AUTH_READY ? crypto.createHash('sha256').update(TOKEN_SECRET).digest() : Buffer.alloc(32);
function scryptOnce(pw) {
  return new Promise((resolve, reject) => crypto.scrypt(pw, SCRYPT_SALT, 32, SCRYPT_OPTS, (e, dk) => e ? reject(e) : resolve(dk)));
}
let _ownerDkP = null;
function ownerDk() { if (!_ownerDkP) _ownerDkP = scryptOnce(OWNER_PASSWORD); return _ownerDkP; }   // derived once, then cached

/* Two controls, two different jobs. The counter limits guesses; the concurrency ceiling
 * protects the box. scrypt is memory-hard by design (~16MB per operation at these
 * parameters), so unbounded parallel logins would exhaust RAM on a 512MB instance long
 * before they exhausted anyone's patience. Neither needs durable persistence: with a
 * high-entropy password, a restart handing an attacker five more guesses is not useful.
 * Durable limits belong on the endpoints where a SUCCESSFUL request costs quota. */
const LOGIN_FAILS = new Map();
const LOGIN_MAX = 5, LOGIN_WINDOW_MS = 60000;
let SCRYPT_INFLIGHT = 0;
const SCRYPT_MAX_INFLIGHT = 2;

app.post('/api/login', async (req, res) => {
  if (!AUTH_READY) return res.status(503).json({ error: 'auth_not_configured' });
  const ip = req.ip || 'x', now = Date.now();
  if (LOGIN_FAILS.size > 500) { for (const [k, v] of LOGIN_FAILS) if (v.exp < now) LOGIN_FAILS.delete(k); }
  const w = LOGIN_FAILS.get(ip);
  if (w && w.exp > now && w.n >= LOGIN_MAX) return res.status(429).json({ error: 'too_many_attempts' });
  const pw = req.body && req.body.password;
  if (typeof pw !== 'string' || !pw) return res.status(400).json({ error: 'password_required' });
  if (SCRYPT_INFLIGHT >= SCRYPT_MAX_INFLIGHT) return res.status(503).json({ error: 'busy_try_again' });
  SCRYPT_INFLIGHT++;
  try {
    const [given, owner] = await Promise.all([scryptOnce(pw), ownerDk()]);
    const ok = given.length === owner.length && crypto.timingSafeEqual(given, owner);
    if (!ok) {
      const cur = (w && w.exp > now) ? w : { n: 0, exp: now + LOGIN_WINDOW_MS };
      cur.n++; LOGIN_FAILS.set(ip, cur);
      return res.status(401).json({ error: 'invalid_password' });
    }
    LOGIN_FAILS.delete(ip);
    return res.json({ token: issueToken(), expiresAt: Date.now() + TOKEN_TTL_MS });
  } catch (e) {
    console.error('[login] scrypt failed:', (e && e.message) || e);
    return res.status(500).json({ error: 'login_failed' });
  } finally { SCRYPT_INFLIGHT--; }
});

/* ALLOWLIST, not a blocklist. The header comment at the top of this file documents seven
 * routes when thirteen exist — that drift happened during normal development. With a
 * blocklist the next route added would be PUBLIC by default and nothing would flag it.
 * With an allowlist it is protected by default and fails loudly. Add to this set only
 * deliberately. */
const PUBLIC_PATHS = new Set(['/api/health', '/api/market', '/api/macro', '/api/events', '/api/news', '/api/login']);

app.use((req, res, next) => {
  if (req.method === 'OPTIONS') return next();                 // preflight is answered by cors() above
  const p = ((req.path || '').replace(/\/+$/, '')) || '/';
  if (PUBLIC_PATHS.has(p)) return next();
  if (!AUTH_READY) return res.status(503).json({ error: 'auth_not_configured', detail: 'Set OWNER_PASSWORD and TOKEN_SECRET on the server.' });
  const h = req.headers.authorization || '';
  const payload = verifyToken(h.startsWith('Bearer ') ? h.slice(7).trim() : '');
  if (!payload) return res.status(401).json({ error: 'unauthorised' });
  req.auth = payload;
  /* Sliding refresh — in the RESPONSE BODY, never a custom header. Browsers expose only the
   * CORS-safelisted response headers to JavaScript unless the server names others in
   * Access-Control-Expose-Headers, and this service sets none. A header would be silently
   * invisible to the frontend: everything would look correct for 12 hours and then log the
   * owner out with no discoverable cause. */
  if (Date.now() - payload.iat > TOKEN_REFRESH_MS) {
    const fresh = issueToken();
    const orig = res.json.bind(res);
    res.json = (obj) => orig((obj && typeof obj === 'object' && !Array.isArray(obj)) ? Object.assign({}, obj, { token: fresh }) : obj);
  }
  next();
});
/* ══════════════════════════════════════════════════════════════════════════════ */


/* ── ERROR SURFACES (step 3) ────────────────────────────────────────────────────
 * Split by route class, per owner ruling.
 *   PUBLIC routes  -> fixed generic strings. These are the routes whose upstream calls
 *                     carry FRED_API_KEY / FINNHUB_API_KEY in the URL QUERY STRING, and
 *                     the caller could be anyone. If an upstream ever echoes the request
 *                     URL inside its error body, the old code would have relayed it.
 *   AUTHENTICATED  -> classified, not dumped. The only reader is the owner, and the
 *                     classification preserves the diagnostic that actually matters
 *                     ("rate-limited / daily quota") without the provider's raw text.
 * Everything raw goes to console.error, i.e. the Render log, which only the owner sees.
 * Before this change there was no logging at all in this file beyond the startup line. */
function logUpstream(where, e) {
  try { console.error('[' + where + ']', String((e && e.message) || e).slice(0, 400)); } catch (_) {}
}
// Public-facing: never varies with upstream text.
function publicErr(where, e) { logUpstream(where, e); return 'upstream data source unavailable'; }

/* ───────── FRED helpers ───────── */
async function fredObs(series, limit = 1) {
  if (!FRED) return [];
  const url = `https://api.stlouisfed.org/fred/series/observations?series_id=${series}&api_key=${FRED}&file_type=json&sort_order=desc&limit=${limit}`;
  const j = await getJson(url);
  return (j.observations || []).map(o => ({ date: o.date, value: num(o.value) }));
}
async function fredLatest(series) {
  // pull a few in case the most recent is missing (".")
  const obs = await fredObs(series, 6);
  const first = obs.find(o => o.value != null);
  return first ? first.value : null;
}

/* ───────── /api/health ───────── */
app.get('/api/health', (req, res) => {
  /* PUBLIC payload is deliberately minimal. The frontend needs this before sign-in for the
   * build chip and the "backend reachable" check, so it stays open — but the provider
   * enumeration below is a targeting aid (it tells an attacker which quota is worth
   * draining) with no value to a logged-out page. Full detail requires a valid token. */
  const h = req.headers.authorization || '';
  const authed = !!verifyToken(h.startsWith('Bearer ') ? h.slice(7).trim() : '');
  if (!authed) return res.json({ ok: true, version: API_VERSION, ts: Date.now() });
  res.json({
    ok: true,
    version: API_VERSION,
    /* Observed client address, so the TRUST_PROXY setting can be verified without a
     * public debug endpoint (owner ruling 9). Authenticated-only. */
    client: { ip: req.ip, xff: req.headers['x-forwarded-for'] || null, trustProxy: app.get('trust proxy') },
    keys: {
      etoro: ETORO_ON, finnhub: !!FINNHUB, fred: !!FRED, supabase: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY),
      openai: !!process.env.OPENAI_API_KEY, anthropic: !!process.env.ANTHROPIC_API_KEY,
      gemini: !!process.env.GEMINI_API_KEY, perplexity: !!process.env.PERPLEXITY_API_KEY,
      openrouter: !!process.env.OPENROUTER_API_KEY, groq: !!process.env.GROQ_API_KEY, grok: GROK_ON
    },
    committeeSeats: loadSeats().filter(s => providerHasKey(s.provider)).length,
    /* FIXED: this used to report `GEO_MODEL || GEMINI_MODEL || 'gemini-2.5-flash'`, but
     * runGeoOfficer() actually calls the GEO_MODEL constant, which falls back to a different
     * default and ignores GEMINI_MODEL entirely. With GEMINI_MODEL set and GEO_MODEL unset
     * the two genuinely disagreed, so the dashboard reported a model that was not the one
     * doing the work. Report the constant that is actually used. */
    geoOfficer: (process.env.GEMINI_API_KEY) ? { on: true, model: GEO_MODEL, by: 'gemini' } : { on: false },
    ts: Date.now()
  });
});


/* ══════════════ PRICE FEED RELIABILITY ══════════════════════════════════════════
 * The gate for the Paper Wildcard. Three problems this addresses, in order of severity:
 *
 *  1. NO HISTORY EXISTED. Nothing recorded what a price actually did. The Wildcard must
 *     record what really happened to a price, so it cannot be built on a system with no
 *     memory of prices. Every quote observed is now written to investing.price_observations.
 *     Deliberately named "observations", not OHLC — see the migration comment.
 *
 *  2. ONE PROVIDER, PARTIAL COVERAGE. Finnhub's free tier serves US listings. Non-US
 *     holdings (e.g. .L / .HK lines) return nothing and were silently absent from the
 *     response, so the frontend could not tell "no coverage" from "not asked for".
 *     Coverage is now reported explicitly per symbol.
 *
 *  3. AN ACCURACY DEFECT WAS ALREADY KNOWN. See the note above estimateTodayPl: Finnhub's
 *     daily percentage came back roughly 9x reality, which is why Today P/L is blank. A
 *     single unverifiable source cannot be trusted with the Wildcard's evidence, so this
 *     layer is built provider-agnostic and cross-checks whenever more than one is enabled.
 *
 * NO NEW PROVIDER IS ENABLED HERE. "Yahoo redundancy" is on the do-not-build list, so the
 * registry below has exactly one live entry and the shape needed to add another as a config
 * change rather than a rewrite. Adding one is the owner's call, not this file's.          */

const PRICE_STALE_MS = 15 * 60 * 1000;   // a quote older than this is stale — but ONLY while a session is running

/* A quote from Friday's close is not "stale" on a Saturday, it is simply the last price that
 * exists. The first build flagged it anyway, which would have cried wolf every weekend and
 * every night — precisely the false alarm this project exists to avoid.
 *
 * Deliberately the UNION of US summer and winter session hours (13:30-21:00 UTC), so this
 * never claims "closed" during a real session. NO HOLIDAY CALENDAR: on a market holiday this
 * returns true and quotes may read stale. That errs toward flagging rather than hiding, which
 * is the right way round — an unexpected "stale" invites a look, a wrongly hidden one does not. */
function usMarketLikelyOpen(d) {
  d = d || new Date();
  const day = d.getUTCDay();
  if (day === 0 || day === 6) return false;
  const mins = d.getUTCHours() * 60 + d.getUTCMinutes();
  return mins >= (13 * 60 + 30) && mins <= (21 * 60);
}
const PRICE_DISPUTE_PC = 1.0;            // two sources differing by more than this = disputed, no price

// Each adapter: (symbols) -> { SYM: {price, asOf} }. Must never throw; must omit what it cannot serve.
const PRICE_SOURCES = {
  finnhub: {
    on: () => !!FINNHUB,
    covers: 'US listings only (free tier)',
    fetch: async (symbols) => {
      const out = {};
      await Promise.all(symbols.map(async sym => {
        try {
          const j = await getJson(`https://finnhub.io/api/v1/quote?symbol=${encodeURIComponent(sym)}&token=${FINNHUB}`);
          // j.c === 0 is Finnhub's "I don't have this symbol" answer, NOT a price of zero.
          if (j && typeof j.c === 'number' && j.c > 0) {
            out[sym] = { price: j.c, dp: num(j.dp), change: num(j.d), prevClose: num(j.pc), asOf: j.t ? j.t * 1000 : Date.now() };
          }
        } catch (e) { logUpstream('price:finnhub:' + sym, e); }
      }));
      return out;
    }
  }
  /* To add a second source later: another entry with the same shape. The cross-check below
   * activates automatically once two are live. Not doing that unilaterally. */
};
const livePriceSources = () => Object.keys(PRICE_SOURCES).filter(k => PRICE_SOURCES[k].on());

// Record what we saw. Fire-and-forget, never blocks or fails a response.
async function recordPrices(quotes, source) {
  if (!sbOn()) return;
  const syms = Object.keys(quotes || {});
  if (!syms.length) return;
  await Promise.all(syms.map(async sym => {
    const px = quotes[sym] && quotes[sym].price;
    if (!(px > 0)) return;
    try {
      const r = await fetch(`${SB_URL}/rest/v1/rpc/record_price`, {
        method: 'POST', headers: sbHeaders(true),
        body: JSON.stringify({ p_symbol: sym, p_price: px, p_source: source })
      });
      if (!r.ok) throw new Error('rpc ' + r.status + ' ' + (await r.text()).slice(0, 120));
    } catch (e) { logUpstream('price:record:' + sym, e); }
  }));
}

/* Merge across sources. Where two disagree by more than PRICE_DISPUTE_PC, NO price is
 * returned for that symbol and it is marked disputed. Picking one silently is how a wrong
 * number ends up presented as fact — and this system's whole premise is that an honest
 * "no value" beats a confident wrong one. */
function mergeQuotes(bySource) {
  const merged = {}, disputed = [], names = Object.keys(bySource);
  const allSyms = [...new Set(names.flatMap(n => Object.keys(bySource[n])))];
  for (const sym of allSyms) {
    const got = names.filter(n => bySource[n][sym]).map(n => ({ src: n, ...bySource[n][sym] }));
    if (!got.length) continue;
    if (got.length === 1) { merged[sym] = { ...got[0], sources: [got[0].src], agreement: 'single-source' }; continue; }
    const prices = got.map(g => g.price);
    const spread = (Math.max(...prices) - Math.min(...prices)) / Math.min(...prices) * 100;
    if (spread > PRICE_DISPUTE_PC) {
      disputed.push({ symbol: sym, spreadPc: +spread.toFixed(2), sources: got.map(g => ({ src: g.src, price: g.price })) });
      continue;                                   // deliberately no price
    }
    merged[sym] = { ...got[0], sources: got.map(g => g.src), agreement: 'agreed', spreadPc: +spread.toFixed(2) };
  }
  return { merged, disputed };
}

/* ───────── /api/prices ───────── */
app.get('/api/prices', async (req, res) => {
  const symbols = String(req.query.symbols || 'VOO,QQQ,NVDA,MSFT,VXUS,SCHD')
    .split(',').map(s => s.trim().toUpperCase()).filter(s => /^[A-Z0-9.\-]{1,12}$/.test(s))
    .filter((v, i, a) => a.indexOf(v) === i).sort().slice(0, 25);
  /* Sorted + de-duplicated + shape-validated: the cache key is built from this list, so
   * permutations previously minted separate entries and junk symbols could mint unlimited ones. */

  const live = livePriceSources();
  if (!live.length) {
    return res.json({ prices: {}, sources: [], covered: [], unavailable: symbols, disputed: [],
      note: 'No price source configured (set FINNHUB_API_KEY).', ts: Date.now() });
  }

  try {
    const data = await cached('prices:' + symbols.join(','), 30000, async () => {
      const bySource = {};
      await Promise.all(live.map(async n => { bySource[n] = await PRICE_SOURCES[n].fetch(symbols); }));
      const { merged, disputed } = mergeQuotes(bySource);

      /* Record ONLY on a cache miss. A served cache hit is the same observation again;
       * counting it would inflate the observation count and make the history look denser
       * than the evidence actually is. */
      recordPrices(merged, live.join('+')).catch(() => {});

      const covered = Object.keys(merged);
      /* Explicit, not implied. Previously a symbol the feed could not serve was simply
       * absent from the response, so the caller could not distinguish "no coverage" from
       * "not requested". Non-US listings hit this constantly on Finnhub's free tier. */
      const unavailable = symbols.filter(x => !merged[x] && !disputed.some(d => d.symbol === x));
      return {
        prices: merged, sources: live, covered, unavailable,
        disputed,
        coverageNote: live.map(n => n + ': ' + PRICE_SOURCES[n].covers).join(' · ')
      };
    });
    const now = Date.now();
    const open = usMarketLikelyOpen();
    // Only meaningful while a session is running. Outside one, age is expected, not a fault.
    const stale = open
      ? Object.entries(data.prices || {}).filter(([, q]) => q.asOf && (now - q.asOf) > PRICE_STALE_MS).map(([k]) => k)
      : [];
    res.json({ ...data, stale, marketOpen: open, staleAfterMs: PRICE_STALE_MS,
      marketNote: open ? null : 'US session closed — these are last-close prices, not stale data.',
      ts: now });
  } catch (e) {
    res.json({ prices: {}, sources: live, covered: [], unavailable: symbols, disputed: [],
      error: publicErr('prices', e), ts: Date.now() });
  }
});

/* ───────── /api/price-history ─────────
 * Serves what was actually observed. Days with no observation have no row and are simply
 * absent — nothing is interpolated, averaged or carried forward. A gap is shown as a gap.
 * See the migration comment: these are observations, NOT exchange OHLC bars. */
app.get('/api/price-history', async (req, res) => {
  const symbol = String(req.query.symbol || '').trim().toUpperCase();
  const days = Math.min(365, Math.max(1, +req.query.days || 90));
  if (!/^[A-Z0-9.\-]{1,12}$/.test(symbol)) return res.status(400).json({ error: 'symbol required' });
  if (!sbOn()) return res.json({ symbol, rows: [], note: 'No durable store configured.', ts: Date.now() });
  try {
    const r = await fetch(`${SB_URL}/rest/v1/price_observations?symbol=eq.${encodeURIComponent(symbol)}&select=*&order=day.desc&limit=${days}`, { headers: sbHeaders(false) });
    if (!r.ok) throw new Error('supabase ' + r.status + ' ' + (await r.text()).slice(0, 120));
    const rows = (await r.json()).reverse();
    res.json({
      symbol, rows, count: rows.length,
      note: 'Observed prices, not exchange OHLC. first_seen_price is the first quote this system saw that day, not the market open.',
      ts: Date.now()
    });
  } catch (e) {
    logUpstream('price-history', e);
    res.status(502).json({ symbol, rows: [], error: shortReason(String((e && e.message) || e)), ts: Date.now() });
  }
});


/* Stooq provider probe REMOVED 14 Aug 2026 (ruling 9). It answered its question:
 * every request returned an identical 796-byte JavaScript browser-verification page with
 * HTTP 200 — Stooq is unreachable from a server, and a naive r.ok check would have ingested
 * that HTML as price data. Dead experimental price infrastructure is not left running.
 * Finding recorded in claude/price-provider-inspection-2026-08-08.md.                    */


/* ───────── /api/market ───────── */
app.get('/api/market', async (req, res) => {
  try {
    const data = await cached('market', 60000, async () => {
      const [spx, ndx, vix, y2, y10, dxy] = await Promise.all([
        fredLatest('SP500').catch(() => null),
        fredLatest('NASDAQCOM').catch(() => null),
        fredLatest('VIXCLS').catch(() => null),
        fredLatest('DGS2').catch(() => null),
        fredLatest('DGS10').catch(() => null),
        fredLatest('DTWEXBGS').catch(() => null)
      ]);
      return { spx, ndx, vix, y2, y10, dxy, source: FRED ? 'fred' : 'none' };
    });
    res.json({ ...data, note: 'FRED values are daily close (may lag intraday).', ts: Date.now() });
  } catch (e) { res.json({ error: publicErr('market', e), ts: Date.now() }); }
});

/* ───────── /api/macro ───────── */
async function cpiYoY() {
  // CPIAUCSL is a monthly index; YoY = latest vs 12 months prior
  const obs = await fredObs('CPIAUCSL', 14);
  const vals = obs.filter(o => o.value != null);
  if (vals.length < 13) return { cpi: null, cpiPrev: null };
  const cpi = +(((vals[0].value / vals[12].value) - 1) * 100).toFixed(1);
  const cpiPrev = vals.length > 13 ? +(((vals[1].value / vals[13].value) - 1) * 100).toFixed(1) : null;
  return { cpi, cpiPrev };
}
async function fearGreed() {
  // CNN's index has no official API; this unofficial endpoint is best-effort.
  try {
    const j = await getJson('https://production.dataviz.cnn.io/index/fearandgreed/graphdata', {
      headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json' }
    }, 7000);
    const s = j && j.fear_and_greed && j.fear_and_greed.score;
    return s != null ? Math.round(s) : null;
  } catch (_) { return null; }
}
app.get('/api/macro', async (req, res) => {
  try {
    const data = await cached('macro', 6 * 3600000, async () => {
      const [{ cpi, cpiPrev }, fedRate, fg] = await Promise.all([
        cpiYoY().catch(() => ({ cpi: null, cpiPrev: null })),
        fredLatest('DFF').catch(() => null),   // effective fed funds rate, daily
        fearGreed()
      ]);
      return {
        cpi, cpiPrev,
        fedRate: fedRate != null ? +fedRate.toFixed(2) : null,
        cutProb: null,   // no reliable free source (CME FedWatch is gated) — keep manual
        fg,
        breadth: null,   // no reliable free source — keep manual
        source: FRED ? 'fred+cnn' : 'cnn'
      };
    });
    res.json({ ...data, ts: Date.now() });
  } catch (e) { res.json({ error: publicErr('macro', e), ts: Date.now() }); }
});

/* ───────── /api/events ───────── */
async function earningsDate(symbol) {
  if (!FINNHUB) return null;
  const today = new Date().toISOString().slice(0, 10);
  const to = new Date(Date.now() + 120 * 86400000).toISOString().slice(0, 10);
  try {
    const j = await getJson(`https://finnhub.io/api/v1/calendar/earnings?from=${today}&to=${to}&symbol=${symbol}&token=${FINNHUB}`);
    const arr = (j.earningsCalendar || []).filter(e => e.date >= today).sort((a, b) => a.date.localeCompare(b.date));
    return arr.length ? arr[0].date : null;
  } catch (_) { return null; }
}
app.get('/api/events', async (req, res) => {
  try {
    const data = await cached('events', 6 * 3600000, async () => {
      const [nvda, msft] = await Promise.all([earningsDate('NVDA'), earningsDate('MSFT')]);
      // Macro release dates need a paid economic calendar; left blank for you to set
      // in the dashboard. Earnings come straight from Finnhub when a key is present.
      const events = [
        { name: 'US CPI', date: '', time: '13:30', impact: 'high', watch: 'Inflation print — drives the Fed.' },
        { name: 'US PPI', date: '', time: '13:30', impact: 'med', watch: 'Producer prices, CPI preview.' },
        { name: 'Jobs report (NFP)', date: '', time: '13:30', impact: 'high', watch: 'Labour strength vs rate cuts.' },
        { name: 'FOMC decision', date: '', time: '19:00', impact: 'high', watch: 'Rate decision + guidance.' },
        { name: 'NVDA earnings', date: nvda || '', time: '21:00', impact: 'high', watch: 'Your biggest single-stock risk.' },
        { name: 'MSFT earnings', date: msft || '', time: '21:00', impact: 'med', watch: 'Cloud + AI capex read.' }
      ];
      return { events, source: FINNHUB ? 'finnhub-earnings' : 'config', note: 'Macro release dates need manual entry (no free economic calendar).' };
    });
    res.json({ ...data, ts: Date.now() });
  } catch (e) { res.json({ events: [], error: publicErr('events', e), ts: Date.now() }); }
});

/* ───────── /api/news ───────── */
app.get('/api/news', async (req, res) => {
  try {
    const data = await cached('news', 5 * 60000, async () => {
      if (!FINNHUB) return { news: [], source: 'none' };
      const j = await getJson(`https://finnhub.io/api/v1/news?category=general&token=${FINNHUB}`);
      const news = (Array.isArray(j) ? j : []).slice(0, 8).map(n => ({
        headline: n.headline, source: n.source, url: n.url,
        datetime: n.datetime ? n.datetime * 1000 : null, summary: (n.summary || '').slice(0, 240)
      }));
      return { news, source: 'finnhub' };
    });
    res.json({ ...data, ts: Date.now() });
  } catch (e) { res.json({ news: [], error: publicErr('news', e), ts: Date.now() }); }
});

/* ───────── /api/portfolio (eToro READ-ONLY stub) ─────────
 * Read-only sync of holdings, value, cash and P/L. This NEVER places orders,
 * never requests trade/leverage/CFD scopes, and never executes anything.
 *
 * eToro's portfolio API requires approved read-only partner access, and the
 * exact response shape depends on that access. So the upstream URL + key are
 * env-configured and the response is run through a tolerant mapper. Until you
 * have access (or point ETORO_API_URL at your own read-only adapter), this
 * returns source:"manual" so the dashboard keeps using manual/last-known data.
 */
function n2(v) { const x = num(v); return x == null ? null : x; }
// NOTE: `crypto` is now required near the top, with the auth block (it is needed before the routes).
function etoroHeaders() {
  return { 'x-request-id': crypto.randomUUID(), 'x-api-key': ETORO_KEY, 'x-user-key': ETORO_USER_KEY, 'Accept': 'application/json' };
}
// Resolve eToro numeric instrument IDs -> ticker symbols (symbolFull). Cached long, since symbols don't change.
async function etoroSymbols(ids) {
  const out = {};
  const need = [];
  ids.forEach(id => { const hit = cache.get('etoroSym:' + id); if (hit && hit.exp > Date.now()) out[id] = hit.data; else need.push(id); });
  if (need.length) {
    const url = `${ETORO_BASE}/api/v1/market-data/instruments?instrumentIds=${need.join(',')}`;
    const j = await getJson(url, { headers: etoroHeaders() }, 12000);
    const arr = (j && (j.instrumentDisplayDatas || j.instruments)) || [];
    arr.forEach(d => {
      const id = d.instrumentID ?? d.instrumentId;
      const rec = { symbol: String(d.symbolFull || '').toUpperCase(), name: d.instrumentDisplayName || d.symbolFull || '' };
      if (id != null) { out[id] = rec; cache.set('etoroSym:' + id, { data: rec, exp: Date.now() + 86400000 }); }
    });
  }
  return out;
}
// Map eToro clientPortfolio -> our normalised portfolio. Long-only real-asset investor: value = invested + unrealised P/L.
// Estimate TODAY's P/L from each holding's market value × its live daily % move (Finnhub 'dp').
// Using value×percent (not units×per-share-change) keeps it scale-independent: eToro's dollar
// values are reliable, and a percentage can't be thrown off by eToro's unit scaling.
// Still an ESTIMATE — eToro's own figure uses its own pricing, so expect it within a dollar or two.
async function estimateTodayPl(holdings) {
  if (!FINNHUB || !Array.isArray(holdings) || !holdings.length) return { todayPlUsd: null, partial: false, covered: 0, total: 0 };
  let sum = 0, covered = 0;
  await Promise.all(holdings.map(async h => {
    const sym = String(h.symbol || '').toUpperCase();
    const val = n2(h.valueUsd);
    if (!sym || sym.startsWith('ID') || !val) return;
    try {
      const j = await getJson(`https://finnhub.io/api/v1/quote?symbol=${sym}&token=${FINNHUB}`);
      if (j && typeof j.dp === 'number' && j.c) {
        const dp = j.dp / 100;
        sum += val * dp / (1 + dp);   // today's $ change implied by this holding's % move on its current value
        covered++;
      }
    } catch (_) { /* skip this symbol */ }
  }));
  const total = holdings.filter(h => n2(h.valueUsd)).length;
  if (!covered) return { todayPlUsd: null, partial: true, covered: 0, total };
  return { todayPlUsd: +sum.toFixed(2), partial: covered < total, covered, total };
}

async function mapEtoroPnl(raw) {
  const cp = (raw && (raw.clientPortfolio || raw)) || {};
  const positions = Array.isArray(cp.positions) ? cp.positions : [];
  // aggregate positions by instrument
  const byId = {};
  positions.forEach(p => {
    const id = p.instrumentId ?? p.instrumentID;
    if (id == null) return;
    if (p.mirrorId || p.mirrorID) return;   // skip ONLY genuine copy/mirror positions (mirrorId 1,2,…); direct positions carry mirrorId 0/absent and must stay
    const cost = n2(p.initialAmountInDollars ?? p.amount ?? p.unitsBaseValueDollars) || 0;
    // eToro returns unrealizedPnL as a nested object { pnL, exposureInAccountCurrency, ... }; tolerate a plain number too.
    const u = p.unrealizedPnL;
    const uObj = (u && typeof u === 'object') ? u : null;
    const pnl = n2(uObj ? (uObj.pnL ?? uObj.pnlAssetCurrency) : (u ?? p.pnL ?? p.pnl ?? p.netProfit)) || 0;
    const exposure = uObj ? n2(uObj.exposureInAccountCurrency ?? uObj.exposureInAssetCurrency) : null;
    const value = exposure != null ? exposure : (cost + pnl);   // current market value
    const units = n2(p.units) || 0;
    const a = byId[id] || (byId[id] = { value: 0, units: 0, pl: 0 });
    a.value += value; a.units += units; a.pl += pnl;
  });
  const ids = Object.keys(byId);
  let symMap = {};
  try { if (ids.length) symMap = await etoroSymbols(ids); } catch (_) { /* symbols best-effort */ }
  const holdings = ids.map(id => {
    const a = byId[id], s = symMap[id] || {};
    const valueUsd = +(a.value).toFixed(2);
    const units = a.units;
    return {
      symbol: s.symbol || ('ID' + id), name: s.name || ('Instrument ' + id),
      units, currentPrice: units > 0 ? +(valueUsd / units).toFixed(4) : null,
      valueUsd, plUsd: +(a.pl).toFixed(2)
    };
  }).filter(h => h.valueUsd > 0);
  // Copy trades (copied investors) live in clientPortfolio.mirrors[], separate from direct positions.
  // Each copy is shown as one line at its net value = uninvested copy cash + value of its held positions.
  // units:1 / currentPrice:value so the front-end's units×price math reproduces the copy's value.
  const mirrors = Array.isArray(cp.mirrors) ? cp.mirrors : [];
  const mirrorHoldings = mirrors.map(m => {
    const mp = Array.isArray(m.positions) ? m.positions : [];
    let posVal = 0, posPl = 0;
    mp.forEach(p => {
      const u = p.unrealizedPnL; const uObj = (u && typeof u === 'object') ? u : null;
      const pnl = n2(uObj ? (uObj.pnL ?? uObj.pnlAssetCurrency) : (u ?? p.pnL ?? p.pnl ?? p.netProfit)) || 0;
      const exposure = uObj ? n2(uObj.exposureInAccountCurrency ?? uObj.exposureInAssetCurrency) : null;
      const cost = n2(p.initialAmountInDollars ?? p.amount ?? p.unitsBaseValueDollars) || 0;
      posVal += (exposure != null ? exposure : (cost + pnl)); posPl += pnl;
    });
    const value = +(((n2(m.availableAmount) || 0)) + posVal).toFixed(2);
    const idTag = (m.mirrorId ?? m.parentCid ?? m.cid ?? '');
    return { symbol: 'COPY' + idTag, name: 'Copy trade' + (idTag !== '' ? ' #' + idTag : ''), units: 1, currentPrice: value, valueUsd: value, plUsd: +posPl.toFixed(2), isCopy: true };
  }).filter(h => h.valueUsd > 0);
  const allHoldings = holdings.concat(mirrorHoldings);
  const cash = n2(cp.credit) || 0;   // 'credit' = funds available for new actions (buying power); bonusCredit excluded
  const cpPnl = cp.unrealizedPnL;
  const totalPl = (cpPnl && typeof cpPnl === 'object') ? n2(cpPnl.pnL ?? cpPnl.pnlAssetCurrency) : n2(cpPnl);
  // NOTE: the free price feed (Finnhub) reported today's per-stock % moves ~9x larger than reality
  // (it implied a ~1.8% drop when eToro showed the account flat at -0.08%), so estimateTodayPl gives
  // an untrustworthy figure. Rather than show a wrong number we leave Today P/L blank until it can be
  // sourced from eToro's own daily change. estimateTodayPl is kept below for when we revisit it.
  const out = normalisePortfolio({ holdings: allHoldings, availableCashUsd: cash, totalPlUsd: totalPl, todayPlUsd: null });
  out.todayPlEstimated = false; out.todayPlPartial = false; out.todayPlNote = 'pending accurate source (eToro daily change)';
  return out;
}
function normalisePortfolio(p) {
  const holdings = (p.holdings || []).map(h => {
    const units = n2(h.units), price = n2(h.currentPrice);
    const valueUsd = h.valueUsd != null ? n2(h.valueUsd) : (units != null && price != null ? units * price : null);
    return { symbol: h.symbol, name: h.name || h.symbol, units, currentPrice: price, valueUsd, plUsd: n2(h.plUsd), allocationPercent: null };
  });
  const cash = n2(p.availableCashUsd) || 0;
  const invested = holdings.reduce((s, h) => s + (h.valueUsd || 0), 0);
  const total = invested + cash;
  const allocationPercentages = {};
  holdings.forEach(h => { h.allocationPercent = total > 0 ? +(((h.valueUsd || 0) / total) * 100).toFixed(2) : 0; allocationPercentages[h.symbol] = h.allocationPercent; });
  allocationPercentages.CASH = total > 0 ? +((cash / total) * 100).toFixed(2) : 0;
  const totalPl = p.totalPlUsd != null ? n2(p.totalPlUsd) : holdings.reduce((s, h) => s + (h.plUsd || 0), 0);
  return {
    portfolioValueUsd: +total.toFixed(2),
    availableCashUsd: +cash.toFixed(2),
    todayPlUsd: n2(p.todayPlUsd),
    totalPlUsd: totalPl,
    holdings, allocationPercentages,
    lastUpdated: new Date().toISOString()
  };
}

app.get('/api/portfolio', async (req, res) => {
  if (!ETORO_ON) {
    return res.json({
      source: 'manual', connected: false,
      note: 'eToro read-only not configured. Set ETORO_API_KEY + ETORO_USER_KEY (read-only) to enable. Dashboard uses manual/last-known data.',
      portfolioValueUsd: null, availableCashUsd: null, todayPlUsd: null, totalPlUsd: null,
      holdings: [], allocationPercentages: {}, lastUpdated: null, ts: Date.now()
    });
  }
  try {
    const data = await cached('portfolio', 60000, async () => {
      // READ-ONLY request to eToro's PnL/portfolio endpoint. No order/trade endpoints are ever called.
      const raw = await getJson(`${ETORO_BASE}/api/v1/trading/info/${ETORO_ENV}/pnl`, { headers: etoroHeaders() }, 15000);
      return mapEtoroPnl(raw);
    });
    res.json({ ...data, source: 'etoro', connected: true, env: ETORO_ENV, ts: Date.now() });
  } catch (e) {
    res.json({
      source: 'manual', connected: false, error: (logUpstream('portfolio', e), shortReason(String((e && e.message) || e))),
      note: 'eToro sync unavailable — using manual/last known data.',
      holdings: [], allocationPercentages: {}, ts: Date.now()
    });
  }
});

/* ───────── Phase 3: AI Committee (adversarial + synthesiser) ───────── */
const fs = require('fs');
const path = require('path');
const PROMPT_DIR = path.join(__dirname, 'prompts');
const VERDICTS = ['BUY AGGRESSIVELY', 'DEPLOY ON PLAN', 'BUY GRADUALLY', 'WATCH', 'HOLD', 'WAIT', 'REDUCE RISK'];
const STANCE = { 'BUY AGGRESSIVELY': 6, 'DEPLOY ON PLAN': 5, 'BUY GRADUALLY': 4, 'WATCH': 3, 'HOLD': 2, 'WAIT': 1, 'REDUCE RISK': 0 };
// The Devil's Advocate may only ever pick from these — it is structurally barred from recommending buying.
const DEFENSIVE_VERDICTS = ['WATCH', 'HOLD', 'WAIT', 'REDUCE RISK'];
function coerceDefensive(v) { return DEFENSIVE_VERDICTS.includes(v) ? v : 'WAIT'; }
// Shared rubric so every seat (and the chair) uses the ladder the same way.
const VERDICT_GUIDE = '\n\nVERDICT LADDER (use these exact words):\n' +
  '- DEPLOY ON PLAN: routine — proceed with the written Investment Policy as scheduled. This is maintenance, not aggression.\n' +
  '- BUY GRADUALLY: ease in over several tranches rather than all at once.\n' +
  '- WATCH: conditions mixed; prepare but wait for a specific trigger.\n' +
  '- HOLD: do nothing; stay the course.\n' +
  '- WAIT: deliberately keep cash; a known event or risk justifies patience.\n' +
  '- REDUCE RISK: trim exposure or raise cash.\n' +
  '- BUY AGGRESSIVELY: RESERVED for genuine market dislocations only (deep drawdown, VIX spike, extreme fear). Do NOT use it for ordinary rebalancing or deploying idle cash.';

// Built-in fallbacks used only if a prompt file is missing.
const DEFAULTS = {
  'system-investing.md': 'You advise Andrew Collins, a long-term eToro ETF/stock investor in Bahrain. Advice only — never place trades, never suggest leverage/CFDs/options/shorting/crypto. '
    + 'His written Investment Policy is the primary authority: Monthly Plan = BHD500 into ISAC.L, ON POLICY. There are NO target allocation percentages; current composition is DESCRIPTIVE only. '
    + 'Never recommend a rebalance, a target allocation, or redirecting the Monthly Plan because weights differ. Your role is to identify genuine EXCEPTIONS to the policy, not to design a better portfolio. '
    + 'Treasury Bills and Savings are ring-fenced and non-deployable — never treat them as available capital. Be blunt and decision-led.',
  'deep-triggers.md': 'From your role, give a blunt independent read of the current position, market, the biggest risk, the best opportunity, and whether conditions justify an exception to the written Investment Policy today. Do not propose a target allocation or a rebalance. End with ONE verdict.',
  roles: {
    pm: 'Portfolio Manager. Focus on whether the written Investment Policy should proceed as scheduled, sizing of any discretionary deployment, and long-term compounding. There are no target weights to hit \\u2014 do not propose a target allocation or a rebalance. Pragmatic, action-oriented.',
    risk: 'Risk Manager. Assess portfolio-specific risk: concentration (single names like NVDA/AIA), diversification, drawdown capacity and position sizing. Constructive but cautious.',
    macro: 'Macro Analyst. Read the VIX, yields, the yield curve, CPI and the Fed, plus any headlines/catalysts in the packet. Judge the regime and whether conditions favour deploying or waiting.',
    news: 'News / Research Analyst. Weigh the headlines and catalysts in the packet. Separate signal from noise; flag anything that genuinely changes the picture.',
    devil: 'Devil\u2019s Advocate. You exist to STOP a bad decision. Make the strongest possible case AGAINST the majority recommendation every time — never endorse buying. Argue: why hold cash, why valuations (e.g. VOO) may be rich, why inflation could stay sticky, why the opportunity score may be misleading, and the single most likely way the committee is wrong.',
    synthesiser: 'You are the chair. Judge which argument is strongest given the data — do not average or vote. One seat is a mandated Devil\u2019s Advocate; weigh its case honestly on merit (do not dismiss it), but recognise its stance is structurally bearish. Make one decisive call.',
    idiotGuideStyle: 'Plain, blunt, no jargon. Concrete numeric actions.'
  }
};
const _pcache = {};
const _psource = {};   // step 7: 'file' when an override exists on disk, 'default' when built-in
function loadPrompt(file) {
  try {
    const fp = path.join(PROMPT_DIR, file);
    const st = fs.statSync(fp);
    const c = _pcache[file];
    if (c && c.mt === st.mtimeMs) { _psource[file] = 'file'; return c.data; }   // serve cached unless the file changed
    const txt = fs.readFileSync(fp, 'utf8');
    _pcache[file] = { mt: st.mtimeMs, data: txt };
    _psource[file] = 'file';
    return txt;
  } catch (_) { _psource[file] = 'default'; return DEFAULTS[file] || ''; }
}
function loadRoles() {
  const txt = loadPrompt('ai-roles.json');
  if (txt) { try { return Object.assign({}, DEFAULTS.roles, JSON.parse(txt)); } catch (_) {} }
  return DEFAULTS.roles;
}
function roleLabel(role) { return { pm: 'portfolio mgr', risk: 'risk manager', macro: 'macro', news: 'news/research', devil: 'devil\u2019s advocate' }[role] || role || ''; }

function parseJsonLoose(text) {
  if (!text) return null;
  try { return JSON.parse(text); } catch (_) {}
  const a = text.indexOf('{'), b = text.lastIndexOf('}');
  if (a >= 0 && b > a) { try { return JSON.parse(text.slice(a, b + 1)); } catch (_) {} }
  return null;
}
function coerceVerdict(v) {
  if (!v) return null;
  const up = String(v).toUpperCase();
  return VERDICTS.find(x => up.includes(x)) || null;
}

// Each call takes (userContent, systemContent) so the handler controls the prompt.
async function callOpenAI(user, system, modelOverride) {
  const key = process.env.OPENAI_API_KEY; if (!key) return null;
  const j = await getJson('https://api.openai.com/v1/chat/completions', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
    body: JSON.stringify({ model: modelOverride || process.env.OPENAI_MODEL || 'gpt-4o-mini', temperature: 0.4, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] })
  }, 40000);
  return j.choices && j.choices[0] && j.choices[0].message.content;
}
async function callAnthropic(user, system, modelOverride) {
  const key = process.env.ANTHROPIC_API_KEY; if (!key) return null;
  const j = await getJson('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: modelOverride || process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5', max_tokens: 900, system, messages: [{ role: 'user', content: user }] })
  }, 40000);
  return j.content && j.content[0] && j.content[0].text;
}
// Multi-turn chat over Claude — sends the full conversation (not a single user turn) so the
// assistant remembers the thread. Used by /api/ask. Defaults to Sonnet 4.6 (best speed/quality balance).
// Chat (/api/ask) provider — defaults to Gemini so chat is free. Set CHAT_PROVIDER=anthropic to use Claude instead.
const CHAT_PROVIDER = (process.env.CHAT_PROVIDER || 'gemini').toLowerCase();
const CHAT_MODEL = process.env.CHAT_MODEL || (CHAT_PROVIDER === 'anthropic' ? (process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6') : (process.env.GEMINI_MODEL || 'gemini-2.5-flash'));
async function callAnthropicChat(messages, system, model) {
  const key = process.env.ANTHROPIC_API_KEY; if (!key) return null;
  const j = await getJson('https://api.anthropic.com/v1/messages', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: model || CHAT_MODEL, max_tokens: 1200, system, messages })
  }, 45000);
  return j.content && j.content.filter(b => b && b.type === 'text').map(b => b.text).join('\n');
}
async function callGemini(user, system, modelOverride, grounded) {
  const key = process.env.GEMINI_API_KEY; if (!key) return null;
  const model = modelOverride || process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const body = { contents: [{ parts: [{ text: system + '\n\n' + user }] }] };
  if (grounded) body.tools = [{ google_search: {} }];   // live Google Search grounding — real-time web/news, free up to 5k prompts/mo on 3.x
  const j = await getJson(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }, 40000);
  const c = j.candidates && j.candidates[0] && j.candidates[0].content;
  return c && c.parts && c.parts.map(p => p && p.text).filter(Boolean).join('\n');   // join all parts (grounded replies can be multi-part)
}
async function callOpenRouter(user, system, modelOverride) {
  const key = process.env.OPENROUTER_API_KEY; if (!key) return null;
  const j = await getJson('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key,
      'HTTP-Referer': 'https://investing-command-centre.local', 'X-Title': 'Investing Command Centre' },
    body: JSON.stringify({ model: modelOverride || process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.3-70b-instruct:free', temperature: 0.4, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] })
  }, 45000);
  return j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
}
async function callPerplexity(user, system, modelOverride) {
  const key = process.env.PERPLEXITY_API_KEY; if (!key) return null;
  const j = await getJson('https://api.perplexity.ai/chat/completions', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
    body: JSON.stringify({ model: modelOverride || process.env.PERPLEXITY_MODEL || 'sonar', temperature: 0.3, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] })
  }, 40000);
  return j.choices && j.choices[0] && j.choices[0].message.content;
}
async function callGrok(user, system, modelOverride) {
  const key = process.env.GROK_API_KEY || process.env.XAI_API_KEY; if (!key) return null;
  const body = { model: modelOverride || GROK_MODEL, temperature: 0.4, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] };
  // Live/web search is an opt-in PAID tool (~$5/1000 calls). Stays OFF unless GROK_LIVE_SEARCH=on.
  // When enabled later, confirm the current tool shape in xAI docs before relying on it.
  if (GROK_LIVE_SEARCH) body.tools = [{ type: 'web_search' }];
  const j = await getJson('https://api.x.ai/v1/chat/completions', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
    body: JSON.stringify(body)
  }, 45000);
  return j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
}
// Groq — free, no-credit-card inference (fast LPU hardware), OpenAI-compatible. Its own quota pool,
// separate from OpenRouter, so it keeps the committee independent when OpenRouter's free tier is spent.
// NOTE: this is GROQ (api.groq.com), not xAI's Grok above — different company, different key.
async function callGroq(user, system, modelOverride) {
  const key = process.env.GROQ_API_KEY; if (!key) return null;
  const j = await getJson('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key },
    body: JSON.stringify({ model: modelOverride || process.env.GROQ_MODEL || 'llama-3.3-70b-versatile', temperature: 0.4, messages: [{ role: 'system', content: system }, { role: 'user', content: user }] })
  }, 45000);
  return j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
}
// Multi-turn chat over Gemini (free tier) — used by /api/ask so chat costs nothing.
async function callGeminiChat(messages, system, model) {
  const key = process.env.GEMINI_API_KEY; if (!key) return null;
  const mdl = model || process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const contents = (messages || []).map(m => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] }));
  const j = await getJson(`https://generativelanguage.googleapis.com/v1beta/models/${mdl}:generateContent?key=${key}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents })
  }, 45000);
  return j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts && j.candidates[0].content.parts.map(p => p.text).filter(Boolean).join('\n');
}
// Provider router — one entry per provider. OpenRouter alone covers many model families.
const PROVIDERS = { openai: callOpenAI, anthropic: callAnthropic, gemini: callGemini, perplexity: callPerplexity, openrouter: callOpenRouter, groq: callGroq, xai: callGrok };
function providerHasKey(p) {
  return { openai: !!process.env.OPENAI_API_KEY, anthropic: !!process.env.ANTHROPIC_API_KEY, gemini: !!process.env.GEMINI_API_KEY, perplexity: !!process.env.PERPLEXITY_API_KEY, openrouter: !!process.env.OPENROUTER_API_KEY, groq: !!process.env.GROQ_API_KEY, xai: !!(process.env.GROK_API_KEY || process.env.XAI_API_KEY) }[p];
}
async function callProvider(provider, model, user, system) {
  const fn = PROVIDERS[provider]; if (!fn) return null;
  return fn(user, system, model);
}
// One attempt at a single model — never throws. Returns { ok, content, error }.
async function callSeatModel(provider, model, user, system) {
  try {
    const c = await callProvider(provider, model, user, system);
    if (c) return { ok: true, content: c };
    return { ok: false, error: providerHasKey(provider) ? 'empty response' : 'no API key' };
  } catch (e) {
    logUpstream('seat:' + provider + ':' + model, e);
    return { ok: false, error: String((e && e.message) || e).slice(0, 160) };
  }
}
// Try the seat's primary model (one retry), then its cross-provider fallback. Never throws.
// Returns { content, modelUsed, providerUsed, usedFallback, error }.
async function callWithFallback(seat, user, system) {
  const attempts = [];
  let r = await callSeatModel(seat.provider, seat.model, user, system);
  if (!r.ok) r = await callSeatModel(seat.provider, seat.model, user, system); // retry primary once
  if (r.ok) return { content: r.content, modelUsed: seat.model, providerUsed: seat.provider, usedFallback: false };
  attempts.push(seat.provider + ' ' + seat.model + ' → ' + r.error);
  if (seat.fallbackModel) {
    const fp = seat.fallbackProvider || seat.provider;
    if (providerHasKey(fp)) {
      const fr = await callSeatModel(fp, seat.fallbackModel, user, system);
      if (fr.ok) return { content: fr.content, modelUsed: seat.fallbackModel, providerUsed: fp, usedFallback: true };
      attempts.push('fallback ' + fp + ' ' + seat.fallbackModel + ' → ' + fr.error);
    } else {
      attempts.push('fallback ' + fp + ' → no API key');
    }
  }
  return { content: null, modelUsed: null, providerUsed: null, usedFallback: false, error: attempts.join(' | ') };
}
// Short, human-readable failure tag for the seat table.
function shortReason(r) {
  if (!r) return 'no response';
  if (/429|rate.?limit|quota|too many|exhaust/i.test(r)) return 'rate-limited / daily quota';
  if (/401|403|permission|unauthor|forbidden/i.test(r)) return 'auth / permission';
  if (/timeout|abort|timed? ?out/i.test(r)) return 'timeout';
  if (/empty response/i.test(r)) return 'empty reply';
  if (/no API key/i.test(r)) return 'no API key';
  if (/5\d\d/.test(r)) return 'provider error (5xx)';
  // Was: return r.slice(0, 70) — a raw dump of upstream text. Classify instead; the full
  // string is in the Render log. "provider quota exceeded" is the diagnostic that matters
  // and it is preserved above; this branch only catches genuinely novel failures.
  return 'provider error (unclassified \u2014 see server log)';
}

// Committee seats — genuine diversity = different model FAMILIES + different roles.
// Fully config-driven: set COMMITTEE_SEATS (a JSON array) in the environment to add/remove
// models with NO code change. Seats whose provider has no key are skipped automatically.
const DEFAULT_SEATS = [
  { seat: 'Portfolio Manager', role: 'pm',    provider: 'gemini',     model: 'gemini-2.5-flash',                         fallbackProvider: 'groq',       fallbackModel: 'llama-3.3-70b-versatile' },
  { seat: 'Risk Manager',      role: 'risk',  provider: 'groq',       model: 'llama-3.3-70b-versatile',                 fallbackProvider: 'openrouter', fallbackModel: 'meta-llama/llama-3.3-70b-instruct:free' },
  { seat: 'Macro Analyst',     role: 'macro', provider: 'openrouter', model: 'meta-llama/llama-3.3-70b-instruct:free',  fallbackProvider: 'groq',       fallbackModel: 'llama-3.3-70b-versatile' },
  { seat: 'Devil\u2019s Advocate', role: 'devil', provider: 'openrouter', model: 'deepseek/deepseek-chat-v3.1:free',    fallbackProvider: 'groq',       fallbackModel: 'llama-3.3-70b-versatile' }
];
function loadSeats() {
  const env = process.env.COMMITTEE_SEATS;
  if (env) { try { const a = JSON.parse(env); if (Array.isArray(a) && a.length) return a; } catch (_) {} }
  return DEFAULT_SEATS;
}
// Synthesiser: prefer an explicit env choice, else Gemini (reliable), else the first seat with a key.
function pickSynth(seats) {
  const ep = process.env.SYNTH_PROVIDER, em = process.env.SYNTH_MODEL;
  if (ep && providerHasKey(ep)) return { seat: 'Chair', provider: ep, model: em || undefined };
  if (providerHasKey('gemini')) return { seat: 'Chair', provider: 'gemini', model: process.env.GEMINI_MODEL || 'gemini-2.5-flash' };
  const s = seats.find(x => providerHasKey(x.provider));
  return s ? { seat: 'Chair', provider: s.provider, model: s.model } : null;
}
const DEBATE_ROUNDS = Math.max(1, Math.min(2, +process.env.DEBATE_ROUNDS || 2));

// Compact summary of the committee's own recent history, injected into the prompt.
function memDate(ts) { try { return new Date(ts).toISOString().slice(0, 10); } catch (_) { return '?'; } }
function buildMemory(runs, journal) {
  const lines = [];
  if (Array.isArray(runs) && runs.length) {
    lines.push('RECENT COMMITTEE VERDICTS (oldest first):');
    runs.slice(-6).forEach(r => {
      lines.push(`- ${memDate(r.ts)}: ${r.verdict || '?'} (agreement ${r.consensus != null ? r.consensus + '%' : '?'})${r.recommended ? '; rec: ' + String(r.recommended).slice(0, 90) : ''}`);
    });
  }
  if (Array.isArray(journal) && journal.length) {
    lines.push('WHAT WAS ADVISED vs WHAT ANDREW ACTUALLY DID:');
    journal.slice(-6).forEach(j => {
      lines.push(`- ${memDate(j.ts)}: advised "${String(j.recommended_action || '').slice(0, 70)}" | did "${String(j.actual_action || 'not logged').slice(0, 50)}"${j.outcome ? ` | outcome "${String(j.outcome).slice(0, 50)}"` : ''}`);
    });
  }
  if (!lines.length) return '';
  lines.unshift('COMMITTEE MEMORY — consider whether you keep making the same call while cash stays high, whether prior advice was acted on, and whether past calls look right in hindsight. The Devil\u2019s Advocate MUST flag stale repetition.');
  const s = lines.join('\n');
  return s.length > 1900 ? s.slice(0, 1900) : s;
}

const MODEL_ASK = '\n\nRespond ONLY with compact JSON, no markdown:\n{"verdict":"<one of: ' + VERDICTS.join(' | ') + '>","keyArgument":"<your single strongest point>","weakestAssumption":"<the weakest assumption in the optimistic case>","risk":"<the biggest risk being ignored>","deploy":"<exact $ split for new cash today, or WAIT FOR <event>>","reasoning":"<2-3 blunt sentences>"}';
const SYNTH_ASK = '\n\nYou MUST judge which argument is strongest. DO NOT average the verdicts and DO NOT just take the majority. Decide.\n\nRespond ONLY with compact JSON, no markdown:\n{"finalVerdict":"<one of: ' + VERDICTS.join(' | ') + '>","agree":["<points all/most models agree on>"],"disagree":["<genuine points of disagreement>"],"strongestArgument":"<which view is strongest and why>","weakestAssumption":"<the weakest assumption anyone is relying on>","riskWarning":"<one blunt sentence>","idiotGuide":{"do":["..."],"dont":["..."],"checkAgain":"..."}}';
const GEO_ASK = '\n\nYou are NOT a market analyst and you do NOT give buy/sell/hold advice. You never see the portfolio. Your ONLY job: name near-term (next 1\u20134 weeks) GLOBAL or GEOPOLITICAL events that could make the committee\u2019s verdict wrong \u2014 wars, sanctions, elections, oil/energy shocks, central-bank surprises, tariffs, major-power tensions.\n\nRespond ONLY with compact JSON, no markdown:\n{"summary":"<2 sentences on the geopolitical risk backdrop right now>","events":["<near-term event + date if known + why it matters to markets>","..."],"couldMakeWrong":"<the single scenario most likely to blindside the committee\u2019s verdict>","watch":"<the one headline or indicator to watch>"}';

// Dedicated Geopolitical Risk Officer brief. Same underlying model as a committee seat can use, but a
// DELIBERATELY different role and weighting — perspective diversity, not model diversity. It assumes the
// consensus is complacent and over-weights low-probability/high-impact tail risk.
const GEO_MODEL = process.env.GEO_MODEL || 'gemini-3.5-flash';   // 3.x family gets 5,000 free grounded prompts/month; independent of GEMINI_MODEL
const GEO_SYS = 'You are the GEOPOLITICAL RISK OFFICER on an investment committee \u2014 a distinct seat, deliberately NOT a portfolio manager and NOT a markets analyst. Your lens is geopolitics, macro-strategy and tail risk. You think like a sovereign-risk desk: assume the market consensus is complacent and your job is to surface what it is ignoring. You weight low-probability, high-impact events (wars, blockades, sanctions, energy shocks, central-bank surprises, election/regime shocks, major-power escalation) more heavily than a markets analyst would. You have LIVE Google Search access \u2014 base your read on the most recent real headlines from the last few days, not on prior knowledge, and prefer concrete dated developments over generic risks. You never see the portfolio and you never give buy/sell/hold advice.' + GEO_ASK;
// Gemini can throw a transient "HTTP 503 ... high demand" when overloaded. The Geo Officer retries
// these capacity/rate errors with exponential backoff before giving up. Resilience only — this path
// NEVER touches the committee verdict. Permanent errors (4xx) and timeouts are NOT retried, so the
// overall request stays inside its time budget.
const GEO_BACKOFF_MS = [2000, 5000, 10000];
function geoIsTransient(msg) { return /HTTP\s+(429|5\d\d)/.test(String(msg || '')); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Geopolitical Risk Officer (Gemini, dedicated geopolitical prompt). Runs independently of the committee —
// geopolitical risk exists whether or not the 4 seats responded. NEVER receives portfolio holdings/history.
async function runGeoOfficer(geoPacket, verdict, ROLES) {
  if (!providerHasKey('gemini') || typeof geoPacket !== 'string' || !geoPacket.trim()) return null;
  const geoUser = 'MACRO / MARKET / NEWS CONTEXT (no portfolio data):\n' + geoPacket +
    '\n\nThe committee\u2019s current verdict: ' + (verdict || 'no verdict (committee unavailable this run)') +
    '.\nName the near-term global/geopolitical events that could make a deploy-or-wait decision wrong right now, and the one thing to watch.';
  // Attempt 1 immediately, then retry transient (429/5xx) failures after 2s, 5s, 10s.
  let raw = null;
  const delays = [0].concat(GEO_BACKOFF_MS);
  for (let i = 0; i < delays.length; i++) {
    if (delays[i]) await sleep(delays[i]);
    try {
      raw = await callGemini(geoUser, GEO_SYS, GEO_MODEL, true);   // grounded = live Google Search
      break;
    } catch (e) {
      const msg = String((e && e.message) || e);
      const last = i === delays.length - 1;
      if (!last && geoIsTransient(msg)) continue;
      const tries = i + 1;
      logUpstream('geo', msg);
      // Classified, not dumped (step 3). This is the path that produces the visible
      // "quota exhausted" signal, so it must stay informative — shortReason maps both
      // 429 and the word "quota" to 'rate-limited / daily quota'.
      return { error: shortReason(msg) + (tries > 1 ? ' (after ' + tries + ' attempts)' : ''), by: 'gemini', model: GEO_MODEL, attempts: tries };
    }
  }
  if (!raw) return { error: 'Geopolitical Officer (Gemini) returned an empty response.', by: 'gemini', model: GEO_MODEL };
  const g = parseJsonLoose(raw);
  if (!g) return { error: 'Geopolitical Officer replied but not in the expected JSON format.', note: String(raw).slice(0, 240), by: 'gemini', model: GEO_MODEL };
  return {
    summary: g.summary || '', events: Array.isArray(g.events) ? g.events.slice(0, 5) : [],
    couldMakeWrong: g.couldMakeWrong || '', watch: g.watch || '',
    by: 'gemini', model: GEO_MODEL
  };
}

/* ── DEEP TRIGGERS RESULT CACHE (V2 §3.8, Ruling 5) ────────────────────────────
 * Purpose: protect free-tier provider quota across page reloads and devices. That is
 * why it lives here and not in the browser — a frontend cache dies on refresh.
 *
 * TTL 25 minutes. VISIBLE, never silent: every served hit carries cached/cachedAt/ageMs
 * so the frontend can say "Using analysis from 8 minutes ago" and offer a fresh run.
 *
 * Key = hash(normalised packet) + bucket + seat fingerprint.
 *   - The packet's first line is a fresh ISO timestamp on every build, so hashing it raw
 *     would give a 0% hit rate — a cache that looks like it works and silently does
 *     nothing. NORM_PACKET strips volatile lines before hashing.
 *   - Bucket is mandatory: the resolver returns DIFFERENT actions for the same verdict
 *     depending on bucket, so a Monthly Plan run must never be replayed for Broker Cash
 *     or the Opportunity Reserve.
 *   - Seat fingerprint: if the seat/model configuration changes, past results don't apply.
 *
 * NEVER caches a failed or empty run. A quota-exhausted "no seats responded" result must
 * not be served for 25 minutes dressed up as analysis — that is the opposite of the point,
 * and an honest "no verdict" has to stay honest.
 *
 * In-memory by design. Render free instances sleep, so this is opportunistic, not
 * guaranteed: a cold start empties it. It still solves repeated runs within a session.  */
const DEEP_TTL_MS = 25 * 60 * 1000;
const DEEP_CACHE = new Map();

function normPacket(p) {
  return String(p)
    .split('\n')
    .filter(l => !/^MARKET BRIEFING PACKET/i.test(l))   // volatile: carries a fresh ISO timestamp
    .join('\n')
    .trim();
}
function deepCacheKey(packet, cashContext, seats) {
  const bucket = (cashContext && cashContext.bucket) || 'none';
  const seatFp = seats.map(x => x.seat + ':' + x.provider + ':' + x.model).sort().join('|');
  return crypto.createHash('sha256')
    .update(normPacket(packet) + '\u0000' + bucket + '\u0000' + seatFp)
    .digest('hex');
}
function deepCacheGet(key) {
  const hit = DEEP_CACHE.get(key);
  if (!hit) return null;
  const age = Date.now() - hit.ts;
  if (age > DEEP_TTL_MS) { DEEP_CACHE.delete(key); return null; }
  return { data: hit.data, ageMs: age, cachedAt: hit.ts };
}
function deepCacheSet(key, data) {
  // Refuse to cache a degraded run — an empty committee is not a result worth replaying.
  if (!data || !Array.isArray(data.models) || !data.models.length) return false;
  if (data.seatsResponded === 0) return false;
  DEEP_CACHE.set(key, { ts: Date.now(), data });
  if (DEEP_CACHE.size > 40) {           // cheap sweep: drop anything already expired
    const now = Date.now();
    for (const [k, v] of DEEP_CACHE) if (now - v.ts > DEEP_TTL_MS) DEEP_CACHE.delete(k);
  }
  return true;
}

app.post('/api/deep-triggers', async (req, res) => {
  const packet = req.body && req.body.packet;
  const cashContext = (req.body && req.body.cashContext) || null; // {bucket:'plan'|'discretionary'|'drypowder', amount?, monthlyLimit?}; ring-fenced cash is never sent
  const forceFresh = !!(req.body && req.body.fresh);
  if (!packet || typeof packet !== 'string') return res.status(400).json({ error: 'missing packet' });

  const TASK = loadPrompt('deep-triggers.md');
  const ROLES = loadRoles();
  const seats = loadSeats().filter(s => providerHasKey(s.provider));

  // Cache lookup happens AFTER seats are known so the key reflects the live seat config.
  const CACHE_KEY = deepCacheKey(packet, cashContext, seats);
  if (!forceFresh) {
    const hit = deepCacheGet(CACHE_KEY);
    if (hit) {
      return res.json(Object.assign({}, hit.data, {
        cached: true, cachedAt: hit.cachedAt, ageMs: hit.ageMs, ttlMs: DEEP_TTL_MS
      }));
    }
  }

  // Daily cap is checked only once a cache miss is certain: a served cache hit makes no
  // upstream call, so charging it against the allowance would be wrong.
  const capDT = await bumpUsage('deep-triggers');
  if (!capDT.allowed) return res.status(429).json({ error: 'daily_limit_reached', used: capDT.used, cap: capDT.cap, note: 'Daily Deep Triggers allowance reached. It resets at midnight UTC.' });

  // Committee memory — feed the committee its own recent track record so it can self-critique
  // (repeating the same call? was advice acted on? did past calls look right?). Best-effort.
  let MEMORY = '';
  if (sbOn()) {
    try {
      const [runs, journal] = await Promise.all([
        sbRead('committee_runs', 8).catch(() => []),
        sbRead('journal', 8).catch(() => [])
      ]);
      MEMORY = buildMemory(runs, journal);
    } catch (e) { logUpstream('memory:read', e); /* no memory this run */ }
  }
  const SYSTEM = loadPrompt('system-investing.md') + VERDICT_GUIDE + (MEMORY ? '\n\n' + MEMORY : '');

  // ROUND 1 — independent views. Each seat (a distinct model family) reads the same packet in its own role.
  const r1 = await Promise.allSettled(seats.map(async s => {
    const isDevil = s.role === 'devil';
    const mandate = (ROLES[s.role] || ROLES[s.seat] || '') +
      (isDevil ? '\n\nYou may ONLY choose a verdict from: WATCH, HOLD, WAIT, REDUCE RISK. You never endorse buying. Make the bear case as strong as it can honestly be.' : '');
    const system = SYSTEM + '\n\nYOUR SEAT: ' + s.seat + '\nYOUR MANDATE: ' + mandate + '\n\n' + TASK + MODEL_ASK;
    const res = await callWithFallback(s, packet, system);
    if (!res.content) return { __failed: true, seat: s.seat, role: roleLabel(s.role), provider: s.provider, model: s.model, isDevil, reason: res.error || 'no response' };
    const p = parseJsonLoose(res.content) || {};
    let verdict = coerceVerdict(p.verdict) || coerceVerdict(res.content);
    if (isDevil) verdict = coerceDefensive(verdict);
    return {
      name: s.seat, seat: s.seat, role: roleLabel(s.role), isDevil, provider: s.provider, model: s.model,
      modelUsed: res.modelUsed, providerUsed: res.providerUsed, usedFallback: res.usedFallback,
      verdict, independentVerdict: verdict,
      keyArgument: p.keyArgument || '', weakestAssumption: p.weakestAssumption || '',
      risk: p.risk || '', deploy: p.deploy || '',
      text: p.reasoning || (typeof res.content === 'string' ? res.content.slice(0, 600) : '')
    };
  }));
  const r1res = r1.map(r => r.status === 'fulfilled' ? r.value : null).filter(Boolean);
  let models = r1res.filter(v => !v.__failed);
  const failures = {}; r1res.filter(v => v.__failed).forEach(v => { failures[v.seat] = v.reason; });
  const buildSeatStatus = () => seats.map(s => {
    const m = models.find(x => x.seat === s.seat);
    return {
      seat: s.seat, role: roleLabel(s.role), provider: s.provider, model: s.model,
      fallbackModel: s.fallbackModel || null, isDevil: s.role === 'devil',
      status: m ? 'ok' : 'failed',
      modelUsed: m ? (m.modelUsed || s.model) : null,
      providerUsed: m ? (m.providerUsed || s.provider) : null,
      usedFallback: m ? !!m.usedFallback : false,
      verdict: m ? m.verdict : null, independentVerdict: m ? m.independentVerdict : null,
      // reasonDetail (raw upstream body) REMOVED step 3 — `reason` above is the classified
      // form and carries the same signal. Raw text goes to the Render log only.
      reason: m ? null : shortReason(failures[s.seat])
    };
  });
  if (!models.length) {
    // Committee unavailable (e.g. all free seats rate-limited), but the Geopolitical Risk Officer is
    // independent and on a separate provider — still run it so the user gets the external-risk read.
    const geoRisk = await runGeoOfficer(req.body && req.body.geoPacket, null, ROLES);
    return res.json({ models: [], consensus: 0, verdict: null, agree: [], disagree: [], strongestArgument: '', weakestAssumption: '', risk: 'No committee models responded (often the free-tier daily limit). Add OPENROUTER_API_KEY and/or GEMINI_API_KEY, or wait for the quota to reset.', ifIHad1000: null, idiotGuide: null, synthesised: false, seatsConfigured: seats.length, seatsResponded: 0, seatStatus: buildSeatStatus(), tally: {}, geoRisk, ts: Date.now() });
  }

  // ROUND 2 — rebuttal. Each seat sees the others' round-1 arguments and challenges the weakest.
  // The Devil's Advocate is told explicitly to attack the consensus. Best-effort: a failed rebuttal keeps the round-1 view.
  if (DEBATE_ROUNDS >= 2 && models.length >= 2) {
    const r2 = await Promise.allSettled(models.map(async v => {
      const s = seats.find(x => x.seat === v.seat) || {};
      const isDevil = s.role === 'devil';
      const others = models.filter(o => o.seat !== v.seat).map(o => ({ seat: o.seat, verdict: o.verdict, keyArgument: o.keyArgument, risk: o.risk }));
      const system = SYSTEM + '\n\nYOUR SEAT: ' + v.seat + '\nYOUR MANDATE: ' + (ROLES[s.role] || '') +
        (isDevil ? '\n\nYou are the DEVIL\u2019S ADVOCATE. Attack the emerging consensus. Name what the others are ignoring. Do not soften and do not endorse buying. Verdict must be one of: WATCH, HOLD, WAIT, REDUCE RISK.' : '\n\nThe other members have spoken. Challenge the single weakest argument among them, then state your FINAL position — change it only if genuinely persuaded.') +
        '\n\nOTHER MEMBERS\u2019 VIEWS:\n' + JSON.stringify(others) + '\n\n' + TASK + MODEL_ASK;
      const res = await callWithFallback(s, packet, system);
      if (!res.content) return v;   // keep the round-1 view if the rebuttal can't be produced
      const p = parseJsonLoose(res.content) || {};
      let verdict = coerceVerdict(p.verdict) || v.verdict;
      if (isDevil) verdict = coerceDefensive(verdict);
      return Object.assign({}, v, {
        verdict, modelUsed: res.modelUsed || v.modelUsed, providerUsed: res.providerUsed || v.providerUsed,
        usedFallback: res.usedFallback || v.usedFallback,
        keyArgument: p.keyArgument || v.keyArgument,
        weakestAssumption: p.weakestAssumption || v.weakestAssumption,
        risk: p.risk || v.risk, deploy: p.deploy || v.deploy,
        text: p.reasoning || v.text, rebutted: true
      });
    }));
    models = r2.map((r, i) => r.status === 'fulfilled' ? r.value : models[i]);
  }

  // consensus = how much the seats agree after debate (NOT the final call)
  const verdicts = models.map(m => m.verdict).filter(Boolean);
  const tally = {}; verdicts.forEach(v => tally[v] = (tally[v] || 0) + 1);
  let top = null, topN = 0;
  Object.entries(tally).forEach(([k, n]) => { if (n > topN || (n === topN && top && STANCE[k] < STANCE[top])) { top = k; topN = n; } });
  const consensus = verdicts.length ? Math.round(topN / verdicts.length * 100) : 0;

  // Seat status — covers EVERY configured seat, so a seat that failed/timed out is shown as 'failed'
  // (instead of silently dropping out and making the survivors look like 100% agreement).
  const seatStatus = buildSeatStatus();
  const seatsConfigured = seats.length, seatsResponded = models.length;

  // SYNTHESIS — the chair judges the strongest argument and makes ONE decisive call (does not average).
  let synth = null;
  const synthModel = pickSynth(seats);
  if (synthModel) {
    try {
      const system = SYSTEM + '\n\nYOU ARE THE COMMITTEE CHAIR / SYNTHESISER.\n' + (ROLES.synthesiser || '') + '\n\nIdiot\'s Guide style: ' + (ROLES.idiotGuideStyle || '') + SYNTH_ASK;
      const absent = seatStatus.filter(s => s.status === 'failed').map(s => s.seat);
      const user = 'DATA PACKET:\n' + packet + '\n\nCOMMITTEE VIEWS (after debate):\n' + JSON.stringify(models.map(m => ({ seat: m.seat, model: m.model, verdict: m.verdict, keyArgument: m.keyArgument, weakestAssumption: m.weakestAssumption, risk: m.risk, deploy: m.deploy, reasoning: m.text })), null, 1) +
        '\n\nNOTE: The members listed above are the ONLY ones who responded (' + seatsResponded + ' of ' + seatsConfigured + ').' +
        (absent.length ? ' These seats did NOT respond and have NO view this run: ' + absent.join(', ') + '. Do NOT invent, quote, paraphrase, or attribute any opinion to them. If the Devil\u2019s Advocate is among the absent, explicitly note the bear case was not heard rather than imagining what it "would" say.' : '');
      const raw = await callProvider(synthModel.provider, synthModel.model, user, system);
      synth = parseJsonLoose(raw);
    } catch (_) { /* fall back to majority below */ }
  }

  const verdict = (synth && coerceVerdict(synth.finalVerdict)) || top;
  const out = {
    models, consensus, verdict,
    agree: (synth && synth.agree) || [],
    disagree: (synth && synth.disagree) || (models.length > 1 && verdicts.length > 1 && new Set(verdicts).size > 1 ? ['Seats split: ' + verdicts.join(', ')] : []),
    strongestArgument: (synth && synth.strongestArgument) || '',
    weakestAssumption: (synth && synth.weakestAssumption) || models.map(m => m.weakestAssumption).filter(Boolean)[0] || '',
    risk: (synth && synth.riskWarning) || models.map(m => m.risk).filter(Boolean)[0] || '',
    // V2 (Ruling 3): ifIHad1000 is RETIRED. The chair is no longer asked for a dollar split,
    // and none is derived from seat commentary. The Monthly Plan destination is set by written
    // policy; a second allocation engine competing with the resolved action is the exact
    // single-authority violation V2 exists to remove. Always null.
    ifIHad1000: null,
    idiotGuide: (synth && synth.idiotGuide) || null,
    synthesised: !!synth, synthBy: synthModel ? synthModel.provider : null,
    rounds: DEBATE_ROUNDS, seats: models.length,
    tally, seatStatus, seatsConfigured, seatsResponded,
    ts: Date.now()
  };

  // Post-synthesis resolution: honest colour + bucket-aware action. Does NOT change the verdict.
  try { out.resolution = resolveCommitteeAction({ verdict: out.verdict, consensus: out.consensus, seatsResponded: out.seatsResponded, seatsConfigured: out.seatsConfigured, cashContext }); }
  // Our own resolver, not an upstream provider — the message is safe and diagnostic
  // (committee-resolver throws on unknown bucket names). Logged as well as returned.
  catch (e) { logUpstream('resolver', e); out.resolution = { error: String(e.message) }; }

  // GEOPOLITICAL RISK OFFICER (Gemini, with Google Search grounding) — separate from the
  // voting committee, not in the tally. NOTE: not Grok/xAI; xAI is not a production dependency.
  out.geoRisk = await runGeoOfficer(req.body && req.body.geoPacket, verdict, ROLES);

  // Cache the completed run (no-op for degraded/empty runs — see deepCacheSet).
  deepCacheSet(CACHE_KEY, out);
  res.json(Object.assign({}, out, { cached: false, cachedAt: Date.now(), ageMs: 0, ttlMs: DEEP_TTL_MS }));

  // History — log this run server-side for the long-term dataset (per-seat verdicts + full synthesis + packet).
  // Fire-and-forget: never blocks or crashes the response. This is the long-term performance goldmine.
  if (sbOn()) {
    sbAppend('committee_runs', [{
      ts: Date.now(), verdict, consensus, recommended: out.ifIHad1000, synth_by: out.synthBy, rounds: DEBATE_ROUNDS,
      models: models.map(m => ({ seat: m.seat, role: m.role, provider: m.provider, model: m.model, modelUsed: m.modelUsed || m.model, usedFallback: !!m.usedFallback, status: 'ok', independentVerdict: m.independentVerdict, verdict: m.verdict, keyArgument: m.keyArgument, weakestAssumption: m.weakestAssumption, risk: m.risk, deploy: m.deploy, reasoning: m.text })),
      detail: {
        tally, seatsConfigured, seatsResponded, seatStatus, failures,
        agree: out.agree, disagree: out.disagree, strongestArgument: out.strongestArgument,
        weakestAssumption: out.weakestAssumption, risk: out.risk, ifIHad1000: out.ifIHad1000,
        idiotGuide: out.idiotGuide, synthesised: out.synthesised, synthBy: out.synthBy, geoRisk: out.geoRisk
      },
      packet
    }]).catch(e => logUpstream('committee_runs:write', e));
  }
});

/* ───────── /api/ask — conversational assistant over the user's live data ─────────
 * Multi-turn chat backed by Claude. The frontend sends the running message history plus a
 * fresh snapshot of the dashboard each turn, so answers reflect what's on screen right now.
 * Read-only and advisory: it never trades, and the user approves every action himself. */
const CHAT_SYS = 'You are the assistant built into Andrew\u2019s personal Investing Command Centre. ' +
  'You help him think through his own portfolio and general finance questions \u2014 comparisons, trade-offs, education, sanity-checks. ' +
  'Treat the LIVE SNAPSHOT below as the ground truth for his current holdings, cash, scores and latest committee verdict. ' +
  'His written Investment Policy is authoritative: Monthly Plan = BHD500 into ISAC.L, ON POLICY. There are no target allocation percentages \u2014 ' +
  'current composition is descriptive only. Never recommend rebalancing or redirecting the Monthly Plan because weights differ from some target. ' +
  'Treasury Bills and Savings are ring-fenced and non-deployable; never treat them as available capital. ' +
  'Be concise and direct. Give analysis and options; never instruct him to execute \u2014 he approves every trade himself on eToro and you cannot trade. ' +
  'Do not invent prices or figures not in the snapshot or general knowledge; if something isn\u2019t there, say so plainly. ' +
  'You are not a licensed financial adviser; frame conclusions as his decision to make.';
app.post('/api/ask', async (req, res) => {
  try {
    const useAnthropic = CHAT_PROVIDER === 'anthropic';
    const haveKey = useAnthropic ? !!process.env.ANTHROPIC_API_KEY : !!process.env.GEMINI_API_KEY;
    if (!haveKey) return res.status(400).json({ error: 'Chat is off \u2014 the chat provider (' + CHAT_PROVIDER + ') has no API key set on the backend.' });
    const body = req.body || {};
    let msgs = (Array.isArray(body.messages) ? body.messages : [])
      .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
      .map(m => ({ role: m.role, content: m.content.slice(0, 4000) }))
      .slice(-20);
    if (!msgs.length || msgs[msgs.length - 1].role !== 'user') return res.status(400).json({ error: 'Need a question to answer.' });
    const capAsk = await bumpUsage('ask');
    if (!capAsk.allowed) return res.status(429).json({ error: 'Daily chat allowance reached (' + capAsk.used + '/' + capAsk.cap + '). It resets at midnight UTC.' });
    const context = typeof body.context === 'string' ? body.context.slice(0, 10000) : '';
    const system = CHAT_SYS + (context ? '\n\n=== LIVE SNAPSHOT (his command centre, right now) ===\n' + context : '\n\n(No live snapshot was provided this turn.)');
    const reply = useAnthropic ? await callAnthropicChat(msgs, system, CHAT_MODEL) : await callGeminiChat(msgs, system, CHAT_MODEL);
    if (!reply) return res.status(502).json({ error: 'The assistant returned an empty response \u2014 try again.' });
    res.json({ reply, model: CHAT_MODEL });
  } catch (e) {
    logUpstream('ask', e);
    res.status(502).json({ error: shortReason(String((e && e.message) || e)) });
  }
});
const PROMPT_FILES = ['system-investing.md', 'deep-triggers.md', 'ai-roles.json'];
app.get('/api/prompts', (req, res) => {
  /* `dir: PROMPT_DIR` REMOVED (step 3) — it leaked the absolute server path.
   * `sources` ADDED (step 7): the frontend's "Prompt files" light previously went GREEN
   * whenever this endpoint responded, because it only counted filenames. It could not
   * distinguish a built-in default from a file override, so it asserted an integrity it
   * had never checked. Now the backend says which each one is and the light can mean
   * something. loadPrompt() precedence is unchanged — a file still wins. */
  const out = {}, sources = {};
  PROMPT_FILES.forEach(f => { out[f] = loadPrompt(f); sources[f] = _psource[f] || 'default'; });
  res.json({ files: PROMPT_FILES, prompts: out, sources, overrides: PROMPT_FILES.filter(f => sources[f] === 'file'), ts: Date.now() });
});
/* POST /api/prompts REMOVED (step 2, owner ruling).
 * It was an unauthenticated remote write into the committee's own instructions and had no
 * caller anywhere in the shipped frontend — only a GET, in the system check. Deleting the
 * route removes that attack outright rather than defending against it.
 * loadPrompt() precedence is DELIBERATELY UNCHANGED: a file in prompts/ still wins over the
 * built-in DEFAULTS. The override mechanism is legitimate; only the remote write is gone.
 * Prompts are now changed by committing a file to the backend repo. */

/* ═══════════════ WILDCARD V2 ═══════════════════════════════════════════════════
 * A CONTAINED experimental module. Governance amendment dated 14 Aug 2026.
 *
 * SEPARATE FROM THE PORTFOLIO IN EVERY RESPECT. Different capital (BHD50 experimental
 * pot), different horizon (intraday), different rules. It must never appear on the main
 * decision surface and must never influence the Monthly Plan. The architecture rule that
 * two panels must not independently tell the owner what to do is preserved by keeping
 * Wildcard behind its own nav entry, silent unless opened.
 *
 * NO BROKER API. NO AUTOMATIC EXECUTION. The module emits instructions; the owner
 * executes them by hand in Trading 212 Invest.
 *
 * RULING 4 — NO SEAT IS EVER A HARD DEPENDENCY. Every seat stores an explicit
 * source of 'api' or 'manual'. A provider failure must never block a run: the owner
 * copies the prompt, pastes the answer back, and the run continues identically.
 *
 * RULING 3 — NEVER FAKE MEASUREMENT. Anything requiring real price history stays null
 * and is reported as UNAVAILABLE. It is never inferred from an AI response.           */

const WC_SEATS = {
  grok:       { label: 'Grok — Live Intelligence',  provider: 'xai',        stage: 'night',
                brief: 'Current market and news, catalyst freshness, social/trader attention, sector momentum, breaking developments. NO technical trade construction.' },
  gemini:     { label: 'Gemini — Research',         provider: 'gemini',     stage: 'night',
                brief: 'Company facts, earnings and guidance, filings, dilution, lockups, controversies, macro. Prefer primary sources.' },
  perplexity: { label: 'Perplexity — Evidence Auditor', provider: 'perplexity', stage: 'night',
                brief: 'Verify important claims, identify contradictions, detect stale data and old news presented as new, flag weak sourcing. NO trade recommendation.' },
  claude:     { label: 'Claude — Trade Structure',  provider: 'anthropic',  stage: 'locked',
                brief: 'Using ONLY the locked evidence pack: technical structure, entry, invalidation, realistic upside, downside, reward:risk, time stop, maximum hold, grade.' },
  deepseek:   { label: 'DeepSeek — Red Team',       provider: 'openrouter', model: 'deepseek/deepseek-chat-v3.1:free', stage: 'locked',
                brief: 'Using ONLY the locked evidence pack: try to kill this trade. Chasing? Stale catalyst? Stop inside normal noise? Reward/risk overstated? Macro conflict? Dilution/supply risk? Bull trap? State veto conditions.' },
  synthesis:  { label: 'Final Synthesis',           provider: 'gemini',     stage: 'locked',
                brief: 'Combine the evidence and the disagreements. Do NOT average votes. Decide.' }
};

/* Which numbered step of the owner-facing flow each seat belongs to. The frontend shows
 * ONE step at a time, so it needs this from the server rather than hard-coding a seat list
 * that would drift the moment a seat is added or removed. */
const WC_STEPS = { grok: 'evidence', gemini: 'evidence', perplexity: 'audit',
                   claude: 'test', deepseek: 'test', synthesis: 'decision' };

/* Ruling 4 stands: MANUAL always exists for every seat, and Grok is MANUAL by ruling
 * regardless of whether a key exists — it has produced stale and confidently wrong market
 * data, so AUTO must be earned.
 *
 * AMENDED 14 Aug: MANUAL is no longer the DEFAULT for every seat. Defaulting everything to
 * manual reproduced the five-app copy/paste workflow inside a nicer interface, which is the
 * opposite of the point. A seat whose provider has a working key now defaults to AUTO; a
 * failure exposes MANUAL immediately. "MANUAL is always possible" and "MANUAL is always
 * first" are different claims, and only the first one was ever the ruling. */
function wcSeatModes() {
  const out = {};
  for (const [k, v] of Object.entries(WC_SEATS)) {
    const hasKey = providerHasKey(v.provider);
    const autoAvailable = k === 'grok' ? false : hasKey;
    out[k] = {
      label: v.label, stage: v.stage, provider: v.provider,
      step: WC_STEPS[k] || 'evidence',
      autoAvailable,
      defaultMode: autoAvailable ? 'auto' : 'manual',
      manualAlwaysAvailable: true,
      note: k === 'grok'
        ? 'MANUAL by ruling — Grok has returned stale/incorrect data before; AUTO must be earned.'
        : (hasKey ? 'AUTO by default; MANUAL if it fails.' : 'No API key — MANUAL only.')
    };
  }
  return out;
}

async function sbWc(method, path, body) {
  if (!sbOn()) throw new Error('no durable store configured');
  const r = await fetch(`${SB_URL}/rest/v1/${path}`, {
    method,
    headers: { ...sbHeaders(method !== 'GET'), Prefer: 'return=representation' },
    body: body ? JSON.stringify(body) : undefined
  });
  if (!r.ok) throw new Error('supabase ' + r.status + ' ' + (await r.text()).slice(0, 200));
  const txt = await r.text();
  return txt ? JSON.parse(txt) : null;
}

const WC_TICKER = /^[A-Z0-9.\-]{1,12}$/;

/* The three stages are DISTINCT and all three must survive into the permanent record:
 *   night  — Grok / Gemini / Perplexity gathering and auditing evidence
 *   locked — Claude / DeepSeek / synthesis reasoning from the frozen pack
 *   live   — the recheck before execution
 * The first version collapsed anything non-live to 'night', which would have destroyed
 * exactly the night→locked→live trail this module exists to preserve. Constrained set,
 * rejected loudly — never coerced to a default. */
const WC_STAGES = ['night', 'locked', 'live'];

/* Which prior evidence a seat must see before it can honestly do its job.
 * Perplexity audits Grok and Gemini — it cannot audit research it was never shown, and
 * asking it to recreate that research independently would defeat the point of auditing. */
/* What each seat must SEE before it can honestly do its job, and at which stage that
 * evidence lives.
 *
 * SYNTHESIS WAS MISSING ENTIRELY. The chair's brief says "Combine the evidence and the
 * disagreements" — but with no entry here it received the locked pack and nothing else. It
 * was asked to judge a disagreement between two analyses it had never been shown. The run
 * displayed 4 TRADE — DONE while the chair had no trade-stage reasoning at all, so any
 * verdict more precise than NONE would have been invented. */
const WC_REQUIRES = {
  perplexity: { stage: 'night',  seats: ['grok', 'gemini'],
                heading: 'EVIDENCE TO AUDIT — these are the actual responses from the earlier seats.',
                rubric:  'Audit THESE. Do not substitute your own research for them.' },
  synthesis:  { stage: 'locked', seats: ['claude', 'deepseek'],
                heading: 'DERIVED ANALYSIS — NOT ADDITIONAL FACTUAL EVIDENCE.',
                rubric:  'These two reasoned ONLY from the locked pack above. Judge their conclusions '
                       + 'and their disagreement. Do NOT treat their statements as new verified facts, '
                       + 'and do NOT let them add anything to the evidence pack.' }
};

/* Pure function so it can be tested without a database or a running server. */
function buildSeatPrompt(seatKey, def, run, priorResponses) {
  const parts = [def.label, '', def.brief];
  const used = [], missing = [];
  if (run && Array.isArray(run.candidates)) parts.push('', 'CANDIDATES: ' + run.candidates.join(', '));

  const req = WC_REQUIRES[seatKey] || null;
  const needs = req ? req.seats : [];
  /* Collected but NOT emitted yet. A locked-stage seat must show the frozen pack FIRST and
   * derived analysis after it, so the reader can never mistake one for the other. */
  const derived = [];
  if (needs.length) {
    for (const n of needs) {
      /* pickLatestOk, not .find(). The old line took the FIRST matching row out of a query
       * with no ORDER BY — so the moment REVIEW → REPLACE stored a corrected answer, the
       * auditor could still be handed the SUPERSEDED one, and nothing on screen would say so.
       * One rule now governs every "which response" decision in this file. */
      const r = pickLatestOk(priorResponses, n, req.stage);
      if (r) {
        used.push({ seat: n, stage: req.stage, source: r.source, chars: String(r.raw_response).length });
        derived.push('', '--- ' + n.toUpperCase() + ' (' + r.source + ') ---', String(r.raw_response));
      } else {
        missing.push(n);
      }
    }
  }
  // Night-stage seats carry their evidence inline; there is no pack to come first.
  if (derived.length && def.stage !== 'locked') {
    parts.push('', req.heading, req.rubric, ...derived);
  }

  /* Locked-stage seats see the frozen pack and nothing else.
   *
   * THE BUG THIS REPLACES. The old line was `if (stage === 'locked' && run.evidence_pack)`.
   * Nothing in the codebase ever WROTE evidence_pack, so the condition was always false and
   * the branch was silently skipped — while the brief above still said "Using ONLY the locked
   * evidence pack". Claude was handed a prompt that claimed to carry evidence and carried
   * none, and answered, correctly, "I don't have the locked evidence pack content."
   *
   * A missing pack is now a REFUSAL, not an omission. The caller gets told what is wrong
   * instead of getting a confident-looking prompt with the evidence quietly removed. */
  if (def.stage === 'locked') {
    if (!run || !run.evidence_pack || !run.evidence_pack_hash) {
      return { prompt: null, evidenceUsed: [], missing,
               needsLock: true,
               error: 'evidence pack is not locked — this seat must not be asked to reason from a pack that does not exist' };
    }
    // The hash goes IN the prompt text. Two seats holding the same hash is then checkable
    // from the prompts themselves, not merely asserted by the server that built them.
    parts.push('',
      'LOCKED EVIDENCE PACK — this is your ONLY factual input. Do not add outside knowledge.',
      'PACK HASH: ' + run.evidence_pack_hash,
      canonicalJson(run.evidence_pack));

    /* FAIL CLOSED. A chair asked to judge a disagreement it cannot see would produce a
     * confident verdict from half the inputs — exactly the failure this whole module exists
     * to prevent. Refuse, and name what is missing. */
    if (needs.length && missing.length) {
      return { prompt: null, evidenceUsed: used, missing,
               tradeIncomplete: true,
               error: 'trade-stage analysis incomplete — cannot synthesise a disagreement that was never supplied' };
    }
    if (derived.length) {
      parts.push('', req.heading, req.rubric, ...derived);
    }
  }
  return { prompt: parts.join('\n'), evidenceUsed: used, missing,
           packHash: (run && run.evidence_pack_hash) || null };
}

/* ── The frozen evidence pack ────────────────────────────────────────────────────
 * Deterministic serialisation: keys sorted at every level, so the same evidence always
 * produces the same bytes and therefore the same hash. Note what is NOT in here — a
 * timestamp. buildPacket() opens with a fresh ISO stamp, which is exactly why anything
 * hashing it gets a 0% match rate while appearing to work. locked_at lives in its own
 * column, outside the hashed content. */
function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}
function packHashOf(pack) {
  return crypto.createHash('sha256').update(canonicalJson(pack)).digest('hex').slice(0, 32);
}

/* Every night seat must be present and OK before the pack can be built. A pack assembled
 * from two of three seats would still hash, still look locked, and would silently be a
 * different experiment from the one the design describes. */
const WC_PACK_SEATS = ['grok', 'gemini', 'perplexity'];

/* WHICH response gets frozen, when a seat has several.
 *
 * Reruns and failed attempts both leave rows behind, so "the grok response" is not a single
 * thing. The rule is: the LATEST response with status 'ok'. A newer FAILED attempt must not
 * displace an older successful one, and an older success must not win over a newer one.
 *
 * The previous version filtered then called .pop(), which takes the last element of whatever
 * order the database happened to return. It worked only because the caller's query carried
 * `order=created_at.asc` — and `created_at` was not even in the SELECT, so this function had
 * nothing to sort by and no way to notice. Drop that clause, swap the store, or reorder the
 * query and it would silently freeze an arbitrary answer while looking entirely normal.
 *
 * Ordering is now decided HERE, from values this function can see, and does not depend on
 * the caller's query at all. `id` is the tie-break so two rows sharing a timestamp still
 * resolve the same way every time rather than by arrival order. */
function pickLatestOk(responses, seat, stage) {
  const want = stage || 'night';
  const rows = (responses || []).filter(x =>
    x.seat === seat && x.stage === want && x.status === 'ok' && x.raw_response);
  if (!rows.length) return null;
  return rows.slice().sort((a, b) => {
    const ta = Date.parse(a.created_at || '') || 0, tb = Date.parse(b.created_at || '') || 0;
    if (ta !== tb) return tb - ta;                       // newest first
    return String(b.id || '').localeCompare(String(a.id || ''));   // deterministic tie-break
  })[0];
}

function buildEvidencePack(run, responses) {
  const missing = [], seats = {};
  for (const s of WC_PACK_SEATS) {
    const r = pickLatestOk(responses, s);
    if (!r) { missing.push(s); continue; }
    /* Provenance is recorded as found and never invented. An unknown provider or model
     * stays null rather than being filled in with the seat's configured default — the pack
     * must say what actually answered, not what was supposed to. */
    seats[s] = { seat: s, source: r.source, provider: r.provider || null,
                 model: r.model || null, response: String(r.raw_response) };
  }
  if (missing.length) return { missing, pack: null };
  return { missing: [], pack: { candidates: (run && run.candidates) || [], seats } };
}

// Create a run. The record exists from the FIRST action, before any seat is called —
// the whole point of moving logging ahead of the debate engine. A run that is abandoned
// half way is still a run, and still evidence about the process.
app.post('/api/wildcard/run', async (req, res) => {
  const raw = (req.body && req.body.candidates) || [];
  const candidates = (Array.isArray(raw) ? raw : String(raw).split(','))
    .map(x => String(x).trim().toUpperCase()).filter(Boolean);
  if (candidates.length !== 3) return res.status(400).json({ error: 'exactly three candidates required' });
  const bad = candidates.filter(c => !WC_TICKER.test(c));
  if (bad.length) return res.status(400).json({ error: 'invalid ticker(s)', invalid: bad });
  if (new Set(candidates).size !== 3) return res.status(400).json({ error: 'candidates must be distinct' });
  try {
    const rows = await sbWc('POST', 'wildcard_runs', [{
      candidates, candidate_source: (req.body && req.body.source) || null
    }]);
    res.json({ run: Array.isArray(rows) ? rows[0] : rows, seats: wcSeatModes(), ts: Date.now() });
  } catch (e) { logUpstream('wildcard:create', e); res.status(502).json({ error: shortReason(String((e && e.message) || e)) }); }
});

/* Seat modes, independent of any run. The UI must be able to show "GROK — MANUAL" on an
 * empty screen, before anything exists — and this needs no durable store, so it still
 * answers when Supabase is down. */
app.get('/api/wildcard/seats', (req, res) => res.json({ seats: wcSeatModes(), ts: Date.now() }));

app.get('/api/wildcard/runs', async (req, res) => {
  const limit = Math.min(200, Math.max(1, +req.query.limit || 30));
  try {
    res.json({ runs: await sbWc('GET', `wildcard_runs?select=*&order=trade_date.desc,created_at.desc&limit=${limit}`), ts: Date.now() });
  } catch (e) { logUpstream('wildcard:list', e); res.status(502).json({ error: shortReason(String((e && e.message) || e)) }); }
});

app.get('/api/wildcard/run/:id', async (req, res) => {
  const id = String(req.params.id || '');
  if (!/^[0-9a-f-]{36}$/i.test(id)) return res.status(400).json({ error: 'bad run id' });
  try {
    const [run] = await sbWc('GET', `wildcard_runs?id=eq.${id}&select=*`);
    if (!run) return res.status(404).json({ error: 'run not found' });
    const seatRows = await sbWc('GET', `wildcard_seat_responses?run_id=eq.${id}&select=*&order=created_at.asc`);
    const [trade] = await sbWc('GET', `wildcard_trades?run_id=eq.${id}&select=*`) || [];
    res.json({ run, seatResponses: seatRows || [], trade: trade || null, seats: wcSeatModes(), ts: Date.now() });
  } catch (e) { logUpstream('wildcard:get', e); res.status(502).json({ error: shortReason(String((e && e.message) || e)) }); }
});

/* The exact prompt a seat is given. In MANUAL mode this is what COPY PROMPT copies, so the
 * pasted-back answer is genuinely comparable to an API one — same words, same evidence. */
app.get('/api/wildcard/prompt/:seat', async (req, res) => {
  const seat = String(req.params.seat || '').toLowerCase();
  const def = WC_SEATS[seat];
  if (!def) return res.status(400).json({ error: 'unknown seat', known: Object.keys(WC_SEATS) });
  const runId = String(req.query.run || '');
  const allowIncomplete = String(req.query.allowIncomplete || '') === '1';

  // No run supplied: the generic role prompt only, and it says so rather than implying
  // it carries evidence it does not have.
  if (!runId) {
    const built = buildSeatPrompt(seat, def, null, []);
    /* A locked-stage seat with no run has no pack by definition, so it is refused here for
     * the same reason it is refused with a run. The previous version returned HTTP 200 with
     * a null prompt and a note saying "Generic role prompt" — which was no longer true and
     * would have read as a working endpoint returning nothing. */
    if (built.needsLock || built.tradeIncomplete) {
      return res.status(409).json({ seat, stage: def.stage,
        needsLock: !!built.needsLock, tradeIncomplete: !!built.tradeIncomplete,
        error: built.needsLock ? 'evidence pack not locked' : 'trade analysis incomplete',
        note: 'This seat reasons from stored run material. Supply a run that has it.' });
    }
    return res.json({ seat, label: def.label, stage: def.stage, prompt: built.prompt,
      evidenceUsed: [], incomplete: ((WC_REQUIRES[seat] || {}).seats || []).length > 0,
      missing: (WC_REQUIRES[seat] || {}).seats || [],
      note: 'Generic role prompt — no run supplied, so no prior evidence is attached.', ts: Date.now() });
  }
  if (!/^[0-9a-f-]{36}$/i.test(runId)) return res.status(400).json({ error: 'bad run id' });

  let run = null, prior = [];
  try {
    [run] = await sbWc('GET', `wildcard_runs?id=eq.${runId}&select=candidates,evidence_pack,evidence_pack_hash`);
    if (!run) return res.status(404).json({ error: 'run not found' });
    // id + created_at are what pickLatestOk orders by. Without them every row scores 0 and
    // selection collapses to the tie-break — the same gap that was found in the lock query.
    prior = await sbWc('GET', `wildcard_seat_responses?run_id=eq.${runId}&select=id,created_at,seat,stage,source,status,raw_response&order=created_at.asc`) || [];
  } catch (e) {
    // A store failure must NOT fall back to a bare prompt. Handing Perplexity a prompt with
    // no evidence, while it believes it has some, is worse than refusing.
    logUpstream('wildcard:prompt', e);
    return res.status(502).json({ error: shortReason(String((e && e.message) || e)),
      note: 'Refusing to build a prompt without being able to read the prior evidence.' });
  }

  const built = buildSeatPrompt(seat, def, run, prior);
  const { prompt, evidenceUsed, missing } = built;

  /* Like the lock, allowIncomplete does NOT override this. "Proceed without the evidence" is
   * a coherent choice for an audit; it is not coherent for a chair whose entire job is to
   * judge a disagreement between two analyses it was never shown. */
  if (built.tradeIncomplete) {
    return res.status(409).json({
      error: 'trade analysis incomplete', seat, tradeIncomplete: true, missing: built.missing,
      note: 'FINAL BLOCKED — TRADE ANALYSIS INCOMPLETE. Missing: ' + built.missing.join(', ')
          + '. The chair judges Claude\'s and DeepSeek\'s conclusions; without them it would be '
          + 'inventing the reasoning it is supposed to be weighing.'
    });
  }

  /* A locked-stage seat with no frozen pack is refused outright, and allowIncomplete does
   * NOT override it. "Proceed without the evidence" is a coherent choice for an audit; it is
   * not a coherent choice for a seat whose entire instruction is "use ONLY the locked pack". */
  if (built.needsLock) {
    return res.status(409).json({
      error: 'evidence pack not locked', seat, needsLock: true,
      note: 'Lock the audited evidence first (POST /api/wildcard/lock). This seat reasons from '
          + 'the frozen pack alone, so a prompt without it would be a different experiment.'
    });
  }
  if (missing.length && !allowIncomplete) {
    return res.status(409).json({
      error: 'required prior evidence is missing', seat, missing, evidenceUsed,
      note: 'Run those seats first, or re-request with allowIncomplete=1 to proceed deliberately. '
          + 'An incomplete audit is recorded as incomplete, never presented as a full one.'
    });
  }
  res.json({
    seat, label: def.label, stage: def.stage, prompt,
    evidenceUsed, missing, incomplete: missing.length > 0,
    packHash: built.packHash || null,
    note: missing.length
      ? 'PROCEEDING INCOMPLETE — missing: ' + missing.join(', ') + '. Record this against the run.'
      : 'Paste the full reply back via POST /api/wildcard/seat with source:"manual".',
    ts: Date.now()
  });
});

/* ═══ THE LOCK ═══════════════════════════════════════════════════════════════════
 * Freezes the audited night evidence into an immutable pack and hashes it. This is the
 * step that was missing entirely: the column existed, the prompt builder read it, nothing
 * ever wrote it.
 *
 * FREEZING MEANS FREEZING. If a run is already locked this returns the existing pack
 * untouched — it never re-freezes, even if a seat has been re-answered since. Re-locking
 * would change the hash under Claude and DeepSeek and quietly destroy the one property the
 * whole design exists to provide: that both of them reasoned from identical evidence.
 * Re-locking deliberately requires ?relock=1 and is recorded by the hash changing. */
app.post('/api/wildcard/lock', async (req, res) => {
  const runId = String((req.body && req.body.runId) || '');
  if (!/^[0-9a-f-]{36}$/i.test(runId)) return res.status(400).json({ error: 'bad run id' });
  const relock = String((req.body && req.body.relock) || '') === '1';

  let run, prior;
  try {
    [run] = await sbWc('GET', `wildcard_runs?id=eq.${runId}&select=id,candidates,evidence_pack,evidence_pack_hash,evidence_locked_at`);
    if (!run) return res.status(404).json({ error: 'run not found' });
    prior = await sbWc('GET', `wildcard_seat_responses?run_id=eq.${runId}&select=id,created_at,seat,stage,source,status,provider,model,raw_response&order=created_at.asc`) || [];
  } catch (e) {
    logUpstream('wildcard:lock:read', e);
    return res.status(502).json({ error: shortReason(String((e && e.message) || e)) });
  }

  if (run.evidence_pack && run.evidence_pack_hash && !relock) {
    return res.json({ locked: true, alreadyLocked: true,
      packHash: run.evidence_pack_hash, lockedAt: run.evidence_locked_at,
      seats: Object.keys((run.evidence_pack && run.evidence_pack.seats) || {}),
      note: 'Already locked. The pack was NOT rebuilt — re-freezing would change the hash '
          + 'and break the identical-evidence guarantee.', ts: Date.now() });
  }

  const { missing, pack } = buildEvidencePack(run, prior);
  if (missing.length) {
    return res.status(409).json({ error: 'cannot lock — night evidence incomplete', missing,
      note: 'Every night seat (' + WC_PACK_SEATS.join(', ') + ') must have an OK response first. '
          + 'A pack built from some of them would still hash and still look locked.' });
  }

  const hash = packHashOf(pack);
  const lockedAt = new Date().toISOString();
  try {
    const rows = await sbWc('PATCH', `wildcard_runs?id=eq.${runId}`,
      { evidence_pack: pack, evidence_pack_hash: hash, evidence_locked_at: lockedAt, stage: 'locked' });
    const saved = Array.isArray(rows) ? rows[0] : rows;
    // Trust the row that came back, not the value we sent. A write that silently did not
    // land would otherwise be reported as a successful lock.
    if (!saved || saved.evidence_pack_hash !== hash) {
      return res.status(502).json({ error: 'lock did not persist',
        note: 'The database did not return the hash that was written. Nothing is locked.' });
    }
    res.json({ locked: true, alreadyLocked: false, packHash: hash, lockedAt,
      seats: Object.keys(pack.seats), candidates: pack.candidates,
      chars: Object.values(pack.seats).reduce((n, x) => n + x.response.length, 0), ts: Date.now() });
  } catch (e) {
    logUpstream('wildcard:lock:write', e);
    res.status(502).json({ error: shortReason(String((e && e.message) || e)) });
  }
});

// Store a seat response — API or MANUAL, identical treatment downstream.
app.post('/api/wildcard/seat', async (req, res) => {
  const b = req.body || {};
  const seat = String(b.seat || '').toLowerCase();
  if (!WC_SEATS[seat]) return res.status(400).json({ error: 'unknown seat', known: Object.keys(WC_SEATS) });
  if (!/^[0-9a-f-]{36}$/i.test(String(b.runId || ''))) return res.status(400).json({ error: 'bad run id' });
  // Ruling 4: source is mandatory and explicit. Never defaulted, never guessed.
  if (b.source !== 'api' && b.source !== 'manual') return res.status(400).json({ error: 'source must be "api" or "manual"' });
  if (typeof b.rawResponse !== 'string' || !b.rawResponse.trim()) return res.status(400).json({ error: 'rawResponse required' });
  // Stage is never defaulted. An unrecognised stage is a bug in the caller, not something to guess at.
  if (!WC_STAGES.includes(b.stage)) return res.status(400).json({ error: 'stage must be one of: ' + WC_STAGES.join(', ') });

  /* ONCE LOCKED, THE NIGHT IS CLOSED.
   *
   * Freezing already protects the pack — a late night answer could not change it, because
   * buildEvidencePack only runs at lock time. But accepting the write anyway was its own
   * defect: the row would be stored, the API would answer 200, and the owner would believe
   * he had replaced a piece of evidence when the frozen pack was untouched. A write that
   * succeeds while achieving nothing is worse than one that fails.
   *
   * Locked- and live-stage writes stay open. Those are Claude, DeepSeek, the synthesis and
   * the recheck — the whole reason the pack was frozen in the first place. */
  if (b.stage === 'night') {
    let run;
    try {
      [run] = await sbWc('GET', `wildcard_runs?id=eq.${b.runId}&select=evidence_locked_at,evidence_pack_hash`);
    } catch (e) {
      // Refuse rather than write blind. If the lock state cannot be read, storing evidence
      // that may already be frozen is exactly the silent corruption this guard prevents.
      logUpstream('wildcard:seat:lockcheck', e);
      return res.status(502).json({ error: shortReason(String((e && e.message) || e)),
        note: 'Refusing to store night evidence without being able to confirm the run is unlocked.' });
    }
    if (!run) return res.status(404).json({ error: 'run not found' });
    if (run.evidence_locked_at || run.evidence_pack_hash) {
      return res.status(409).json({ error: 'evidence is locked', locked: true,
        packHash: run.evidence_pack_hash || null, lockedAt: run.evidence_locked_at || null,
        note: 'This run\'s night evidence was frozen. Replace responses BEFORE locking — '
            + 'afterwards the pack is immutable and a new answer would change nothing.' });
    }
  }

  try {
    const rows = await sbWc('POST', 'wildcard_seat_responses', [{
      /* The stage is written EXACTLY as validated against WC_STAGES above.
       * This line previously read `b.stage === 'live' ? 'live' : 'night'`, which silently
       * collapsed 'locked' into 'night' ON THE WAY INTO THE DATABASE — the same defect that
       * was caught and only half-fixed: the validation was corrected, the write was not.
       * A locked-stage response recorded as 'night' destroys the night→locked→live trail
       * this module exists to preserve, and it would have looked completely normal. */
      run_id: b.runId, stage: b.stage, seat,
      provider: b.provider || WC_SEATS[seat].provider,
      model: b.model || WC_SEATS[seat].model || null,
      source: b.source,
      raw_response: String(b.rawResponse).slice(0, 200000),
      parsed: parseJsonLoose(b.rawResponse),      // best-effort; raw text is always kept regardless
      status: b.status === 'failed' ? 'failed' : 'ok',
      fail_reason: b.failReason || null,
      fallback_used: !!b.fallbackUsed,
      prompt_sent: b.promptSent || null
    }]);
    res.json({ saved: Array.isArray(rows) ? rows[0] : rows, ts: Date.now() });
  } catch (e) { logUpstream('wildcard:seat', e); res.status(502).json({ error: shortReason(String((e && e.message) || e)) }); }
});
/* ═══════════════ END WILDCARD V2 ══════════════════════════════════════════════ */

/* ───────── Our own portfolio history DB (independent of eToro) ─────────
 * Durable store for snapshots + decision journal. The frontend is local-first
 * (localStorage) and mirrors here so history survives device changes.
 *
 * Storage backend, picked automatically:
 *   1. Supabase  — if SUPABASE_URL + SUPABASE_SERVICE_KEY are set (durable, shared)
 *   2. JSON file — backend/data/history.json
 *   3. In-memory — if the filesystem is read-only
 * Supabase failures fall back to the file store so a write never crashes.
 */
const DATA_DIR = path.join(__dirname, 'data');
const HIST_FILE = path.join(DATA_DIR, 'history.json');
let _hist = null;
function histLoad() {
  if (_hist) return _hist;
  try { _hist = JSON.parse(fs.readFileSync(HIST_FILE, 'utf8')); } catch (_) { _hist = { snapshots: [], journal: [] }; }
  if (!_hist.snapshots) _hist.snapshots = []; if (!_hist.journal) _hist.journal = [];
  return _hist;
}
function histSave() { try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(HIST_FILE, JSON.stringify(_hist)); } catch (_) { /* in-memory only */ } }

// ---- Supabase (service-role, server-side only; targets the `investing` schema) ----
const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const SB_SCHEMA = process.env.SUPABASE_SCHEMA || 'investing';
const sbOn = () => !!(SB_URL && SB_KEY);
function sbHeaders(write) {
  const h = { apikey: SB_KEY, Authorization: 'Bearer ' + SB_KEY, 'Content-Type': 'application/json' };
  h[write ? 'Content-Profile' : 'Accept-Profile'] = SB_SCHEMA;   // select the investing schema
  return h;
}
const iso = (ms) => ms == null ? null : new Date(typeof ms === 'number' ? ms : Date.parse(ms)).toISOString();
function mapSnap(e) {
  return { ts: iso(e.ts) || new Date().toISOString(), trigger: e.trigger, value: e.value, cash: e.cash, dry_powder: e.dryPowder,
    cash_pc: e.cashPc, holdings: e.holdings, alloc: e.alloc, tot_pl: e.totPl, day_pl: e.dayPl, danger: e.danger,
    opportunity: e.opportunity, status: e.status, light: e.light, ai_verdict: e.aiVerdict, suggested_deploy: e.suggestedDeploy, source: e.source };
}
function mapJournal(e) {
  return { id: e.id, ts: iso(e.ts) || new Date().toISOString(), conditions: e.conditions, ai_verdict: e.aiVerdict,
    recommended_action: e.recommendedAction, actual_action: e.actualAction || null, notes: e.notes || null,
    outcome: e.outcome || null, outcome_ts: iso(e.outcomeTs), updated_at: new Date().toISOString() };
}
function mapCommitteeRun(e) {
  return { ts: iso(e.ts) || new Date().toISOString(), verdict: e.verdict, consensus: e.consensus,
    recommended: e.recommended || null, synth_by: e.synth_by || null, rounds: e.rounds || null,
    models: e.models || [], detail: e.detail || {}, packet: e.packet || null };
}
async function sbAppend(type, incoming) {
  if (type === 'journal') {
    const r = await fetch(`${SB_URL}/rest/v1/journal?on_conflict=id`, { method: 'POST', headers: { ...sbHeaders(true), Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify(incoming.map(mapJournal)) });
    if (!r.ok) throw new Error('supabase journal ' + r.status + ' ' + (await r.text()).slice(0, 160));
  } else if (type === 'committee_runs') {
    const r = await fetch(`${SB_URL}/rest/v1/committee_runs`, { method: 'POST', headers: { ...sbHeaders(true), Prefer: 'return=minimal' }, body: JSON.stringify(incoming.map(mapCommitteeRun)) });
    if (!r.ok) throw new Error('supabase committee_runs ' + r.status + ' ' + (await r.text()).slice(0, 160));
  } else {
    const r = await fetch(`${SB_URL}/rest/v1/snapshots`, { method: 'POST', headers: { ...sbHeaders(true), Prefer: 'return=minimal' }, body: JSON.stringify(incoming.map(mapSnap)) });
    if (!r.ok) throw new Error('supabase snapshots ' + r.status + ' ' + (await r.text()).slice(0, 160));
  }
}
async function sbRead(type, limit) {
  const table = type === 'journal' ? 'journal' : type === 'committee_runs' ? 'committee_runs' : 'snapshots';
  const r = await fetch(`${SB_URL}/rest/v1/${table}?select=*&order=ts.desc&limit=${limit}`, { headers: sbHeaders(false) });
  if (!r.ok) throw new Error('supabase read ' + r.status);
  const rows = await r.json();
  return rows.reverse();   // return oldest-first to match the file store
}


/* ── DURABLE DAILY USAGE CAP (step 5) ───────────────────────────────────────────
 * Bounds what a STOLEN TOKEN or a runaway client can spend. Authentication is what
 * stops anonymous quota drain; this is the second line behind it.
 *
 * ATOMICITY IS THE WHOLE POINT. Do NOT reimplement this as
 *      read count -> count + 1 -> write it back
 * in JavaScript. Two simultaneous requests would both read 7, both conclude 8 is
 * within the cap, and both proceed — the limit fails exactly when parallel requests
 * arrive, which is the only case it exists for. This file is already parallel by
 * nature (Promise.allSettled in the committee rounds, Promise.all in prices).
 * The increment and the check therefore happen in ONE statement inside Postgres;
 * Node sends one call and receives an allowed/denied answer.
 *
 * Requires the SQL in supabase-usage-cap.sql to have been applied.
 *
 * FAILS OPEN, deliberately. If Supabase is unreachable or the function is missing,
 * the request proceeds and the reason is logged. That is correct HERE and only here:
 * the caller has already passed authentication, so refusing would lock the owner out
 * of his own dashboard for no security gain. Auth fails closed; this does not.       */
const DAILY_CAPS = {
  'deep-triggers': Math.max(1, +process.env.CAP_DEEP_TRIGGERS || 60),
  'ask':           Math.max(1, +process.env.CAP_ASK || 250)
};
async function bumpUsage(endpoint) {
  const cap = DAILY_CAPS[endpoint];
  if (!cap || !sbOn()) return { allowed: true, skipped: 'no_store' };
  try {
    const r = await fetch(`${SB_URL}/rest/v1/rpc/bump_usage`, {
      method: 'POST', headers: sbHeaders(true),
      body: JSON.stringify({ p_endpoint: endpoint, p_limit: cap })
    });
    if (!r.ok) throw new Error('rpc ' + r.status + ' ' + (await r.text()).slice(0, 120));
    const rows = await r.json();
    const row = Array.isArray(rows) ? rows[0] : rows;
    if (!row || typeof row.allowed !== 'boolean') throw new Error('unexpected rpc shape');
    return row;
  } catch (e) {
    logUpstream('usage-cap:' + endpoint, e);
    return { allowed: true, skipped: 'unavailable' };
  }
}

app.get('/api/history', async (req, res) => {
  const type = req.query.type;
  const limit = Math.min(500, +req.query.limit || 200);
  if (sbOn()) {
    try {
      if (type === 'snapshots') return res.json({ snapshots: await sbRead('snapshots', limit), backend: 'supabase', ts: Date.now() });
      if (type === 'journal') return res.json({ journal: await sbRead('journal', limit), backend: 'supabase', ts: Date.now() });
      if (type === 'committee_runs') return res.json({ committee_runs: await sbRead('committee_runs', limit), backend: 'supabase', ts: Date.now() });
      const [snapshots, journal] = await Promise.all([sbRead('snapshots', limit), sbRead('journal', limit)]);
      return res.json({ snapshots, journal, backend: 'supabase', ts: Date.now() });
    } catch (e) { logUpstream('history:read', e); /* fall through to file store */ }
  }
  const h = histLoad();
  if (type === 'snapshots') return res.json({ snapshots: h.snapshots.slice(-limit), backend: 'file', ts: Date.now() });
  if (type === 'journal') return res.json({ journal: h.journal.slice(-limit), backend: 'file', ts: Date.now() });
  res.json({ snapshots: h.snapshots.slice(-limit), journal: h.journal.slice(-limit), backend: 'file', ts: Date.now() });
});
app.post('/api/history', async (req, res) => {
  const { type, entry, entries } = req.body || {};
  if (!['snapshots', 'journal'].includes(type)) return res.status(400).json({ error: 'type must be snapshots or journal' });
  const incoming = Array.isArray(entries) ? entries : (entry ? [entry] : []);
  if (!incoming.length) return res.status(400).json({ error: 'no entry/entries provided' });
  if (sbOn()) {
    try { await sbAppend(type, incoming); return res.json({ ok: true, type, count: incoming.length, backend: 'supabase', ts: Date.now() }); }
    catch (e) { logUpstream('history:write', e); /* fall back to file store below, never crash */ }
  }
  const h = histLoad();
  if (type === 'journal') { incoming.forEach(e => { const i = h.journal.findIndex(x => x.id === e.id); if (i >= 0) h.journal[i] = e; else h.journal.push(e); }); h.journal = h.journal.slice(-500); }
  else { h.snapshots.push(...incoming); h.snapshots = h.snapshots.slice(-1000); }
  histSave();
  res.json({ ok: true, type, count: incoming.length, total: h[type].length, backend: 'file', ts: Date.now() });
});

app.use((req, res) => res.status(404).json({ error: 'not_found' }));
app.listen(PORT, () => console.log(`Investing Command Centre backend on :${PORT}`));
