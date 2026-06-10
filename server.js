'use strict';
/*
 * Investing Command Centre — secure data + AI proxy
 * --------------------------------------------------
 * Holds all API keys server-side. The frontend calls these endpoints and
 * never sees a key. Every adapter fails soft: a missing key or a dead
 * upstream returns null for that field instead of crashing the response.
 *
 * Endpoints
 *   GET  /api/health
 *   GET  /api/prices?symbols=VOO,QQQ,NVDA,MSFT,VXUS,SCHD
 *   GET  /api/market          -> spx, ndx, vix, y2, y10, dxy
 *   GET  /api/macro           -> cpi, cpiPrev, fedRate, cutProb, fg, breadth
 *   GET  /api/events          -> upcoming CPI/PPI/Jobs/Fed + NVDA/MSFT earnings
 *   GET  /api/news            -> market headlines
 *   POST /api/deep-triggers   -> { packet } => AI consensus, verdict, risk, $1000, idiot guide
 */

try { require('dotenv').config(); } catch (_) { /* dotenv optional: hosted platforms inject env vars directly */ }
const express = require('express');
const cors = require('cors');

const app = express();
app.use(express.json({ limit: '128kb' }));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));

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
  return data;
}

// very light per-IP rate limit (protects your keys from a runaway client)
const hits = new Map();
app.use((req, res, next) => {
  const ip = req.ip || 'x';
  const now = Date.now();
  const w = hits.get(ip) || { n: 0, exp: now + 60000 };
  if (w.exp < now) { w.n = 0; w.exp = now + 60000; }
  w.n++; hits.set(ip, w);
  if (w.n > 120) return res.status(429).json({ error: 'rate_limited' });
  next();
});

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
  res.json({
    ok: true,
    keys: {
      etoro: ETORO_ON, finnhub: !!FINNHUB, fred: !!FRED, supabase: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY),
      openai: !!process.env.OPENAI_API_KEY, anthropic: !!process.env.ANTHROPIC_API_KEY,
      gemini: !!process.env.GEMINI_API_KEY, perplexity: !!process.env.PERPLEXITY_API_KEY,
      openrouter: !!process.env.OPENROUTER_API_KEY, grok: GROK_ON
    },
    committeeSeats: loadSeats().filter(s => providerHasKey(s.provider)).length,
    geoOfficer: GROK_ON ? { on: true, model: GROK_MODEL, liveSearch: GROK_LIVE_SEARCH } : { on: false },
    ts: Date.now()
  });
});

/* ───────── /api/prices ───────── */
app.get('/api/prices', async (req, res) => {
  const symbols = String(req.query.symbols || 'VOO,QQQ,NVDA,MSFT,VXUS,SCHD')
    .split(',').map(s => s.trim().toUpperCase()).filter(Boolean).slice(0, 25);
  try {
    const data = await cached('prices:' + symbols.join(','), 30000, async () => {
      const out = {};
      if (!FINNHUB) return { prices: {}, source: 'none', note: 'set FINNHUB_API_KEY' };
      await Promise.all(symbols.map(async sym => {
        try {
          const j = await getJson(`https://finnhub.io/api/v1/quote?symbol=${sym}&token=${FINNHUB}`);
          if (j && j.c) out[sym] = { price: j.c, dp: num(j.dp), change: num(j.d), prevClose: num(j.pc) };
        } catch (_) { /* leave symbol out */ }
      }));
      return { prices: out, source: 'finnhub' };
    });
    res.json({ ...data, ts: Date.now() });
  } catch (e) { res.json({ prices: {}, source: 'error', error: String(e.message), ts: Date.now() }); }
});

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
  } catch (e) { res.json({ error: String(e.message), ts: Date.now() }); }
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
  } catch (e) { res.json({ error: String(e.message), ts: Date.now() }); }
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
  } catch (e) { res.json({ events: [], error: String(e.message), ts: Date.now() }); }
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
  } catch (e) { res.json({ news: [], error: String(e.message), ts: Date.now() }); }
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
const crypto = require('crypto');
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
  const cash = n2(cp.credit) || 0;   // 'credit' = funds available for new actions (buying power); bonusCredit excluded
  const cpPnl = cp.unrealizedPnL;
  const totalPl = (cpPnl && typeof cpPnl === 'object') ? n2(cpPnl.pnL ?? cpPnl.pnlAssetCurrency) : n2(cpPnl);
  // NOTE: the free price feed (Finnhub) reported today's per-stock % moves ~9x larger than reality
  // (it implied a ~1.8% drop when eToro showed the account flat at -0.08%), so estimateTodayPl gives
  // an untrustworthy figure. Rather than show a wrong number we leave Today P/L blank until it can be
  // sourced from eToro's own daily change. estimateTodayPl is kept below for when we revisit it.
  const out = normalisePortfolio({ holdings, availableCashUsd: cash, totalPlUsd: totalPl, todayPlUsd: null });
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
      source: 'manual', connected: false, error: String(e.message),
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
  '- DEPLOY ON PLAN: routine — put excess cash to work in underweight core holdings to hit existing targets. This is maintenance, not aggression.\n' +
  '- BUY GRADUALLY: ease in over several tranches rather than all at once.\n' +
  '- WATCH: conditions mixed; prepare but wait for a specific trigger.\n' +
  '- HOLD: do nothing; stay the course.\n' +
  '- WAIT: deliberately keep cash; a known event or risk justifies patience.\n' +
  '- REDUCE RISK: trim exposure or raise cash.\n' +
  '- BUY AGGRESSIVELY: RESERVED for genuine market dislocations only (deep drawdown, VIX spike, extreme fear). Do NOT use it for ordinary rebalancing or deploying idle cash.';

// Built-in fallbacks used only if a prompt file is missing.
const DEFAULTS = {
  'system-investing.md': 'You advise Andrew Collins, a long-term eToro ETF/stock investor in Bahrain. Advice only — never place trades, never suggest leverage/CFDs/options/shorting/crypto. Scope: portfolio, markets, dry powder, deployment, risk, opportunity. Be blunt and decision-led.',
  'deep-triggers.md': 'From your role, give a blunt independent read of the portfolio, market, the biggest risk, the best opportunity, and whether to deploy today and where. End with ONE verdict.',
  roles: {
    pm: 'Portfolio Manager. Focus on allocation, deployment of dry powder, hitting target weights, and long-term compounding. Pragmatic, action-oriented.',
    risk: 'Risk Manager. Assess portfolio-specific risk: concentration (single names like NVDA/AIA), diversification, drawdown capacity and position sizing. Constructive but cautious.',
    macro: 'Macro Analyst. Read the VIX, yields, the yield curve, CPI and the Fed, plus any headlines/catalysts in the packet. Judge the regime and whether conditions favour deploying or waiting.',
    news: 'News / Research Analyst. Weigh the headlines and catalysts in the packet. Separate signal from noise; flag anything that genuinely changes the picture.',
    devil: 'Devil\u2019s Advocate. You exist to STOP a bad decision. Make the strongest possible case AGAINST the majority recommendation every time — never endorse buying. Argue: why hold cash, why valuations (e.g. VOO) may be rich, why inflation could stay sticky, why the opportunity score may be misleading, and the single most likely way the committee is wrong.',
    synthesiser: 'You are the chair. Judge which argument is strongest given the data — do not average or vote. One seat is a mandated Devil\u2019s Advocate; weigh its case honestly on merit (do not dismiss it), but recognise its stance is structurally bearish. Make one decisive call.',
    idiotGuideStyle: 'Plain, blunt, no jargon. Concrete numeric actions.'
  }
};
const _pcache = {};
function loadPrompt(file) {
  try {
    const fp = path.join(PROMPT_DIR, file);
    const st = fs.statSync(fp);
    const c = _pcache[file];
    if (c && c.mt === st.mtimeMs) return c.data;          // serve cached unless the file changed
    const txt = fs.readFileSync(fp, 'utf8');
    _pcache[file] = { mt: st.mtimeMs, data: txt };
    return txt;
  } catch (_) { return DEFAULTS[file] || ''; }
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
    body: JSON.stringify({ model: modelOverride || process.env.ANTHROPIC_MODEL || 'claude-3-5-haiku-latest', max_tokens: 900, system, messages: [{ role: 'user', content: user }] })
  }, 40000);
  return j.content && j.content[0] && j.content[0].text;
}
async function callGemini(user, system, modelOverride) {
  const key = process.env.GEMINI_API_KEY; if (!key) return null;
  const model = modelOverride || process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const j = await getJson(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: system + '\n\n' + user }] }] })
  }, 40000);
  return j.candidates && j.candidates[0] && j.candidates[0].content.parts[0].text;
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
// Provider router — one entry per provider. OpenRouter alone covers many model families.
const PROVIDERS = { openai: callOpenAI, anthropic: callAnthropic, gemini: callGemini, perplexity: callPerplexity, openrouter: callOpenRouter, xai: callGrok };
function providerHasKey(p) {
  return { openai: !!process.env.OPENAI_API_KEY, anthropic: !!process.env.ANTHROPIC_API_KEY, gemini: !!process.env.GEMINI_API_KEY, perplexity: !!process.env.PERPLEXITY_API_KEY, openrouter: !!process.env.OPENROUTER_API_KEY, xai: !!(process.env.GROK_API_KEY || process.env.XAI_API_KEY) }[p];
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
  return r.slice(0, 70);
}

// Committee seats — genuine diversity = different model FAMILIES + different roles.
// Fully config-driven: set COMMITTEE_SEATS (a JSON array) in the environment to add/remove
// models with NO code change. Seats whose provider has no key are skipped automatically.
const DEFAULT_SEATS = [
  { seat: 'Portfolio Manager', role: 'pm',    provider: 'gemini',     model: 'gemini-2.5-flash',                         fallbackProvider: 'openrouter', fallbackModel: 'meta-llama/llama-3.3-70b-instruct:free' },
  { seat: 'Risk Manager',      role: 'risk',  provider: 'openrouter', model: 'meta-llama/llama-3.3-70b-instruct:free',  fallbackProvider: 'gemini',     fallbackModel: 'gemini-2.5-flash' },
  { seat: 'Macro Analyst',     role: 'macro', provider: 'openrouter', model: 'qwen/qwen3-235b-a22b:free',               fallbackProvider: 'gemini',     fallbackModel: 'gemini-2.5-flash' },
  { seat: 'Devil\u2019s Advocate', role: 'devil', provider: 'openrouter', model: 'deepseek/deepseek-chat-v3.1:free',    fallbackProvider: 'gemini',     fallbackModel: 'gemini-2.5-flash' }
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
const SYNTH_ASK = '\n\nYou MUST judge which argument is strongest. DO NOT average the verdicts and DO NOT just take the majority. Decide.\n\nRespond ONLY with compact JSON, no markdown:\n{"finalVerdict":"<one of: ' + VERDICTS.join(' | ') + '>","agree":["<points all/most models agree on>"],"disagree":["<genuine points of disagreement>"],"strongestArgument":"<which view is strongest and why>","weakestAssumption":"<the weakest assumption anyone is relying on>","riskWarning":"<one blunt sentence>","ifIHad1000":"<exact $ split totalling 1000, or WAIT FOR <event>>","idiotGuide":{"do":["..."],"dont":["..."],"checkAgain":"..."}}';
const GEO_ASK = '\n\nYou are NOT a market analyst and you do NOT give buy/sell/hold advice. You never see the portfolio. Your ONLY job: name near-term (next 1\u20134 weeks) GLOBAL or GEOPOLITICAL events that could make the committee\u2019s verdict wrong \u2014 wars, sanctions, elections, oil/energy shocks, central-bank surprises, tariffs, major-power tensions.\n\nRespond ONLY with compact JSON, no markdown:\n{"summary":"<2 sentences on the geopolitical risk backdrop right now>","events":["<near-term event + date if known + why it matters to markets>","..."],"couldMakeWrong":"<the single scenario most likely to blindside the committee\u2019s verdict>","watch":"<the one headline or indicator to watch>"}';

// Geopolitical Risk Officer (Grok). Runs independently of the committee — geopolitical risk exists
// whether or not the 4 seats responded. NEVER receives portfolio holdings/history, only geoPacket.
async function runGeoOfficer(geoPacket, verdict, ROLES) {
  if (!GROK_ON || typeof geoPacket !== 'string' || !geoPacket.trim()) return null;
  let raw;
  try {
    const geoSystem = (ROLES.geopolitics || 'You are the committee\u2019s Geopolitical Risk Officer.') + GEO_ASK;
    const geoUser = 'MACRO / MARKET / NEWS CONTEXT (no portfolio data):\n' + geoPacket +
      '\n\nThe committee\u2019s current verdict: ' + (verdict || 'no verdict (committee unavailable this run)') +
      '.\nName the near-term global/geopolitical events that could make a deploy-or-wait decision wrong right now, and the one thing to watch.';
    raw = await callGrok(geoUser, geoSystem);
  } catch (e) {
    return { error: String((e && e.message) || e).slice(0, 220), by: 'grok', model: GROK_MODEL };
  }
  if (!raw) return { error: 'Grok returned an empty response — the xAI account may need an active payment method/credit before API calls work.', by: 'grok', model: GROK_MODEL };
  const g = parseJsonLoose(raw);
  if (!g) return { error: 'Grok replied but not in the expected JSON format.', note: String(raw).slice(0, 240), by: 'grok', model: GROK_MODEL };
  return {
    summary: g.summary || '', events: Array.isArray(g.events) ? g.events.slice(0, 5) : [],
    couldMakeWrong: g.couldMakeWrong || '', watch: g.watch || '',
    by: 'grok', model: GROK_MODEL, liveSearch: GROK_LIVE_SEARCH
  };
}

app.post('/api/deep-triggers', async (req, res) => {
  const packet = req.body && req.body.packet;
  if (!packet || typeof packet !== 'string') return res.status(400).json({ error: 'missing packet' });

  const TASK = loadPrompt('deep-triggers.md');
  const ROLES = loadRoles();
  const seats = loadSeats().filter(s => providerHasKey(s.provider));

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
    } catch (_) { /* no memory this run */ }
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
      reason: m ? null : shortReason(failures[s.seat]), reasonDetail: m ? null : (failures[s.seat] || null)
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
    ifIHad1000: (synth && synth.ifIHad1000) || models.map(m => m.deploy).filter(Boolean)[0] || null,
    idiotGuide: (synth && synth.idiotGuide) || null,
    synthesised: !!synth, synthBy: synthModel ? synthModel.provider : null,
    rounds: DEBATE_ROUNDS, seats: models.length,
    tally, seatStatus, seatsConfigured, seatsResponded,
    ts: Date.now()
  };

  // GEOPOLITICAL RISK OFFICER (Grok) — separate from the voting committee, not in the tally.
  out.geoRisk = await runGeoOfficer(req.body && req.body.geoPacket, verdict, ROLES);
  res.json(out);

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
    }]).catch(() => {});
  }
});

/* ───────── Prompt management (admin) ───────── */
const PROMPT_FILES = ['system-investing.md', 'deep-triggers.md', 'ai-roles.json'];
app.get('/api/prompts', (req, res) => {
  const out = {};
  PROMPT_FILES.forEach(f => out[f] = loadPrompt(f));
  res.json({ dir: PROMPT_DIR, files: PROMPT_FILES, prompts: out, ts: Date.now() });
});
app.post('/api/prompts', (req, res) => {
  const { file, content } = req.body || {};
  if (!PROMPT_FILES.includes(file)) return res.status(400).json({ error: 'unknown file', allowed: PROMPT_FILES });
  if (typeof content !== 'string') return res.status(400).json({ error: 'content must be a string' });
  if (file === 'ai-roles.json') { try { JSON.parse(content); } catch (e) { return res.status(400).json({ error: 'invalid JSON: ' + e.message }); } }
  try {
    fs.mkdirSync(PROMPT_DIR, { recursive: true });
    fs.writeFileSync(path.join(PROMPT_DIR, file), content, 'utf8');
    delete _pcache[file];
    res.json({ ok: true, file, savedBytes: content.length, ts: Date.now() });
  } catch (e) {
    res.status(500).json({ error: 'write failed (filesystem may be read-only on this host): ' + e.message });
  }
});

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
    } catch (e) { /* fall through to file store */ }
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
    catch (e) { /* fall back to file store below, never crash */ }
  }
  const h = histLoad();
  if (type === 'journal') { incoming.forEach(e => { const i = h.journal.findIndex(x => x.id === e.id); if (i >= 0) h.journal[i] = e; else h.journal.push(e); }); h.journal = h.journal.slice(-500); }
  else { h.snapshots.push(...incoming); h.snapshots = h.snapshots.slice(-1000); }
  histSave();
  res.json({ ok: true, type, count: incoming.length, total: h[type].length, backend: 'file', ts: Date.now() });
});

app.use((req, res) => res.status(404).json({ error: 'not_found' }));
app.listen(PORT, () => console.log(`Investing Command Centre backend on :${PORT}`));
