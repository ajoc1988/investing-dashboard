'use strict';
/**
 * committee-resolver.js — v3 (participation-aware).
 *
 * Post-synthesis resolution: turns (verdict, consensus, participation, cashContext)
 * into an honest display colour + a bucket-aware action. Does NOT decide the verdict.
 *
 * v3 fixes the false-green found on 2026-06-15: 1 of 4 seats responding with a
 * buy verdict was scoring 100% consensus -> green. Confidence is now CAPPED by
 * participation, so a verdict from a near-empty committee can never read confident.
 *
 *   agreement     = how much the RESPONDING seats agree (consensus %)
 *   participation = how many of the configured seats actually responded
 *   confidence    = the MORE CAUTIOUS of the two
 *
 * Participation ceiling (max band allowed):
 *   4/4 -> strong (green allowed) | 3/4 -> lean (amber-green max)
 *   2/4 -> amber max | 1/4 -> amber max + lowConfidence flag | 0/4 -> no decision
 *
 * Note on the "1/4 = red" idea: a single seat voting BUY is blindness, not danger,
 * so 1/4 caps to AMBER (+lowConfidence), never RED — RED would falsely imply the
 * environment is dangerous when really the committee just didn't show up.
 *
 * Verdict ladder — MUST match STANCE in server.js:
 *   BUY AGGRESSIVELY 6 | DEPLOY ON PLAN 5 | BUY GRADUALLY 4   <- buy-type
 *   WATCH 3 | HOLD 2 | WAIT 1 | REDUCE RISK 0                  <- defensive
 */

const STANCE = {
  'BUY AGGRESSIVELY': 6, 'DEPLOY ON PLAN': 5, 'BUY GRADUALLY': 4,
  'WATCH': 3, 'HOLD': 2, 'WAIT': 1, 'REDUCE RISK': 0
};
const BUY_FLOOR = 4;
const DEPLOYABLE_BUCKETS = Object.freeze(['plan', 'discretionary', 'drypowder']);

// Ordinal confidence bands (high -> low). 'none' = no decision.
const BAND_RANK = { strong: 3, lean: 2, 'no-consensus': 1, none: 0 };
const moreCautious = (a, b) => (BAND_RANK[a] <= BAND_RANK[b] ? a : b);

function isBuy(verdict) { return (STANCE[verdict] ?? -1) >= BUY_FLOOR; }

function participationCeiling(responded, configured) {
  if (!configured || configured <= 0 || responded == null) {
    return { ceiling: 'strong', ratio: null, known: false }; // can't assess -> don't cap (server always passes these)
  }
  const ratio = responded / configured;
  let ceiling;
  if (ratio >= 1)         ceiling = 'strong';        // 4/4
  else if (ratio >= 0.75) ceiling = 'lean';          // 3/4
  else                    ceiling = 'no-consensus';  // 2/4 and 1/4
  return { ceiling, ratio, known: true };
}

/** Agreement band capped by participation -> band + display colour. */
function confidence(verdict, consensus, seatsResponded, seatsConfigured) {
  const buy = isBuy(verdict);

  let agreeBand;
  if (consensus >= 100)     agreeBand = 'strong';
  else if (consensus >= 75) agreeBand = 'lean';
  else                      agreeBand = 'no-consensus';

  const part = participationCeiling(seatsResponded, seatsConfigured);
  const band = moreCautious(agreeBand, part.ceiling);

  let colour;
  if (band === 'strong')    colour = buy ? 'green' : 'red';
  else if (band === 'lean') colour = buy ? 'amber-green' : 'amber-red';
  else                      colour = 'amber';

  return {
    agreementPct: consensus,
    band,
    colour,
    direction: buy ? 'buy' : 'defensive',
    participation: { responded: seatsResponded ?? null, configured: seatsConfigured ?? null, ratio: part.ratio, known: part.known },
    cappedByParticipation: BAND_RANK[part.ceiling] < BAND_RANK[agreeBand],
    lowConfidence: part.known && part.ratio < 0.5
  };
}

/**
 * @param {{verdict:string, consensus:number, seatsResponded?:number, seatsConfigured?:number, cashContext?:object}} x
 */
function resolve({ verdict, consensus, seatsResponded, seatsConfigured, cashContext }) {
  consensus = Number(consensus) || 0;
  const conf = confidence(verdict, consensus, seatsResponded, seatsConfigured);

  if (!verdict) {
    return { action: 'wait', confidence: { ...conf, band: 'none', colour: 'grey' }, note: 'no committee verdict', bucketAware: false };
  }

  // Defensive verdict: chair says don't buy — cash bucket is irrelevant.
  if (!isBuy(verdict)) {
    return { action: 'wait', confidence: conf, note: `defensive verdict (${verdict})`, bucketAware: false };
  }

  const partNote = conf.cappedByParticipation
    ? ` [confidence capped: ${conf.participation.responded}/${conf.participation.configured} seats]` : '';

  // Buy-type verdict, no bucket declared: reflect confidence, don't gate.
  if (!cashContext) {
    return {
      action: (conf.band === 'strong' || conf.band === 'lean') ? 'deploy' : 'review',
      confidence: conf, note: 'buy verdict; no cash bucket declared' + partNote,
      bucketAware: false, needsBucket: true
    };
  }
  if (!DEPLOYABLE_BUCKETS.includes(cashContext.bucket)) {
    throw new Error(`Invalid or ring-fenced cash bucket: ${cashContext.bucket}. Only ${DEPLOYABLE_BUCKETS.join(', ')} may reach the committee.`);
  }

  // Action keys off the FINAL (capped) band, never raw consensus.
  if (conf.band === 'strong' || conf.band === 'lean') {
    return { action: 'deploy', confidence: conf, cashContext, note: `${conf.band} ${verdict.toLowerCase()}` + partNote, bucketAware: true };
  }
  // Capped to no-consensus -> bucket decides. Plan proceeds (DCA default); rest waits.
  if (cashContext.bucket === 'plan') {
    return { action: 'deploy', confidence: conf, cashContext, note: `low confidence — proceed on plan default only` + partNote, bucketAware: true };
  }
  return { action: 'wait', confidence: conf, cashContext, note: `low confidence — hold ${cashContext.bucket}` + partNote, bucketAware: true };
}

module.exports = { resolve, confidence, isBuy, STANCE, DEPLOYABLE_BUCKETS };

// --- boot-test: `node committee-resolver.js` ---
if (require.main === module) {
  const C = [
    ['DEPLOY ON PLAN', 100, 1, 4, { bucket: 'plan' }],          // <- the screenshot bug: 1/4 buy
    ['DEPLOY ON PLAN', 100, 1, 4, { bucket: 'discretionary' }],
    ['DEPLOY ON PLAN', 100, 4, 4, { bucket: 'discretionary' }], // 4/4 unanimous
    ['DEPLOY ON PLAN', 100, 3, 4, { bucket: 'discretionary' }], // 3/4 unanimous
    ['DEPLOY ON PLAN', 100, 2, 4, { bucket: 'plan' }],          // 2/4 unanimous
    ['DEPLOY ON PLAN',  50, 4, 4, { bucket: 'plan' }],          // 4/4 split, plan
    ['DEPLOY ON PLAN',  50, 4, 4, { bucket: 'discretionary' }], // 4/4 split, discretionary
    ['WAIT',           100, 4, 4, { bucket: 'plan' }],          // 4/4 clear wait
    ['WAIT',           100, 1, 4, { bucket: 'plan' }],          // 1/4 wait
    [null,               0, 0, 4, { bucket: 'plan' }],          // no decision
  ];
  for (const [v, c, sr, sc, ctx] of C) {
    const r = resolve({ verdict: v, consensus: c, seatsResponded: sr, seatsConfigured: sc, cashContext: ctx });
    console.log(`${String(v).padEnd(16)} ${String(c).padStart(3)}% ${sr}/${sc} ${(ctx?ctx.bucket:'-').padEnd(8)} -> ${r.action.toUpperCase().padEnd(7)} ${r.confidence.colour.padEnd(11)} ${r.confidence.lowConfidence?'LOWCONF ':'        '}(${r.note})`);
  }
  try { resolve({ verdict: 'DEPLOY ON PLAN', consensus: 100, seatsResponded: 4, seatsConfigured: 4, cashContext: { bucket: 'emergency' } }); }
  catch (e) { console.log('ring-fence guard -> THREW: ' + e.message.split('.')[0]); }
}
