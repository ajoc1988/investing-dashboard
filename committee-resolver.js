'use strict';
/**
 * committee-resolver.js — post-synthesis resolution layer.
 *
 * IMPORTANT: this does NOT replace a chair tie-break — server.js has none.
 * The chair is the synthesiser LLM (server.js ~line 827, synth.finalVerdict).
 * This runs AFTER `out` is built and converts (verdict, consensus, cashContext)
 * into an honest display colour + a bucket-aware action. It never changes how
 * the verdict itself is decided.
 *
 * Verdict ladder — MUST match STANCE in server.js:
 *   BUY AGGRESSIVELY 6 | DEPLOY ON PLAN 5 | BUY GRADUALLY 4   <- buy-type
 *   WATCH 3 | HOLD 2 | WAIT 1 | REDUCE RISK 0                  <- defensive
 *
 * consensus = % of RESPONDING seats on the modal verdict (server.js line 805).
 */

const STANCE = {
  'BUY AGGRESSIVELY': 6, 'DEPLOY ON PLAN': 5, 'BUY GRADUALLY': 4,
  'WATCH': 3, 'HOLD': 2, 'WAIT': 1, 'REDUCE RISK': 0
};
const BUY_FLOOR = 4;               // STANCE >= 4 => the chair wants cash deployed
const DEPLOYABLE_BUCKETS = Object.freeze(['plan', 'discretionary', 'drypowder']);

// THE knob: at/above this agreement %, non-plan cash may deploy. Below it, only
// `plan` money proceeds (everything else waits). Set to 100 to require unanimity
// before discretionary / dry-powder cash is ever deployed on a split committee.
const ACTIONABLE_MAJORITY = 75;

function isBuy(verdict) { return (STANCE[verdict] ?? -1) >= BUY_FLOOR; }

/** consensus % + verdict direction -> band + display colour (no bucket needed). */
function confidence(verdict, consensus) {
  const buy = isBuy(verdict);
  let band, colour;
  if (consensus >= 100)                     { band = 'strong';       colour = buy ? 'green' : 'red'; }
  else if (consensus >= ACTIONABLE_MAJORITY){ band = 'lean';         colour = buy ? 'amber-green' : 'amber-red'; }
  else                                      { band = 'no-consensus'; colour = 'amber'; }
  return { agreementPct: consensus, band, colour, direction: buy ? 'buy' : 'defensive' };
}

/**
 * @param {{verdict:string, consensus:number, cashContext?:{bucket:string,amount?:number,monthlyLimit?:number}}} x
 * @returns {{action:'deploy'|'wait'|'review', confidence:object, note:string, bucketAware:boolean, needsBucket?:boolean, cashContext?:object}}
 */
function resolve({ verdict, consensus, cashContext }) {
  consensus = Number(consensus) || 0;
  const conf = confidence(verdict, consensus);

  if (!verdict) {
    return { action: 'wait', confidence: { ...conf, band: 'none', colour: 'grey' }, note: 'no committee verdict', bucketAware: false };
  }

  // Defensive verdict: chair says don't buy — cash bucket is irrelevant.
  if (!isBuy(verdict)) {
    return { action: 'wait', confidence: conf, note: `defensive verdict (${verdict})`, bucketAware: false };
  }

  // Buy-type verdict but no declared bucket: reflect confidence, don't gate, ask for one.
  if (!cashContext) {
    return {
      action: consensus >= ACTIONABLE_MAJORITY ? 'deploy' : 'review',
      confidence: conf, note: 'buy verdict; no cash bucket declared',
      bucketAware: false, needsBucket: true
    };
  }
  if (!DEPLOYABLE_BUCKETS.includes(cashContext.bucket)) {
    // Ring-fenced (emergency/business) cash must never reach the committee.
    throw new Error(`Invalid or ring-fenced cash bucket: ${cashContext.bucket}. Only ${DEPLOYABLE_BUCKETS.join(', ')} may reach the committee.`);
  }

  // Clear majority -> deploy any deployable bucket.
  if (consensus >= ACTIONABLE_MAJORITY) {
    return { action: 'deploy', confidence: conf, cashContext, note: `clear majority (${consensus}%) — ${verdict.toLowerCase()}`, bucketAware: true };
  }

  // Split / low agreement -> bucket decides (the agreed rule). Confidence stays amber.
  if (cashContext.bucket === 'plan') {
    return { action: 'deploy', confidence: conf, cashContext, note: `low agreement (${consensus}%) — proceed on plan only`, bucketAware: true };
  }
  return { action: 'wait', confidence: conf, cashContext, note: `low agreement (${consensus}%) — hold ${cashContext.bucket}`, bucketAware: true };
}

module.exports = { resolve, confidence, isBuy, STANCE, DEPLOYABLE_BUCKETS, ACTIONABLE_MAJORITY };

// --- standalone boot-test: `node committee-resolver.js` ---
if (require.main === module) {
  const C = [
    ['DEPLOY ON PLAN', 50, { bucket: 'discretionary' }],  // the screenshot case
    ['DEPLOY ON PLAN', 50, { bucket: 'plan' }],
    ['DEPLOY ON PLAN', 50, { bucket: 'drypowder' }],
    ['DEPLOY ON PLAN', 75, { bucket: 'discretionary' }],
    ['BUY AGGRESSIVELY', 100, { bucket: 'drypowder' }],
    ['WAIT', 100, { bucket: 'plan' }],
    ['WATCH', 50, { bucket: 'plan' }],
    ['DEPLOY ON PLAN', 67, null],                          // buy verdict, no bucket declared
    [null, 0, { bucket: 'plan' }],                         // committee didn't respond
  ];
  for (const [v, c, ctx] of C) {
    const r = resolve({ verdict: v, consensus: c, cashContext: ctx });
    console.log(`${String(v).padEnd(16)} ${String(c).padStart(3)}% ${(ctx?ctx.bucket:'(none)').padEnd(14)} -> ${r.action.toUpperCase().padEnd(7)} ${r.confidence.colour.padEnd(11)} (${r.note})`);
  }
  try { resolve({ verdict: 'DEPLOY ON PLAN', consensus: 100, cashContext: { bucket: 'emergency' } }); }
  catch (e) { console.log('ring-fence guard:'.padEnd(40) + 'THREW — ' + e.message.split('.')[0]); }
}
