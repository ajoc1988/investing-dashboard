'use strict';
/**
 * committee-resolver.js  —  Build step 1 of the verdict-logic rework.
 *
 * Scope (deliberately narrow):
 *   1. Defines the cashContext the committee must receive.
 *   2. Resolves seat votes -> confidence band + display colour (5-step).
 *   3. Resolves seat votes + cash bucket -> a committee ACTION,
 *      with action DECOUPLED from displayed confidence.
 *
 * Out of scope (later steps): the Deep-Trigger / tactical verdict,
 * the two-verdict display, and any UI. The tactical overlay combines
 * with the `action` returned here at the DISPLAY layer, not here.
 *
 * Locked spec
 *   Confidence (by % agreement among RESPONDING seats):
 *     4-0 -> green       | 3-1 -> amber-green (lean) | 2-2 -> amber (no consensus)
 *     1-3 -> amber-red   | 0-4 -> red
 *   Bucket tie (2-2) rules:
 *     plan          -> PROCEED on plan, but confidence shows amber
 *     discretionary -> WAIT
 *     drypowder     -> WAIT
 *     ring-fenced   -> never passed in (throws if it is)
 *
 * CommonJS module. Convert to import/export if the backend is ESM.
 */

const DEPLOYABLE_BUCKETS = Object.freeze(['plan', 'discretionary', 'drypowder']);

/**
 * @typedef {Object} CashContext
 * @property {'plan'|'discretionary'|'drypowder'} bucket
 * @property {number} amount         amount under consideration
 * @property {number} [monthlyLimit] optional cap for plan deployments
 */

/**
 * @typedef {Object} Votes
 * @property {number} deploy seats voting DEPLOY ON PLAN
 * @property {number} wait   seats voting WAIT
 */

/** Votes -> confidence band + display colour. Independent of cash bucket. */
function confidence(votes) {
  const total = votes.deploy + votes.wait;
  if (total === 0) {
    return { agreementPct: null, band: 'none', colour: 'grey', lean: 'none' };
  }
  const majority = Math.max(votes.deploy, votes.wait);
  const agreementPct = Math.round((majority / total) * 100);
  const lean = votes.deploy === votes.wait ? 'split'
             : votes.deploy > votes.wait ? 'deploy' : 'wait';

  let band, colour;
  if (agreementPct >= 100) {
    band = 'strong';
    colour = lean === 'deploy' ? 'green' : 'red';
  } else if (agreementPct >= 75) {
    band = 'lean';
    colour = lean === 'deploy' ? 'amber-green' : 'amber-red';
  } else {
    band = 'no-consensus';            // 2-2, or any sub-75% spread (e.g. a seat didn't run)
    colour = 'amber';
  }
  return { agreementPct, band, colour, lean };
}

/**
 * Resolve the committee's strategic action.
 * ACTION is intentionally independent of the displayed confidence colour.
 *
 * @param {Votes} votes
 * @param {CashContext} cashContext
 * @returns {{action:'deploy'|'wait', confidence:object, cashContext:CashContext, note:string}}
 */
function resolveCommittee(votes, cashContext) {
  if (!cashContext || !DEPLOYABLE_BUCKETS.includes(cashContext.bucket)) {
    // Ring-fenced (emergency/business) cash must never reach the committee.
    // Enforce by loud failure, not silent handling — omission is the rule.
    throw new Error(
      `Invalid or ring-fenced cash bucket: ${cashContext && cashContext.bucket}. ` +
      `Only ${DEPLOYABLE_BUCKETS.join(', ')} may be passed to the committee.`
    );
  }

  const conf = confidence(votes);
  let action, note;

  if (conf.lean === 'deploy') {
    action = 'deploy';
    note = conf.band === 'strong' ? 'clear deploy' : 'lean deploy';
  } else if (conf.lean === 'wait') {
    action = 'wait';
    note = conf.band === 'strong' ? 'clear wait' : 'lean wait';
  } else {
    // 2-2 split: action depends on the cash bucket; confidence stays amber.
    if (cashContext.bucket === 'plan') {
      action = 'deploy';
      note = 'split committee — proceed on plan (confidence amber)';
    } else {
      action = 'wait';
      note = `split committee — hold ${cashContext.bucket}`;
    }
  }

  return { action, confidence: conf, cashContext, note };
}

module.exports = { resolveCommittee, confidence, DEPLOYABLE_BUCKETS };

// --- standalone boot-test: `node committee-resolver.js` ---
if (require.main === module) {
  const cases = [
    ['4-0',               { deploy: 4, wait: 0 }, { bucket: 'discretionary', amount: 500 }],
    ['3-1',               { deploy: 3, wait: 1 }, { bucket: 'discretionary', amount: 500 }],
    ['1-3',               { deploy: 1, wait: 3 }, { bucket: 'discretionary', amount: 500 }],
    ['0-4',               { deploy: 0, wait: 4 }, { bucket: 'plan',          amount: 500 }],
    ['2-2 plan',          { deploy: 2, wait: 2 }, { bucket: 'plan',          amount: 500 }],
    ['2-2 discretionary', { deploy: 2, wait: 2 }, { bucket: 'discretionary', amount: 500 }],
    ['2-2 drypowder',     { deploy: 2, wait: 2 }, { bucket: 'drypowder',     amount: 7000 }],
    ['2-1 (seat missing)',{ deploy: 2, wait: 1 }, { bucket: 'plan',          amount: 500 }],
  ];
  for (const [label, votes, ctx] of cases) {
    const r = resolveCommittee(votes, ctx);
    console.log(
      `${label.padEnd(20)} -> ${r.action.toUpperCase().padEnd(7)} ` +
      `colour=${r.confidence.colour.padEnd(11)} agree=${String(r.confidence.agreementPct)}%  (${r.note})`
    );
  }
  try {
    resolveCommittee({ deploy: 4, wait: 0 }, { bucket: 'emergency', amount: 8000 });
  } catch (e) {
    console.log('ring-fence guard     -> THREW as expected: ' + e.message.split('.')[0]);
  }
}
