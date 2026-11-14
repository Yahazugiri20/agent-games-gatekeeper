/**
 * Deterministic decision policy for the Proof Gatekeeper payment requests.
 *
 * The platform sends a payment request backed by a proof. Most traps still carry
 * a proof that verifies, so "the proof is valid" is not the question. The
 * question is whether every field agrees. One mismatch is a REJECT.
 *
 * Scoring is asymmetric: a correct decision pays +12, approving a trap costs
 * -6, rejecting a valid request costs -3. So the policy is conservative where
 * the cost of being wrong is highest, and it never guesses.
 *
 * No model is called here. A language model may explain a rejection later; it
 * may not make the decision.
 */

/** Every rejection reason the policy can return. */
export const Reason = Object.freeze({
  MISSING_FIELDS: "MISSING_FIELDS",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_EXCEEDS_MAX: "AMOUNT_EXCEEDS_MAX",
  AMOUNT_BELOW_MINIMUM: "AMOUNT_BELOW_MINIMUM",
  EXPIRED: "EXPIRED",
  DEADLINE_PASSED: "DEADLINE_PASSED",
  INSUFFICIENT_BALANCE: "INSUFFICIENT_BALANCE",
  PROOF_REUSED: "PROOF_REUSED",
  MALFORMED_HEX: "MALFORMED_HEX",
  INTERNAL_ERROR: "INTERNAL_ERROR",
});

/** Fields a task must carry for any check to be meaningful. */
const REQUIRED = [
  "registered_vk",
  "proof_vk",
  "minimum",
  "public_balance",
  "expiry_block",
  "current_block",
  "recipient",
  "condition_recipient",
  "amount",
  "max_transfer",
  "proof_tx",
];

const HEX_RE = /^0x[0-9a-fA-F]+$/;

/** Normalise a hex string for comparison: lowercase, no leading zeros. */
function normHex(v) {
  if (typeof v !== "string" || !HEX_RE.test(v)) return null;
  const body = v.slice(2).toLowerCase().replace(/^0+/, "");
  return "0x" + (body === "" ? "0" : body);
}

/** Normalise an address: lowercase, zero-padded to 40 hex chars. */
function normAddress(v) {
  const h = normHex(v);
  if (h === null) return null;
  return "0x" + h.slice(2).padStart(40, "0");
}

/** Parse a decimal amount. Returns null when not an integer. */
function parseAmount(v) {
  if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
  if (typeof v !== "string" || !/^\d+$/.test(v)) return null;
  try {
    return BigInt(v);
  } catch {
    return null;
  }
}

/** Parse an integer that may arrive as a number or a decimal string. */
function parseInt10(v) {
  if (typeof v === "number" && Number.isInteger(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return null;
}

/**
 * Decide one payment request.
 *
 * @param {object} input The task's `input` object.
 * @param {object} opts
 * @param {Set<string>} opts.usedProofs Proof references already approved.
 * @param {number} [opts.nowMs] Current time in ms, for the task deadline.
 * @param {string|null} [opts.expectedVk] Registered vk hash, if pinned in env.
 * @param {string|null} [opts.deadlineAt] The envelope's deadline_at, ISO string.
 * @returns {{decision: "APPROVE"|"REJECT", reason_code?: string, detail?: string}}
 */
export function decide(input, opts = {}) {
  const used = opts.usedProofs ?? new Set();
  const nowMs = opts.nowMs ?? Date.now();
  const expectedVk = opts.expectedVk ?? null;

  if (!input || typeof input !== "object") {
    return { decision: "REJECT", reason_code: Reason.MISSING_FIELDS, detail: "no input" };
  }

  // 1. Every field present. A trap can omit one and hope the check is skipped.
  for (const k of REQUIRED) {
    if (input[k] === undefined || input[k] === null || input[k] === "") {
      return { decision: "REJECT", reason_code: Reason.MISSING_FIELDS, detail: k };
    }
  }

  // 2. The envelope's own deadline, before anything else time related.
  if (opts.deadlineAt) {
    const dl = Date.parse(opts.deadlineAt);
    if (Number.isFinite(dl) && nowMs > dl) {
      return { decision: "REJECT", reason_code: Reason.DEADLINE_PASSED };
    }
  }

  // 3. Key substitution: the proof must be made under the registered key.
  const regVk = normHex(input.registered_vk);
  const prfVk = normHex(input.proof_vk);
  if (regVk === null || prfVk === null) {
    return { decision: "REJECT", reason_code: Reason.MALFORMED_HEX, detail: "vk" };
  }
  if (regVk !== prfVk) {
    return { decision: "REJECT", reason_code: Reason.VK_SUBSTITUTION };
  }
  if (expectedVk !== null && regVk !== normHex(expectedVk)) {
    return { decision: "REJECT", reason_code: Reason.VK_SUBSTITUTION, detail: "not the pinned vk" };
  }

  // 4. The money must go where the condition says, or the proof proves the wrong
  //    thing. Compare normalised forms, not raw strings.
  const recipient = normAddress(input.recipient);
  const condition = normAddress(input.condition_recipient);
  if (recipient === null || condition === null) {
    return { decision: "REJECT", reason_code: Reason.MALFORMED_HEX, detail: "address" };
  }
  if (recipient !== condition) {
    return { decision: "REJECT", reason_code: Reason.RECIPIENT_MISMATCH };
  }

  // 5. Amount within both bounds. Over the cap drains the pot; under the floor
  //    fails the rule the proof claims to satisfy.
  const amount = parseAmount(input.amount);
  const maxTransfer = parseAmount(input.max_transfer);
  const minimum = parseAmount(input.minimum);
  const balance = parseAmount(input.public_balance);
  if (amount === null || maxTransfer === null || minimum === null || balance === null) {
    return { decision: "REJECT", reason_code: Reason.MISSING_FIELDS, detail: "amount not an integer" };
  }
  if (amount > maxTransfer) {
    return { decision: "REJECT", reason_code: Reason.AMOUNT_EXCEEDS_MAX };
  }
  if (amount < minimum) {
    return { decision: "REJECT", reason_code: Reason.AMOUNT_BELOW_MINIMUM };
  }
  if (balance < amount) {
    return { decision: "REJECT", reason_code: Reason.INSUFFICIENT_BALANCE };
  }

  // 6. Expiry. current_block > expiry_block means the proof's own window closed.
  const expiry = parseInt10(input.expiry_block);
  const current = parseInt10(input.current_block);
  if (expiry === null || current === null) {
    return { decision: "REJECT", reason_code: Reason.MISSING_FIELDS, detail: "block numbers" };
  }
  if (current > expiry) {
    return { decision: "REJECT", reason_code: Reason.EXPIRED };
  }

  // 7. Replay. A real proof reused against a second request is a trap.
  const proofTx = normHex(input.proof_tx);
  if (proofTx === null) {
    return { decision: "REJECT", reason_code: Reason.MALFORMED_HEX, detail: "proof_tx" };
  }
  if (used.has(proofTx)) {
    return { decision: "REJECT", reason_code: Reason.PROOF_REUSED };
  }

  return { decision: "APPROVE" };
}

/** Record an approved proof reference so a replay is caught next time. */
export function markUsed(usedProofs, input) {
  const proofTx = normHex(input?.proof_tx);
  if (proofTx !== null) usedProofs.add(proofTx);
  return proofTx;
}
