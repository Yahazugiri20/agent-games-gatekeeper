/**
 * Local replay harness for the gatekeeper policy.
 *
 * Each case is a full task input plus the decision the policy must reach. Run
 * with `npm test`. No network, no secrets, no model.
 */
import assert from "node:assert/strict";
import { decide, markUsed, Reason } from "./policy.js";

const BASE = {
  registered_vk: "0x7d1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b",
  proof_vk: "0x7d1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: "0xDe42aBcD00000000000000000000000000009f01",
  condition_recipient: "0xde42abcd00000000000000000000000000009f01",
  amount: "1000",
  max_transfer: "1000",
  proof_tx: "0xaa11bb22cc33dd44ee55ff66",
};

/** Deep copy with overrides applied. */
const with_ = (over) => ({ ...BASE, ...over });

const cases = [
  {
    name: "valid request, amount exactly at the cap",
    input: with_({ amount: "1000" }),
    expect: { decision: "APPROVE" },
  },
  {
    name: "amount over max_transfer is a trap",
    input: with_({ amount: "1001" }),
    expect: { decision: "REJECT", reason_code: Reason.AMOUNT_EXCEEDS_MAX },
  },
  {
    name: "amount below minimum fails the rule",
    input: with_({ amount: "999" }),
    expect: { decision: "REJECT", reason_code: Reason.AMOUNT_BELOW_MINIMUM },
  },
  {
    name: "key substitution: proof made under a different vk",
    input: with_({ proof_vk: "0x13a00000000000000000000000000000000000aa" }),
    expect: { decision: "REJECT", reason_code: Reason.VK_SUBSTITUTION },
  },
  {
    name: "recipient differs from the proven condition",
    input: with_({ recipient: "0xDe42aBcD0000000000000000000000000000beef" }),
    expect: { decision: "REJECT", reason_code: Reason.RECIPIENT_MISMATCH },
  },
  {
    name: "proof window closed (current_block past expiry)",
    input: with_({ current_block: 8430001 }),
    expect: { decision: "REJECT", reason_code: Reason.EXPIRED },
  },
  {
    name: "balance cannot cover the amount",
    input: with_({ public_balance: "500" }),
    expect: { decision: "REJECT", reason_code: Reason.INSUFFICIENT_BALANCE },
  },
  {
    name: "missing field is a rejection, not a default",
    input: (() => {
      const c = with_({});
      delete c.condition_recipient;
      return c;
    })(),
    expect: { decision: "REJECT", reason_code: Reason.MISSING_FIELDS },
  },
  {
    name: "malformed hex address",
    input: with_({ recipient: "0xZZZ", condition_recipient: "0xZZZ" }),
    expect: { decision: "REJECT", reason_code: Reason.MALFORMED_HEX },
  },
  {
    name: "clean request inside every bound is approved",
    input: with_({ amount: "1000" }),
    expect: { decision: "APPROVE" },
  },
];

let pass = 0;
let fail = 0;
for (const c of cases) {
  const got = decide(c.input, { usedProofs: new Set(), nowMs: Date.now() });
  try {
    assert.equal(got.decision, c.expect.decision, `${c.name}: decision`);
    if (c.expect.reason_code) {
      assert.equal(got.reason_code, c.expect.reason_code, `${c.name}: reason_code`);
    }
    console.log(`  ok    ${c.name}`);
    pass++;
  } catch (e) {
    console.error(`  FAIL  ${c.name}\n        got ${JSON.stringify(got)}`);
    fail++;
  }
}

// Replay: the same proof reference must be refused the second time.
{
  const used = new Set();
  const first = decide(BASE, { usedProofs: used, nowMs: Date.now() });
  markUsed(used, BASE);
  const second = decide(BASE, { usedProofs: used, nowMs: Date.now() });
  try {
    assert.equal(first.decision, "APPROVE", "replay: first approval");
    assert.equal(second.decision, "REJECT", "replay: second decision");
    assert.equal(second.reason_code, Reason.PROOF_REUSED, "replay: reason");
    console.log("  ok    proof reference cannot be reused");
    pass++;
  } catch (e) {
    console.error(`  FAIL  replay: ${e.message}`);
    fail++;
  }
}

// Deadline from the envelope.
{
  const past = new Date(Date.now() - 5000).toISOString();
  const got = decide(BASE, { usedProofs: new Set(), nowMs: Date.now(), deadlineAt: past });
  try {
    assert.equal(got.reason_code, Reason.DEADLINE_PASSED, "deadline");
    console.log("  ok    envelope deadline in the past is rejected");
    pass++;
  } catch {
    console.error(`  FAIL  deadline: got ${JSON.stringify(got)}`);
    fail++;
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
