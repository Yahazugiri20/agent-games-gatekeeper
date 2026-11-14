# Agent Games — Proof Gatekeeper agent

An agent for [zkVerify Agent Games](https://agentgames.zkverify.io/), Event 01.
The platform sends a signed payment request backed by a Groth16 proof; this
service decides APPROVE or REJECT and answers with a signed body.

## Why the decision is not the proof

Most traps in this event still carry a proof that verifies. "The proof is valid"
is therefore never the question. The question is whether the proof backs *this*
request: right key, right recipient, right amount, right window, not reused. One
field disagreeing is a rejection.

Scoring is asymmetric, which sets the policy:

| outcome | points |
|---|---|
| correct decision | +12 |
| approving a trap | −6 |
| rejecting a valid request | −3 |
| timeout or offline | −2 |
| proof omitted or invalid | −2 |

So the policy is conservative exactly where being wrong costs most, and it never
guesses. `src/policy.js` is deterministic code. No model is consulted, because a
model that can be argued into an approval is a liability at −6 per mistake.

## The seven checks

In order, each returning a stable `reason_code`:

1. **MISSING_FIELDS** — every field the checks depend on is present.
2. **DEADLINE_PASSED** — the envelope's `deadline_at` has not elapsed.
3. **VK_SUBSTITUTION** — `proof_vk` equals `registered_vk` after hex
   normalisation, and equals the pinned hash when `GATEKEEPER_VK_HASH` is set.
4. **RECIPIENT_MISMATCH** — `recipient` equals `condition_recipient` after
   zero-padding both to 40 hex characters.
5. **AMOUNT_EXCEEDS_MAX / AMOUNT_BELOW_MINIMUM / INSUFFICIENT_BALANCE** — the
   amount sits inside both bounds and is covered by the balance.
6. **EXPIRED** — `current_block` has not passed `expiry_block`.
7. **PROOF_REUSED** — this `proof_tx` has not backed an earlier approval.

Anything that throws, times out, or does not parse answers REJECT. Failing closed
is the only safe default: −2 for a timeout beats −6 for a wrong approval.

## Layout

```
src/policy.js    the seven checks; pure, no I/O, no network
src/hmac.js      HMAC-SHA256 over the raw body, constant-time compare
src/proof.js     Groth16 generation and Kurier submission, best effort
src/server.js    Express endpoint: verify, decide, sign, respond
src/test.js      policy replay: 12 cases, no network
src/smoke.js     end-to-end: signed preflight, trap, approve, bad signature
```

## Run

```bash
npm install
npm test        # policy cases
node src/smoke.js   # end-to-end against a local server
npm start
```

Environment:

| variable | purpose |
|---|---|
| `AGENT_GAMES_HMAC_SECRET` | 32-byte secret from the dashboard. Required. |
| `GATEKEEPER_VK_HASH` | Optional pin for the registered vk hash. |
| `KURIER_API_KEY` | Optional; enables on-chain proof submission. |
| `CIRCUIT_DIR` | Where `gatekeeper.wasm` / `gatekeeper_final.zkey` live. |
| `PORT` | Listen port, default 8080. |

Secrets live in `.env` only, which is gitignored. `.env.example` ships with
blank values.

## Endpoint

`POST /agent` — the registered path. Also `GET /health`.

Every inbound request is authenticated over the raw bytes before
`JSON.parse`, so a formatting change, a duplicate key, or trailing whitespace
cannot slip past the check. Every outbound body carries
`x-agent-games-signature` over the exact bytes sent.

Preflight answers `{ ok: true, protocolVersion: "v1" }`, signed.

## Proof generation

The proof is the reliability bonus, not the score. A valid proof with a wrong
decision still loses points, so `src/proof.js` never blocks a response: if the
circuit artefacts are absent, generation exceeds its budget, or Kurier fails, the
decision goes out without a proof. Download the artefacts from
[the build page](https://agentgames.zkverify.io/build) into `circuits/`.

## Deployment

Any host that serves HTTPS on a public address and accepts a POST. The platform
will not reach localhost or a private IP. Set `AGENT_GAMES_HMAC_SECRET` in the
host's environment, register the full handler path (`/agent`, not `/`), and run
the platform's preflight before the first scored round.

## Status

Policy and transport verified locally: 12/12 policy cases, full smoke run green.
Proof generation is wired but untested here because the circuit artefacts are not
committed, and the live gamemode needs the platform's secret.
