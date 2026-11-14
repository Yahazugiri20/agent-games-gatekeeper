/**
 * Proof Gatekeeper agent — HTTPS endpoint for the zkVerify Agent Games.
 *
 * Protocol: the platform POSTs a signed JSON envelope, this service decides,
 * and returns a signed JSON body. Every inbound request is authenticated over
 * the raw bytes before parsing. Every outbound body is signed the same way.
 *
 * Failure policy: fail closed. Any error, timeout, or uncertainty answers
 * REJECT, never APPROVE. A 5xx that the platform reads as a timeout costs -2;
 * a wrong APPROVE costs -6.
 */
import express from "express";
import { SIGNATURE_HEADER, verify, sign } from "./hmac.js";
import { decide, markUsed } from "./policy.js";
import * as proof from "./proof.js";

const PORT = Number(process.env.PORT ?? 8080);
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET ?? "";
const EXPECTED_VK = process.env.GATEKEEPER_VK_HASH ?? null;
const KURIER_API_KEY = process.env.KURIER_API_KEY ?? "";
const ARTEFACT_DIR = process.env.CIRCUIT_DIR ?? "circuits";
// the platform allows 60 s; stop decision work well before that
const DECISION_BUDGET_MS = 45_000;

if (!SECRET) {
  console.error("AGENT_GAMES_HMAC_SECRET is not set; every request will be rejected");
}

const usedProofs = new Set();
const app = express();
app.disable("x-powered-by");

/** Capture the raw body for HMAC, and parse it afterwards. */
app.use(
  express.raw({ type: ["application/json", "application/*+json"], limit: "1mb" })
);

/** Send a JSON body with a valid signature over the exact bytes sent. */
function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  res.status(status);
  res.set("content-type", "application/json");
  if (SECRET) res.set(SIGNATURE_HEADER, sign(body, SECRET));
  res.send(body);
}

app.get("/health", (_req, res) => {
  sendSigned(res, 200, { ok: true, service: "proof-gatekeeper", version: "1.0.0" });
});

app.post("/agent", async (req, res) => {
  const started = Date.now();
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from("");

  // 1. Authenticate before parsing.
  if (!verify(raw, req.get(SIGNATURE_HEADER), SECRET)) {
    return sendSigned(res, 401, { error: "bad signature" });
  }

  let env;
  try {
    env = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendSigned(res, 400, { decision: "REJECT", reason_code: "MALFORMED_JSON" });
  }

  // 2. Preflight handshake.
  if (env?.type === "agent-games.preflight.v1") {
    return sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
  }

  // 3. Task. Decide deterministically, then try to attach a proof.
  if (env?.type !== "agent-games.proof-gatekeeper.v1") {
    return sendSigned(res, 400, { decision: "REJECT", reason_code: "UNKNOWN_TYPE" });
  }

  let verdict;
  try {
    verdict = decide(env.input, {
      usedProofs,
      nowMs: Date.now(),
      expectedVk: EXPECTED_VK,
      deadlineAt: env.deadline_at,
    });
  } catch (e) {
    console.error("[decide] threw:", e.message);
    verdict = { decision: "REJECT", reason_code: "INTERNAL_ERROR" };
  }

  const body = { decision: verdict.decision };
  if (verdict.reason_code) body.reason_code = verdict.reason_code;

  // Proof generation is best effort and bounded: it must never turn an APPROVE
  // into a timeout.
  if (verdict.decision === "APPROVE" && Date.now() - started < DECISION_BUDGET_MS) {
    const generated = await proof.prove(env.input, DECISION_BUDGET_MS - (Date.now() - started));
    if (generated) {
      body.proof = generated.proof;
      body.public_signals = generated.publicSignals;
      if (KURIER_API_KEY && EXPECTED_VK) {
        const tx = await proof.submitToKurier({
          proof: generated.proof,
          publicSignals: generated.publicSignals,
          vkHash: EXPECTED_VK,
          apiKey: KURIER_API_KEY,
        });
        if (tx) body.proof_tx = tx;
      }
    }
    markUsed(usedProofs, env.input);
  }

  console.log(
    `[task] ${env.task_id ?? "?"} ${body.decision}${body.reason_code ? "/" + body.reason_code : ""} ` +
      `${Date.now() - started}ms`
  );
  return sendSigned(res, 200, body);
});

// Any unexpected request shape: reject, never approve.
app.use((req, res) => {
  if (req.path === "/agent") {
    return sendSigned(res, 400, { decision: "REJECT", reason_code: "BAD_REQUEST" });
  }
  return sendSigned(res, 404, { error: "not found" });
});

await proof.init(ARTEFACT_DIR);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`proof-gatekeeper listening on 0.0.0.0:${PORT}`);
});
