/**
 * Groth16 proof generation for the gatekeeper circuit.
 *
 * The proof is the reliability bonus, not the score: a valid proof with a wrong
 * decision still loses points, and an omitted or invalid proof costs -2. So this
 * module never blocks a decision. If artefacts are missing or generation fails,
 * the response goes out without a proof and the decision stands.
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

let snarkjs = null;
let wasm = null;
let zkey = null;
let loaded = false;

/** Load snarkjs and the circuit artefacts once. Returns true when usable. */
export async function init(artefactDir = "circuits") {
  if (loaded) return wasm !== null && zkey !== null;
  loaded = true;
  const wasmPath = join(artefactDir, "gatekeeper.wasm");
  const zkeyPath = join(artefactDir, "gatekeeper_final.zkey");
  if (!existsSync(wasmPath) || !existsSync(zkeyPath)) {
    console.warn(
      `[proof] artefacts missing (${wasmPath}, ${zkeyPath}); decisions will be sent without a proof`
    );
    return false;
  }
  try {
    snarkjs = (await import("snarkjs")).default ?? (await import("snarkjs"));
    wasm = readFileSync(wasmPath);
    zkey = readFileSync(zkeyPath);
    return true;
  } catch (e) {
    console.warn("[proof] init failed:", e.message);
    return false;
  }
}

/**
 * Generate a proof for the circuit's input signals.
 *
 * @param {object} signals Circuit inputs, as the circuit expects them.
 * @param {number} [timeoutMs] Budget for generation; the task allows 60 s total.
 * @returns {Promise<{proof: object, publicSignals: string[]}|null>}
 */
export async function prove(signals, timeoutMs = 25_000) {
  if (!snarkjs || !wasm || !zkey) return null;
  const work = snarkjs.groth16.fullProve(signals, wasm, zkey);
  const timer = new Promise((resolve) => setTimeout(() => resolve(null), timeoutMs));
  try {
    const out = await Promise.race([work, timer]);
    if (!out) {
      console.warn("[proof] generation exceeded budget; sending without a proof");
      return null;
    }
    return { proof: out.proof, publicSignals: out.publicSignals };
  } catch (e) {
    console.warn("[proof] generation failed:", e.message);
    return null;
  }
}

/** Submit a proof to zkVerify through Kurier and wait for Finalized. */
export async function submitToKurier({ proof, publicSignals, vkHash, apiKey }) {
  if (!apiKey || !vkHash) return null;
  const API = "https://api.kurier.xyz/api/v1";
  try {
    const submit = await fetch(`${API}/submit-proof/${apiKey}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        chainId: 1,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: {
          vk: vkHash,
          proof: proof,
          publicSignals: publicSignals,
        },
      }),
    });
    if (!submit.ok) {
      console.warn("[kurier] submit failed:", submit.status);
      return null;
    }
    const { jobId } = await submit.json();
    return await pollFinalized(API, apiKey, jobId);
  } catch (e) {
    console.warn("[kurier] error:", e.message);
    return null;
  }
}

async function pollFinalized(API, apiKey, jobId, tries = 20) {
  for (let i = 0; i < tries; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const res = await fetch(`${API}/job-status/${apiKey}/${jobId}`);
      const body = await res.json();
      const status = String(body.status ?? "").toLowerCase();
      if (status === "finalized") return body.txHash ?? jobId;
      if (status === "failed" || status === "error") return null;
    } catch {
      // transient; keep polling until the budget runs out
    }
  }
  return null;
}
