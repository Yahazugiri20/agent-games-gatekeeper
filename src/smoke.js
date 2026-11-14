/**
 * End-to-end smoke test: start the server, send a signed preflight and one
 * signed task, and assert the signed responses. No circuit artefacts and no
 * network are required; the proof module degrades to "no proof attached".
 */
import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";

const SECRET = "test-secret-do-not-use";
const PORT = 18099;

function sign(body) {
  return createHmac("sha256", SECRET).update(Buffer.from(body, "utf8")).digest("hex");
}

const server = spawn("node", ["src/server.js"], {
  env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, CIRCUIT_DIR: "missing" },
  stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (d) => process.stdout.write("[srv] " + d));
server.stderr.on("data", (d) => process.stderr.write("[srv] " + d));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function post(path, obj, { badSig = false } = {}) {
  const body = JSON.stringify(obj);
  const res = await fetch(`http://127.0.0.1:${PORT}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": badSig ? "deadbeef" : sign(body),
    },
    body,
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, text, json: JSON.parse(text) };
}

function assertSigned(res, label) {
  const got = res.headers.get("x-agent-games-signature");
  if (got !== sign(res.text)) throw new Error(`${label}: response signature invalid`);
}

let failures = 0;
function check(label, cond, extra = "") {
  if (cond) console.log(`  ok    ${label}`);
  else {
    console.error(`  FAIL  ${label} ${extra}`);
    failures++;
  }
}

try {
  // wait for listen
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/health`);
      if (r.ok) break;
    } catch {}
    await sleep(250);
  }

  const pre = await post("/agent", {
    type: "agent-games.preflight.v1",
    agent_id: "agt_test",
    issued_at: new Date().toISOString(),
    nonce: "abc123",
  });
  check("preflight returns ok:true", pre.json.ok === true, JSON.stringify(pre.json));
  check("preflight protocolVersion v1", pre.json.protocolVersion === "v1");
  assertSigned(pre, "preflight");
  check("preflight response is signed", true);

  const task = await post("/agent", {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_test_1",
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: "0x7d1f",
      proof_vk: "0x13aa",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: "0xDe42aBcD00000000000000000000000000009f01",
      condition_recipient: "0xDe42aBcD00000000000000000000000000009f01",
      amount: "1000",
      max_transfer: "1000",
      proof_tx: "0xaabbcc",
    },
  });
  check("trap is rejected", task.json.decision === "REJECT", JSON.stringify(task.json));
  check("trap reason is key substitution", task.json.reason_code === "VK_SUBSTITUTION");
  assertSigned(task, "task");
  check("task response is signed", true);

  const bad = await post("/agent", { type: "agent-games.preflight.v1" }, { badSig: true });
  check("bad signature is refused", bad.status === 401, `${bad.status}`);

  const good = await post("/agent", {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_test_2",
    deadline_at: new Date(Date.now() + 60_000).toISOString(),
    input: {
      registered_vk: "0x7d1f",
      proof_vk: "0x7d1f",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: "0xde42abcd00000000000000000000000000009f01",
      condition_recipient: "0xDE42ABCD00000000000000000000000000009F01",
      amount: "1000",
      max_transfer: "1000",
      proof_tx: "0xfeed01",
    },
  });
  check("clean request approved", good.json.decision === "APPROVE", JSON.stringify(good.json));
  assertSigned(good, "approve");
} catch (e) {
  console.error("  FAIL  harness threw:", e.message);
  failures++;
} finally {
  server.kill();
}

console.log(failures === 0 ? "\nsmoke ok" : `\n${failures} smoke failure(s)`);
process.exit(failures === 0 ? 0 : 1);
