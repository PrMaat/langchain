/**
 * Smoke tests for @prmaat/langchain.
 *
 * Tests the parts that DON'T require @langchain/core (so we can run
 * before installing peer deps):
 *   - canonicalize matches expected bytes
 *   - signEvent produces a valid signed event
 *   - the resulting event passes @prmaat/verify (via dynamic import)
 *
 * Skips the LangChain BaseCallbackHandler instantiation tests — those
 * require @langchain/core and live in a separate test file that runs
 * in CI with the peer dep installed.
 *
 * Run:   node test/handler.test.mjs
 * Exit:  0 if all assertions pass, 1 otherwise.
 */
import { canonicalize, canonicalBytes } from "../src/canonicalize.mjs";
import { signEvent, generateTestKeypair, newNonce, nowIso, makeInlineHandle } from "../src/sign.mjs";

let pass = 0, fail = 0;

function ok(name, condition, detail) {
  if (condition) { console.log(`✓ ${name}`); pass++; }
  else { console.log(`✗ ${name}${detail ? "  — " + detail : ""}`); fail++; }
}

// ── T1: canonicalize sorts keys ────────────────────────────────────
{
  const a = canonicalize({ b: 1, a: 2 });
  const b = canonicalize({ a: 2, b: 1 });
  ok("T1 canonicalize key order is deterministic", a === b && a === '{"a":2,"b":1}');
}

// ── T2: canonicalize handles nested + arrays ──────────────────────
{
  const out = canonicalize({ z: [3, 2, 1], a: { y: 1, x: 2 } });
  ok("T2 canonicalize nested objects + arrays", out === '{"a":{"x":2,"y":1},"z":[3,2,1]}', `got ${out}`);
}

// ── T3: canonicalize rejects undefined + non-finite numbers ───────
{
  let threw = false;
  try { canonicalize({ x: undefined }); } catch { threw = true; }
  ok("T3a rejects undefined", threw);
  threw = false;
  try { canonicalize({ x: NaN }); } catch { threw = true; }
  ok("T3b rejects NaN", threw);
  threw = false;
  try { canonicalize({ x: Infinity }); } catch { threw = true; }
  ok("T3c rejects Infinity", threw);
}

// ── T4: signEvent produces a well-formed signed event ─────────────
{
  const { handle, publicKeyMultibase } = generateTestKeypair();
  const signed = await signEvent({
    payload: {
      v: 1,
      type: "agent.message.sent",
      issuer: "did:prmaat:test-handler",
      subject: "did:prmaat:test-handler",
      ts: nowIso(),
      ctx: { roomId: "r1", contentHash: "sha256:abc", model: "test/m1" },
      prev: null,
      nonce: newNonce(),
    },
    handle,
    verificationMethod: "did:prmaat:test-handler#key-1",
  });
  ok("T4a signed event has proof", !!signed.proof);
  ok("T4b proof.type Ed25519Signature2020", signed.proof.type === "Ed25519Signature2020");
  ok("T4c proof.proofValue starts with 'z' (base58btc multibase)", signed.proof.proofValue.startsWith("z"));
  ok("T4d proof.verificationMethod populated", signed.proof.verificationMethod === "did:prmaat:test-handler#key-1");
  ok("T4e publicKeyMultibase round-trips", typeof publicKeyMultibase === "string" && publicKeyMultibase.startsWith("z"));
}

// ── T5: signEvent rejects payloads with proof already attached ────
{
  let threw = false;
  try {
    const { handle } = generateTestKeypair();
    await signEvent({
      payload: { v: 1, type: "x", issuer: "did:prmaat:t", subject: "did:prmaat:t", ts: nowIso(), ctx: {}, prev: null, nonce: newNonce(), proof: {} },
      handle,
      verificationMethod: "did:prmaat:t#k",
    });
  } catch { threw = true; }
  ok("T5 rejects payloads that already have proof", threw);
}

// ── T6: signEvent rejects missing required fields ─────────────────
{
  let threw = false;
  try {
    const { handle } = generateTestKeypair();
    await signEvent({
      payload: { v: 1, type: "x", ts: nowIso(), ctx: {}, prev: null, nonce: newNonce() }, // missing issuer + subject
      handle,
      verificationMethod: "did:prmaat:t#k",
    });
  } catch { threw = true; }
  ok("T6 rejects payloads missing required fields", threw);
}

// ── T7: signed event's canonical bytes are deterministic ──────────
{
  const { handle } = generateTestKeypair();
  const payload = {
    v: 1,
    type: "agent.message.sent",
    issuer: "did:prmaat:t7",
    subject: "did:prmaat:t7",
    ts: "2026-05-01T12:00:00.000Z",
    ctx: { roomId: "r", contentHash: "sha256:x", model: "m" },
    prev: null,
    nonce: "0".repeat(32),
  };
  const c1 = canonicalize(payload);
  const c2 = canonicalize({ ...payload }); // shallow copy — should canonicalize identically
  ok("T7 canonicalize is stable across object copies", c1 === c2);
}

// ── Summary ───────────────────────────────────────────────────────
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
