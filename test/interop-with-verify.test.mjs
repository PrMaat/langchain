/**
 * Interop test: an event signed by @prmaat/langchain MUST verify
 * cleanly with @prmaat/verify. This is the cross-package guarantee
 * that matters most — if signer and verifier disagree on
 * canonicalization, the moat collapses.
 *
 * Imports verify directly from the sibling /Users/Mike/prmaat-public/verify
 * because it's not on npm yet. Once @prmaat/verify ships to npm,
 * this becomes a normal `import { verifySignedEvent } from "@prmaat/verify"`.
 *
 * Run:   node test/interop-with-verify.test.mjs
 * Exit:  0 if interop holds, 1 otherwise.
 */
import { signEvent, generateTestKeypair, newNonce, nowIso } from "../src/sign.mjs";
import { verifySignedEvent } from "../../verify/src/verify.mjs";

let pass = 0, fail = 0;
function ok(name, condition, detail) {
  if (condition) { console.log(`✓ ${name}`); pass++; }
  else { console.log(`✗ ${name}${detail ? "  — " + detail : ""}`); fail++; }
}

// ── T1: round-trip — sign with langchain, verify with verify ──────
{
  const { handle, publicKeyMultibase } = generateTestKeypair();
  const didId = "did:prmaat:interop-test-1";
  const kid = "key-1";
  const verificationMethod = `${didId}#${kid}`;

  const signed = await signEvent({
    payload: {
      v: 1,
      type: "agent.message.sent",
      issuer: didId,
      subject: didId,
      ts: nowIso(),
      ctx: { roomId: "interop-room", contentHash: "sha256:hello", model: "test/interop" },
      prev: null,
      nonce: newNonce(),
    },
    handle,
    verificationMethod,
  });

  // Build a DID Doc with custody="os-keychain" (cheat — handle is
  // actually inline-runtime, but we override the declared custody so
  // the verifier passes us through. In production the bridge handle
  // would actually report bridge-isolated.)
  const didDoc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: didId,
    verificationMethod: [{
      id: verificationMethod,
      type: "Ed25519VerificationKey2020",
      controller: didId,
      publicKeyMultibase,
      "prmaat:custody": "os-keychain", // pretend custody is OK
    }],
    assertionMethod: [verificationMethod],
  };

  let result, err = null;
  try {
    result = verifySignedEvent({ event: signed, didDocument: didDoc });
  } catch (e) {
    err = e;
  }
  ok("T1 langchain-signed event verifies in @prmaat/verify",
     err === null && result?.ok === true,
     err ? err.message : `result=${JSON.stringify(result)}`);
  ok("T1b reports basic conformance",
     result?.conformance === "prmaat-v0.1.basic",
     `got ${result?.conformance}`);
}

// ── T2: tampering detection — modify signed event and re-verify ──
{
  const { handle, publicKeyMultibase } = generateTestKeypair();
  const didId = "did:prmaat:interop-test-2";
  const kid = "key-1";
  const verificationMethod = `${didId}#${kid}`;

  const signed = await signEvent({
    payload: {
      v: 1, type: "agent.message.sent",
      issuer: didId, subject: didId,
      ts: nowIso(),
      ctx: { roomId: "r", contentHash: "sha256:original", model: "m" },
      prev: null, nonce: newNonce(),
    },
    handle, verificationMethod,
  });

  // Tamper with the content hash AFTER signing
  signed.ctx.contentHash = "sha256:tampered";

  const didDoc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: didId,
    verificationMethod: [{
      id: verificationMethod, type: "Ed25519VerificationKey2020",
      controller: didId, publicKeyMultibase,
      "prmaat:custody": "os-keychain",
    }],
    assertionMethod: [verificationMethod],
  };

  let threw = false, msg = "";
  try { verifySignedEvent({ event: signed, didDocument: didDoc }); }
  catch (e) { threw = true; msg = e.message; }
  ok("T2 tampered langchain-signed event FAILS verification",
     threw && msg.startsWith("SIGNATURE_INVALID"),
     msg);
}

// ── T3: runtime custody is rejected ──────────────────────────────
{
  const { handle, publicKeyMultibase } = generateTestKeypair();
  const didId = "did:prmaat:interop-test-3";
  const verificationMethod = `${didId}#key-1`;

  const signed = await signEvent({
    payload: {
      v: 1, type: "agent.message.sent",
      issuer: didId, subject: didId,
      ts: nowIso(),
      ctx: { roomId: "r", contentHash: "sha256:x", model: "m" },
      prev: null, nonce: newNonce(),
    },
    handle, verificationMethod,
  });

  // Honestly declared custody="runtime" — should fail per §2.3
  const didDoc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: didId,
    verificationMethod: [{
      id: verificationMethod, type: "Ed25519VerificationKey2020",
      controller: didId, publicKeyMultibase,
      "prmaat:custody": "runtime",
    }],
    assertionMethod: [verificationMethod],
  };

  let threw = false, msg = "";
  try { verifySignedEvent({ event: signed, didDocument: didDoc }); }
  catch (e) { threw = true; msg = e.message; }
  ok("T3 honest runtime custody is rejected (spec §2.3 bright line)",
     threw && msg.startsWith("CUSTODY_INSUFFICIENT"),
     msg);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
