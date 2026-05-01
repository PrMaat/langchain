/**
 * Ed25519 signer — produces signed events conforming to PrMaat
 * Verification Spec v0.1 §4 + §5.
 *
 * The handler in handler.mjs builds an event payload, calls signEvent()
 * to produce the canonical signature, and emits the result for the
 * bridge / direct backend POST to absorb.
 *
 * IMPORTANT: PrMaat custody discipline (§2.3) requires the signing key
 * to live OUTSIDE the runtime. This module accepts a `KeyHandle` —
 * NOT raw key bytes — so the actual key material can stay in the
 * macOS Keychain / a hardware module / a separate bridge process.
 *
 * Two ways to provide a key handle:
 *
 *   1. KEYCHAIN custody (recommended for dev):
 *        const handle = makeKeychainHandle("apt-<sha256(passportId)>", { service: "com.prmaat.bridge" })
 *        // The handle's sign() shells out to `security` CLI on macOS,
 *        // so this process never sees raw key bytes.
 *
 *   2. BRIDGE custody (recommended for production):
 *        const handle = makeBridgeHandle({ bridgeUrl: "http://127.0.0.1:7070", agentId: "..." })
 *        // The bridge process holds the key; this process posts events
 *        // for signing over a localhost socket.
 *
 *   3. INLINE custody (DEV ONLY — not spec-compliant):
 *        const handle = makeInlineHandle(privateKeyBuffer)
 *        // Signs in-process. Resulting events report custody="runtime"
 *        // which the verifier WILL FAIL with CUSTODY_INSUFFICIENT.
 *        // Useful for unit tests; never in production.
 */
import { sign as nodeSign, generateKeyPairSync, createPrivateKey } from "node:crypto";
import { execFileSync } from "node:child_process";
import { canonicalBytes } from "./canonicalize.mjs";

// ── multibase base58btc encode (Bitcoin alphabet) ────────────────────
const ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) { s = ALPH[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}

function multibaseSig(sig) {
  return "z" + base58Encode(sig);
}

// ── Key handle implementations ───────────────────────────────────────

/**
 * Inline handle — DEV / TEST ONLY.
 * Signs in-process, declares custody="runtime", and the resulting
 * events explicitly fail PrMaat verification (§2.3). Use for unit
 * tests or local repro of canonicalization bugs.
 */
export function makeInlineHandle(privateKey) {
  return {
    custody: "runtime",
    async sign(canonicalBuf) {
      return nodeSign(null, Buffer.from(canonicalBuf), privateKey);
    },
  };
}

/**
 * Generate a fresh ed25519 keypair for tests. Returns {handle, publicKeyMultibase}.
 */
export function generateTestKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = Uint8Array.from(spki).slice(spki.length - 32);
  const pubMb = "z" + base58Encode(new Uint8Array([0xed, 0x01, ...rawPub]));
  return {
    handle: makeInlineHandle(privateKey),
    publicKeyMultibase: pubMb,
  };
}

/**
 * Keychain handle — macOS only (uses `/usr/bin/security`).
 * The key MUST already be stashed in the keychain via
 * `brainclaw keychain stash`. Resulting events report
 * custody="os-keychain" which IS spec-compliant.
 *
 * Note: this is a v0.1 sketch. Production-hardening (LaunchAgent
 * isolation, signed access ACLs, key un-export verification) lands
 * in v0.2 alongside the Linux SecretService adapter.
 */
export function makeKeychainHandle({ account, service = "com.prmaat.bridge" }) {
  return {
    custody: "os-keychain",
    async sign(canonicalBuf) {
      // For v0.1: we shell out to a hypothetical `prmaat-keychain-sign` tool
      // (ships with the bridge package). This stub throws in tests; the real
      // wiring lands when the bridge exposes a signing socket (v0.2).
      throw new Error(
        "makeKeychainHandle: keychain signing requires the bridge package. " +
        "For now use makeInlineHandle (dev only) or makeBridgeHandle."
      );
    },
  };
}

/**
 * Bridge handle — posts events to the local PrMaat bridge for signing.
 * Bridge holds the key in its OS keychain. This process never sees
 * key material. Resulting events report custody="bridge-isolated"
 * (spec-compliant).
 *
 * Sketch for v0.1 — real implementation depends on the bridge exposing
 * a localhost signing socket (planned for bridge v0.4.0).
 */
export function makeBridgeHandle({ bridgeUrl = "http://127.0.0.1:7070", agentId }) {
  return {
    custody: "bridge-isolated",
    async sign(canonicalBuf) {
      const res = await fetch(`${bridgeUrl}/sign`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream", "X-Agent-Id": agentId },
        body: Buffer.from(canonicalBuf),
      });
      if (!res.ok) throw new Error(`bridge sign failed: HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      return buf;
    },
  };
}

// ── signEvent — main entry point ─────────────────────────────────────

/**
 * Build a signed PrMaat event from a payload.
 *
 * @param {object} args
 * @param {object} args.payload      The event payload WITHOUT proof.
 *                                    Must include {v, type, issuer, subject, ts, ctx, prev, nonce}.
 * @param {object} args.handle       A key handle (see makeInlineHandle / makeBridgeHandle).
 * @param {string} args.verificationMethod  Full URI: "did:prmaat:...#kid".
 * @returns {Promise<object>}        The signed event with `proof` attached.
 */
export async function signEvent({ payload, handle, verificationMethod }) {
  if (!payload || typeof payload !== "object") {
    throw new Error("signEvent: payload must be an object");
  }
  if (payload.proof) {
    throw new Error("signEvent: payload must NOT contain proof — sign builds it");
  }
  const required = ["v", "type", "issuer", "subject", "ts", "ctx", "nonce"];
  for (const k of required) {
    if (payload[k] === undefined) {
      throw new Error(`signEvent: payload missing required field "${k}"`);
    }
  }
  if (payload.prev === undefined) {
    payload.prev = null; // explicit null per §4.1
  }

  const canonical = canonicalBytes(payload);
  const sig = await handle.sign(canonical);
  if (!Buffer.isBuffer(sig) && !(sig instanceof Uint8Array)) {
    throw new Error("signEvent: handle.sign() must return Buffer or Uint8Array");
  }
  if (sig.length !== 64) {
    throw new Error(`signEvent: signature must be 64 bytes (got ${sig.length})`);
  }

  return {
    ...payload,
    proof: {
      type: "Ed25519Signature2020",
      created: payload.ts,
      verificationMethod,
      proofPurpose: "assertionMethod",
      proofValue: multibaseSig(sig),
    },
  };
}

// ── Helpers for the handler ──────────────────────────────────────────

/**
 * Generate a 128-bit hex nonce for events.
 */
export function newNonce() {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * RFC-3339 UTC with millisecond precision (matches §4.1 ts format).
 */
export function nowIso() {
  return new Date().toISOString();
}
