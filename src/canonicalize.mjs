/**
 * PrMaat canonicalization (spec v0.1 §4) — vendored from @prmaat/verify
 * to keep this package zero-dep for now. When @prmaat/verify is published
 * to npm we'll switch to importing from there.
 *
 * Same exact bytes-out behavior as @prmaat/verify/src/canonicalize.mjs.
 * Verifiers and signers MUST agree on canonicalization or signatures
 * desync — DO NOT modify without updating both packages.
 */
function canonicalizeValue(v) {
  if (v === null) return "null";
  if (v === undefined) {
    throw new Error("CANONICALIZATION_INVALID: undefined values not allowed");
  }
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(v)) {
      throw new Error("CANONICALIZATION_INVALID: non-finite numbers (NaN, Infinity) not allowed");
    }
    return String(v);
  }
  if (t === "string") return JSON.stringify(v.normalize("NFC"));
  if (Array.isArray(v)) return "[" + v.map(canonicalizeValue).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map(k => JSON.stringify(k.normalize("NFC")) + ":" + canonicalizeValue(v[k])).join(",") + "}";
  }
  throw new Error(`CANONICALIZATION_INVALID: unsupported type ${t}`);
}

export function canonicalize(obj) {
  return canonicalizeValue(obj);
}

export function canonicalBytes(obj) {
  return new TextEncoder().encode(canonicalize(obj));
}
