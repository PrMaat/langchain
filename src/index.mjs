/**
 * @prmaat/langchain — entry point.
 *
 * Re-exports the public API surface. Users typically import:
 *
 *   import { PrMaatCallbackHandler, makeBridgeHandle } from "@prmaat/langchain";
 *
 * Power users importing canonicalization / signing primitives can:
 *
 *   import { canonicalize, signEvent } from "@prmaat/langchain";
 */
export { PrMaatCallbackHandler, makePrMaatCallbackHandler } from "./handler.mjs";
export {
  signEvent,
  newNonce,
  nowIso,
  generateTestKeypair,
  makeInlineHandle,
  makeKeychainHandle,
  makeBridgeHandle,
} from "./sign.mjs";
export { canonicalize, canonicalBytes } from "./canonicalize.mjs";
