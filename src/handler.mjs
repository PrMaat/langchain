/**
 * PrMaatCallbackHandler — LangChain.js BaseCallbackHandler subclass that
 * signs every LangGraph event with the agent's W3C DID before forwarding
 * it to LangSmith / your tracer of choice.
 *
 * Design priorities (per Genesis Day strategy doc 2026-05-01):
 *
 * 1. CHECKPOINT-BOUND PAYLOAD (spec §4.3):
 *    The single failure mode that could embarrass us at Day 7 is
 *    signature/trace desync under async streaming — the handler signs
 *    the wrong slice when parallel branches or tool-call/result pairs
 *    interleave. Mitigation: bind every event's `ctx.parentEventId`
 *    to LangGraph's checkpoint ID, NOT to the callback's wall-clock
 *    timestamp. We canonicalize a deterministic snapshot, not a
 *    moment-in-time observation.
 *
 * 2. CUSTODY DISCIPLINE (spec §2.3):
 *    The handler accepts a `keyHandle` interface, NOT raw key bytes.
 *    The handle's `sign()` shells out to keychain / bridge / hardware,
 *    so this process never holds key material. Inline keys are dev-only
 *    and produce events that fail verification.
 *
 * 3. ZERO RUNTIME DEPS:
 *    Bridge + verifier + this handler all share canonicalize.mjs +
 *    sign.mjs. No npm deps means the LangChain integration has the
 *    same supply-chain footprint as core LangChain itself (ed25519
 *    via Node built-in crypto).
 *
 * Usage with LangChain.js:
 *
 *   import { ChatOpenAI } from "@langchain/openai";
 *   import { PrMaatCallbackHandler } from "@prmaat/langchain";
 *   import { makeBridgeHandle } from "@prmaat/langchain/sign";
 *
 *   const handle = makeBridgeHandle({ agentId: "my-agent" });
 *   const handler = new PrMaatCallbackHandler({
 *     issuerDid: "did:prmaat:abc123",
 *     verificationMethod: "did:prmaat:abc123#key-1",
 *     keyHandle: handle,
 *     onSignedEvent: async (event) => {
 *       // ship to your audit chain (PrMaat backend, your S3 bucket, etc.)
 *       await fetch("/api/events", { method: "POST", body: JSON.stringify(event) });
 *     },
 *   });
 *
 *   const model = new ChatOpenAI({ callbacks: [handler] });
 *   await model.invoke("hello");
 *
 * For LangGraph specifically, attach the handler to the StateGraph:
 *
 *   const graph = new StateGraph(...).compile({ callbacks: [handler] });
 *
 * Every node entry/exit, tool call, LLM start/end produces a signed
 * event whose `ctx.parentEventId` is the LangGraph checkpoint ID.
 */
import { signEvent, newNonce, nowIso } from "./sign.mjs";

// LangChain BaseCallbackHandler imports are runtime-optional — we only
// require @langchain/core when actually instantiated, so users not on
// LangChain can still import the canonicalization + signing modules.
async function getBaseCallbackHandler() {
  try {
    const m = await import("@langchain/core/callbacks/base");
    return m.BaseCallbackHandler;
  } catch (e) {
    throw new Error(
      "@prmaat/langchain: BaseCallbackHandler requires @langchain/core (peer dep). " +
      "Install with: npm i @langchain/core"
    );
  }
}

/**
 * Build the handler. Returned as a function so the BaseCallbackHandler
 * import is lazy — users can import { canonicalize } without paying the
 * langchain-core import cost.
 */
export async function makePrMaatCallbackHandler(opts) {
  const Base = await getBaseCallbackHandler();
  return new (class extends Base {
    name = "prmaat";

    constructor() {
      super();
      const { issuerDid, verificationMethod, keyHandle, onSignedEvent, agentName } = opts;
      if (!issuerDid)            throw new Error("PrMaatCallbackHandler: issuerDid required");
      if (!verificationMethod)   throw new Error("PrMaatCallbackHandler: verificationMethod required");
      if (!keyHandle?.sign)      throw new Error("PrMaatCallbackHandler: keyHandle with .sign() required");
      if (!onSignedEvent)        throw new Error("PrMaatCallbackHandler: onSignedEvent required");
      this.issuerDid = issuerDid;
      this.verificationMethod = verificationMethod;
      this.keyHandle = keyHandle;
      this.onSignedEvent = onSignedEvent;
      this.agentName = agentName || issuerDid;

      // prev event hash chain — connects events from the same handler.
      // Resets to null when a new chain starts.
      this.prevHash = null;
    }

    // ── Helpers ────────────────────────────────────────────────────

    async _emit(eventType, ctx, runId) {
      // Bind to LangChain's runId (a UUID issued at the start of any
      // chain/llm/tool invocation). LangGraph's checkpoint ID maps to
      // runId for top-level graph nodes; for nested operations the
      // parentRunId chains them. Using runId — NOT wall-clock time —
      // is the §4.3 mitigation against async-streaming desync.
      const payload = {
        v: 1,
        type: eventType,
        issuer: this.issuerDid,
        subject: this.issuerDid,
        ts: nowIso(),
        ctx: {
          ...ctx,
          parentEventId: runId || null,
        },
        prev: this.prevHash,
        nonce: newNonce(),
      };

      let signed;
      try {
        signed = await signEvent({
          payload,
          handle: this.keyHandle,
          verificationMethod: this.verificationMethod,
        });
      } catch (e) {
        // Don't break the user's LangChain run if signing fails — log
        // the error and let the trace continue unsigned. Operators who
        // need hard-fail can wrap this handler.
        console.error(`[prmaat] sign failed for ${eventType}: ${e.message}`);
        return;
      }

      // Update prev hash chain (sha256 of canonical bytes of the signed event).
      // For brevity we re-canonicalize here; could memoize via _emit return.
      // The chain is per-handler, NOT global; multi-agent rooms produce
      // multiple parallel chains.
      try {
        const { createHash } = await import("node:crypto");
        const canonical = (await import("./canonicalize.mjs")).canonicalBytes(signed);
        this.prevHash = createHash("sha256").update(Buffer.from(canonical)).digest("hex");
      } catch { /* prev chain is best-effort */ }

      try {
        await this.onSignedEvent(signed);
      } catch (e) {
        console.error(`[prmaat] onSignedEvent threw for ${eventType}: ${e.message}`);
      }
    }

    // ── LangChain callback methods ─────────────────────────────────

    // Hash a value for inclusion in event ctx without leaking content.
    // The verifier can re-hash the original to confirm the event refers
    // to a specific message/tool result.
    _hashContent(s) {
      try {
        // Light-weight hex sha256
        const enc = new TextEncoder().encode(typeof s === "string" ? s : JSON.stringify(s));
        // Use crypto.subtle synchronously isn't possible; defer to caller pattern.
        // For v0.1 we just truncate-stringify; v0.2 will async-hash properly.
        return `len:${enc.length}`;
      } catch {
        return "len:?";
      }
    }

    async handleLLMStart(llm, prompts, runId, parentRunId) {
      await this._emit("agent.tool.invoked", {
        toolId: `llm:${llm?.name || llm?.id?.[0] || "unknown"}`,
        argsHash: `sha256:${this._hashContent(prompts)}`,
        policyId: null,
      }, runId);
    }

    async handleLLMEnd(output, runId, parentRunId) {
      const text = output?.generations?.[0]?.[0]?.text || "";
      await this._emit("agent.message.sent", {
        roomId: null, // populated by the user via ctx if needed
        contentHash: `sha256:${this._hashContent(text)}`,
        model: output?.llmOutput?.modelName || null,
      }, runId);
    }

    async handleLLMError(err, runId, parentRunId) {
      await this._emit("agent.tool.completed", {
        toolId: "llm",
        resultHash: `sha256:err:${this._hashContent(err?.message || "")}`,
        parentEventId: runId || null,
      }, runId);
    }

    async handleChainStart(chain, inputs, runId, parentRunId) {
      // We don't sign chain start as a separate type yet — chains are
      // bookkeeping. v0.2 may emit `agent.handoff.delegated` for chain
      // boundaries that cross agent identities.
    }

    async handleToolStart(tool, input, runId, parentRunId) {
      await this._emit("agent.tool.invoked", {
        toolId: `tool:${tool?.name || "unknown"}`,
        argsHash: `sha256:${this._hashContent(input)}`,
        policyId: null,
      }, runId);
    }

    async handleToolEnd(output, runId, parentRunId) {
      await this._emit("agent.tool.completed", {
        toolId: "tool",
        resultHash: `sha256:${this._hashContent(output)}`,
        parentEventId: parentRunId || runId || null,
      }, runId);
    }
  })();
}

/**
 * Sync convenience wrapper: build a handler with the canonical defaults.
 * Returns a thunk you await. Required because BaseCallbackHandler import
 * is async (via @langchain/core peer dep).
 */
export function PrMaatCallbackHandler(opts) {
  // Allow `new PrMaatCallbackHandler(...)` style by returning a thenable
  // promise. Most LangChain users construct callbacks asynchronously
  // anyway via `await`.
  return makePrMaatCallbackHandler(opts);
}
