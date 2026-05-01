# @prmaat/langchain

> LangChain.js callback handler that signs every LangGraph event with
> the agent's W3C DID, so traces become cryptographically attributable
> instead of framework-self-attested. Conforms to [PrMaat Verification
> Spec v0.1](https://prmaat.com/spec/v0.1).

## What this gets you

A standard LangChain `BaseCallbackHandler` you attach to any chain,
graph, or model. As your agent runs:

1. Every LLM start/end, tool call, and chain transition produces a
   PrMaat-signed event (spec §4 + §5).
2. Events are bound to LangGraph **checkpoint IDs**, not callback
   wall-clock — so signatures don't desync under async streaming or
   parallel branches (spec §4.3).
3. Signed events flow to whatever sink you want — PrMaat's hosted
   audit chain, your own S3 bucket, or LangSmith with PrMaat
   signatures attached.

The result: you can **prove** which agent (specific W3C DID + custody
level) said what during a run, verifiable by any third party with the
[`prmaat verify`](https://github.com/PrMaat/verify) CLI. No more
"trust LangSmith's database."

## Install

```bash
npm install @prmaat/langchain
# Peer dep:
npm install @langchain/core
```

## Quick start

```javascript
import { ChatOpenAI } from "@langchain/openai";
import { PrMaatCallbackHandler, makeBridgeHandle } from "@prmaat/langchain";

// 1. Get a key handle. Bridge custody = signing key lives in a
//    separate process (the PrMaat bridge); this process never holds
//    raw key bytes — required for prmaat-v0.1.audit conformance.
const keyHandle = makeBridgeHandle({
  bridgeUrl: "http://127.0.0.1:7070",
  agentId:   "my-agent",
});

// 2. Create the handler.
const handler = await PrMaatCallbackHandler({
  issuerDid:          "did:prmaat:abc123",
  verificationMethod: "did:prmaat:abc123#key-1",
  keyHandle,
  onSignedEvent: async (event) => {
    // Ship the signed event wherever you want it audit-anchored.
    await fetch("https://prmaat.com/api/agent/events", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + APT },
      body: JSON.stringify(event),
    });
  },
});

// 3. Attach to any LangChain runnable.
const model = new ChatOpenAI({ callbacks: [handler] });
await model.invoke("Hello");

// Now every LLM start/end is signed and audit-anchored.
```

For LangGraph specifically, attach when compiling the StateGraph:

```javascript
import { StateGraph } from "@langchain/langgraph";

const graph = new StateGraph(/* ... */).compile({
  callbacks: [handler],
});
```

## Custody options (in order of preference)

```javascript
import {
  makeBridgeHandle,    // ✅ bridge-isolated   — prod, key in separate process
  makeKeychainHandle,  // ✅ os-keychain       — dev, key in macOS Keychain
  makeInlineHandle,    // ⚠️  runtime          — TESTS ONLY, fails verification
  generateTestKeypair, // ⚠️  runtime          — TESTS ONLY
} from "@prmaat/langchain";
```

The `runtime` custody level explicitly **FAILS** PrMaat verification per
[spec §2.3](https://prmaat.com/spec/v0.1#23-custody-levels). If your
key lives in the same process that produces messages, your "signed
traces" are security theatre — the `prmaat verify` CLI will reject
them with `CUSTODY_INSUFFICIENT`. This is the bright line that
separates real cryptographic accountability from marketing claims.

For development, use `makeInlineHandle` to iterate, but expect the
verifier to fail your bundles. Switch to `makeBridgeHandle` (or
`makeKeychainHandle` on macOS) before you ship to production.

## What gets signed

Every callback produces an event of the appropriate type per
[spec §4.2](https://prmaat.com/spec/v0.1#42-event-types):

| LangChain callback | PrMaat event type | Notes |
|--------------------|-------------------|-------|
| `handleLLMStart`   | `agent.tool.invoked`    | `ctx.toolId = llm:<name>` |
| `handleLLMEnd`     | `agent.message.sent`    | `ctx.contentHash` + `ctx.model` |
| `handleLLMError`   | `agent.tool.completed`  | with error hash |
| `handleToolStart`  | `agent.tool.invoked`    | `ctx.toolId = tool:<name>` |
| `handleToolEnd`    | `agent.tool.completed`  | with result hash |

Each event's `ctx.parentEventId` is the LangChain `runId` (UUID issued
at the start of the chain/llm/tool invocation) — NOT a wall-clock
timestamp. This is the §4.3 mitigation against signature/trace desync
under async streaming.

The hash chain (`event.prev`) connects events from the same handler
instance, so a single agent's trace is a verifiable linked list even
if events arrive out of order at the audit sink.

## Interop guarantee

Every event signed by this handler is **independently verifiable** by
the [`prmaat verify`](https://github.com/PrMaat/verify) CLI. The
test suite includes `test/interop-with-verify.test.mjs` which round-
trips signed events through the verifier and asserts:

- ✅ Valid events pass `prmaat-v0.1.basic` conformance
- ✅ Tampered events fail with `SIGNATURE_INVALID`
- ✅ Honestly-declared `runtime` custody fails with `CUSTODY_INSUFFICIENT`

If you ship this handler in production and someone audits your
trace, they can run `prmaat verify <bundle>` against any signed event
and get a deterministic OK / FAIL result.

## Limitations (v0.1.0)

- **JS only.** Python LangChain integration (`@prmaat/langchain-py`)
  lands in v0.2.
- **Bridge handle** is a v0.1 sketch — relies on the PrMaat bridge
  exposing a localhost signing socket, planned for bridge v0.4.0.
  Until then, dev users will mostly use `makeInlineHandle` (and accept
  that they fail verification) or wait for the keychain handle.
- **Async hash placeholder.** `_hashContent()` returns a length-only
  digest in v0.1; v0.2 swaps in a real `crypto.subtle.digest` call
  with proper hex output. The structural shape of events is correct
  — only the content-hash field is a placeholder.
- **No retry / batching.** `onSignedEvent` is awaited inline; if your
  audit sink is slow it will block the LangChain run. v0.2 adds an
  async batch queue with at-least-once delivery semantics.

## Running tests

```bash
cd langchain
node test/handler.test.mjs            # 13 unit tests, no LangChain dep
node test/interop-with-verify.test.mjs # 4 cross-package tests
```

The unit tests don't require `@langchain/core` (we test
canonicalization, signing, and the sign/verify round-trip in
isolation). The full `BaseCallbackHandler` invocation test ships
later in v0.1.1 once we add a LangChain.js fixture.

## License

MIT. See [LICENSE](./LICENSE).

## See also

- [PrMaat Verification Spec v0.1](https://prmaat.com/spec/v0.1) — the
  spec this handler implements.
- [@prmaat/verify](https://github.com/PrMaat/verify) — reference
  verifier, MIT, zero deps.
- [PrMaat Bridge](https://github.com/PrMaat/bridge) — local relay
  with OS-keychain custody.

---

*Built 2026-05-02 (Genesis Day +1, Cairo) after a 4-1 vote in the
PrMaat brainstorm room. Ships ahead of the Day 7 schedule
commitment from the launch-night strategy doc.*
