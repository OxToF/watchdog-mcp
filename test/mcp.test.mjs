// node --test test/mcp.test.mjs
// The MCP server against a fake EVM Watchdog that demands x402 payment on Base.
// The payer is a throwaway key; EIP-3009 is signed offline, nothing reaches a chain.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttp } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../src/index.mjs";
import { signerFor, scrub, SERVICES } from "../src/payer.mjs";

const MERCHANT = "0x0e659996c75dcb352e95e130d79831e3e2fa82a8";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const EVM_KEY = "0x" + randomBytes(32).toString("hex");
const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const dec = (h) => JSON.parse(Buffer.from(h, "base64").toString());

let http, base;
const seen = []; // { path, paid, token }
let terms = { payTo: MERCHANT, amount: "50000" };

before(async () => {
  http = createHttp((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const sig = req.headers["payment-signature"];
      seen.push({ path: req.url, method: req.method, paid: !!sig, token: req.headers.authorization || null });
      if (req.method === "GET" || req.method === "DELETE") {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify({ status: req.method === "DELETE" ? "cancelled" : "active", events: [] }));
      }
      const accepts = [{ scheme: "exact", network: "eip155:8453", amount: terms.amount, asset: USDC, payTo: terms.payTo, maxTimeoutSeconds: 120, extra: { name: "USD Coin", version: "2" } }];
      const required = { x402Version: 2, error: "PAYMENT-SIGNATURE header is required", resource: { url: `${base}${req.url}`, description: "t", mimeType: "application/json" }, accepts };
      if (!sig) {
        res.writeHead(402, { "content-type": "application/json", "payment-required": enc(required), "access-control-expose-headers": "payment-required" });
        return res.end(JSON.stringify({ error: "payment_required" }));
      }
      const p = dec(sig);
      // What a real server checks first: the signed authorization pays our terms.
      assert.equal(p.payload.authorization.to.toLowerCase(), terms.payTo.toLowerCase());
      assert.equal(p.payload.authorization.value, terms.amount);
      res.writeHead(200, { "content-type": "application/json", "payment-response": enc({ success: true, transaction: "0x" + "ab".repeat(32), network: "eip155:8453" }) });
      res.end(JSON.stringify(req.url === "/agent/contract"
        ? { address: "0xabc", proxy: { kind: "uups" }, upgradeController: { kind: "timelock", text: "Timelock: changes wait 24 h after they are scheduled." }, flags: [] }
        : { checked: 2, advisories: [{ id: "GHSA-x", packages: ["solmate 6.2.0"] }], notCheckedCount: 0 }));
    });
  });
  await new Promise((r) => http.listen(0, r));
  base = `http://127.0.0.1:${http.address().port}`;
});
after(() => http.close());

async function client(env) {
  const { server } = createServer({ env: { WATCHDOG_EVM_URL: base, WATCHDOG_SOLANA_URL: base, ...env } });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const c = new Client({ name: "t", version: "0" });
  await c.connect(b);
  return c;
}
const call = async (c, name, args) => { const r = await c.callTool({ name, arguments: args }); return { err: !!r.isError, text: r.content[0].text }; };

test("pays the Watchdog wallet within limits, and accounts for it", async () => {
  terms = { payTo: MERCHANT, amount: "50000" };
  // SERVICES is read at import; point the EVM service at the fake for this process.
  SERVICES.evm.base = base;
  const c = await client({ WATCHDOG_EVM_PRIVATE_KEY: EVM_KEY });
  seen.length = 0;
  const r = await call(c, "evm_contract_control", { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" });
  assert.equal(r.err, false, r.text);
  assert.match(r.text, /Proxy: uups/);
  assert.deepEqual(seen.map((s) => s.paid), [false, true]);
  const w = JSON.parse((await call(c, "watchdog_wallet", {})).text);
  assert.equal(w.spentUsd, 0.05);
  assert.equal(w.payments.length, 1);
  assert.match(w.wallets.base, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(w.wallets.solana, null);
});

test("never pays another wallet, even if the server asks", async () => {
  terms = { payTo: "0x" + "66".repeat(20), amount: "50000" };
  const c = await client({ WATCHDOG_EVM_PRIVATE_KEY: EVM_KEY });
  seen.length = 0;
  const r = await call(c, "evm_contract_control", { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" });
  assert.equal(r.err, true);
  assert.match(r.text, /payTo .* is not the EVM Watchdog wallet/);
  assert.equal(seen.filter((s) => s.paid).length, 0);
});

test("per-call cap and session budget refuse before signing", async () => {
  terms = { payTo: MERCHANT, amount: "2000000" }; // $2
  let c = await client({ WATCHDOG_EVM_PRIVATE_KEY: EVM_KEY });
  seen.length = 0;
  let r = await call(c, "evm_contract_control", { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" });
  assert.match(r.text, /above WATCHDOG_MAX_PER_CALL_USD/);
  assert.equal(seen.filter((s) => s.paid).length, 0);

  terms = { payTo: MERCHANT, amount: "50000" };
  c = await client({ WATCHDOG_EVM_PRIVATE_KEY: EVM_KEY, WATCHDOG_BUDGET_USD: "0.06" });
  assert.equal((await call(c, "evm_contract_control", { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" })).err, false);
  seen.length = 0;
  r = await call(c, "evm_contract_control", { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" });
  assert.match(r.text, /exceed the session budget/);
  assert.equal(seen.filter((s) => s.paid).length, 0);
});

test("a lockfile on disk goes to the right Watchdog", async () => {
  terms = { payTo: MERCHANT, amount: "10000" };
  const dir = mkdtempSync(join(tmpdir(), "wd-mcp-"));
  const lock = join(dir, "package-lock.json");
  writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/solmate": { version: "6.2.0" } } }));
  const c = await client({ WATCHDOG_EVM_PRIVATE_KEY: EVM_KEY });
  seen.length = 0;
  const r = await call(c, "dependency_advisories", { lockfile_path: lock });
  assert.equal(r.err, false, r.text);
  assert.match(r.text, /1 advisory on 2 checked/);
  assert.deepEqual(seen.map((s) => s.path), ["/agent/check", "/agent/check"]);
  assert.equal((await call(c, "dependency_advisories", { lockfile_path: join(dir, "secrets.txt") })).err, true);
});

test("tokens are only sent to the Watchdog that issued them", async () => {
  const c = await client({});
  seen.length = 0;
  const ok = await call(c, "watch_status", { ecosystem: "evm", watchId: "w1", accessToken: "tok" });
  assert.equal(ok.err, false);
  assert.equal(seen[0].token, "Bearer tok");
});

test("keys: wrong type or malformed is refused, and never echoed", async () => {
  const sol = "4".repeat(87) + "Z";
  await assert.rejects(signerFor(SERVICES.solana, { WATCHDOG_SOLANA_PRIVATE_KEY: EVM_KEY }), (e) => /looks like an EVM key/.test(e.message) && !e.message.includes(EVM_KEY.slice(2)));
  await assert.rejects(signerFor(SERVICES.evm, { WATCHDOG_EVM_PRIVATE_KEY: sol }), (e) => /not 64 hex/.test(e.message) && !e.message.includes(sol));
  await assert.rejects(signerFor(SERVICES.solana, { WATCHDOG_SOLANA_PRIVATE_KEY: "0OIl" }), /not base58/);
  const env = { WATCHDOG_EVM_PRIVATE_KEY: EVM_KEY };
  assert.ok(!scrub(`boom ${EVM_KEY} and ${EVM_KEY.slice(2)}`, env).includes(EVM_KEY.slice(2)));
  // Through the tool: a misconfigured wallet is reported, not leaked.
  const c = await client({ WATCHDOG_EVM_PRIVATE_KEY: sol });
  const r = await call(c, "evm_contract_control", { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" });
  assert.equal(r.err, true);
  assert.ok(!r.text.includes(sol));
  const w = await call(c, "watchdog_wallet", {});
  assert.match(w.text, /misconfigured/);
  assert.ok(!w.text.includes(sol));
});
