// Calls to the Watchdog APIs: paid when a key is configured, a quote when not.
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { SERVICES, scrub } from "./payer.mjs";

const decode = (h) => { try { return JSON.parse(Buffer.from(h, "base64").toString("utf8")); } catch { return null; } };

export class Watchdog {
  constructor(payer, { fetchImpl = globalThis.fetch } = {}) {
    this.payer = payer;
    this.fetchImpl = fetchImpl;
  }

  // POST a paid endpoint. Returns { ok, status, data } or { ok: false, quote, message }.
  async paid(rail, path, body) {
    const svc = SERVICES[rail];
    const url = `${svc.base}${path}`;
    const init = { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
    let pay;
    try { pay = await this.payer.paidFetch(rail); }
    catch (e) { return { ok: false, message: e.message }; }
    let res;
    try { res = await (pay || this.fetchImpl)(url, init); }
    catch (e) { return { ok: false, message: scrub(e.message, this.payer.env) }; }
    const data = await res.json().catch(() => ({}));
    if (res.status === 402) {
      const req = decode(res.headers.get("payment-required") || "");
      const a = req && req.accepts && req.accepts.find((x) => x.network === svc.network);
      const quote = a ? { priceUsdc: Number(BigInt(a.amount)) / 1e6, network: a.network, payTo: a.payTo } : null;
      const message = pay
        ? `Payment not accepted: ${data.error || "refused"}.`
        : `This call costs ${quote ? `$${quote.priceUsdc} USDC` : "a payment"} on ${svc.network.startsWith("solana") ? "Solana" : "Base"}. Set ${svc.keyVar} in this MCP server's environment to pay automatically.`;
      return { ok: false, status: 402, quote, message };
    }
    if (res.status >= 400) return { ok: false, status: res.status, message: data.error || `HTTP ${res.status}`, data };
    return { ok: true, status: res.status, data };
  }

  // GET / DELETE with a bearer token (job status, reports, watches). Free.
  async authed(rail, url, token, method = "GET") {
    const svc = SERVICES[rail];
    if (!url.startsWith(`${svc.base}/agent/`)) return { ok: false, message: `refusing to send a token outside ${svc.base}` };
    const res = await this.fetchImpl(url, { method, headers: { authorization: `Bearer ${token}` } });
    const data = await res.json().catch(() => ({}));
    return res.ok ? { ok: true, status: res.status, data } : { ok: false, status: res.status, message: data.error || `HTTP ${res.status}` };
  }
}

// A lockfile from disk, for coding agents that have the repo checked out.
export function readLockfile(path, maxBytes = 2_000_000) {
  const p = resolve(path);
  const st = statSync(p);
  if (!st.isFile()) throw new Error(`${path} is not a file`);
  if (st.size > maxBytes) throw new Error(`${path} is over ${maxBytes} bytes`);
  const name = p.split("/").pop();
  if (!/^(Cargo\.lock|package-lock\.json|yarn\.lock)$/.test(name)) throw new Error(`${name} is not a Cargo.lock, package-lock.json or yarn.lock`);
  return { text: readFileSync(p, "utf8"), rail: name === "Cargo.lock" ? "solana" : "evm" };
}
