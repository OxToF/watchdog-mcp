// Pays Watchdog over x402 from the user's own wallets, within limits the user sets.
//
// Guards, all enforced before anything is signed:
//   - only to the Watchdog merchant wallet of that service, in USDC, on the expected network
//   - at most WATCHDOG_MAX_PER_CALL_USD per call (default 1)
//   - at most WATCHDOG_BUDGET_USD in total for this process (default 5)
// A key never appears in a message: library errors can echo the value they reject.
import { x402Client, wrapFetchWithPayment, decodePaymentResponseHeader } from "@x402/fetch";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { createKeyPairSignerFromBytes, getBase58Encoder } from "@solana/kit";
import { privateKeyToAccount } from "viem/accounts";

export const SERVICES = {
  solana: {
    name: "Solana Watchdog",
    base: (process.env.WATCHDOG_SOLANA_URL || "https://solana-security-watchdog-scan.fly.dev").replace(/\/$/, ""),
    merchant: process.env.WATCHDOG_SOLANA_MERCHANT || "7yMnWMrxzZ3YCtWXRsZEhAFwexHoJzBJy8RgN7Lhvy1P",
    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    usdc: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    keyVar: "WATCHDOG_SOLANA_PRIVATE_KEY",
  },
  evm: {
    name: "EVM Watchdog",
    base: (process.env.WATCHDOG_EVM_URL || "https://evm-watchdog-scan.fly.dev").replace(/\/$/, ""),
    merchant: (process.env.WATCHDOG_EVM_MERCHANT || "0x0e659996c75dcb352e95e130d79831e3e2fa82a8").toLowerCase(),
    network: "eip155:8453",
    usdc: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    keyVar: "WATCHDOG_EVM_PRIVATE_KEY",
  },
};

export class KeyError extends Error {}

// Returns a signer, or null when the variable is unset. Throws KeyError with a message
// that never contains the value.
export async function signerFor(service, env = process.env) {
  const raw = env[service.keyVar] && env[service.keyVar].trim();
  if (!raw) return null;
  if (service === SERVICES.solana) {
    if (/^(0x)?[0-9a-fA-F]{64}$/.test(raw)) throw new KeyError(`${service.keyVar} looks like an EVM key (64 hex characters); it needs a Solana key in base58, as Phantom exports it.`);
    if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(raw)) throw new KeyError(`${service.keyVar} is not base58.`);
    let bytes;
    try { bytes = getBase58Encoder().encode(raw); } catch { throw new KeyError(`${service.keyVar} could not be decoded.`); }
    if (bytes.length !== 64) throw new KeyError(`${service.keyVar} decodes to ${bytes.length} bytes, expected 64.`);
    try { return await createKeyPairSignerFromBytes(Uint8Array.from(bytes)); } catch { throw new KeyError(`${service.keyVar} is not a valid Solana keypair.`); }
  }
  const hex = raw.startsWith("0x") ? raw : `0x${raw}`;
  if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) throw new KeyError(`${service.keyVar} is not 64 hex characters; a Solana base58 key does not work here.`);
  try { return privateKeyToAccount(hex); } catch { throw new KeyError(`${service.keyVar} is not a valid key.`); }
}

const usd = (atomic) => Number(BigInt(atomic)) / 1e6;

export class Payer {
  constructor({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
    this.env = env;
    this.fetchImpl = fetchImpl;
    this.maxPerCallUsd = Number(env.WATCHDOG_MAX_PER_CALL_USD || 1);
    this.budgetUsd = Number(env.WATCHDOG_BUDGET_USD || 5);
    this.spentUsd = 0;
    this.payments = [];
    this._fetchers = {};
    this._signers = {};
  }

  async address(rail) {
    const s = await this._signer(rail);
    return s ? s.address : null;
  }

  async _signer(rail) {
    if (!(rail in this._signers)) this._signers[rail] = await signerFor(SERVICES[rail], this.env);
    return this._signers[rail];
  }

  // The terms this payer would accept from a 402, and why the others were refused.
  screen(rail, requirements) {
    const svc = SERVICES[rail];
    const reasons = [];
    const ok = requirements.filter((r) => {
      const payTo = rail === "evm" ? String(r.payTo).toLowerCase() : r.payTo;
      const asset = rail === "evm" ? String(r.asset).toLowerCase() : r.asset;
      if (r.network !== svc.network) { reasons.push(`network ${r.network} is not ${svc.network}`); return false; }
      if (payTo !== svc.merchant) { reasons.push(`payTo ${r.payTo} is not the ${svc.name} wallet`); return false; }
      if (asset !== svc.usdc) { reasons.push(`asset ${r.asset} is not USDC`); return false; }
      const price = usd(r.amount);
      if (price > this.maxPerCallUsd) { reasons.push(`price $${price} is above WATCHDOG_MAX_PER_CALL_USD ($${this.maxPerCallUsd})`); return false; }
      if (this.spentUsd + price > this.budgetUsd + 1e-9) { reasons.push(`price $${price} would exceed the session budget (spent $${this.spentUsd.toFixed(2)} of WATCHDOG_BUDGET_USD $${this.budgetUsd})`); return false; }
      return true;
    });
    return { ok, reasons };
  }

  // A fetch that pays within the guards, or null when no key is configured for this rail.
  async paidFetch(rail) {
    if (this._fetchers[rail]) return this._fetchers[rail];
    const signer = await this._signer(rail);
    if (!signer) return null;
    const svc = SERVICES[rail];
    const scheme = rail === "solana"
      ? new ExactSvmScheme(signer, this.env.WATCHDOG_SOLANA_RPC_URL ? { rpcUrl: this.env.WATCHDOG_SOLANA_RPC_URL } : undefined)
      : new ExactEvmScheme(signer);
    let pending = null;
    // The library's own $1 cap is off: screen() is stricter (merchant, network, asset,
    // per-call cap, session budget) and says which rule refused.
    const client = x402Client.fromConfig({
      schemes: [{ network: svc.network, client: scheme }],
      spendControls: false,
      policies: [(_v, reqs) => {
        const { ok, reasons } = this.screen(rail, reqs);
        this._lastRefusal = ok.length ? null : reasons;
        pending = ok[0] || null;
        return ok;
      }],
    });
    const paid = wrapFetchWithPayment(this.fetchImpl, client);
    this._fetchers[rail] = async (url, init) => {
      this._lastRefusal = null;
      let res;
      try { res = await paid(url, init); }
      catch (e) {
        if (this._lastRefusal) throw new Error(`Payment refused by this server's limits: ${this._lastRefusal.join("; ")}.`);
        throw new Error(`Payment could not be made: ${scrub(e && e.message, this.env)}`);
      }
      const header = res.headers.get("payment-response");
      if (header && pending) {
        let settled = null;
        try { settled = decodePaymentResponseHeader(header); } catch {}
        if (settled && settled.success) {
          const price = usd(pending.amount);
          this.spentUsd += price;
          this.payments.push({ rail, url, usd: price, transaction: settled.transaction, at: new Date().toISOString() });
        }
      }
      return res;
    };
    return this._fetchers[rail];
  }
}

// Remove anything that could be a key from a message before it leaves this process.
export function scrub(message, env = process.env) {
  let m = String(message || "unknown error");
  for (const v of [env.WATCHDOG_SOLANA_PRIVATE_KEY, env.WATCHDOG_EVM_PRIVATE_KEY]) if (v && v.trim()) m = m.split(v.trim()).join("[key]");
  return m.replace(/\b(0x)?[0-9a-fA-F]{64}\b/g, "[redacted]").replace(/\b[1-9A-HJ-NP-Za-km-z]{80,90}\b/g, "[redacted]").slice(0, 400);
}
