// The tools an agent sees. Each description says when to use it and what it costs.
import { z } from "zod";
import { SERVICES } from "./payer.mjs";
import { readLockfile } from "./watchdog.mjs";

const text = (obj, summary) => ({ content: [{ type: "text", text: (summary ? summary + "\n\n" : "") + JSON.stringify(obj, null, 2) }] });
const fail = (message, extra) => ({ isError: true, content: [{ type: "text", text: message + (extra ? "\n\n" + JSON.stringify(extra, null, 2) : "") }] });
const PAID = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };
const FREE = { readOnlyHint: true, openWorldHint: true };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function flagsLine(flags = []) {
  if (!flags.length) return "No flags.";
  return flags.map((f) => `[${f.severity}] ${f.text}`).join("\n");
}

export function registerTools(server, { payer, watchdog }) {
  server.registerTool("solana_program_authority", {
    title: "Who can change this Solana program?",
    description: "Use before signing a transaction for, or depositing into, a Solana mainnet program. Answers who can replace its code: immutable, a single key, a Squads v4 multisig (threshold, members and time lock read on-chain, the vault re-derived as proof), Squads v3 or SPL Governance; plus the last deploy date, OtterSec verified build, embedded security.txt and severity-ranked flags. Costs $0.05 USDC on Solana, paid over x402 from WATCHDOG_SOLANA_PRIVATE_KEY. An address that holds no program is not charged.",
    inputSchema: { programId: z.string().describe("Program address, base58") },
    annotations: PAID,
  }, async ({ programId }) => {
    const r = await watchdog.paid("solana", "/agent/program", { programId });
    if (!r.ok) return fail(r.message, r.quote ? { quote: r.quote } : undefined);
    return text(r.data, `${r.data.authority ? r.data.authority.text : ""}\n${flagsLine(r.data.flags)}`.trim());
  });

  server.registerTool("evm_contract_control", {
    title: "Who can change this EVM contract?",
    description: "Use before approving a token, depositing into, or signing for a contract on Base or Robinhood Chain. Detects the proxy kind (EIP-1967 transparent, UUPS, beacon, legacy zeppelinos, EIP-1167 clone, diamond, EIP-7702), the live implementation, and follows the upgrade controller and owner to the end: one key, a Safe (threshold of owners), a timelock (delay). Sourcify verification for the address and the implementation. Costs $0.05 USDC on Base, paid over x402 from WATCHDOG_EVM_PRIVATE_KEY. An address with no code is not charged.",
    inputSchema: {
      address: z.string().describe("Contract address, 0x…"),
      chain: z.enum(["base", "robinhood"]).default("base").describe("Chain the contract lives on"),
    },
    annotations: PAID,
  }, async ({ address, chain }) => {
    const r = await watchdog.paid("evm", "/agent/contract", { address, chain });
    if (!r.ok) return fail(r.message, r.quote ? { quote: r.quote } : undefined);
    const c = r.data.upgradeController;
    return text(r.data, `${r.data.proxy ? `Proxy: ${r.data.proxy.kind}.` : "Not a proxy."}${c ? ` Upgrades: ${c.text}` : ""}\n${flagsLine(r.data.flags)}`.trim());
  });

  server.registerTool("dependency_advisories", {
    title: "Known advisories for pinned dependencies",
    description: "Use before adding or upgrading a dependency, or to triage a lockfile. Give lockfile_path (a Cargo.lock, package-lock.json or yarn.lock on disk, read locally) or the lockfile text, or a list of up to 100 packages. Rust crates go to Solana Watchdog (RustSec/OSV), npm packages to EVM Watchdog (GitHub/OSV). Only registry packages are checked; workspace and git dependencies are skipped. Costs $0.01 USDC per call (Solana for crates, Base for npm). Settled only if the answer exists.",
    inputSchema: {
      lockfile_path: z.string().optional().describe("Path to Cargo.lock, package-lock.json or yarn.lock"),
      lockfile: z.string().optional().describe("Lockfile text, if not on disk"),
      ecosystem: z.enum(["rust", "npm"]).optional().describe("Required with lockfile text or packages"),
      packages: z.array(z.object({ name: z.string(), version: z.string() })).max(100).optional().describe("Exact pinned versions"),
    },
    annotations: PAID,
  }, async ({ lockfile_path, lockfile, ecosystem, packages }) => {
    let rail, body;
    try {
      if (lockfile_path) { const l = readLockfile(lockfile_path); rail = l.rail; body = { lockfile: l.text }; }
      else if (lockfile) { if (!ecosystem) return fail("ecosystem (rust or npm) is required with lockfile text."); rail = ecosystem === "rust" ? "solana" : "evm"; body = { lockfile }; }
      else if (packages && packages.length) { if (!ecosystem) return fail("ecosystem (rust or npm) is required with packages."); rail = ecosystem === "rust" ? "solana" : "evm"; body = { packages }; }
      else return fail("Give lockfile_path, lockfile or packages.");
    } catch (e) { return fail(e.message); }
    const r = await watchdog.paid(rail, "/agent/check", body);
    if (!r.ok) return fail(r.message, r.quote ? { quote: r.quote } : undefined);
    const n = (r.data.advisories || []).length;
    return text(r.data, `${n} advisor${n === 1 ? "y" : "ies"} on ${r.data.checked} checked package(s)${r.data.notCheckedCount ? `, ${r.data.notCheckedCount} not checked (retry)` : ""}.`);
  });

  server.registerTool("scan_repo", {
    title: "Security scan of a public GitHub repo",
    description: "Use before a release or an integration: scans a public GitHub repo for advisories on its exact pinned dependencies (split into what ships on-chain and what is tooling), build hygiene, and code leads for known bug classes with file:line. ecosystem 'solana' for Rust/Anchor programs, 'evm' for Solidity (Foundry/Hardhat). Costs $0.50 USDC (Solana or Base). Waits up to wait_seconds for the report; otherwise returns jobId and accessToken for get_scan_report. A scan, not an audit.",
    inputSchema: {
      repo: z.string().describe("https://github.com/OWNER/REPO"),
      ecosystem: z.enum(["solana", "evm"]),
      wait_seconds: z.number().int().min(0).max(240).default(120),
    },
    annotations: PAID,
  }, async ({ repo, ecosystem, wait_seconds }) => {
    const r = await watchdog.paid(ecosystem, "/agent/scan", { repo });
    if (!r.ok) return fail(r.message, r.quote ? { quote: r.quote } : undefined);
    const job = r.data;
    if (!job.statusUrl || !job.accessToken) return text(job, "Scan paid; the server did not return a status URL.");
    const handle = { ecosystem, jobId: job.jobId, accessToken: job.accessToken, statusUrl: job.statusUrl };
    const deadline = Date.now() + wait_seconds * 1000;
    while (Date.now() < deadline) {
      await sleep(10_000);
      const s = await watchdog.authed(ecosystem, job.statusUrl, job.accessToken);
      if (s.ok && s.data.status === "done") return reportOf(watchdog, ecosystem, s.data, job.accessToken, handle);
      if (s.ok && s.data.status === "error") return fail(`Scan failed: ${s.data.error || "unknown"}`, handle);
    }
    return text(handle, "Scan paid and running. Call get_scan_report with these values (the accessToken is shown once: keep it).");
  });

  server.registerTool("get_scan_report", {
    title: "Status and report of a paid scan",
    description: "Free. Returns the status of a scan started with scan_repo and, once done, its JSON report.",
    inputSchema: { ecosystem: z.enum(["solana", "evm"]), jobId: z.string(), accessToken: z.string() },
    annotations: FREE,
  }, async ({ ecosystem, jobId, accessToken }) => {
    const statusUrl = `${SERVICES[ecosystem].base}/agent/jobs/${jobId}`;
    const s = await watchdog.authed(ecosystem, statusUrl, accessToken);
    if (!s.ok) return fail(s.message);
    if (s.data.status !== "done") return text(s.data, `Scan ${s.data.status}.`);
    return reportOf(watchdog, ecosystem, s.data, accessToken, { ecosystem, jobId });
  });

  server.registerTool("watch_create", {
    title: "Get alerted when a program, contract or lockfile changes",
    description: "Use to be told, for 30 days, when something you rely on changes: a Solana program (programId: authority, multisig rules, code upgrade, lost verification), an EVM contract (address + chain: new implementation, controller or owner, weaker Safe or timelock), or a lockfile (lockfile_path: any new advisory). Hourly checks; each change is POSTed to your https webhook, signed with x-watchdog-signature: sha256=HMAC(secret, body). Costs $0.90 USDC for the period (Solana for programs and Cargo.lock, Base for contracts and npm lockfiles). Returns watchId, secret and accessToken, each shown once.",
    inputSchema: {
      webhook: z.string().describe("Public https URL that receives the signed alerts"),
      programId: z.string().optional(),
      address: z.string().optional(),
      chain: z.enum(["base", "robinhood"]).optional(),
      lockfile_path: z.string().optional(),
    },
    annotations: PAID,
  }, async ({ webhook, programId, address, chain, lockfile_path }) => {
    const targets = [programId, address, lockfile_path].filter(Boolean).length;
    if (targets !== 1) return fail("Give exactly one of programId, address or lockfile_path.");
    let rail, body;
    if (programId) { rail = "solana"; body = { programId, webhook }; }
    else if (address) { rail = "evm"; body = { address, chain: chain || "base", webhook }; }
    else {
      try { const l = readLockfile(lockfile_path); rail = l.rail; body = { lockfile: l.text, webhook }; }
      catch (e) { return fail(e.message); }
    }
    const r = await watchdog.paid(rail, "/agent/watch", body);
    if (!r.ok) return fail(r.message, r.quote ? { quote: r.quote } : undefined);
    return text({ ecosystem: rail, ...r.data }, `Watch active until ${r.data.expiresAt}. Save secret and accessToken now: they are shown once.`);
  });

  server.registerTool("watch_status", {
    title: "Events of a watch",
    description: "Free. Lists what a watch has seen (also kept when the webhook was down), or cancels it with cancel: true.",
    inputSchema: { ecosystem: z.enum(["solana", "evm"]), watchId: z.string(), accessToken: z.string(), cancel: z.boolean().default(false) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  }, async ({ ecosystem, watchId, accessToken, cancel }) => {
    const s = await watchdog.authed(ecosystem, `${SERVICES[ecosystem].base}/agent/watch/${watchId}`, accessToken, cancel ? "DELETE" : "GET");
    if (!s.ok) return fail(s.message);
    return text(s.data, `Watch ${s.data.status}, ${(s.data.events || []).length} event(s).`);
  });

  server.registerTool("watchdog_wallet", {
    title: "Payment setup and spend",
    description: "Free. Shows which payment wallets this server is configured with (addresses only), the per-call cap, the session budget, what was spent, and the price of each tool.",
    inputSchema: {},
    annotations: FREE,
  }, async () => {
    const wallet = async (rail) => { try { return await payer.address(rail); } catch (e) { return `misconfigured: ${e.message}`; } };
    return text({
      wallets: { solana: await wallet("solana"), base: await wallet("evm") },
      maxPerCallUsd: payer.maxPerCallUsd, sessionBudgetUsd: payer.budgetUsd, spentUsd: Number(payer.spentUsd.toFixed(6)),
      payments: payer.payments,
      prices: { solana_program_authority: 0.05, evm_contract_control: 0.05, dependency_advisories: 0.01, scan_repo: 0.5, watch_create: 0.9, get_scan_report: 0, watch_status: 0 },
    });
  });
}

async function reportOf(watchdog, ecosystem, status, token, handle) {
  const url = status.report && status.report.json;
  if (!url) return text(status, "Scan done.");
  const rep = await watchdog.authed(ecosystem, url, token);
  return text({ ...handle, summary: status.summary, report: rep.ok ? rep.data : null, reportLinks: status.report }, "Scan done. A scan, not an audit.");
}
