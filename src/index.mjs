#!/usr/bin/env node
// watchdog-mcp: Solana and EVM Watchdog as MCP tools, paid per call over x402.
// stdio transport: nothing but protocol may go to stdout, so logs go to stderr.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Payer } from "./payer.mjs";
import { Watchdog } from "./watchdog.mjs";
import { registerTools } from "./tools.mjs";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function createServer({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  const payer = new Payer({ env, fetchImpl });
  const watchdog = new Watchdog(payer, { fetchImpl });
  const server = new McpServer({ name: "watchdog", version: "0.1.0" }, {
    instructions: "Security checks for Solana and EVM code and deployed programs. Call solana_program_authority or evm_contract_control before signing for a program or contract you have not checked; dependency_advisories before adding a dependency. Paid tools cost cents in USDC, paid automatically within the user's limits; watchdog_wallet shows the setup and spend. Results are checks, not audits.",
  });
  registerTools(server, { payer, watchdog });
  return { server, payer };
}

// Run when launched directly, including through npx's bin symlink; not when imported (tests).
const launched = (() => { try { return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { return false; } })();
if (launched) {
  const { server } = createServer();
  await server.connect(new StdioServerTransport());
  console.error("[watchdog-mcp] ready on stdio");
}
