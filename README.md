# watchdog-mcp

An MCP server for **Solana Watchdog** and **EVM Watchdog**. It gives an agent the
security checks it needs at the moment it decides: before signing for a program,
before approving a contract, before adding a dependency. Each paid call costs cents in
USDC and is paid automatically over [x402](https://x402.org), from a wallet you
provide, within limits you set.

Results are checks, not audits.

## Tools

| Tool | Use it | Price |
|---|---|---|
| `solana_program_authority` | before signing for a Solana program: who can replace its code (single key, Squads multisig with threshold and time lock, DAO, immutable), last deploy, verified build, security.txt | $0.05 (Solana) |
| `evm_contract_control` | before approving or depositing on Base / Robinhood Chain: proxy kind, live implementation, who controls upgrades and ownership (key, Safe, timelock), Sourcify verification | $0.05 (Base) |
| `dependency_advisories` | before adding a dependency: advisories for a `Cargo.lock`, `package-lock.json` or `yarn.lock` on disk, or a package list | $0.01 |
| `scan_repo` | before a release: a full scan of a public GitHub repo (Rust/Anchor or Solidity) | $0.50 |
| `get_scan_report` | status and report of a scan | free |
| `watch_create` | to be alerted for 30 days when a program, contract or lockfile changes, by signed webhook | $0.90 |
| `watch_status` | events of a watch, or cancel it | free |
| `watchdog_wallet` | which wallets are set, caps, what was spent | free |

An address that holds no program or contract is not charged. A dependency check is
settled only once its answer exists.

## Install

Claude Code:

```sh
claude mcp add watchdog \
  -e WATCHDOG_SOLANA_PRIVATE_KEY=<base58 key of a Solana wallet holding a little USDC> \
  -e WATCHDOG_EVM_PRIVATE_KEY=<hex key of a Base wallet holding a little USDC> \
  -- npx -y watchdog-mcp
```

Claude Desktop, Cursor and other clients (`mcpServers` JSON):

```json
{
  "mcpServers": {
    "watchdog": {
      "command": "npx",
      "args": ["-y", "watchdog-mcp"],
      "env": {
        "WATCHDOG_SOLANA_PRIVATE_KEY": "…",
        "WATCHDOG_EVM_PRIVATE_KEY": "…",
        "WATCHDOG_BUDGET_USD": "5"
      }
    }
  }
}
```

From a clone of this repository, `scripts/add-to-claude-code.sh` does the Claude Code step for you: it reads the Solana key from the clipboard, checks it without printing it, and registers the server.

Both keys are optional. Without a key for a chain, its tools return the price and how
to pay instead of an answer.

**Use a dedicated wallet** that holds only what you are willing to spend on checks.
No SOL or ETH is needed: the x402 facilitator pays the network fee.

## Configuration

| Variable | Default | |
|---|---|---|
| `WATCHDOG_SOLANA_PRIVATE_KEY` | none | Solana wallet, base58 (as Phantom exports it) |
| `WATCHDOG_EVM_PRIVATE_KEY` | none | Base wallet, hex |
| `WATCHDOG_MAX_PER_CALL_USD` | `1` | refuse any single payment above this |
| `WATCHDOG_BUDGET_USD` | `5` | refuse payments beyond this total, per server process |
| `WATCHDOG_SOLANA_RPC_URL` | public mainnet | RPC used to build Solana payments |

## What protects your wallet

Every payment is screened before anything is signed:

- it must go to the Watchdog merchant wallet of that service, in USDC, on the expected
  network. A server that asked to be paid elsewhere would be refused;
- it must fit under the per-call cap and the remaining session budget;
- scan and watch access tokens are only ever sent back to the Watchdog that issued them.

Keys never appear in tool output or errors, including when a key is malformed or of
the wrong chain.

## License

MIT
