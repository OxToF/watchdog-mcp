#!/bin/zsh
# Registers this MCP server in Claude Code with a Solana payer key read from the
# clipboard. The key is checked locally and never printed.
#   ./scripts/add-to-claude-code.sh           ($0.20 session budget by default)
#   ./scripts/add-to-claude-code.sh 1         ($1 session budget)
set -u
DIR="${0:A:h:h}"
CLAUDE="$(command -v claude || echo "$HOME/.local/bin/claude")"
BUDGET="${1:-0.2}"
[[ -x "$CLAUDE" ]] || { echo "Claude Code not found. Install it: curl -fsSL https://claude.ai/install.sh | bash"; exit 1; }

echo "Copy the SOLANA private key of the paying wallet (Phantom export, base58, no 0x)"
echo "to the clipboard, then press Enter."
read -r _
KEY="$(pbpaste | tr -d '[:space:]')"
if ! printf '%s' "$KEY" | node -e '
  const k = require("fs").readFileSync(0, "utf8");
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(k)) { console.error("That is an EVM (hex) key. Use the Solana account key, exported from Phantom."); process.exit(1); }
  if (!/^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(k)) { console.error(`The clipboard does not hold a base58 Solana key (${k.length} characters).`); process.exit(1); }
'; then echo "Nothing was registered."; exit 1; fi

"$CLAUDE" mcp remove watchdog >/dev/null 2>&1
cd "$DIR" || exit 1
if "$CLAUDE" mcp add watchdog --env "WATCHDOG_SOLANA_PRIVATE_KEY=$KEY" --env "WATCHDOG_BUDGET_USD=$BUDGET" -- node "$DIR/src/index.mjs" >/dev/null 2>&1; then
  unset KEY; printf '' | pbcopy
  echo "OK: MCP server 'watchdog' registered for $DIR (session budget \$$BUDGET). Clipboard cleared."
  echo "Now run:  cd $DIR && claude"
else
  unset KEY; printf '' | pbcopy
  echo "Registration failed. Check that '$CLAUDE --version' works."
  exit 1
fi
