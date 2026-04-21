#!/usr/bin/env bash
# install.sh — OpenClaw Security Audit Plugin installer
#
# Usage:
#   git clone https://github.com/xxx/openclaw-security-audit \
#       ~/.openclaw/extensions/openclaw-security-audit
#   cd ~/.openclaw/extensions/openclaw-security-audit && ./install.sh
set -euo pipefail

OPENCLAW_HOME="${OPENCLAW_HOME:-$HOME/.openclaw}"
PLUGIN_ID="openclaw-security-audit"
CONFIG="$OPENCLAW_HOME/openclaw.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --openclaw-home) OPENCLAW_HOME="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
step() { echo -e "\n${BOLD}▸ $*${NC}"; }
ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}!${NC}  $*"; }
die()  { echo -e "\n  ${RED}✗  $*${NC}" >&2; exit 1; }

echo -e "\n${BOLD}OpenClaw Security Audit — installer${NC}"
echo    "======================================"

# ── Step 1: Preflight ─────────────────────────────────────────────────────────
step "Checking requirements"
command -v node >/dev/null 2>&1 || die "node not found. Install Node.js ≥ 18: https://nodejs.org"
command -v npm  >/dev/null 2>&1 || die "npm not found."
NODE_MAJOR=$(node --version | sed 's/v//' | cut -d. -f1)
[[ "$NODE_MAJOR" -ge 18 ]] || die "Node.js ≥ 18 required (found $(node --version))"
[[ -d "$OPENCLAW_HOME" ]]  || die "OpenClaw home not found: $OPENCLAW_HOME"
[[ -f "$CONFIG" ]]         || die "openclaw.json not found: $CONFIG"
ok "node $(node --version)  /  npm $(npm --version)"
ok "Plugin dir: $SCRIPT_DIR"

# ── Step 2: Install npm dependencies (duckdb) ─────────────────────────────────
step "Installing npm dependencies"
warn "duckdb binary ~50 MB — first run may take 1–2 minutes"
if npm install --omit=dev --silent 2>&1; then
  ok "npm install complete"
else
  warn "npm install failed — DuckDB risk analysis will be unavailable"
  warn "To retry: cd $SCRIPT_DIR && npm install --omit=dev"
fi

# ── Step 3: Copy audit dashboard to OPENCLAW_HOME ────────────────────────────
step "Installing audit dashboard"
cp "$SCRIPT_DIR/secaudit.js" "$OPENCLAW_HOME/"
cp "$SCRIPT_DIR/secaudit.py" "$OPENCLAW_HOME/"
ok "secaudit.js / secaudit.py  →  $OPENCLAW_HOME/"

# ── Step 4: Patch openclaw.json ───────────────────────────────────────────────
step "Patching openclaw.json"

BACKUP="${CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
cp "$CONFIG" "$BACKUP"
ok "Backup: $(basename "$BACKUP")"

PATCH_JS=$(mktemp /tmp/openclaw-patch-XXXXXX.cjs)
trap 'rm -f "$PATCH_JS"' EXIT

cat > "$PATCH_JS" << 'ENDOFJS'
'use strict';
const fs = require('fs');
const [,, cfgPath, pluginId, installPath] = process.argv;

let cfg;
try {
  cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
} catch (e) {
  process.stderr.write('Cannot parse openclaw.json: ' + e.message + '\n');
  process.exit(1);
}

if (!cfg.plugins)          cfg.plugins          = {};
if (!cfg.plugins.allow)    cfg.plugins.allow    = [];
if (!cfg.plugins.entries)  cfg.plugins.entries  = {};
if (!cfg.plugins.installs) cfg.plugins.installs = {};

if (!cfg.plugins.allow.includes(pluginId))
  cfg.plugins.allow.push(pluginId);

cfg.plugins.entries[pluginId]  = { enabled: true };
cfg.plugins.installs[pluginId] = {
  source:      'path',
  installPath: installPath,
  version:     '1.0.0',
  installedAt: new Date().toISOString(),
};

fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + '\n');
ENDOFJS

if node "$PATCH_JS" "$CONFIG" "$PLUGIN_ID" "$SCRIPT_DIR"; then
  ok "openclaw.json updated"
else
  cp "$BACKUP" "$CONFIG"
  die "Config patch failed — original restored from backup"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}Installation complete!${NC}\n"
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo -e "  ${BOLD}1.${NC}  Restart OpenClaw gateway:"
echo -e "        ${YELLOW}openclaw gateway stop && openclaw gateway &${NC}"
echo ""
echo -e "  ${BOLD}2.${NC}  Launch audit panel (opens http://localhost:7788):"
echo -e "        ${YELLOW}node ~/.openclaw/secaudit.js${NC}"
echo ""
