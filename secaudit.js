#!/usr/bin/env node
/**
 * OpenClaw Security Audit UI  (Node.js, zero npm deps)
 * Usage: node ~/.openclaw/secaudit.js [--port 7788]
 */
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import { URL } from "node:url";
import { execSync } from "node:child_process";

const TRACE_FILE       = `${os.homedir()}/.openclaw/logs/trace.jsonl`;
const RISK_EVENTS_FILE = `${os.homedir()}/.openclaw/logs/risk_events.jsonl`;
const RUN_RISKS_FILE   = `${os.homedir()}/.openclaw/logs/run_risks.json`;
const args = process.argv.slice(2);
const portIdx = args.indexOf("--port");
const PORT = portIdx !== -1 ? parseInt(args[portIdx + 1]) : 7788;

// ── Risk rules (loaded from rules.json, same source as analyze.js / DuckDB) ──

const RULES_FILE = `${os.homedir()}/.openclaw/extensions/trace-collector/rules.json`;

let _rulesCache = null;
function getRules() {
  if (_rulesCache) return _rulesCache;
  try {
    const { rules } = JSON.parse(fs.readFileSync(RULES_FILE, "utf8"));
    _rulesCache = rules
      .filter((r) => r.enabled)
      .map((r) => ({
        // DuckDB uses (?i) inline flag; JS uses the 'i' flag separately
        re:      new RegExp(r.match.replace(/^\(\?i\)/i, ""), "i"),
        level:   (r.risk_level || "LOW").toLowerCase(),
        label:   r.name,
        rule_id: r.id,
        tags:    r.risk_tags || [],
      }));
  } catch {
    _rulesCache = [];
  }
  return _rulesCache;
}

function assessRisk(cmd) {
  if (!cmd) return [];
  return getRules()
    .filter((r) => r.re.test(cmd))
    .map(({ level, label, rule_id, tags }) => ({ level, label, rule_id, tags }));
}

// ── Pre-computed risk data (from analyze.js / DuckDB) ────────────────────────

/**
 * Load risk_events.jsonl → Map<tool_call_id, risk[]>
 * Returns null if the file doesn't exist yet (fallback to inline assessRisk).
 */
function loadRiskEvents() {
  try {
    const riskMap = new Map();
    const lines = fs.readFileSync(RISK_EVENTS_FILE, "utf8").split("\n").filter(Boolean);
    for (const line of lines) {
      try {
        const ev = JSON.parse(line);
        if (!ev.tool_call_id) continue;
        if (!riskMap.has(ev.tool_call_id)) riskMap.set(ev.tool_call_id, []);
        riskMap.get(ev.tool_call_id).push({
          level: (ev.risk_level || "").toLowerCase(),
          label: ev.rule_name || ev.rule_id || "unknown",
          rule_id: ev.rule_id,
          tags: ev.risk_tags || [],
        });
      } catch {}
    }
    return riskMap;
  } catch {
    return null; // file absent → caller falls back to inline assessRisk
  }
}

/** Load run_risks.json → Map<run_id, runRisk> */
function loadRunRisks() {
  try {
    const arr = JSON.parse(fs.readFileSync(RUN_RISKS_FILE, "utf8"));
    return new Map(arr.map((r) => [r.run_id, r]));
  } catch {
    return new Map();
  }
}

// ── Data loading ─────────────────────────────────────────────────────────────

function loadEvents() {
  try {
    return fs.readFileSync(TRACE_FILE, "utf8")
      .split("\n").filter(Boolean)
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    return [];
  }
}

// Mtime-based caches — avoid re-parsing files on every request
let _traceCache = null, _traceMtime = 0;
function loadEventsCached() {
  try {
    const mtime = fs.statSync(TRACE_FILE).mtimeMs;
    if (mtime !== _traceMtime) { _traceCache = loadEvents(); _traceMtime = mtime; }
  } catch { _traceCache = []; _traceMtime = 0; }
  return _traceCache || [];
}

let _sessionCache = null, _sessionMtime = 0;
function loadSessionIndexCached() {
  const dir = `${os.homedir()}/.openclaw/agents/main/sessions`;
  try {
    const mtime = fs.statSync(dir).mtimeMs;
    if (mtime !== _sessionMtime || !_sessionCache) {
      _sessionCache = loadSessionIndex();
      _sessionMtime = mtime;
    }
  } catch { _sessionCache = new Map(); _sessionMtime = 0; }
  return _sessionCache || new Map();
}

/**
 * Build toolCallId → userPrompt mapping from session JSONL files.
 * Chain: assistant messages contain content[].type==="toolCall" blocks
 * whose id is the tool_call_id; the immediately preceding user message
 * is the triggering instruction.
 */
function loadSessionIndex() {
  const sessionsDir = `${os.homedir()}/.openclaw/agents/main/sessions`;
  const index = new Map(); // toolCallId → { userPrompt, sessionId, ts }
  let files;
  try {
    files = fs.readdirSync(sessionsDir).filter(f => f.endsWith(".jsonl") && !f.includes(".bak") && !f.includes(".reset") && !f.includes(".lock"));
  } catch { return index; }

  for (const file of files) {
    try {
      const sessionId = file.replace(".jsonl", "");
      const lines = fs.readFileSync(`${sessionsDir}/${file}`, "utf8")
        .split("\n").filter(Boolean)
        .map(l => { try { return JSON.parse(l); } catch { return null; } })
        .filter(Boolean);

      let lastUserPrompt = null;
      let lastUserTs = null;

      for (const entry of lines) {
        if (entry.type !== "message") continue;
        const msg = entry.message ?? entry;
        const role = msg.role;
        const content = msg.content ?? [];

        if (role === "user") {
          // Extract plain text, strip Sender metadata header
          const raw = Array.isArray(content)
            ? content.filter(c => c.type === "text").map(c => c.text).join(" ")
            : String(content ?? "");
          // Format: "Sender (untrusted metadata):\n```json\n{...}\n```\n\n[timestamp] real content"
          // Strip the full Sender block (including newlines), leaving real content
          const clean = raw.replace(/^Sender\s*\(.*?\):\n```[\s\S]*?```\n\n?/, "").trim();
          // Strip timestamp prefix [Wed 2026-04-08 16:31 GMT+8]
          lastUserPrompt = clean.replace(/^\[[^\]]+\]\s*/, "").trim().slice(0, 200);
          lastUserTs = entry.timestamp;

        } else if (role === "assistant") {
          for (const block of content) {
            if (block.type === "toolCall" && block.id) {
              index.set(block.id, {
                userPrompt: lastUserPrompt,
                userTs: lastUserTs,
                sessionId,
              });
            }
          }
        }
      }
    } catch { /* skip bad file */ }
  }
  return index;
}

function buildReport(events) {
  // Pre-computed risks from DuckDB analysis (null = not available, use inline rules)
  const riskMap   = loadRiskEvents();
  const runRiskMap = loadRunRisks();
  const sessionIndex = loadSessionIndexCached();  // toolCallId → { userPrompt, sessionId }

  const runs = new Map();   // run_id → run
  const tcMap = new Map();  // tool_call_id → tc entry

  const getRun = (runId, e) => {
    if (!runs.has(runId)) {
      runs.set(runId, {
        run_id: runId,
        session_id: e.session_id ?? null,
        ts: e.ts,
        status: null,
        duration_ms: null,
        tool_calls: [],
      });
    }
    return runs.get(runId);
  };

  for (const e of events) {
    const runId = e.run_id ?? "unknown";
    const run = getRun(runId, e);

    if (e.event === "tool_call") {
      const effect = e.system_effect ?? {};
      const inp    = e.input ?? {};

      // command: prefer system_effect.command (what actually ran), fall back to input
      const cmd = effect.command ?? inp.command ?? inp.cmd ?? null;

      const si = sessionIndex.get(e.tool_call_id);
      const tc = {
        tool_call_id: e.tool_call_id ?? null,
        tool:         e.tool ?? null,
        command:      cmd,
        workdir:      effect.workdir ?? inp.cwd ?? inp.workdir ?? null,
        yield_ms:     inp.yieldMs ?? null,
        ts:           e.ts,
        // Use pre-computed DuckDB risks when available; fallback to inline rules
        risks: riskMap
          ? (riskMap.get(e.tool_call_id) || [])
          : assessRisk(cmd),
        // triggering instruction correlated from session JSONL
        user_prompt:  si?.userPrompt ?? null,
        user_ts:      si?.userTs ?? null,
        // filled by tool_result
        result_status: null,
        exit_code:     null,
        actual_cwd:    null,
        duration_ms:   null,
        stdout:        null,
      };
      run.tool_calls.push(tc);
      if (tc.tool_call_id) tcMap.set(tc.tool_call_id, tc);

    } else if (e.event === "tool_result") {
      const tc = tcMap.get(e.tool_call_id);
      if (!tc) continue;

      const res     = e.result  ?? {};
      const details = e.output?.details ?? {};
      const content = e.output?.content ?? [];

      tc.result_status = res.status ?? null;
      // prefer details.durationMs (OS measured), fall back to result.durationMs (plugin measured)
      tc.duration_ms   = details.durationMs ?? res.durationMs ?? null;
      tc.exit_code     = details.exitCode   ?? null;
      tc.actual_cwd    = details.cwd        ?? null;
      // stdout: details.aggregated is the full joined text
      tc.stdout        = details.aggregated
                         ?? content.find(c => c.type === "text")?.text
                         ?? null;

    } else if (e.event === "run_end") {
      run.status      = e.status      ?? null;
      run.duration_ms = e.duration_ms ?? null;
    }
  }

  // attach _run_id to every tc for cross-reference in the UI
  for (const run of runs.values()) {
    for (const tc of run.tool_calls) tc._run_id = run.run_id;
  }

  const runList  = [...runs.values()].sort((a, b) => (b.ts ?? "").localeCompare(a.ts ?? ""));
  const allTc    = runList.flatMap(r => r.tool_calls);
  const riskCalls = allTc.filter(tc => tc.risks.length > 0)
                         .sort((a, b) => (b.ts ?? "").localeCompare(a.ts ?? ""));

  // Attach run-level risk summary from run_risks.json
  for (const run of runList) {
    const rr = runRiskMap.get(run.run_id);
    if (rr) {
      run.max_risk_level  = rr.max_risk_level;
      run.all_risk_tags   = rr.all_risk_tags;
      run.risk_hit_count  = rr.hit_count;
    }
  }

  return {
    summary: {
      total_runs:         runList.length,
      runs_with_exec:     runList.filter(r => r.tool_calls.length > 0).length,
      total_tool_calls:   allTc.length,
      nonzero_exit:       allTc.filter(tc => tc.exit_code != null && tc.exit_code !== 0).length,
      risk_calls:         riskCalls.length,
      high_risk_calls:    riskCalls.filter(tc => tc.risks.some(r => r.level === "high")).length,
      risk_source:        riskMap ? "duckdb" : "inline",
    },
    runs:       runList,
    all_tc:     allTc.sort((a, b) => (b.ts ?? "").localeCompare(a.ts ?? "")),
    risk_calls: riskCalls,
  };
}

// ── Fast report from pre-computed risk_* files ────────────────────────────────
/**
 * Primary path: build report from risk_events.jsonl + run_risks.json only.
 * Falls back to full trace scan when pre-computed files are unavailable.
 */
function buildRiskReport() {
  const runRiskMap = loadRunRisks();

  let riskLines;
  try {
    riskLines = fs.readFileSync(RISK_EVENTS_FILE, "utf8").split("\n").filter(Boolean);
  } catch {
    // Fallback: DuckDB outputs missing → full inline scan
    return buildReport(loadEventsCached());
  }

  const sessionIndex = loadSessionIndexCached();

  // Group by tool_call_id (one row per rule match, may have multiple rows per call)
  const tcMap = new Map();
  for (const line of riskLines) {
    try {
      const ev = JSON.parse(line);
      if (!ev.tool_call_id) continue;
      if (!tcMap.has(ev.tool_call_id)) {
        const si = sessionIndex.get(ev.tool_call_id);
        tcMap.set(ev.tool_call_id, {
          tool_call_id:  ev.tool_call_id,
          tool:          null,
          command:       ev.command,
          workdir:       null,
          yield_ms:      null,
          ts:            ev.ts,
          risks:         [],
          user_prompt:   si?.userPrompt ?? null,
          user_ts:       si?.userTs ?? null,
          result_status: null,
          exit_code:     null,
          actual_cwd:    null,
          duration_ms:   null,
          stdout:        null,
          _run_id:       ev.run_id,
        });
      }
      tcMap.get(ev.tool_call_id).risks.push({
        level:   (ev.risk_level || "").toLowerCase(),
        label:   ev.rule_name || ev.rule_id || "unknown",
        rule_id: ev.rule_id,
        tags:    ev.risk_tags || [],
      });
    } catch {}
  }

  const riskCalls = [...tcMap.values()]
    .sort((a, b) => (b.ts ?? "").localeCompare(a.ts ?? ""));

  const runs = [...runRiskMap.values()].map(rr => ({
    run_id:         rr.run_id,
    session_id:     null,
    ts:             rr.first_hit_ts,
    status:         null,
    duration_ms:    null,
    tool_calls:     [],
    max_risk_level: rr.max_risk_level,
    all_risk_tags:  rr.all_risk_tags,
    risk_hit_count: rr.hit_count,
  })).sort((a, b) => (b.ts ?? "").localeCompare(a.ts ?? ""));

  // Expose when risk_events.jsonl was last written (for UI freshness indicator)
  let last_analyzed_ts = null;
  try { last_analyzed_ts = new Date(fs.statSync(RISK_EVENTS_FILE).mtimeMs).toISOString(); } catch {}

  return {
    summary: {
      total_runs:        runs.length,
      runs_with_exec:    runs.length,
      total_tool_calls:  riskCalls.length,
      nonzero_exit:      null,         // unknown without full scan
      risk_calls:        riskCalls.length,
      high_risk_calls:   riskCalls.filter(tc => tc.risks.some(r => r.level === "high")).length,
      risk_source:       "duckdb",
      last_analyzed_ts,
    },
    runs,
    all_tc:     [],   // populated by /api/report
    risk_calls: riskCalls,
  };
}

// ── HTML ─────────────────────────────────────────────────────────────────────

const HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenClaw Security Audit</title>
<style>
/* ── OpenClaw design tokens — light theme (data-theme-mode=light) ── */
:root{
  --bg:#f8f9fa;--bg-accent:#f1f3f5;--bg-elevated:#fff;--bg-hover:#eceef0;
  --card:#fff;--text:#3c3c43;--text-strong:#1a1a1e;--muted:#6e6e73;
  --border:#e5e5ea;--border-strong:#d1d1d6;
  --ok:#15803d;--ok-subtle:#15803d14;--ok-muted:#15803dbf;
  --warn:#b45309;--warn-subtle:#b4530914;--warn-muted:#b45309bf;
  --danger:#dc2626;--danger-subtle:#dc262614;--danger-muted:#dc2626bf;
  --accent:#dc2626;--accent-subtle:#dc262614;
  --accent-2:#0d9488;--accent-2-subtle:#0d948814;
  --grid-line:#0000000a;
  --radius-sm:6px;--radius-md:10px;--radius-lg:14px;--radius-full:9999px;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,"SF Mono",Menlo,Monaco,Consolas,monospace;
  --font-body:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  --shadow-sm:0 1px 2px #0000000a;--shadow-md:0 4px 12px #0000000f;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font-body);background:var(--bg);color:var(--text);font-size:13px;line-height:1.4}
header{background:var(--bg);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:16px;font-weight:600;color:var(--text-strong);letter-spacing:.1px}
.pill{background:var(--bg-accent);color:var(--muted);font-size:11px;padding:2px 8px;border-radius:var(--radius-full);border:1px solid var(--border)}
.main{padding:20px 24px;max-width:1500px;margin:0 auto}
/* stats */
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px;box-shadow:var(--shadow-sm)}
.stat .val{font-size:24px;font-weight:700;color:var(--text-strong);margin-bottom:3px}
.stat .lbl{color:var(--muted);font-size:11px}
.stat.warn  .val{color:var(--warn)}
.stat.danger .val{color:var(--danger)}
/* tabs */
.tabs{display:flex;gap:3px;margin-bottom:14px}
.tab{padding:5px 14px;border-radius:var(--radius-md);cursor:pointer;color:var(--muted);font-size:12px;border:1px solid transparent;background:none;font-family:var(--font-body);font-weight:500;transition:background .15s,color .15s}
.tab:hover{background:var(--bg-elevated);color:var(--text)}
.tab.active{background:var(--bg-elevated);color:var(--text-strong);border-color:var(--border)}
.section{display:none}.section.visible{display:block}
/* table */
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 12px;color:var(--muted);font-weight:500;font-size:11px;border-bottom:1px solid var(--border);background:var(--bg-accent);position:sticky;top:0;z-index:1}
td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}
tr.data-row{cursor:pointer}
tr.data-row:hover td{background:var(--bg-hover)}
tr.detail-row td{padding:0;background:var(--bg-accent)}
.stdout-box{display:none;padding:10px 14px;font-family:var(--mono);font-size:11px;color:var(--muted);white-space:pre-wrap;word-break:break-all;max-height:260px;overflow-y:auto;border-left:2px solid var(--border-strong);margin:4px 12px 8px}
tr.detail-row.open .stdout-box{display:block}
/* badges */
.badge-high  {background:var(--danger-subtle);color:var(--danger);font-size:10px;padding:1px 6px;border-radius:var(--radius-sm);white-space:nowrap;display:inline-block;border:1px solid color-mix(in srgb,var(--danger) 30%,transparent)}
.badge-medium{background:var(--warn-subtle);color:var(--warn);font-size:10px;padding:1px 6px;border-radius:var(--radius-sm);white-space:nowrap;display:inline-block;border:1px solid color-mix(in srgb,var(--warn) 30%,transparent)}
.badge-ok  {background:var(--ok-subtle);color:var(--ok);font-size:11px;padding:1px 6px;border-radius:var(--radius-sm);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent)}
.badge-err {background:var(--danger-subtle);color:var(--danger);font-size:11px;padding:1px 6px;border-radius:var(--radius-sm);border:1px solid color-mix(in srgb,var(--danger) 30%,transparent)}
.badge-warn{background:var(--warn-subtle);color:var(--warn);font-size:11px;padding:1px 6px;border-radius:var(--radius-sm);border:1px solid color-mix(in srgb,var(--warn) 30%,transparent)}
.exit-ok {color:var(--ok);font-family:var(--mono)}
.exit-err{color:var(--danger);font-family:var(--mono)}
.exit-nil{color:var(--border-strong);font-family:var(--mono)}
/* misc */
.ts    {color:var(--muted);font-size:11px;white-space:nowrap}
.mono  {font-family:var(--mono);font-size:11px}
.run-id{font-family:var(--mono);font-size:11px;color:var(--accent-2)}
.cmd   {font-family:var(--mono);font-size:11px;color:var(--text-strong);word-break:break-all;max-width:420px}
.cwd   {font-family:var(--mono);font-size:10px;color:var(--muted);word-break:break-all;max-width:200px}
.risk-tags{display:flex;flex-wrap:wrap;gap:3px}
.tool-tag  {background:var(--bg-elevated);color:var(--muted);font-size:10px;padding:1px 6px;border-radius:var(--radius-sm);border:1px solid var(--border)}
.yield-tag {background:var(--accent-2-subtle);color:var(--accent-2);font-size:10px;padding:1px 6px;border-radius:var(--radius-sm);border:1px solid color-mix(in srgb,var(--accent-2) 25%,transparent)}
.empty{text-align:center;padding:40px;color:var(--muted)}
.refresh{margin-left:auto;appearance:none;background:var(--bg-elevated);color:var(--text-strong);border:1px solid var(--border);padding:5px 14px;border-radius:var(--radius-md);cursor:pointer;font-size:11px;font-family:var(--font-body);font-weight:500}
.refresh:hover{border-color:var(--border-strong);background:var(--bg-hover)}
.expand-hint{color:var(--border-strong);font-size:10px;margin-left:4px}
.no-exec{color:var(--muted);font-style:italic;font-size:11px}
.user-prompt{font-size:12px;color:var(--text);cursor:default}
.muted-dash{color:var(--border-strong)}
</style>
</head>
<body>
<header>
  <h1>OpenClaw Security Audit</h1>
  <span class="pill">~/.openclaw/logs/trace.jsonl</span>
  <span class="pill" id="analyzed-at" style="display:none"></span>
  <button class="refresh" onclick="load()">Refresh</button>
</header>
<div class="main">
  <div class="stats" id="stats"></div>
  <div class="tabs">
    <button class="tab active" onclick="switchTab('risks',this)">Risk Events</button>
    <button class="tab" onclick="switchTab('all-tc',this)">All Tool Calls</button>
    <button class="tab" onclick="switchTab('runs',this)">All Runs</button>
  </div>

  <!-- Tab: Risk Events -->
  <div id="risks" class="section visible">
    <table>
      <thead><tr>
        <th>Time</th><th>Run ID</th><th>Trigger</th><th>Command</th>
        <th>cwd</th><th>Exit Code</th><th>Duration</th><th>Risk</th>
      </tr></thead>
      <tbody id="risk-body"></tbody>
    </table>
  </div>

  <!-- Tab: All Tool Calls -->
  <div id="all-tc" class="section">
    <table>
      <thead><tr>
        <th>Time</th><th>Run ID</th><th>Trigger</th><th>Command</th>
        <th>cwd</th><th>Exit Code</th><th>Duration</th><th>Tags</th>
      </tr></thead>
      <tbody id="tc-body"></tbody>
    </table>
  </div>

  <!-- Tab: All Runs -->
  <div id="runs" class="section">
    <table>
      <thead><tr>
        <th>Time</th><th>Run ID</th><th>Session</th><th>Status</th><th>Duration</th><th>Exec Count</th><th>Tool Call Details</th>
      </tr></thead>
      <tbody id="runs-body"></tbody>
    </table>
  </div>
</div>

<script>
// ── Data state ────────────────────────────────────────────────────────────────
let _fullData = null;   // cached full report (from /api/report)
let _fullLoading = false;

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmt(ts) {
  if (!ts) return '';
  return new Date(ts).toLocaleString('en-US', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
function shortId(id) { return id ? id.slice(0, 8) : '?'; }
function ms(v) { if (v == null) return '-'; return v < 1000 ? v+'ms' : (v/1000).toFixed(1)+'s'; }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function exitBadge(code) {
  if (code == null) return '<span class="exit-nil">-</span>';
  return code === 0
    ? \`<span class="exit-ok">✓ \${code}</span>\`
    : \`<span class="exit-err">✗ \${code}</span>\`;
}

function riskTags(risks) {
  if (!risks || !risks.length) return '';
  return \`<div class="risk-tags">\${risks.map(r=>\`<span class="badge-\${r.level}">\${esc(r.label)}</span>\`).join('')}</div>\`;
}

function toggleDetail(id) {
  const detailRow = document.getElementById('dr-' + id);
  if (!detailRow) return;
  detailRow.classList.toggle('open');
}

function tcRows(tcs, bodyId) {
  if (!tcs || !tcs.length) return '<tr><td colspan="8" class="empty">No records</td></tr>';
  return tcs.map((tc, i) => {
    const uid = bodyId + '_' + i;
    const hasStdout = tc.stdout && tc.stdout.trim();
    const expandHint = hasStdout ? \`<span class="expand-hint">▶</span>\` : '';
    const yieldTag = tc.yield_ms ? \`<span class="yield-tag">yield:\${tc.yield_ms}ms</span> \` : '';
    const prompt = tc.user_prompt
      ? \`<span class="user-prompt" title="\${esc(tc.user_prompt)}">\${esc(tc.user_prompt.slice(0,60))}\${tc.user_prompt.length>60?'…':''}</span>\`
      : \`<span class="muted-dash">—</span>\`;
    return \`<tr class="data-row" onclick="toggleDetail('\${uid}')">
      <td class="ts">\${fmt(tc.ts)}</td>
      <td><span class="run-id" title="\${esc(tc._run_id)}">\${shortId(tc._run_id)}</span></td>
      <td>\${prompt}</td>
      <td class="cmd">\${yieldTag}\${esc(tc.command||'-')}\${expandHint}</td>
      <td class="cwd">\${esc(tc.actual_cwd || tc.workdir || '-')}</td>
      <td>\${exitBadge(tc.exit_code)}</td>
      <td class="mono">\${ms(tc.duration_ms)}</td>
      <td>\${riskTags(tc.risks)}</td>
    </tr>
    <tr class="detail-row" id="dr-\${uid}">
      <td colspan="8">\${hasStdout ? \`<div class="stdout-box">\${esc(tc.stdout)}</div>\` : ''}</td>
    </tr>\`;
  }).join('');
}

function renderStats(s) {
  const isDuckdb = s.risk_source === 'duckdb';
  // In duckdb (risk-only) mode labels reflect what we actually have
  const runLbl  = isDuckdb ? 'Risk Runs'    : 'Total Runs';
  const tcLbl   = isDuckdb ? 'Risk Events'  : 'Exec Calls';
  const exitVal = s.nonzero_exit == null ? '—' : s.nonzero_exit;
  const exitCls = (s.nonzero_exit != null && s.nonzero_exit > 0) ? 'warn' : '';
  document.getElementById('stats').innerHTML = \`
    <div class="stat"><div class="val">\${s.total_runs}</div><div class="lbl">\${runLbl}</div></div>
    <div class="stat"><div class="val">\${s.runs_with_exec}</div><div class="lbl">Runs with Exec</div></div>
    <div class="stat"><div class="val">\${s.total_tool_calls}</div><div class="lbl">\${tcLbl}</div></div>
    <div class="stat \${exitCls}"><div class="val">\${exitVal}</div><div class="lbl">Non-zero Exit</div></div>
    <div class="stat warn"><div class="val">\${s.risk_calls}</div><div class="lbl">Risk Calls</div></div>
    <div class="stat danger"><div class="val">\${s.high_risk_calls}</div><div class="lbl">High Risk Calls</div></div>
  \`;
}

function renderRuns(runs) {
  document.getElementById('runs-body').innerHTML = runs.map(run => {
    const statusCls = run.status === 'success' ? 'badge-ok' : run.status === 'fail' ? 'badge-err' : 'badge-warn';
    const tcs = (run.tool_calls || []).map(tc => {
      const riskDot = tc.risks && tc.risks.length ? \`<span class="badge-\${tc.risks[0].level}">!</span> \` : '';
      const exit = tc.exit_code != null ? (tc.exit_code === 0 ? \`<span class="exit-ok">0</span>\` : \`<span class="exit-err">\${tc.exit_code}</span>\`) : '';
      return \`<div style="margin-top:3px;display:flex;gap:5px;align-items:flex-start">
        \${riskDot}<span class="tool-tag">\${esc(tc.tool||'?')}</span>
        \${exit}
        <span class="cmd">\${esc((tc.command||'').slice(0,100))}</span>
      </div>\`;
    }).join('');
    const noExec = (!run.tool_calls || run.tool_calls.length === 0) ? '<span class="no-exec">No exec operations</span>' : '';
    return \`<tr>
      <td class="ts">\${fmt(run.ts)}</td>
      <td><span class="run-id">\${shortId(run.run_id)}</span></td>
      <td class="mono" style="color:#4a5568">\${shortId(run.session_id)}</td>
      <td><span class="\${statusCls}">\${run.status||'—'}</span></td>
      <td class="mono">\${ms(run.duration_ms)}</td>
      <td class="mono" style="color:#a0aec0">\${run.tool_calls ? run.tool_calls.length : '—'}</td>
      <td>\${noExec}\${tcs}</td>
    </tr>\`;
  }).join('');
}

// ── Full data lazy loader ─────────────────────────────────────────────────────
async function ensureFullData() {
  if (_fullData) return _fullData;
  if (_fullLoading) {
    // Already in-flight: wait for it
    return new Promise(resolve => {
      const poll = setInterval(() => {
        if (_fullData) { clearInterval(poll); resolve(_fullData); }
      }, 100);
    });
  }
  _fullLoading = true;
  _fullData = await fetch('/api/report').then(r => r.json());
  _fullLoading = false;
  return _fullData;
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(id, btn) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('visible'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById(id).classList.add('visible');
  btn.classList.add('active');

  if (id === 'all-tc') {
    if (_fullData) {
      document.getElementById('tc-body').innerHTML = tcRows(_fullData.all_tc, 'tc');
    } else {
      document.getElementById('tc-body').innerHTML = '<tr><td colspan="8" class="empty">Loading full data…</td></tr>';
      ensureFullData().then(data => {
        renderStats(data.summary);
        document.getElementById('tc-body').innerHTML = tcRows(data.all_tc, 'tc');
      });
    }
  } else if (id === 'runs') {
    if (_fullData) {
      renderRuns(_fullData.runs);
    } else {
      document.getElementById('runs-body').innerHTML = '<tr><td colspan="7" class="empty">Loading full data…</td></tr>';
      ensureFullData().then(data => {
        renderStats(data.summary);
        renderRuns(data.runs);
      });
    }
  }
}

// ── Freshness indicator ───────────────────────────────────────────────────────
function updateAnalyzedAt(ts) {
  const el = document.getElementById('analyzed-at');
  if (!ts || !el) return;
  el.style.display = '';
  el.textContent = 'Analyzed at ' + new Date(ts).toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

// ── Initial load (fast path via /api/risks) ───────────────────────────────────
let _lastRiskCallCount = -1;

async function load() {
  _fullData = null;   // reset full cache on manual refresh
  const data = await fetch('/api/risks').then(r => r.json());
  renderStats(data.summary);
  document.getElementById('risk-body').innerHTML = tcRows(data.risk_calls, 'risk');
  updateAnalyzedAt(data.summary.last_analyzed_ts);
  _lastRiskCallCount = data.summary.risk_calls;
  // If user is on a full tab (e.g., after refresh), load full data immediately
  const activeId = document.querySelector('.section.visible')?.id;
  if (activeId === 'all-tc' || activeId === 'runs') {
    ensureFullData().then(full => {
      renderStats(full.summary);
      if (activeId === 'all-tc') document.getElementById('tc-body').innerHTML = tcRows(full.all_tc, 'tc');
      if (activeId === 'runs') renderRuns(full.runs);
    });
  }
}

// ── Auto-poll: refresh risk events when analyze.js produces new data ──────────
setInterval(async () => {
  if (document.hidden) return;   // don't poll while tab is backgrounded
  try {
    const data = await fetch('/api/risks').then(r => r.json());
    updateAnalyzedAt(data.summary.last_analyzed_ts);
    // Only re-render if risk count changed (avoids flicker on unchanged data)
    if (data.summary.risk_calls !== _lastRiskCallCount) {
      _lastRiskCallCount = data.summary.risk_calls;
      renderStats(data.summary);
      document.getElementById('risk-body').innerHTML = tcRows(data.risk_calls, 'risk');
      // Invalidate full cache so next full-tab visit re-fetches
      _fullData = null;
    }
  } catch {}
}, 5000);  // poll every 5 s

load();
</script>
</body>
</html>`;

// ── HTTP server ───────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const { pathname } = new URL(req.url, `http://localhost:${PORT}`);
  if (pathname === "/api/risks") {
    // Fast path: read only pre-computed risk_* files (primary)
    const body = Buffer.from(JSON.stringify(buildRiskReport()), "utf8");
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": body.length });
    res.end(body);
  } else if (pathname === "/api/report") {
    // Full path: complete trace.jsonl scan (mtime-cached); for all_tc / full runs
    const body = Buffer.from(JSON.stringify(buildReport(loadEventsCached())), "utf8");
    res.writeHead(200, { "Content-Type": "application/json", "Content-Length": body.length });
    res.end(body);
  } else {
    const body = Buffer.from(HTML, "utf8");
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length });
    res.end(body);
  }
});

server.listen(PORT, "127.0.0.1", () => {
  const url = `http://localhost:${PORT}`;
  console.log(`[secaudit] serving at ${url}`);
  console.log(`[secaudit] reading ${TRACE_FILE}`);
  try {
    const open = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
    execSync(`${open} ${url}`);
  } catch {}
});
