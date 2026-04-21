#!/usr/bin/env python3
"""
Minimal OpenClaw Security Audit UI
Usage: python3 ~/.openclaw/secaudit.py [--port 7788]
Opens a browser at http://localhost:7788
"""
import json, os, sys, re, webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

TRACE_FILE = Path.home() / ".openclaw/logs/trace.jsonl"
PORT = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 7788

# ── Risk rules (loaded from rules.json, same source as analyze.js / DuckDB) ──

_RULES_FILE = Path.home() / ".openclaw/extensions/trace-collector/rules.json"
_rules_cache = None

def _get_rules():
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache
    try:
        with open(_RULES_FILE) as f:
            data = json.load(f)
        _rules_cache = [
            {
                "pattern": re.sub(r"^\(\?i\)", "", r["match"]),
                "level":   r["risk_level"].lower(),
                "label":   r["name"],
                "rule_id": r["id"],
                "tags":    r.get("risk_tags", []),
            }
            for r in data.get("rules", []) if r.get("enabled")
        ]
    except Exception:
        _rules_cache = []
    return _rules_cache

def assess_risk(command: str) -> list[dict]:
    if not command:
        return []
    hits = []
    for rule in _get_rules():
        if re.search(rule["pattern"], command, re.IGNORECASE):
            hits.append({"level": rule["level"], "label": rule["label"], "rule_id": rule["rule_id"]})
    return hits

# ── Data loading ─────────────────────────────────────────────────────────────

def load_events():
    if not TRACE_FILE.exists():
        return []
    events = []
    with open(TRACE_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events

def build_report(events):
    runs = {}      # run_id -> {run_end, tool_calls[]}
    tool_calls = {}  # tool_call_id -> tool_call event

    for e in events:
        run_id = e.get("run_id", "unknown")
        if run_id not in runs:
            runs[run_id] = {"run_id": run_id, "tool_calls": [], "status": None,
                            "session_id": e.get("session_id"), "ts": e.get("ts"),
                            "duration_ms": None}

        if e["event"] == "tool_call":
            tc_id = e.get("tool_call_id")
            cmd = None
            effect = e.get("system_effect") or {}
            inp = e.get("input") or {}
            if effect.get("type") == "exec":
                cmd = effect.get("command") or inp.get("command") or inp.get("cmd")
            elif inp.get("command") or inp.get("cmd"):
                cmd = inp.get("command") or inp.get("cmd")

            risks = assess_risk(cmd) if cmd else []
            entry = {
                "tool_call_id": tc_id,
                "tool": e.get("tool"),
                "command": cmd,
                "workdir": effect.get("workdir"),
                "ts": e.get("ts"),
                "risks": risks,
                "result_status": None,
                "duration_ms": None,
            }
            runs[run_id]["tool_calls"].append(entry)
            if tc_id:
                tool_calls[tc_id] = entry

        elif e["event"] == "tool_result":
            tc_id = e.get("tool_call_id")
            if tc_id and tc_id in tool_calls:
                res = e.get("result") or {}
                tool_calls[tc_id]["result_status"] = res.get("status")
                tool_calls[tc_id]["duration_ms"] = res.get("durationMs")

        elif e["event"] == "run_end":
            runs[run_id]["status"] = e.get("status")
            runs[run_id]["duration_ms"] = e.get("duration_ms")

    run_list = sorted(runs.values(), key=lambda r: r.get("ts") or "", reverse=True)

    total_runs = len(run_list)
    total_tool_calls = sum(len(r["tool_calls"]) for r in run_list)
    risk_calls = [tc for r in run_list for tc in r["tool_calls"] if tc["risks"]]
    high_risk = [tc for tc in risk_calls if any(x["level"] == "high" for x in tc["risks"])]

    return {
        "summary": {
            "total_runs": total_runs,
            "total_tool_calls": total_tool_calls,
            "risk_calls": len(risk_calls),
            "high_risk_calls": len(high_risk),
        },
        "runs": run_list,
        "risk_calls": sorted(risk_calls, key=lambda x: x.get("ts") or "", reverse=True),
    }

# ── HTML ─────────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenClaw Security Audit</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;font-size:14px}
header{background:#1a1d2e;border-bottom:1px solid #2d3748;padding:16px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:18px;font-weight:600;color:#fff}
header .badge{background:#2d3748;color:#a0aec0;font-size:11px;padding:2px 8px;border-radius:999px}
.main{padding:24px;max-width:1400px;margin:0 auto}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat{background:#1a1d2e;border:1px solid #2d3748;border-radius:8px;padding:16px 20px}
.stat .val{font-size:28px;font-weight:700;color:#fff;margin-bottom:4px}
.stat .lbl{color:#718096;font-size:12px}
.stat.danger .val{color:#fc8181}
.stat.warn .val{color:#f6ad55}
.tabs{display:flex;gap:4px;margin-bottom:16px}
.tab{padding:6px 14px;border-radius:6px;cursor:pointer;color:#718096;font-size:13px;border:none;background:none}
.tab.active{background:#2d3748;color:#fff}
.section{display:none}.section.visible{display:block}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 12px;color:#718096;font-weight:500;font-size:12px;border-bottom:1px solid #2d3748;background:#1a1d2e;position:sticky;top:0}
td{padding:9px 12px;border-bottom:1px solid #1e2536;vertical-align:top}
tr:hover td{background:#1e2536}
.cmd{font-family:'SF Mono',Menlo,monospace;font-size:12px;color:#90cdf4;word-break:break-all;max-width:520px}
.badge-high{background:#742a2a;color:#fc8181;font-size:11px;padding:2px 6px;border-radius:4px;white-space:nowrap}
.badge-medium{background:#7b341e;color:#f6ad55;font-size:11px;padding:2px 6px;border-radius:4px;white-space:nowrap}
.badge-ok{background:#1c4532;color:#68d391;font-size:11px;padding:2px 6px;border-radius:4px}
.badge-err{background:#742a2a;color:#fc8181;font-size:11px;padding:2px 6px;border-radius:4px}
.ts{color:#4a5568;font-size:11px;white-space:nowrap}
.run-id{font-family:'SF Mono',Menlo,monospace;font-size:11px;color:#667eea}
.risk-tags{display:flex;flex-wrap:wrap;gap:4px}
.empty{text-align:center;padding:48px;color:#4a5568}
.tool-tag{background:#2d3748;color:#a0aec0;font-size:11px;padding:1px 6px;border-radius:3px}
.refresh{margin-left:auto;background:#2d3748;color:#a0aec0;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px}
.refresh:hover{background:#3d4a5c;color:#fff}
.runs-table .tc-list{margin-top:6px;padding-left:0}
.tc-row{font-size:12px;color:#718096;margin-top:3px;display:flex;gap:6px;align-items:flex-start}
</style>
</head>
<body>
<header>
  <h1>OpenClaw Security Audit</h1>
  <span class="badge" id="tracePath">~/.openclaw/logs/trace.jsonl</span>
  <button class="refresh" onclick="load()">Refresh</button>
</header>
<div class="main">
  <div class="stats" id="stats"></div>
  <div class="tabs">
    <button class="tab active" onclick="switchTab('risks',this)">Risk Events</button>
    <button class="tab" onclick="switchTab('runs',this)">All Runs</button>
  </div>
  <div id="risks" class="section visible">
    <table>
      <thead><tr><th>Time</th><th>Run ID</th><th>Tool</th><th>Command</th><th>Risk</th><th>Result</th></tr></thead>
      <tbody id="risk-body"></tbody>
    </table>
  </div>
  <div id="runs" class="section">
    <table>
      <thead><tr><th>Time</th><th>Run ID</th><th>Status</th><th>Duration</th><th>Tool Calls</th></tr></thead>
      <tbody id="runs-body"></tbody>
    </table>
  </div>
</div>
<script>
function switchTab(id,btn){
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('visible'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById(id).classList.add('visible');
  btn.classList.add('active');
}

function fmt(ts){if(!ts)return'';const d=new Date(ts);return d.toLocaleString('en-US',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function shortId(id){return id?id.slice(0,8):'?'}
function ms(v){if(!v&&v!==0)return'-';return v<1000?v+'ms':(v/1000).toFixed(1)+'s'}

async function load(){
  const r=await fetch('/api/report');
  const data=await r.json();

  const s=data.summary;
  document.getElementById('stats').innerHTML=`
    <div class="stat"><div class="val">${s.total_runs}</div><div class="lbl">Total Runs</div></div>
    <div class="stat"><div class="val">${s.total_tool_calls}</div><div class="lbl">Total Tool Calls</div></div>
    <div class="stat warn"><div class="val">${s.risk_calls}</div><div class="lbl">Risk Calls</div></div>
    <div class="stat danger"><div class="val">${s.high_risk_calls}</div><div class="lbl">High Risk Calls</div></div>
  `;

  // Risk table
  const rb=document.getElementById('risk-body');
  if(!data.risk_calls.length){
    rb.innerHTML='<tr><td colspan="6" class="empty">No risk events</td></tr>';
  } else {
    rb.innerHTML=data.risk_calls.map(tc=>{
      const tags=tc.risks.map(r=>`<span class="badge-${r.level}">${r.label}</span>`).join(' ');
      const res=tc.result_status?`<span class="badge-${tc.result_status==='ok'?'ok':'err'}">${tc.result_status}</span>`:'';
      // find run_id for this tool call
      const runId = (data.runs.find(r=>r.tool_calls.some(c=>c.tool_call_id===tc.tool_call_id))||{}).run_id||'';
      return `<tr>
        <td class="ts">${fmt(tc.ts)}</td>
        <td><span class="run-id" title="${runId}">${shortId(runId)}</span></td>
        <td><span class="tool-tag">${tc.tool||'?'}</span></td>
        <td class="cmd">${esc(tc.command||'-')}</td>
        <td><div class="risk-tags">${tags}</div></td>
        <td>${res}</td>
      </tr>`;
    }).join('');
  }

  // Runs table
  const runsb=document.getElementById('runs-body');
  runsb.innerHTML=data.runs.map(run=>{
    const statusCls=run.status==='success'?'badge-ok':run.status==='fail'?'badge-err':'';
    const tcs=run.tool_calls.map(tc=>{
      const riskDot=tc.risks.length?`<span class="badge-${tc.risks[0].level}">!</span>`:'';
      return `<div class="tc-row">${riskDot}<span class="tool-tag">${tc.tool||'?'}</span><span class="cmd">${esc((tc.command||'').slice(0,80))}</span></div>`;
    }).join('');
    return `<tr>
      <td class="ts">${fmt(run.ts)}</td>
      <td><span class="run-id">${shortId(run.run_id)}</span></td>
      <td><span class="${statusCls}">${run.status||'running'}</span></td>
      <td>${ms(run.duration_ms)}</td>
      <td>${tcs||'<span style="color:#4a5568">-</span>'}</td>
    </tr>`;
  }).join('');
}

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

load();
</script>
</body>
</html>"""

# ── HTTP Handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass  # silence access log

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/report":
            events = load_events()
            report = build_report(events)
            body = json.dumps(report, ensure_ascii=False, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)


if __name__ == "__main__":
    url = f"http://localhost:{PORT}"
    print(f"[secaudit] serving at {url}")
    print(f"[secaudit] reading {TRACE_FILE}")
    webbrowser.open(url)
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
