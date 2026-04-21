#!/usr/bin/env node
/**
 * analyze.js — DuckDB-based security risk analysis
 *
 * Reads  : ~/.openclaw/logs/trace.jsonl
 *          ./rules.json  (same dir as this script)
 * Writes : ~/.openclaw/logs/risk_events.jsonl
 *          ~/.openclaw/logs/run_risks.json
 *
 * Spawned by index.js on agent_end. Also runnable manually:
 *   node analyze.js
 */

import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { createRequire } from "module";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const HOME = process.env.HOME;
const LOGS_DIR = path.join(HOME, ".openclaw/logs");
const TRACE_FILE = path.join(LOGS_DIR, "trace.jsonl");
const RISK_EVENTS_FILE = path.join(LOGS_DIR, "risk_events.jsonl");
const RUN_RISKS_FILE = path.join(LOGS_DIR, "run_risks.json");
const RULES_FILE = path.join(__dirname, "rules.json");

// ── Helpers ───────────────────────────────────────────────────────────────────

function riskScore(level) {
  return level === "HIGH" ? 3 : level === "MEDIUM" ? 2 : 1;
}

/** Wrap DuckDB callback-based conn.all in a Promise */
function qp(conn, sql, ...args) {
  return new Promise((resolve, reject) =>
    conn.all(sql, ...args, (err, rows) =>
      err ? reject(err) : resolve(rows || [])
    )
  );
}

/** Wrap DuckDB callback-based conn.run in a Promise */
function qrun(conn, sql, ...args) {
  return new Promise((resolve, reject) =>
    conn.run(sql, ...args, (err) =>
      err ? reject(err) : resolve()
    )
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function analyze() {
  fs.mkdirSync(LOGS_DIR, { recursive: true });

  if (!fs.existsSync(TRACE_FILE)) {
    console.log("[analyze] trace.jsonl not found, skipping");
    return;
  }
  if (!fs.existsSync(RULES_FILE)) {
    console.log("[analyze] rules.json not found, skipping");
    return;
  }

  // Load rules
  const { rules } = JSON.parse(fs.readFileSync(RULES_FILE, "utf8"));
  const activeRules = rules.filter((r) => r.enabled);
  if (activeRules.length === 0) {
    console.log("[analyze] no enabled rules, skipping");
    return;
  }

  // Load DuckDB
  let duckdb;
  try {
    duckdb = require("duckdb");
  } catch {
    console.error("[analyze] duckdb not installed. Run: npm install duckdb  (in plugin dir)");
    process.exit(1);
  }

  const DB_FILE = path.join(LOGS_DIR, "secaudit.duckdb");
  const db = new duckdb.Database(DB_FILE);
  const conn = db.connect();

  // ── events view (reads trace.jsonl via DuckDB) ────────────────────────────
  // Use explicit columns schema to handle heterogeneous JSONL (tool_call /
  // tool_result / run_end rows have different fields). Fields missing from a
  // row come back as NULL — no "column not found" binder error.
  // Backward compat: old events store command inside system_effect.command;
  // new events promote it to a top-level field. COALESCE handles both.
  const tracePathSql = TRACE_FILE.replace(/'/g, "''");
  await qrun(conn, `
    CREATE OR REPLACE VIEW events AS
    WITH raw AS (
      SELECT
        event,
        run_id,
        session_id,
        COALESCE(agent_id, 'unknown')                                   AS agent_id,
        COALESCE(user_id,  'unknown')                                   AS user_id,
        tool_call_id,
        tool,
        COALESCE(command, json_extract_string(system_effect, '$.command')) AS command,
        COALESCE(cmd_main, '')                                          AS cmd_main,
        cmd_category,
        cmd_domain,
        ts
      FROM read_json_auto(
        '${tracePathSql}',
        ignore_errors = true,
        columns = {
          event:          'VARCHAR',
          run_id:         'VARCHAR',
          session_id:     'VARCHAR',
          agent_id:       'VARCHAR',
          user_id:        'VARCHAR',
          tool_call_id:   'VARCHAR',
          tool:           'VARCHAR',
          command:        'VARCHAR',
          cmd_main:       'VARCHAR',
          cmd_category:   'VARCHAR',
          cmd_domain:     'VARCHAR',
          system_effect:  'JSON',
          ts:             'VARCHAR'
        }
      )
      WHERE event = 'tool_call'
    )
    SELECT * FROM raw WHERE command IS NOT NULL
  `);

  // ── rules table ───────────────────────────────────────────────────────────
  await qrun(conn, `
    CREATE OR REPLACE TABLE rules (
      id          VARCHAR,
      name        VARCHAR,
      category    VARCHAR,
      match_field VARCHAR,
      match_type  VARCHAR,
      match       VARCHAR,
      risk_level  VARCHAR,
      risk_tags   VARCHAR,
      enabled     BOOLEAN
    )
  `);

  for (const r of activeRules) {
    await qrun(
      conn,
      "INSERT INTO rules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      r.id,
      r.name,
      r.category,
      r.match_field,
      r.match_type,
      r.match,
      r.risk_level,
      JSON.stringify(r.risk_tags),
      r.enabled
    );
  }

  // ── risk_events: CROSS JOIN events × rules, filter by regex ──────────────
  // regexp_extract(str, pattern) returns first match or '' — used as boolean test
  const rows = await qp(conn, `
    SELECT
      e.ts,
      e.run_id,
      e.session_id,
      e.agent_id,
      e.user_id,
      e.tool_call_id,
      e.command,
      e.cmd_main,
      e.cmd_category,
      e.cmd_domain,
      r.id         AS rule_id,
      r.name       AS rule_name,
      r.risk_level,
      r.risk_tags
    FROM events e
    CROSS JOIN rules r
    WHERE (
      (r.match_field = 'command'  AND regexp_extract(COALESCE(e.command,  ''), r.match) <> '')
      OR
      (r.match_field = 'cmd_main' AND regexp_extract(COALESCE(e.cmd_main, ''), r.match) <> '')
    )
    ORDER BY e.ts
  `);

  conn.close();
  db.close();

  // Parse risk_tags JSON strings (stored as VARCHAR in rules table)
  const riskEvents = rows.map((row) => ({
    ...row,
    risk_tags: (() => {
      try { return JSON.parse(row.risk_tags || "[]"); } catch { return []; }
    })(),
  }));

  // ── Write risk_events.jsonl ───────────────────────────────────────────────
  const riskLines = riskEvents.map((e) => JSON.stringify(e));
  fs.writeFileSync(RISK_EVENTS_FILE, riskLines.join("\n") + (riskLines.length ? "\n" : ""));

  // ── run_risks aggregation (pure JS groupBy) ───────────────────────────────
  const runMap = new Map();
  for (const ev of riskEvents) {
    if (!runMap.has(ev.run_id)) {
      runMap.set(ev.run_id, {
        run_id: ev.run_id,
        max_risk_level: "LOW",
        _max_score: 0,
        all_risk_tags: new Set(),
        hit_count: 0,
        first_hit_ts: ev.ts,
        last_hit_ts: ev.ts,
      });
    }
    const entry = runMap.get(ev.run_id);
    entry.hit_count++;
    const score = riskScore(ev.risk_level);
    if (score > entry._max_score) {
      entry._max_score = score;
      entry.max_risk_level = ev.risk_level;
    }
    (ev.risk_tags || []).forEach((t) => entry.all_risk_tags.add(t));
    if (ev.ts < entry.first_hit_ts) entry.first_hit_ts = ev.ts;
    if (ev.ts > entry.last_hit_ts) entry.last_hit_ts = ev.ts;
  }

  const runRisks = [...runMap.values()].map(({ _max_score, all_risk_tags, ...rest }) => ({
    ...rest,
    all_risk_tags: [...all_risk_tags],
  }));
  fs.writeFileSync(RUN_RISKS_FILE, JSON.stringify(runRisks, null, 2));

  console.log(
    `[analyze] done — ${riskEvents.length} risk events across ${runRisks.length} runs`
  );
}

analyze().catch((e) => {
  console.error("[analyze] fatal:", e.message);
  process.exit(1);
});
