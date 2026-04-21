import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { spawn } from "child_process";

const __pluginDir = path.dirname(fileURLToPath(import.meta.url));
const ANALYZE_SCRIPT = path.join(__pluginDir, "analyze.js");
const LOG = path.join(process.env.HOME, ".openclaw/logs/trace.jsonl");

// ── Command classification ────────────────────────────────────────────────────

const CMD_CATEGORY = {
  wget:    { category: "download",   domain: "network" },
  curl:    { category: "download",   domain: "network" },
  git:     { category: "vcs",        domain: "network" },
  ssh:     { category: "remote",     domain: "network" },
  scp:     { category: "remote",     domain: "network" },
  rsync:   { category: "remote",     domain: "network" },
  ftp:     { category: "remote",     domain: "network" },
  nc:      { category: "remote",     domain: "network" },
  rm:      { category: "fs_write",   domain: "filesystem" },
  mv:      { category: "fs_write",   domain: "filesystem" },
  cp:      { category: "fs_write",   domain: "filesystem" },
  mkdir:   { category: "fs_write",   domain: "filesystem" },
  touch:   { category: "fs_write",   domain: "filesystem" },
  dd:      { category: "fs_write",   domain: "filesystem" },
  cat:     { category: "fs_read",    domain: "filesystem" },
  ls:      { category: "fs_read",    domain: "filesystem" },
  find:    { category: "fs_read",    domain: "filesystem" },
  grep:    { category: "fs_read",    domain: "filesystem" },
  head:    { category: "fs_read",    domain: "filesystem" },
  tail:    { category: "fs_read",    domain: "filesystem" },
  chmod:   { category: "permission", domain: "system" },
  chown:   { category: "permission", domain: "system" },
  sudo:    { category: "privilege",  domain: "system" },
  su:      { category: "privilege",  domain: "system" },
  python:  { category: "exec",       domain: "process" },
  python3: { category: "exec",       domain: "process" },
  node:    { category: "exec",       domain: "process" },
  bash:    { category: "exec",       domain: "process" },
  sh:      { category: "exec",       domain: "process" },
  zsh:     { category: "exec",       domain: "process" },
  perl:    { category: "exec",       domain: "process" },
  ruby:    { category: "exec",       domain: "process" },
};

const WRAPPER_CMDS = new Set(["sudo", "su", "env", "time", "nice", "nohup", "strace"]);

/**
 * Parse a raw shell command string into structured fields.
 * - cmd_main: first meaningful command token (after cd/env-var stripping)
 * - cmd_category / cmd_domain: from CMD_CATEGORY lookup
 *   (looks past wrapper commands like sudo for categorization)
 */
function parseCommand(rawCmd) {
  if (!rawCmd || typeof rawCmd !== "string") {
    return { command: null, cmd_main: null, cmd_category: null, cmd_domain: null };
  }

  const command = rawCmd.trim();

  // Strip leading `cd <path> &&` or `cd <path>;` chains.
  // Handles plain paths, double-quoted, and single-quoted paths.
  let stripped = command.replace(/^(?:cd\s+(?:"[^"]*"|'[^']*'|\S+)\s*(?:&&|;)\s*)+/g, "").trim();

  // Tokenize
  const tokens = stripped.split(/\s+/);

  // Skip KEY=VALUE env var tokens at the start
  let i = 0;
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i++;

  const firstToken = tokens[i] || "";
  const cmd_main = path.basename(firstToken).replace(/^['"]+|['"]+$/g, "") || null;

  // For cmd_category lookup, peer past wrapper commands
  let classifyKey = (cmd_main || "").toLowerCase();
  if (WRAPPER_CMDS.has(classifyKey)) {
    let j = i + 1;
    while (j < tokens.length) {
      const tok = tokens[j];
      const base = path.basename(tok).toLowerCase();
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tok) || WRAPPER_CMDS.has(base)) {
        j++;
      } else {
        classifyKey = base;
        break;
      }
    }
  }

  const info = CMD_CATEGORY[classifyKey] || { category: "other", domain: "other" };
  return { command, cmd_main, cmd_category: info.category, cmd_domain: info.domain };
}

// ── Logging ───────────────────────────────────────────────────────────────────

function write(data) {
  const record = { ...data, ts: new Date().toISOString() };
  try {
    fs.appendFileSync(LOG, JSON.stringify(record) + "\n");
  } catch (e) {
    console.error(`[trace-collector] write failed: ${e.message}`);
  }
  try {
    console.log(`[trace-collector][${record.event || "trace"}] ${JSON.stringify(record)}`);
  } catch {}
}

// ── Analysis trigger ──────────────────────────────────────────────────────────

let _lastAnalyzeMs = 0;
const ANALYZE_COOLDOWN_MS = 10_000; // at most once every 10s after exec completion

function spawnAnalyze(runId) {
  try {
    const child = spawn(process.execPath, [ANALYZE_SCRIPT, "--run-id", runId || ""], {
      detached: true,
      stdio: "ignore",
    });
    child.unref();
  } catch (e) {
    console.error(`[trace-collector] spawn analyze failed: ${e.message}`);
  }
}

// ── Plugin registration ───────────────────────────────────────────────────────

// register must be synchronous — cannot be async
export function register(api) {
  const pending = new Map();

  api.on("before_tool_call", (event, ctx) => {
    const toolCallId =
      event.toolCallId ||
      ctx.toolCallId ||
      (globalThis.crypto?.randomUUID?.() ||
        `${Date.now()}-${Math.random().toString(16).slice(2)}`);

    let system_effect;
    let cmdFields = { command: null, cmd_main: null, cmd_category: null, cmd_domain: null };

    try {
      const tool = (event.toolName || "").toLowerCase();
      if (tool.includes("exec") || tool.includes("shell")) {
        const p = event.params;
        const rawCmd =
          typeof p === "string" ? p : p?.command || p?.cmd || p?.argv;
        const workdir = p?.cwd || p?.workdir || process.cwd();
        system_effect = { type: "exec", command: rawCmd, workdir };
        cmdFields = parseCommand(rawCmd);
      }
    } catch {}

    write({
      event: "tool_call",
      run_id: ctx.runId || event.runId,
      session_id: ctx.sessionId,
      agent_id: ctx.agentId || process.env.OPENCLAW_AGENT_ID || "main",
      user_id: process.env.USER || process.env.LOGNAME || "unknown",
      tool_call_id: toolCallId,
      tool: event.toolName,
      input: event.params,
      ...cmdFields,
      system_effect,
    });

    const isExec = !!(system_effect);
    pending.set(toolCallId, { startMs: Date.now(), isExec });
  });

  api.on("after_tool_call", (event, ctx) => {
    const toolCallId = ctx.toolCallId;
    const start = toolCallId ? pending.get(toolCallId) : undefined;
    const durationMs =
      event.durationMs || (start ? Date.now() - start.startMs : undefined);
    const resultStatus = event.result?.isError ? "error" : "ok";

    write({
      event: "tool_result",
      run_id: ctx.runId,
      session_id: ctx.sessionId,
      tool_call_id: toolCallId,
      tool: ctx.toolName,
      result: { status: resultStatus, durationMs },
      output: event.result,
    });

    // Throttled real-time analysis: trigger after exec tool calls, at most once per cooldown
    if (start?.isExec) {
      const now = Date.now();
      if (now - _lastAnalyzeMs > ANALYZE_COOLDOWN_MS) {
        _lastAnalyzeMs = now;
        spawnAnalyze(ctx.runId);
      }
    }

    if (toolCallId) pending.delete(toolCallId);
  });

  api.on("agent_end", (event, ctx) => {
    const runId = ctx.runId;
    write({
      event: "run_end",
      run_id: runId,
      session_id: ctx.sessionId,
      status: event.success ? "success" : "fail",
      error: event.error,
      duration_ms: event.durationMs,
    });

    // Trigger async risk analysis (non-blocking)
    spawnAnalyze(runId);
  });

  console.log("[openclaw-security-audit] hooks registered successfully");
}
