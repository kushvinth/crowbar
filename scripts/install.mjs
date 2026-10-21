#!/usr/bin/env node
// crowbar installer.
//   npx crowbar-cli setup     detect your agents, show the changes, apply them on approval
//   npx crowbar-cli setup --remove   undo it: unregister the server, delete the skill
//   npx crowbar-cli           print the manual steps instead (changes nothing)
// Setup registers the MCP server and installs the skill for each agent it finds.
// It backs up every config file before editing it and never touches one it can't parse.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline/promises";
import { fileURLToPath } from "node:url";

const PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKILL = path.join(PKG, "skills", "crowbar", "SKILL.md");
const HOME = os.homedir();
const b = (s) => `\x1b[1m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const ok = (s) => `\x1b[32m${s}\x1b[0m`;
const warn = (s) => `\x1b[33m${s}\x1b[0m`;

export function which(cmd) {
  const r = spawnSync(process.platform === "win32" ? "where" : "which", [cmd], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.split(/\r?\n/)[0].trim() : null;
}

// One entry per agent: how to tell it is installed, and what setup changes.
export function agents(uvx) {
  const args = ["--from", "crowbar-cli", "crowbar-mcp"];
  // key: the object that holds MCP servers, so --remove deletes only crowbar's entry
  const json = (file, key, mutate) => ({ kind: "json", file, key, mutate });
  return [
    {
      id: "claude", name: "Claude Code",
      present: () => !!which("claude") || fs.existsSync(path.join(HOME, ".claude")),
      // Claude Code owns ~/.claude.json; register through its CLI rather than editing it
      steps: [{ kind: "cmd", argv: ["claude", "mcp", "add", "--scope", "user", "crowbar", "--", uvx, ...args],
                undo: ["claude", "mcp", "remove", "--scope", "user", "crowbar"],
                needs: "claude", skipIf: ["claude", "mcp", "get", "crowbar"] },
              { kind: "skill", dir: path.join(HOME, ".claude", "skills", "crowbar") }],
    },
    {
      id: "codex", name: "Codex",
      present: () => !!which("codex") || fs.existsSync(path.join(HOME, ".codex")),
      steps: [{ kind: "toml", file: path.join(HOME, ".codex", "config.toml"),
                table: "mcp_servers.crowbar",
                body: `command = ${JSON.stringify(uvx)}\nargs = ${JSON.stringify(args)}\n` },
              { kind: "skill", dir: path.join(HOME, ".codex", "skills", "crowbar") }],
    },
    {
      id: "cursor", name: "Cursor",
      present: () => fs.existsSync(path.join(HOME, ".cursor")),
      steps: [json(path.join(HOME, ".cursor", "mcp.json"), "mcpServers",
                   (c) => { (c.mcpServers ??= {}).crowbar = { command: uvx, args }; }),
              { kind: "skill", dir: path.join(HOME, ".cursor", "skills", "crowbar") }],
    },
    {
      id: "gemini", name: "Gemini CLI",
      present: () => !!which("gemini") || fs.existsSync(path.join(HOME, ".gemini")),
      steps: [json(path.join(HOME, ".gemini", "settings.json"), "mcpServers",
                   (c) => { (c.mcpServers ??= {}).crowbar = { command: uvx, args }; })],
    },
    {
      id: "opencode", name: "opencode",
      present: () => !!which("opencode") || fs.existsSync(path.join(HOME, ".config", "opencode")),
      steps: [json(path.join(HOME, ".config", "opencode", "opencode.json"), "mcp",
                   (c) => { c.$schema ??= "https://opencode.ai/config.json";
                            (c.mcp ??= {}).crowbar = { type: "local", command: [uvx, ...args], enabled: true }; }),
              { kind: "skill", dir: path.join(HOME, ".config", "opencode", "skills", "crowbar") }],
    },
  ];
}

export function describe(step, remove = false) {
  switch (step.kind) {
    case "cmd": return `run    ${(remove ? step.undo : step.argv).join(" ")}`;
    case "skill": return remove ? `delete ${step.dir}` : `skill  ${path.join(step.dir, "SKILL.md")}`;
    case "toml": return `edit   ${step.file}  [${step.table}]`;
    default: return `edit   ${step.file}  (mcp server "crowbar")`;
  }
}

function backup(file, stamp) {
  if (!fs.existsSync(file)) return null;
  const dst = `${file}.crowbar-backup-${stamp}`;
  fs.copyFileSync(file, dst);
  return dst;
}

// Applies one step. Returns a one-line result; throws on anything it refuses to do.
export function apply(step, stamp = Date.now()) {
  if (step.kind === "skill") {
    fs.mkdirSync(step.dir, { recursive: true });
    fs.copyFileSync(SKILL, path.join(step.dir, "SKILL.md"));
    return `skill installed  ${step.dir}`;
  }
  if (step.kind === "cmd") {
    if (!which(step.needs)) return `skipped (${step.needs} not on PATH)`;
    if (spawnSync(step.skipIf[0], step.skipIf.slice(1), { stdio: "ignore" }).status === 0)
      return "already registered";
    const r = spawnSync(step.argv[0], step.argv.slice(1), { encoding: "utf8" });
    if (r.status !== 0) throw new Error((r.stderr || r.stdout || "failed").trim());
    return "registered";
  }
  fs.mkdirSync(path.dirname(step.file), { recursive: true });
  const text = fs.existsSync(step.file) ? fs.readFileSync(step.file, "utf8") : "";
  if (step.kind === "toml") {
    const header = `[${step.table}]`;
    if (text.split(/\r?\n/).some((l) => l.trim() === header)) return "already registered";
    const saved = backup(step.file, stamp);
    const sep = text && !text.endsWith("\n") ? "\n\n" : text ? "\n" : "";
    fs.writeFileSync(step.file, `${text}${sep}${header}\n${step.body}`);
    return saved ? `updated (backup ${path.basename(saved)})` : "created";
  }
  let cfg;
  try {
    cfg = text.trim() ? JSON.parse(text) : {};
  } catch {
    // JSONC with comments or a broken file: leave it alone rather than rewrite it
    throw new Error(`${step.file} is not plain JSON - add crowbar by hand (npx crowbar-cli prints the block)`);
  }
  const saved = backup(step.file, stamp);
  step.mutate(cfg);
  fs.writeFileSync(step.file, JSON.stringify(cfg, null, 2) + "\n");
  return saved ? `updated (backup ${path.basename(saved)})` : "created";
}

// Undoes one step. Leaves everything that is not crowbar's alone.
export function unapply(step, stamp = Date.now()) {
  if (step.kind === "skill") {
    if (!fs.existsSync(step.dir)) return "skill not installed";
    fs.rmSync(step.dir, { recursive: true, force: true });
    return `skill removed  ${step.dir}`;
  }
  if (step.kind === "cmd") {
    if (!which(step.needs)) return `skipped (${step.needs} not on PATH)`;
    if (spawnSync(step.skipIf[0], step.skipIf.slice(1), { stdio: "ignore" }).status !== 0)
      return "not registered";
    const r = spawnSync(step.undo[0], step.undo.slice(1), { encoding: "utf8" });
    if (r.status !== 0) throw new Error((r.stderr || r.stdout || "failed").trim());
    return "unregistered";
  }
  if (!fs.existsSync(step.file)) return "not registered";
  const text = fs.readFileSync(step.file, "utf8");
  if (step.kind === "toml") {
    const lines = text.split(/\r?\n/);
    const start = lines.findIndex((l) => l.trim() === `[${step.table}]`);
    if (start === -1) return "not registered";
    let end = start + 1;   // the table runs to the next header that is not one of its own sub-tables
    while (end < lines.length && !(/^\s*\[/.test(lines[end]) && !lines[end].trim().startsWith(`[${step.table}.`))) end++;
    let from = start;      // and takes the blank lines setup put before it
    while (from > 0 && !lines[from - 1].trim()) from--;
    const saved = backup(step.file, stamp);
    const rest = [...lines.slice(0, from), ...(from && end < lines.length ? [""] : []), ...lines.slice(end)];
    fs.writeFileSync(step.file, rest.join("\n").replace(/\n*$/, rest.some((l) => l.trim()) ? "\n" : ""));
    return `removed (backup ${path.basename(saved)})`;
  }
  let cfg;
  try {
    cfg = text.trim() ? JSON.parse(text) : {};
  } catch {
    throw new Error(`${step.file} is not plain JSON - remove crowbar by hand`);
  }
  if (!cfg[step.key]?.crowbar) return "not registered";
  const saved = backup(step.file, stamp);
  delete cfg[step.key].crowbar;
  fs.writeFileSync(step.file, JSON.stringify(cfg, null, 2) + "\n");
  return `removed (backup ${path.basename(saved)})`;
}

function flag(argv, name) {
  const i = argv.indexOf(name);
  return i === -1 ? null : (argv[i + 1] ?? "");
}

async function setup(argv) {
  const yes = argv.includes("--yes") || argv.includes("-y");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = async (q, def = true) => {
    if (yes) return def;
    const a = (await rl.question(`${q} ${def ? "[Y/n]" : "[y/N]"} `)).trim().toLowerCase();
    return a ? a.startsWith("y") : def;
  };
  try {
    if (argv.includes("--remove")) return await remove(argv, ask);
    console.log(`\n${b("crowbar setup")} - CVE intelligence for your agents.\n`);

    let uvx = which("uvx");
    if (!uvx) {
      console.log(warn("uv is not installed.") + " crowbar's MCP server runs through uvx.");
      if (process.platform !== "win32" && await ask("Install uv now (https://astral.sh/uv)?")) {
        spawnSync("sh", ["-c", "curl -LsSf https://astral.sh/uv/install.sh | sh"], { stdio: "inherit" });
        uvx = which("uvx") || [path.join(HOME, ".local", "bin", "uvx"), path.join(HOME, ".cargo", "bin", "uvx")]
          .find((p) => fs.existsSync(p)) || null;
      }
      if (!uvx) {
        console.log("Install uv, then run setup again: https://docs.astral.sh/uv/getting-started/installation/");
        return 1;
      }
    }

    const only = flag(argv, "--agents")?.split(",").filter(Boolean);
    const found = agents(uvx).filter((a) => (only ? only.includes(a.id) : a.present()));
    if (!found.length) {
      console.log("No supported agent found (Claude Code, Codex, Cursor, Gemini CLI, opencode).");
      console.log(`Pick one explicitly: ${b("npx crowbar-cli setup --agents claude,cursor")}`);
      return 1;
    }

    console.log(`${b("Proposed changes")} ${dim(`(MCP server: ${uvx} --from crowbar-cli crowbar-mcp)`)}\n`);
    for (const a of found) {
      console.log(`  ${b(a.name)}`);
      for (const s of a.steps) console.log(`    ${describe(s)}`);
    }
    console.log(dim("\n  Config files are backed up next to themselves before any edit.\n"));
    if (!(await ask("Apply these changes?"))) {
      console.log("Nothing changed.");
      return 0;
    }

    const stamp = Date.now();
    let failed = 0;
    for (const a of found) {
      for (const s of a.steps) {
        try {
          console.log(`  ${ok("✓")} ${a.name}: ${apply(s, stamp)}`);
        } catch (e) {
          failed++;
          console.log(`  ${warn("!")} ${a.name}: ${e.message}`);
        }
      }
    }

    const noIndex = argv.includes("--no-index");
    if (!noIndex && await ask("\nBuild the local CVE index now (lite tier, ~150 MB, a few minutes)?")) {
      const run = (args) => spawnSync(uvx, ["crowbar-cli", ...args], { stdio: "inherit" }).status === 0;
      if (!(run(["sync", "--tier", "lite"]) && run(["build", "--tier", "lite"]))) {
        console.log(warn("Index build did not finish.") + " Your agent will build it on first use, or run:");
        console.log(`  ${b("uvx crowbar-cli sync --tier lite && uvx crowbar-cli build --tier lite")}`);
      }
    } else if (!noIndex) {
      console.log(dim("Skipped. The skill builds the index the first time your agent needs it."));
    }

    console.log(`\n${b("Restart your agents")} so they load crowbar. Then ask one: ${dim('"is log4j 2.14 exploitable?"')}`);
    return failed ? 1 : 0;
  } finally {
    rl.close();
  }
}

async function remove(argv, ask) {
  console.log(`\n${b("crowbar setup --remove")} - take crowbar out of your agents.\n`);
  const only = flag(argv, "--agents")?.split(",").filter(Boolean);
  const found = agents(which("uvx") || "uvx").filter((a) => (only ? only.includes(a.id) : a.present()));
  if (!found.length) {
    console.log("No supported agent found (Claude Code, Codex, Cursor, Gemini CLI, opencode).");
    return 0;
  }
  console.log(`${b("Proposed changes")}\n`);
  for (const a of found) {
    console.log(`  ${b(a.name)}`);
    for (const s of a.steps) console.log(`    ${describe(s, true)}`);
  }
  console.log(dim("\n  Config files are backed up next to themselves before any edit. The index is kept.\n"));
  if (!(await ask("Remove crowbar from these agents?"))) {
    console.log("Nothing changed.");
    return 0;
  }
  const stamp = Date.now();
  let failed = 0;
  for (const a of found) {
    for (const s of a.steps) {
      try {
        console.log(`  ${ok("✓")} ${a.name}: ${unapply(s, stamp)}`);
      } catch (e) {
        failed++;
        console.log(`  ${warn("!")} ${a.name}: ${e.message}`);
      }
    }
  }
  console.log(`\n${b("Restart your agents.")} The index stays in ${process.env.CROWBAR_HOME || "~/.crowbar"}; delete that folder to free the space.`);
  return failed ? 1 : 0;
}

function guide() {
  console.log(`\n${b("crowbar")} - offline vulnerability intelligence for your terminal and your agent.\n`);
  console.log(`${b("One command:")}  npx crowbar-cli setup   ${dim("(detects your agents, asks before changing anything)")}`);
  console.log(`${b("Undo:")}         npx crowbar-cli setup --remove\n`);
  console.log(`${b("Or by hand")} - the MCP server command is the same for every agent:\n`);
  console.log(`   { "command": "uvx", "args": ["--from", "crowbar-cli", "crowbar-mcp"] }\n`);
  console.log("   Claude Code:  " + b("claude mcp add crowbar -- uvx --from crowbar-cli crowbar-mcp"));
  console.log("   Skill:        " + b("npx skills add kushvinth/crowbar"));
  console.log("   Index:        " + b("uvx crowbar-cli sync --tier lite && uvx crowbar-cli build --tier lite"));
  console.log(dim("\n   Tiers: lite ~150MB · medium ~500MB · heavy ~2GB · extreme (every source)"));
  if (!which("uvx")) console.log(warn("\n   uv is not installed: ") + "curl -LsSf https://astral.sh/uv/install.sh | sh");
  console.log(`\nDocs: ${b("https://github.com/kushvinth/crowbar")}\n`);
  return 0;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log("usage: npx crowbar-cli [setup] [--remove] [--yes] [--agents claude,codex,cursor,gemini,opencode] [--no-index]");
    process.exit(0);
  }
  process.exit(argv[0] === "setup" ? await setup(argv.slice(1)) : guide());
}
