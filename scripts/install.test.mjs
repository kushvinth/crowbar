// node --test scripts/install.test.mjs   (no network, no real agent configs: HOME is a temp dir)
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "install.mjs");
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "cb-setup-"));
process.env.HOME = HOME;                       // read by os.homedir() at import time
const { agents, apply, unapply } = await import("./install.mjs");
const step = (id, kind) => agents("/opt/uv/uvx").find((a) => a.id === id).steps.find((s) => s.kind === kind);
const read = (...p) => fs.readFileSync(path.join(HOME, ...p), "utf8");

test("json merge keeps existing servers and backs the file up", () => {
  fs.mkdirSync(path.join(HOME, ".cursor"), { recursive: true });
  fs.writeFileSync(path.join(HOME, ".cursor/mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } } }));
  assert.match(apply(step("cursor", "json"), 1), /backup mcp.json.crowbar-backup-1/);
  const cfg = JSON.parse(read(".cursor/mcp.json"));
  assert.deepEqual(Object.keys(cfg.mcpServers).sort(), ["crowbar", "other"]);
  assert.deepEqual(cfg.mcpServers.crowbar, { command: "/opt/uv/uvx", args: ["--from", "crowbar-cli", "crowbar-mcp"] });
  assert.ok(fs.existsSync(path.join(HOME, ".cursor/mcp.json.crowbar-backup-1")));
});

test("toml append is idempotent and preserves the file", () => {
  fs.mkdirSync(path.join(HOME, ".codex"), { recursive: true });
  fs.writeFileSync(path.join(HOME, ".codex/config.toml"), 'model = "o4"');
  apply(step("codex", "toml"), 2);
  assert.equal(apply(step("codex", "toml"), 3), "already registered");
  const toml = read(".codex/config.toml");
  assert.ok(toml.startsWith('model = "o4"\n\n[mcp_servers.crowbar]\n'));
  assert.equal(toml.match(/\[mcp_servers\.crowbar\]/g).length, 1);
});

test("refuses to rewrite a config it cannot parse (JSONC)", () => {
  fs.mkdirSync(path.join(HOME, ".gemini"), { recursive: true });
  const jsonc = '{ // my settings\n "theme": "dark" }';
  fs.writeFileSync(path.join(HOME, ".gemini/settings.json"), jsonc);
  assert.throws(() => apply(step("gemini", "json")), /not plain JSON/);
  assert.equal(read(".gemini/settings.json"), jsonc);
});

test("skill lands where the agent reads it", () => {
  apply(step("opencode", "skill"));
  assert.match(read(".config/opencode/skills/crowbar/SKILL.md"), /^---\nname: crowbar/);
});

test("setup --yes wires the chosen agents end to end", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cb-e2e-"));
  const bin = path.join(home, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "uvx"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  const r = spawnSync(process.execPath, [SCRIPT, "setup", "--yes", "--no-index", "--agents", "cursor,opencode"], {
    env: { ...process.env, HOME: home, PATH: `${bin}:/usr/bin:/bin` }, encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const cursor = JSON.parse(fs.readFileSync(path.join(home, ".cursor/mcp.json"), "utf8"));
  assert.equal(cursor.mcpServers.crowbar.command, path.join(bin, "uvx"));
  assert.ok(fs.existsSync(path.join(home, ".config/opencode/skills/crowbar/SKILL.md")));
  assert.match(r.stdout, /Restart your agents/);
});

test("toml removal drops only crowbar's table and its sub-tables", () => {
  const file = path.join(HOME, ".codex/config.toml");
  fs.writeFileSync(file, 'model = "o4"\n\n[mcp_servers.crowbar]\ncommand = "uvx"\n\n'
    + '[mcp_servers.crowbar.env]\nX = "1"\n\n[mcp_servers.other]\ncommand = "y"\n');
  assert.match(unapply(step("codex", "toml"), 4), /removed \(backup config.toml.crowbar-backup-4\)/);
  assert.equal(read(".codex/config.toml"), 'model = "o4"\n\n[mcp_servers.other]\ncommand = "y"\n');
  assert.equal(unapply(step("codex", "toml"), 5), "not registered");
});

test("setup --remove undoes setup and keeps everything else", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cb-rm-"));
  const bin = path.join(home, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "uvx"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  fs.mkdirSync(path.join(home, ".cursor"));
  fs.writeFileSync(path.join(home, ".cursor/mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } } }));
  fs.mkdirSync(path.join(home, ".codex"));
  fs.writeFileSync(path.join(home, ".codex/config.toml"), 'model = "o4"\n');
  const run = (...a) => spawnSync(process.execPath, [SCRIPT, "setup", "--yes", "--no-index", "--agents", "cursor,codex", ...a],
    { env: { ...process.env, HOME: home, PATH: `${bin}:/usr/bin:/bin` }, encoding: "utf8" });
  assert.equal(run().status, 0);
  const r = run("--remove");
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(home, ".cursor/mcp.json"), "utf8")),
    { mcpServers: { other: { command: "x" } } });
  assert.equal(fs.readFileSync(path.join(home, ".codex/config.toml"), "utf8"), 'model = "o4"\n');
  assert.ok(!fs.existsSync(path.join(home, ".cursor/skills/crowbar")));
  assert.ok(!fs.existsSync(path.join(home, ".codex/skills/crowbar")));
  assert.match(r.stdout, /Restart your agents/);
});
