#!/usr/bin/env node
/**
 * Copy the Agent App Framework's PocketBase adapter into this toolkit.
 *
 *   node toolkits/blueprint-pocketbase-kit/scripts/sync-upstream.mjs [path-to-Agent-App]   (default: ../Agent-App)
 *   node toolkits/blueprint-pocketbase-kit/scripts/sync-upstream.mjs --check [path]         (exit 1 on drift)
 *
 * The adapter is the framework's, not ours: the files below are copied byte for
 * byte from `toolkits/blueprint-pocketbase-react/template` and pinned in
 * framework.lock.json by SHA-256. The one file this toolkit adapts is the
 * launcher, which also sets the environment variable the marketplace apps' own
 * engine hooks read (CRAFTBOT_APP_ENV) — recorded as a patch so it is re-applied,
 * never hand-edited.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const kit = resolve(here, "..");
const marketplace = resolve(kit, "..", "..");
const args = process.argv.slice(2);
const check = args.includes("--check");
const upstreamRepo = resolve(args.find((a) => !a.startsWith("--")) ?? join(marketplace, "..", "Agent-App"));
const upstream = join(upstreamRepo, "toolkits", "blueprint-pocketbase-react", "template");

const VERBATIM = ["pb-fetch.mjs", "pb-check.mjs", "pb/pb_hooks/_a2app.pb.js", "pb/pb_hooks/_a2app_impl.js", "pb/pb_hooks/_a2app_rules.js"];

const SERVE_PATCH = {
  find: "{ stdio: \"inherit\", env: { ...process.env, A2APP_PUBLIC_DIR: publicDir, A2APP_ENV: env } },",
  replace:
    "// The marketplace apps' engine hooks read CRAFTBOT_APP_ENV (\"shadow\" on a dev\n" +
    "    // boot) to skip first-run downloads on disposable instances.\n" +
    "    { stdio: \"inherit\", env: { ...process.env, A2APP_PUBLIC_DIR: publicDir, A2APP_ENV: env, CRAFTBOT_APP_ENV: env === \"dev\" ? \"shadow\" : \"live\" } },",
};

// A marketplace patch to the framework's adapter: GET /api/_a2app keeps the
// schema fingerprint until the declarations or collections change, instead of
// rebuilding it on every request (about a second for an app with hundreds of
// operations, against the CLI identity check's 1.5 s). See schemaVersion() in
// the patched file. Re-applied on every sync; if upstream changes this function
// the sync stops, so the patch is re-checked rather than silently lost.
const IMPL_PATCH = {
  file: "pb/pb_hooks/_a2app_impl.js",
  find: "function schemaVersion(core, d, binding) {\n  var defs = binding.entities();\n  var prints = {};\n  var names = Object.keys(defs);\n  for (var i = 0; i < names.length; i++) {\n    var def = defs[names[i]];\n    prints[names[i]] = { fields: def.fields, module: def.module };\n    if (def.auth) prints[names[i]].auth = true;\n  }\n  return core.schemaFingerprint(prints, d.operations);\n}\n",
  replace: "function schemaVersion(core, d, binding) {\n  // Kept until its inputs change, not rebuilt on every request (marketplace\n  // patch, toolkits/blueprint-pocketbase-kit/scripts/sync-upstream.mjs). The\n  // fingerprint hashes every operation and field one character at a time in\n  // the hooks VM: about a second for an app with HR OS's 465 operations, on\n  // every GET /api/_a2app, where the framework CLI's identity check gives up\n  // after 1.5 s and reports the app \"unreachable\". Its inputs are the\n  // declarations (d.key: manifest, operations and events files) and the\n  // collections, so the key is both; the value is unchanged.\n  var key = d.key + \"|\" + collectionsKey();\n  var store = $app.store();\n  var cached = store.get(\"a2app.schemaVersion\");\n  if (cached && cached.key === key) return cached.value;\n  var defs = binding.entities();\n  var prints = {};\n  var names = Object.keys(defs);\n  for (var i = 0; i < names.length; i++) {\n    var def = defs[names[i]];\n    prints[names[i]] = { fields: def.fields, module: def.module };\n    if (def.auth) prints[names[i]].auth = true;\n  }\n  var value = core.schemaFingerprint(prints, d.operations);\n  store.set(\"a2app.schemaVersion\", { key: key, value: value });\n  return value;\n}\n\n// Every collection's id, name and last change. All of them, not only the\n// declared entities: a relation field carries its target's NAME, so renaming\n// another collection changes this app's fingerprint too.\nfunction collectionsKey() {\n  var parts = [];\n  try {\n    var cols = $app.findAllCollections();\n    for (var i = 0; i < cols.length; i++) {\n      parts.push(cols[i].id + \":\" + cols[i].name + \":\" + String(cols[i].updated));\n    }\n  } catch (_e) {\n    // Unknown schema: a key that never matches, so nothing stale is served.\n    return \"?\" + String(Date.now());\n  }\n  parts.sort();\n  return parts.join(\",\");\n}\n",
};

const sha = (buf) => createHash("sha256").update(buf).digest("hex");
const norm = (text) => text.replace(/\r\n/g, "\n");

if (!existsSync(upstream)) {
  console.error(`no Agent App Framework PocketBase blueprint at ${upstream}`);
  process.exit(2);
}

const files = {};
for (const rel of VERBATIM) files[rel] = norm(readFileSync(join(upstream, rel), "utf8"));
const serve = norm(readFileSync(join(upstream, "pb-serve.mjs"), "utf8"));
if (!serve.includes(SERVE_PATCH.find)) {
  console.error("pb-serve.mjs changed upstream: the launcher patch no longer applies — update SERVE_PATCH");
  process.exit(1);
}
files["pb-serve.mjs"] = serve.replace(SERVE_PATCH.find, SERVE_PATCH.replace);
if (!files[IMPL_PATCH.file].includes(IMPL_PATCH.find)) {
  console.error(
    "_a2app_impl.js changed upstream: the schemaVersion cache patch no longer applies — " +
      "check that GET /api/_a2app stays fast for an app with many operations, then update or drop IMPL_PATCH",
  );
  process.exit(1);
}
files[IMPL_PATCH.file] = files[IMPL_PATCH.file].replace(IMPL_PATCH.find, IMPL_PATCH.replace);

let commit = "unknown";
let branch = "unknown";
let dirty = false;
try {
  commit = execFileSync("git", ["-C", upstreamRepo, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  branch = execFileSync("git", ["-C", upstreamRepo, "rev-parse", "--abbrev-ref", "HEAD"], { encoding: "utf8" }).trim();
  dirty = execFileSync("git", ["-C", upstreamRepo, "status", "--porcelain", "--", "toolkits/blueprint-pocketbase-react"], { encoding: "utf8" }).trim() !== "";
} catch {
  /* not a git checkout */
}

const lock = {
  repository: "https://github.com/CraftOS-dev/Agent-App",
  source: "toolkits/blueprint-pocketbase-react/template",
  commit,
  branch,
  uncommittedChanges: dirty,
  files: Object.fromEntries(Object.entries(files).map(([rel, text]) => [rel, "sha256:" + sha(text)])),
  patched: {
    "pb-serve.mjs": "sets CRAFTBOT_APP_ENV for the apps' engine hooks",
    [IMPL_PATCH.file]: "keeps the identity schemaVersion until the declarations or collections change",
  },
};

const drift = [];
for (const [rel, text] of Object.entries(files)) {
  const dest = join(kit, "template", rel);
  const current = existsSync(dest) ? norm(readFileSync(dest, "utf8")) : null;
  if (current !== text) drift.push(rel);
  if (!check) {
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, text);
  }
}
if (check) {
  if (drift.length) {
    console.error(`out of date with the framework: ${drift.join(", ")} — run sync-upstream.mjs`);
    process.exit(1);
  }
  console.log("the kit's adapter files match the framework");
} else {
  writeFileSync(join(kit, "framework.lock.json"), JSON.stringify(lock, null, 2) + "\n");
  console.log(`synced ${Object.keys(files).length} file(s) from ${upstream} (${branch} ${commit.slice(0, 12)}${dirty ? ", with uncommitted changes" : ""})`);
}
