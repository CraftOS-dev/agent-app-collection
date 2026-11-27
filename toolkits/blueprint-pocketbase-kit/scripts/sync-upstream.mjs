#!/usr/bin/env node
/**
 * RETIRED. The kit's A2App adapter is maintained in the marketplace.
 *
 *   node toolkits/blueprint-pocketbase-kit/scripts/sync-upstream.mjs           (refuses, and says why)
 *   node toolkits/blueprint-pocketbase-kit/scripts/sync-upstream.mjs --check   (nothing to compare: exits 0)
 *
 * This script used to copy the Agent App Framework's PocketBase adapter
 * (`toolkits/blueprint-pocketbase-react/template` in CraftOS-dev/Agent-App) into
 * this toolkit. framework.lock.json records that copy: commit b6d039db with
 * uncommitted changes, from a branch that was never pushed. None of the copied
 * files exist in Agent-App's history, and the framework's adapter on main has
 * since taken a different design: framework-owned accounts (PocketBase's own
 * sign-in turned off), operations as `operations.js` runners instead of the
 * apps' routes through `op()`, state in SQL tables instead of the `_a2app_*`
 * collections. Copying it over these files would break every marketplace app.
 *
 * So the adapter files (`pb/pb_hooks/_a2app.pb.js`, `_a2app_impl.js`,
 * `_a2app_rules.js`, `pb-fetch.mjs`, `pb-check.mjs`) are edited here, in the
 * kit's template, and reach the apps with `tools/agent-app-migrate/sync-system.mjs`.
 * Moving the marketplace onto the framework's adapter is a port of every app,
 * not a sync.
 */
const check = process.argv.slice(2).includes("--check");

if (check) {
  console.log("the kit's adapter is maintained in the marketplace: nothing to compare with the framework");
  process.exit(0);
}
console.error(
  "sync-upstream.mjs is retired: the kit's adapter is maintained in the marketplace (see this file's header). " +
    "Edit toolkits/blueprint-pocketbase-kit/template, then run tools/agent-app-migrate/sync-system.mjs --all.",
);
process.exit(1);
