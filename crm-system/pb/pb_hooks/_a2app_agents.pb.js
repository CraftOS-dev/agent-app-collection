/// <reference path="../pb_data/types.d.ts" />
/**
 * Agent sign-in — PocketBase hook REGISTRATIONS (SYSTEM-OWNED — hash-locked).
 *
 * An agent asks to use the app, a person approves it on the app's account page,
 * and the agent then acts as that person (Agent App Framework spec v0.2, auth
 * §7, device sign-in). The logic is in `_a2app_agents.js`; each handler below
 * require()s it, because PocketBase runs every handler in an isolated runtime.
 */

routerAdd("POST", "/api/_a2app/auth/device", (e) => require(`${__hooks}/_a2app_agents.js`).start(e));
routerAdd("GET", "/api/_a2app/auth/device/{code}", (e) => require(`${__hooks}/_a2app_agents.js`).review(e));
routerAdd("POST", "/api/_a2app/auth/device/{code}", (e) => require(`${__hooks}/_a2app_agents.js`).decide(e));
routerAdd("POST", "/api/_a2app/auth/token", (e) => require(`${__hooks}/_a2app_agents.js`).token(e));

routerAdd("GET", "/api/_a2app/credentials", (e) => require(`${__hooks}/_a2app_agents.js`).listCredentials(e));
routerAdd("DELETE", "/api/_a2app/credentials/{id}", (e) => require(`${__hooks}/_a2app_agents.js`).revokeCredential(e));

routerAdd("GET", "/_a2app/account", (e) => require(`${__hooks}/_a2app_agents.js`).accountPage(e));
