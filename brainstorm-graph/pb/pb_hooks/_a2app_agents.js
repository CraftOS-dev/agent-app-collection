/// <reference path="../pb_data/types.d.ts" />
/**
 * Agent sign-in for apps built on the marketplace kit (SYSTEM-OWNED — hash-locked;
 * maintained in the marketplace, toolkits/blueprint-pocketbase-kit).
 *
 * The Agent App Framework's device sign-in (spec v0.2, auth §7), for apps whose
 * people are PocketBase's own accounts:
 *
 *   POST   /api/_a2app/auth/device          an agent asks (no credential)
 *   GET    /api/_a2app/auth/device/{code}   the person reviews the request
 *   POST   /api/_a2app/auth/device/{code}   … approves (optionally narrower) or denies
 *   POST   /api/_a2app/auth/token           the agent collects its credential
 *   GET    /api/_a2app/credentials          the person's connected agents
 *   DELETE /api/_a2app/credentials/{id}     … revoked (an agent may revoke itself)
 *   GET    /_a2app/account                  the page a person does this on
 *
 * WHO APPROVES (the "manager"). On a multi-user app: a signed-in account (its
 * PocketBase token in Authorization, which the account page reads from the
 * app's own sign-in), and the issued credential then acts as THAT ACCOUNT —
 * `_a2app_impl.js` sets `e.auth` to the person's record, so the app's own
 * collection rules, roles and member gates apply, and the agent never has more
 * than the person. The app's own View is never a manager there. On a
 * single-user app: the app's own View (the owner), and the credential acts as
 * the owner. Everywhere: the app's superuser (the PocketBase dashboard) and the
 * owner's admin credential (`.agent-token`). An agent's own credential never
 * approves or manages anything.
 *
 * THE CODE. The person approves the code the agent showed them; the page then
 * shows a one-time confirmation code. The agent presents it with its
 * deviceCode to collect the credential: it reaches the agent by the loopback
 * redirect (an agent on the person's computer), by the page's message to the
 * frame that embeds it, or typed in by the person. Five wrong codes void the
 * request. Only hashes are stored: the confirmation code's, and the issued
 * token's (as every grant in `_a2app_kv`).
 *
 * Read-only is the default on the page: the person ticks nothing to give an
 * agent reads only, and unticks "Only let it read" to let it make changes.
 */

var DEVICE_TTL_S = 600;
var POLL_INTERVAL_S = 5;
var SLOW_DOWN_STEP_S = 5;
var CONFIRM_TRIES = 5;
var DEFAULT_EXPIRES_S = 30 * 24 * 3600;
var MIN_EXPIRES_S = 60;
var MAX_EXPIRES_S = 365 * 24 * 3600;
var MAX_PENDING = 200;
var MAX_AGENT_NAME = 100;
var MAX_SCOPES = 500;
var CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"; // no vowels (no words), nothing that reads as a digit
var SECRET_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
var OWNER = { principal: "owner", collection: null, name: "Owner" };
// On an app without accounts, anyone who reaches it reads it (its shared link
// shows it to everyone). Such a person may connect an agent that reads as they
// do: never more, never the owner, and they manage nothing else.
var VISITOR = { principal: "visitor", collection: null, name: "Anyone with the link", visitor: true };

/* ============================================================== pure rules */
/* No PocketBase here: `node _a2app_agents.js --selftest` runs these in Node. */

/** A user or confirmation code as typed: case, dash and spaces don't matter. */
function normalizeCode(raw) {
  var s = String(raw === undefined || raw === null ? "" : raw)
    .toUpperCase()
    .replace(/[\s-]/g, "");
  if (s.length !== 8) return "";
  for (var i = 0; i < s.length; i++) if (CODE_ALPHABET.indexOf(s.charAt(i)) < 0) return "";
  return s;
}

function formatCode(compact) {
  return compact.slice(0, 4) + "-" + compact.slice(4);
}

function isInt(v) {
  return typeof v === "number" && isFinite(v) && Math.floor(v) === v;
}

/** The agent's request, checked: `{ ok }` or `{ problem }`. `declared` is every
 *  scope the app has (what "*" stands for). */
function startRequest(body, declared) {
  var b = body && typeof body === "object" ? body : {};
  var name = b.agentName === undefined || b.agentName === null ? "agent" : b.agentName;
  if (typeof name !== "string" || name.trim() === "" || name.trim().length > MAX_AGENT_NAME) {
    return { problem: "agentName must be 1 to " + MAX_AGENT_NAME + " characters." };
  }
  var scopes = b.scopes === undefined || b.scopes === null ? ["*"] : b.scopes;
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > MAX_SCOPES) {
    return { problem: "scopes must be a non-empty list." };
  }
  var seen = {};
  var clean = [];
  for (var i = 0; i < scopes.length; i++) {
    var s = scopes[i];
    if (typeof s !== "string" || (s !== "*" && declared.indexOf(s) < 0)) {
      return { problem: "Unknown scope " + JSON.stringify(s) + ": ask for \"*\" or scopes this app declares." };
    }
    if (!seen[s]) {
      seen[s] = true;
      clean.push(s);
    }
  }
  var expiresIn = b.expiresIn === undefined || b.expiresIn === null ? DEFAULT_EXPIRES_S : b.expiresIn;
  if (!isInt(expiresIn) || expiresIn < MIN_EXPIRES_S || expiresIn > MAX_EXPIRES_S) {
    return { problem: "expiresIn must be whole seconds from " + MIN_EXPIRES_S + " to " + MAX_EXPIRES_S + "." };
  }
  var port = b.loopbackPort === undefined || b.loopbackPort === null ? null : b.loopbackPort;
  if (port !== null && (!isInt(port) || port < 1024 || port > 65535)) {
    return { problem: "loopbackPort must be a port from 1024 to 65535." };
  }
  return { ok: { agentName: name.trim(), scopes: clean, expiresIn: expiresIn, loopbackPort: port } };
}

/** What the person approves: what was asked, or narrower — never wider.
 *  `{ scopes }` or `{ problem }`. */
function narrowScopes(asked, approved, declared) {
  if (approved === undefined || approved === null) return { scopes: asked.slice() };
  if (!Array.isArray(approved) || approved.length === 0) return { problem: "scopes must be a non-empty list." };
  var any = asked.indexOf("*") >= 0;
  var seen = {};
  var out = [];
  for (var i = 0; i < approved.length; i++) {
    var s = approved[i];
    if (typeof s !== "string") return { problem: "scopes must be strings." };
    var allowed = any ? s === "*" || declared.indexOf(s) >= 0 : s !== "*" && asked.indexOf(s) >= 0;
    if (!allowed) return { problem: "You can only approve what the agent asked for, or less: " + JSON.stringify(s) + " was not asked." };
    if (!seen[s]) {
      seen[s] = true;
      out.push(s);
    }
  }
  return { scopes: out };
}

/** Reads only: every entity's read scope and the read-only operations, within
 *  what was asked. */
function readScopesOf(entityNames, operations, asked) {
  var reads = [];
  for (var i = 0; i < entityNames.length; i++) reads.push("data:" + entityNames[i] + ":read");
  for (var j = 0; j < operations.length; j++) if (operations[j].readOnly === true) reads.push("op:" + operations[j].name);
  if (asked.indexOf("*") >= 0) return reads;
  return reads.filter(function (s) {
    return asked.indexOf(s) >= 0;
  });
}

/**
 * The agent polls. `row` is the stored request (or null), `presented` the
 * confirmation code's hash it sent (or ""), `same` a constant-time compare.
 * Returns `{ kind, ... }`: expired | denied | confirmation_required |
 * confirmation_invalid (left, update) | void | issue | slow_down (interval,
 * update) | pending (interval, update). `remove` means the request is done.
 */
function pollOutcome(row, now, presented, same) {
  if (!row || !(row.expiresAtMs > now)) return { kind: "expired", remove: !!row };
  if (row.status === "denied") return { kind: "denied", remove: true };
  if (row.status === "approved") {
    if (!presented) return { kind: "confirmation_required", interval: row.interval };
    if (same(presented, row.confirmationHash)) return { kind: "issue", remove: true };
    var attempts = (Number(row.confirmAttempts) || 0) + 1;
    if (attempts >= CONFIRM_TRIES) return { kind: "void", remove: true };
    return { kind: "confirmation_invalid", left: CONFIRM_TRIES - attempts, update: { confirmAttempts: attempts } };
  }
  if (row.lastPolledAtMs && now - row.lastPolledAtMs < row.interval * 1000) {
    var slower = row.interval + SLOW_DOWN_STEP_S;
    return { kind: "slow_down", interval: slower, update: { interval: slower, lastPolledAtMs: now } };
  }
  return { kind: "pending", interval: row.interval, update: { lastPolledAtMs: now } };
}

/** The app's origin for the links it hands out: A2APP_PUBLIC_URL's, else the
 *  Host the request came to. A proxy in front (a hosted public link) rewrites
 *  this to the address people actually use. */
function originFrom(publicUrl, host) {
  var m = /^(https?:\/\/[^\/?#\s]+)/i.exec(String(publicUrl || "").trim());
  if (m) return m[1];
  return "http://" + (String(host || "").trim() || "127.0.0.1");
}

/* ======================================================== PocketBase side */

function impl() {
  return require(`${__hooks}/_a2app_impl.js`);
}

function I() {
  return impl().internals;
}

function authOf(e) {
  try {
    return e.auth || null;
  } catch (_e) {
    return null;
  }
}

function displayName(record) {
  try {
    var name = String(record.getString("name") || "").trim();
    if (name !== "") return name.slice(0, 100);
  } catch (_e) {
    /* no name field */
  }
  try {
    var email = String(record.getString("email") || "");
    if (email !== "") return email;
  } catch (_e) {
    /* no email field */
  }
  return record.id;
}

function codeParam(e, name) {
  try {
    return String(e.request.pathValue(name) || "");
  } catch (_e) {
    return "";
  }
}

function sha(text) {
  return $security.sha256(text);
}

function secret(length) {
  return $security.randomStringWithAlphabet(length, SECRET_ALPHABET);
}

function newCode() {
  return $security.randomStringWithAlphabet(8, CODE_ALPHABET);
}

function declaredScopes(d) {
  return I().expandScopes({ scopes: ["*"] }, I().makeBinding(d), d);
}

/**
 * Who may approve agents and manage credentials here, or the refusal.
 * `write`: the call changes something, so the app's own page must prove it with
 * an Origin (a browser sends one on every change).
 */
function managerOf(e, d, write, visitorMay) {
  var x = I();
  if (x.isForeignOrigin(e)) return { reply: x.err(403, "forbidden_origin", "Refused: request Origin is not this app's own.") };
  var token = x.presentedToken(e);
  if (token) {
    var grant = x.grantByToken(d, token);
    if (grant && grant.credentialId === "cred_local") return { manager: OWNER };
    return { reply: x.err(403, "not_a_manager", "An agent's credential cannot approve agents or manage credentials.") };
  }
  var auth = authOf(e);
  if (auth) {
    var isSuper = false;
    try {
      isSuper = auth.isSuperuser();
    } catch (_e) {
      isSuper = false;
    }
    if (isSuper) return { manager: OWNER };
    var col = auth.collection();
    if (col && col.type === "auth") return { manager: { principal: auth.id, collection: col.name, name: displayName(auth) } };
  }
  if (d.authMode !== "multi-user") {
    var view = write ? x.headerOf(e, "Origin") !== "" && x.isView(e) : x.isView(e);
    if (view) return { manager: OWNER };
    if (visitorMay) return { manager: VISITOR };
    return { reply: x.err(401, "agent_token_required", "Managing this app's agents happens on its own page, or with its credential.") };
  }
  return { reply: x.err(401, "sign_in_required", "Sign in to the app first: an agent you approve acts as you.", { signInUrl: "/" }) };
}

function deviceKeyFor(userCode) {
  var idx = I().kvGet("device_code", userCode);
  return idx && idx.value && typeof idx.value.key === "string" ? idx.value.key : "";
}

function deviceRow(key) {
  if (key === "") return null;
  var hit = I().kvGet("device", key);
  return hit && hit.value ? hit.value : null;
}

function saveDevice(key, row) {
  var ttl = Math.max(1000, row.expiresAtMs - Date.now());
  I().kvPut("device", key, row, ttl);
  I().kvPut("device_code", row.userCode, { key: key }, ttl);
}

function forgetDevice(key, userCode) {
  I().kvDelete("device", key);
  if (userCode) I().kvDelete("device_code", userCode);
}

function pendingCount() {
  try {
    return $app.countRecords(I().C_KV, $dbx.hashExp({ kind: "device" }));
  } catch (_e) {
    return 0;
  }
}

/** POST /api/_a2app/auth/device — an agent asks to use the app. */
function start(e) {
  var x = I();
  var d = impl().decl();
  if (x.isForeignOrigin(e)) return x.send(e, x.err(403, "forbidden_origin", "Refused: request Origin is not this app's own."));
  var asked = startRequest(x.bodyOf(e), declaredScopes(d));
  if (asked.problem) return x.send(e, x.err(400, "usage", asked.problem));
  impl().ensureState($app);
  if (pendingCount() >= MAX_PENDING) {
    return x.send(e, x.err(429, "rate_limited", "Too many sign-in requests are waiting. Try again in a few minutes.", { retryAfterSeconds: 60 }));
  }
  var deviceCode = secret(43);
  var userCode = newCode();
  var now = Date.now();
  var row = {
    userCode: userCode,
    agentName: asked.ok.agentName,
    scopes: asked.ok.scopes,
    expiresIn: asked.ok.expiresIn,
    loopbackPort: asked.ok.loopbackPort,
    requestedAt: new Date(now).toISOString(),
    expiresAtMs: now + DEVICE_TTL_S * 1000,
    interval: POLL_INTERVAL_S,
    lastPolledAtMs: 0,
    status: "pending",
    confirmAttempts: 0,
  };
  saveDevice(sha(deviceCode), row);
  var page = originFrom($os.getenv("A2APP_PUBLIC_URL"), x.hostOf(e)) + impl().ACCOUNT_URL + "#approve";
  return e.json(200, {
    a2app: true,
    deviceCode: deviceCode,
    userCode: formatCode(userCode),
    verificationUri: page,
    verificationUriComplete: page + "/" + formatCode(userCode),
    expiresIn: DEVICE_TTL_S,
    interval: POLL_INTERVAL_S,
  });
}

function pendingRequest(e) {
  var x = I();
  var userCode = normalizeCode(codeParam(e, "code"));
  var key = userCode === "" ? "" : deviceKeyFor(userCode);
  var row = deviceRow(key);
  if (!row || row.status !== "pending" || !(row.expiresAtMs > Date.now())) {
    return { reply: x.err(404, "device_code_invalid", "No sign-in request is waiting for that code. Ask the agent for a new one.") };
  }
  return { key: key, row: row };
}

/** The request behind {code}, when this manager approved it and its agent has
 *  not collected the credential yet; null otherwise (no one else learns that
 *  a request exists or what became of it). */
function approvedBy(e, manager) {
  var userCode = normalizeCode(codeParam(e, "code"));
  var row = userCode === "" ? null : deviceRow(deviceKeyFor(userCode));
  if (!row || row.status !== "approved" || !(row.expiresAtMs > Date.now())) return null;
  if (row.approvedBy !== manager.principal || (row.approvedCollection || null) !== (manager.collection || null)) return null;
  return row;
}

/** GET /api/_a2app/auth/device/{code} — the person sees what is asked. */
function review(e) {
  var x = I();
  var d = impl().decl();
  var who = managerOf(e, d, false, true);
  if (who.reply) return x.send(e, who.reply);
  var waiting = approvedBy(e, who.manager);
  if (waiting) {
    // Back on the page after approving (a reload, or a browser that opened it
    // in place of the agent's own page): told so, not "nothing is waiting".
    return x.send(e, x.err(409, "already_approved", "You approved this request; your agent is waiting for its confirmation code.", {
      agentName: waiting.agentName,
      expiresAt: new Date(waiting.expiresAtMs).toISOString(),
    }));
  }
  var req = pendingRequest(e);
  if (req.reply) return x.send(e, req.reply);
  var row = req.row;
  var binding = x.makeBinding(d);
  return e.json(200, {
    a2app: true,
    app: { id: d.appId, name: d.appName },
    userCode: formatCode(row.userCode),
    agentName: row.agentName,
    scopes: row.scopes,
    readScopes: readScopesOf(Object.keys(binding.entities()), d.operations, row.scopes),
    expiresIn: row.expiresIn,
    expiresAt: new Date(row.expiresAtMs).toISOString(),
    requestedAt: row.requestedAt,
    loopback: row.loopbackPort !== null && row.loopbackPort !== undefined,
    approver: { principal: who.manager.principal, name: who.manager.name, visitor: who.manager.visitor === true },
  });
}

/** POST /api/_a2app/auth/device/{code} — the person approves or denies. */
function decide(e) {
  var x = I();
  var d = impl().decl();
  var who = managerOf(e, d, true, true);
  if (who.reply) return x.send(e, who.reply);
  var req = pendingRequest(e);
  if (req.reply) return x.send(e, req.reply);
  var body = x.bodyOf(e);
  if (typeof body.approve !== "boolean") return x.send(e, x.err(400, "usage", "Send {\"approve\": true} or {\"approve\": false}."));
  var row = req.row;
  if (!body.approve) {
    row.status = "denied";
    saveDevice(req.key, row);
    return e.json(200, { a2app: true, ok: true, status: "denied" });
  }
  var granted = narrowScopes(row.scopes, body.scopes, declaredScopes(d));
  if (granted.problem) return x.send(e, x.err(400, "usage", granted.problem));
  if (who.manager.visitor) {
    // A visitor's agent reads, whatever it asked for.
    granted = { scopes: readScopesOf(Object.keys(x.makeBinding(d).entities()), d.operations, granted.scopes) };
    if (granted.scopes.length === 0) return x.send(e, x.err(400, "usage", "This app lets visitors' agents only read, and this agent asked for nothing it can read."));
  }
  var confirmation = newCode();
  row.status = "approved";
  row.approvedBy = who.manager.principal;
  row.approvedCollection = who.manager.collection;
  row.approvedName = who.manager.name;
  row.approvedScopes = granted.scopes;
  row.confirmationHash = sha(confirmation);
  row.confirmAttempts = 0;
  saveDevice(req.key, row);
  var port = row.loopbackPort;
  return e.json(200, {
    a2app: true,
    ok: true,
    status: "approved",
    confirmation: formatCode(confirmation),
    redirect: port ? "http://127.0.0.1:" + port + "/a2app/callback?confirmation=" + formatCode(confirmation) : null,
  });
}

/** POST /api/_a2app/auth/token — the agent collects its credential. */
function token(e) {
  var x = I();
  var body = x.bodyOf(e);
  if (typeof body.deviceCode !== "string" || body.deviceCode === "" || body.deviceCode.length > 200) {
    return x.send(e, x.err(400, "usage", "Send the deviceCode the sign-in request returned."));
  }
  var presented = "";
  if (body.confirmation !== undefined && body.confirmation !== null && body.confirmation !== "") {
    var code = normalizeCode(body.confirmation);
    presented = code === "" ? "-" : sha(code);
  }
  var key = sha(body.deviceCode);
  var outcome = null;
  var row = null;
  // One transaction, so two polls with the right code cannot both collect.
  $app.runInTransaction(function (tx) {
    var rec = null;
    try {
      rec = tx.findFirstRecordByFilter(x.C_KV, "kind = 'device' && key = {:k}", { k: key });
    } catch (_e) {
      rec = null;
    }
    try {
      row = rec ? JSON.parse(rec.getString("value") || "null") : null;
    } catch (_e) {
      row = null;
    }
    outcome = pollOutcome(row, Date.now(), presented, function (a, b) {
      return typeof b === "string" && $security.equal(a, b);
    });
    if (!rec) return;
    if (outcome.remove) {
      tx.delete(rec);
      try {
        if (row && row.userCode) tx.delete(tx.findFirstRecordByFilter(x.C_KV, "kind = 'device_code' && key = {:k}", { k: row.userCode }));
      } catch (_e) {
        /* the index row already expired */
      }
    } else if (outcome.update) {
      var keys = Object.keys(outcome.update);
      for (var i = 0; i < keys.length; i++) row[keys[i]] = outcome.update[keys[i]];
      rec.set("value", row);
      tx.save(rec);
    }
  });
  switch (outcome.kind) {
    case "expired":
      return x.send(e, x.err(400, "expired_token", "This sign-in request expired or was already used. Start a new one."));
    case "denied":
      return x.send(e, x.err(400, "access_denied", "The person declined this sign-in."));
    case "void":
      return x.send(e, x.err(400, "access_denied", "Too many wrong confirmation codes. Start a new sign-in."));
    case "confirmation_required":
      return x.send(e, x.err(400, "confirmation_required", "Approved: now send the confirmation code the person was shown.", { interval: outcome.interval }));
    case "confirmation_invalid":
      return x.send(e, x.err(400, "confirmation_invalid", "That is not the confirmation code for this sign-in (" + outcome.left + " tries left).", { triesLeft: outcome.left }));
    case "slow_down":
      return x.send(e, x.err(400, "slow_down", "Polling too fast.", { interval: outcome.interval }));
    case "pending":
      return x.send(e, x.err(400, "authorization_pending", "Waiting for the person to approve.", { interval: outcome.interval }));
  }
  return issue(e, row);
}

function issue(e, row) {
  var x = I();
  var principalName = row.approvedBy === VISITOR.principal ? VISITOR.name : "Owner";
  if (row.approvedCollection) {
    var account = null;
    try {
      account = $app.findRecordById(row.approvedCollection, row.approvedBy);
    } catch (_e) {
      account = null;
    }
    if (!account) return x.send(e, x.err(400, "access_denied", "The account that approved this sign-in no longer exists."));
    principalName = displayName(account);
  }
  var tokenValue = "a2a_" + secret(43);
  var created = new Date();
  var credential = {
    credentialId: "cred_" + $security.randomStringWithAlphabet(16, "0123456789abcdef"),
    principal: row.approvedBy,
    principalName: principalName,
    agentName: row.agentName,
    scopes: row.approvedScopes,
    createdAt: created.toISOString(),
    expiresAt: new Date(created.getTime() + row.expiresIn * 1000).toISOString(),
    lastUsedAt: null,
    task: null,
  };
  impl().putGrant({
    token: tokenValue,
    credentialId: credential.credentialId,
    agentName: credential.agentName,
    principal: credential.principal,
    principalCollection: row.approvedCollection || null,
    principalName: principalName,
    scopes: credential.scopes,
    viaSignIn: true,
    createdAt: credential.createdAt,
    expiresAt: credential.expiresAt,
  });
  return e.json(200, { a2app: true, token: tokenValue, credential: credential });
}

/** Every live grant stored here, with the key it is stored under. */
function grantRows() {
  var x = I();
  var rows = [];
  try {
    rows = $app.findRecordsByFilter(x.C_KV, "kind = 'grant'", "", 1000, 0);
  } catch (_e) {
    rows = [];
  }
  var now = Date.now();
  var out = [];
  for (var i = 0; i < rows.length; i++) {
    var exp = rows[i].getFloat("expires");
    if (exp > 0 && exp < now) continue;
    var value = null;
    try {
      value = JSON.parse(rows[i].getString("value") || "null");
    } catch (_e) {
      value = null;
    }
    if (value && typeof value.credentialId === "string") out.push({ record: rows[i], value: value });
  }
  return out;
}

function mine(manager, value) {
  if (manager.principal === "owner" && manager.collection === null) return true; // the owner sees every agent
  return value.principal === manager.principal && (value.principalCollection || null) === manager.collection;
}

function credentialOut(value, reads) {
  var scopes = Array.isArray(value.scopes) ? value.scopes : [];
  return {
    credentialId: value.credentialId,
    principal: value.principal,
    principalName: value.principalName || null,
    agentName: value.agentName || null,
    scopes: scopes,
    readOnly:
      scopes.length > 0 &&
      scopes.every(function (s) {
        return reads.indexOf(s) >= 0;
      }),
    createdAt: value.createdAt || null,
    expiresAt: value.expiresAt || null,
  };
}

/** GET /api/_a2app/credentials — the agents this person connected. */
function listCredentials(e) {
  var x = I();
  var d = impl().decl();
  var who = managerOf(e, d, false);
  if (who.reply) return x.send(e, who.reply);
  var reads = readScopesOf(Object.keys(x.makeBinding(d).entities()), d.operations, ["*"]);
  var list = grantRows()
    .filter(function (g) {
      return mine(who.manager, g.value);
    })
    .map(function (g) {
      return credentialOut(g.value, reads);
    });
  list.sort(function (a, b) {
    return String(b.createdAt).localeCompare(String(a.createdAt));
  });
  return e.json(200, { a2app: true, signedInAs: { principal: who.manager.principal, name: who.manager.name }, credentials: list });
}

/** DELETE /api/_a2app/credentials/{id} — the person revokes one of their
 *  agents, or an agent signs itself out. */
function revokeCredential(e) {
  var x = I();
  var d = impl().decl();
  var id = codeParam(e, "id");
  var token = x.presentedToken(e);
  if (token) {
    var own = x.grantByToken(d, token);
    if (own && own.credentialId === id && own.credentialId !== "cred_local") {
      x.kvDelete("grant", sha(token));
      return e.json(200, { a2app: true, ok: true, revoked: id });
    }
  }
  var who = managerOf(e, d, true);
  if (who.reply) return x.send(e, who.reply);
  var rows = grantRows();
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].value.credentialId === id && mine(who.manager, rows[i].value)) {
      $app.delete(rows[i].record);
      return e.json(200, { a2app: true, ok: true, revoked: id });
    }
  }
  return x.send(e, x.err(404, "not_found", "No agent of yours has that credential."));
}

/** GET /_a2app/account — the page a person approves and manages agents on. */
function accountPage(e) {
  var html = "";
  try {
    html = toString($os.readFile($filepath.join(__hooks, "a2app_account.html")));
  } catch (_e) {
    return e.json(404, { a2app: true, ok: false, code: "not_found", message: "This app has no account page." });
  }
  try {
    e.response.header().set("Cache-Control", "no-store");
    e.response.header().set("Referrer-Policy", "no-referrer");
    // Never inside another page: one that framed it could steer the person's
    // click onto Approve for a request of its own.
    e.response.header().set("Content-Security-Policy", "frame-ancestors 'self'");
  } catch (_e) {
    /* header plumbing unavailable */
  }
  return e.html(200, html);
}

/* ================================================================ self-test */

function selftest() {
  var failures = 0;
  function check(name, ok) {
    if (!ok) {
      failures++;
      console.error("FAIL " + name);
    }
  }
  var declared = ["data:cards:read", "data:cards:write", "op:boards.list", "op:cards.move"];

  check("code normalises", normalizeCode("bcdf-ghjk") === "BCDFGHJK");
  check("code with spaces", normalizeCode(" BCDF GHJK ") === "BCDFGHJK");
  check("code wrong length", normalizeCode("BCDF-GHJ") === "");
  check("code wrong letters", normalizeCode("ABCD-EFGH") === "");
  check("code formats", formatCode("BCDFGHJK") === "BCDF-GHJK");

  var def = startRequest({}, declared);
  check("start defaults", def.ok && def.ok.agentName === "agent" && def.ok.scopes[0] === "*" && def.ok.expiresIn === DEFAULT_EXPIRES_S && def.ok.loopbackPort === null);
  check("start dedupes scopes", startRequest({ scopes: ["op:boards.list", "op:boards.list"] }, declared).ok.scopes.length === 1);
  check("start unknown scope", !!startRequest({ scopes: ["data:secrets:read"] }, declared).problem);
  check("start empty scopes", !!startRequest({ scopes: [] }, declared).problem);
  check("start long name", !!startRequest({ agentName: new Array(102).join("x") }, declared).problem);
  check("start blank name", !!startRequest({ agentName: "   " }, declared).problem);
  check("start short expiry", !!startRequest({ expiresIn: 59 }, declared).problem);
  check("start long expiry", !!startRequest({ expiresIn: MAX_EXPIRES_S + 1 }, declared).problem);
  check("start fractional expiry", !!startRequest({ expiresIn: 100.5 }, declared).problem);
  check("start low port", !!startRequest({ loopbackPort: 80 }, declared).problem);
  check("start good port", startRequest({ loopbackPort: 51234 }, declared).ok.loopbackPort === 51234);

  check("narrow keeps asked", narrowScopes(["*"], undefined, declared).scopes[0] === "*");
  check("narrow star to reads", narrowScopes(["*"], ["data:cards:read"], declared).scopes.length === 1);
  check("narrow star unknown", !!narrowScopes(["*"], ["data:secrets:read"], declared).problem);
  check("narrow cannot widen", !!narrowScopes(["data:cards:read"], ["data:cards:write"], declared).problem);
  check("narrow cannot add star", !!narrowScopes(["data:cards:read"], ["*"], declared).problem);
  check("narrow empty", !!narrowScopes(["*"], [], declared).problem);

  var ops = [
    { name: "boards.list", readOnly: true },
    { name: "cards.move" },
  ];
  var reads = readScopesOf(["cards"], ops, ["*"]);
  check("reads from star", reads.length === 2 && reads.indexOf("op:boards.list") >= 0 && reads.indexOf("op:cards.move") < 0);
  check("reads within asked", readScopesOf(["cards"], ops, ["op:boards.list", "op:cards.move"]).join() === "op:boards.list");

  var same = function (a, b) {
    return a === b;
  };
  var now = 1000000;
  var pending = { status: "pending", expiresAtMs: now + 1000, interval: 5, lastPolledAtMs: 0 };
  check("poll missing", pollOutcome(null, now, "", same).kind === "expired");
  check("poll expired", pollOutcome({ status: "approved", expiresAtMs: now }, now, "h", same).kind === "expired");
  check("poll pending", pollOutcome(pending, now, "", same).kind === "pending");
  var fast = { status: "pending", expiresAtMs: now + 1000, interval: 5, lastPolledAtMs: now - 1000 };
  var slow = pollOutcome(fast, now, "", same);
  check("poll slow down", slow.kind === "slow_down" && slow.interval === 10 && slow.update.interval === 10);
  check("poll denied", pollOutcome({ status: "denied", expiresAtMs: now + 1 }, now, "", same).remove === true);
  var approved = { status: "approved", expiresAtMs: now + 1000, interval: 5, confirmationHash: "good", confirmAttempts: 0 };
  check("poll needs code", pollOutcome(approved, now, "", same).kind === "confirmation_required");
  var wrong = pollOutcome(approved, now, "bad", same);
  check("poll wrong code", wrong.kind === "confirmation_invalid" && wrong.left === CONFIRM_TRIES - 1);
  check("poll fifth wrong voids", pollOutcome({ status: "approved", expiresAtMs: now + 1, confirmationHash: "good", confirmAttempts: CONFIRM_TRIES - 1 }, now, "bad", same).kind === "void");
  check("poll right code", pollOutcome(approved, now, "good", same).kind === "issue");
  check("poll approved ignores interval", pollOutcome({ status: "approved", expiresAtMs: now + 1, interval: 5, lastPolledAtMs: now, confirmationHash: "good" }, now, "good", same).kind === "issue");

  check("origin from public url", originFrom("https://app.example.com/x/y", "127.0.0.1:8090") === "https://app.example.com");
  check("origin from host", originFrom("", "127.0.0.1:8090") === "http://127.0.0.1:8090");
  check("origin fallback", originFrom(undefined, "") === "http://127.0.0.1");

  if (failures > 0) {
    console.error(failures + " agent sign-in check(s) failed");
    process.exit(1);
  }
  console.log("agent sign-in self-test: ok");
}

module.exports = {
  start: start,
  review: review,
  decide: decide,
  token: token,
  listCredentials: listCredentials,
  revokeCredential: revokeCredential,
  accountPage: accountPage,
  // pure rules, for tests
  normalizeCode: normalizeCode,
  startRequest: startRequest,
  narrowScopes: narrowScopes,
  readScopesOf: readScopesOf,
  pollOutcome: pollOutcome,
  originFrom: originFrom,
};

if (typeof process !== "undefined" && process.argv && process.argv.indexOf("--selftest") >= 0 && typeof $app === "undefined") {
  selftest();
}
