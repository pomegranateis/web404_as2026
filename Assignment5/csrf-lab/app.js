// app.js — CSRF lab (WEB404 Assignment 5)
//
// A small account app with a cookie-based session and a state-changing action
// ("change my email"). The action is implemented twice:
//
//   VULNERABLE:
//     POST /change-email-vulnerable   -> trusts the session cookie alone.
//                                        No anti-CSRF token, no origin check.
//   SECURE:
//     GET  /form-secure               -> issues a form carrying a per-session CSRF token
//     POST /change-email-secure       -> requires a valid CSRF token (synchronizer-token
//                                        pattern) AND checks the Origin header.
//
// The session cookie is deliberately set with SameSite=Lax only (not Strict) so
// the vulnerability lives at the APPLICATION layer (missing token), which is the
// subject of this assignment, rather than being masked by the cookie policy.
//
// Run:  node app.js    ->  http://localhost:3004

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
const PORT = 3004;
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// In-memory "database" and session store.
const users = { alice: { password: "password123", email: "alice@example.com" } };
const sessions = new Map(); // sid -> { username, csrfToken }

function currentUser(req) {
  const sid = req.cookies.sid;
  const sess = sid && sessions.get(sid);
  if (!sess) return null;
  return { sess, user: users[sess.username] };
}

// Login: creates a session and sets the session cookie.
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const u = users[username];
  if (!u || u.password !== password) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  const sid = crypto.randomUUID();
  const csrfToken = crypto.randomBytes(32).toString("hex");
  sessions.set(sid, { username, csrfToken });

  res.cookie("sid", sid, {
    httpOnly: true,     // not readable by JS
    sameSite: "lax",    // see note in the header comment
  });
  res.json({ message: `logged in as ${username}` });
});

// Show the current account state.
app.get("/profile", (req, res) => {
  const ctx = currentUser(req);
  if (!ctx) return res.status(401).json({ error: "not logged in" });
  res.json({ username: ctx.sess.username, email: ctx.user.email });
});

// ───────────────────────────────────────────────────────────────────────────
// VULNERABLE  — performs a state change on the strength of the session cookie
// ALONE. Any request that carries the victim's cookie is honoured — which is
// exactly what a browser does when it submits an attacker's cross-site form.
// ───────────────────────────────────────────────────────────────────────────
app.post("/change-email-vulnerable", (req, res) => {
  const ctx = currentUser(req);
  if (!ctx) return res.status(401).json({ error: "not logged in" });

  ctx.user.email = req.body.email;
  res.json({ message: "email updated", email: ctx.user.email });
});

// ───────────────────────────────────────────────────────────────────────────
// SECURE — synchronizer token pattern + origin check.
// ───────────────────────────────────────────────────────────────────────────

// Issues the real form, embedding the session's secret CSRF token in a hidden field.
// A cross-site attacker cannot read this token (Same-Origin Policy), so they
// cannot forge a request that contains it.
app.get("/form-secure", (req, res) => {
  const ctx = currentUser(req);
  if (!ctx) return res.status(401).send("not logged in");
  res.type("html").send(`<!doctype html><meta charset=utf-8><h2>Change email (secure)</h2>
  <form method=post action=/change-email-secure>
    <input type=hidden name=_csrf value="${ctx.sess.csrfToken}">
    <input name=email value="${ctx.user.email}">
    <button>save</button>
  </form>`);
});

const ALLOWED_ORIGINS = new Set(["http://localhost:3004"]);

app.post("/change-email-secure", (req, res) => {
  const ctx = currentUser(req);
  if (!ctx) return res.status(401).json({ error: "not logged in" });

  // Defence 1 — synchronizer CSRF token: must be present and match the session's.
  const supplied = req.body._csrf || req.headers["x-csrf-token"];
  if (!supplied || supplied !== ctx.sess.csrfToken) {
    return res.status(403).json({ error: "CSRF token missing or invalid" });
  }

  // Defence 2 — origin check: reject requests initiated by another site.
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: "cross-origin request blocked" });
  }

  ctx.user.email = req.body.email;
  res.json({ message: "email updated (secure)", email: ctx.user.email });
});

app.listen(PORT, () => console.log(`CSRF lab running on http://localhost:${PORT}`));
