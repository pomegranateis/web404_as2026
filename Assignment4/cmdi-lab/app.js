// app.js — Command Injection lab (WEB404 Assignment 4)
//
// A small "Network Tools" web CLI: the user types a host and the server runs a
// ping / DNS lookup against it. The feature is implemented twice:
//
//   VULNERABLE:
//     GET /ping-vulnerable?host=...     -> child_process.exec(`ping -c1 ${host}`)
//                                          (runs through a shell -> command injection)
//   SECURE:
//     GET /ping-secure?host=...         -> execFile("ping", ["-c1", host]) + input allowlist
//                                          (no shell -> shell metacharacters are inert)
//
// Run:  node app.js    ->  http://localhost:3003

const express = require("express");
const { exec, execFile } = require("child_process");

const app = express();
const PORT = 3003;

// ───────────────────────────────────────────────────────────────────────────
// VULNERABLE  — DO NOT COPY
// The host value is concatenated straight into a shell command string, so the
// shell interprets ; | && $() etc. as command syntax.
// ───────────────────────────────────────────────────────────────────────────
app.get("/ping-vulnerable", (req, res) => {
  const host = req.query.host ?? "";
  const cmd = `ping -c1 ${host}`; // <-- the single root cause
  console.log("[vulnerable] exec =>", cmd);

  exec(cmd, { timeout: 8000 }, (err, stdout, stderr) => {
    // Output (including anything the injected command printed) is returned to the client.
    res.type("text/plain").send((stdout || "") + (stderr || "") + (err ? `\n[exit ${err.code}]` : ""));
  });
});

// ───────────────────────────────────────────────────────────────────────────
// SECURE — the fix.
//  1) execFile with an argument ARRAY: no shell is spawned, so metacharacters
//     in `host` are passed as a literal argument to ping, never interpreted.
//  2) Input validation allowlist: only valid hostnames / IPv4 addresses pass.
// ───────────────────────────────────────────────────────────────────────────

// RFC-1123-ish hostname, or a dotted IPv4 address.
const HOST_RE =
  /^(?=.{1,253}$)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;

app.get("/ping-secure", (req, res) => {
  const host = String(req.query.host ?? "");

  // Gate 1: reject anything that is not a plain hostname / IP before doing anything.
  if (!HOST_RE.test(host)) {
    return res.status(400).type("text/plain").send("rejected: invalid host");
  }

  // Gate 2: no shell. Arguments are passed as data, not parsed as a command line.
  execFile("ping", ["-c1", "--", host], { timeout: 8000 }, (err, stdout, stderr) => {
    res.type("text/plain").send((stdout || "") + (stderr || "") + (err ? `\n[exit ${err.code}]` : ""));
  });
});

// Minimal CLI form for manual testing.
app.get("/", (req, res) => {
  res.type("html").send(`<!doctype html><meta charset=utf-8><h2>Network Tools</h2>
  <form action=/ping-vulnerable><input name=host placeholder=host value=127.0.0.1>
    <button>ping (vulnerable)</button></form>
  <form action=/ping-secure><input name=host placeholder=host value=127.0.0.1>
    <button>ping (secure)</button></form>`);
});

app.listen(PORT, () => console.log(`Command-injection lab running on http://localhost:${PORT}`));
