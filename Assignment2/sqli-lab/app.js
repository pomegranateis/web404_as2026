// app.js — SQL Injection lab (WEB404 Assignment 2)
//
// One Express server exposing BOTH a vulnerable and a secure version of each
// feature, so the report can show a direct before/after comparison:
//
//   VULNERABLE (string-concatenated SQL):
//     POST /login-vulnerable        -> tautology auth bypass
//     GET  /products-vulnerable     -> UNION, error-based, and boolean-blind SQLi
//
//   SECURE (parameterised queries + input validation):
//     POST /login-secure
//     GET  /products-secure
//
// Run:  node app.js       (Node >= 22.5 for built-in SQLite)

const express = require("express");
const db = require("./db");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = 3001;

// ───────────────────────────────────────────────────────────────────────────
// VULNERABLE ROUTES  — DO NOT COPY THESE PATTERNS INTO REAL CODE
// Every query below is built by concatenating untrusted input straight into
// the SQL string. That is the single root cause of every attack in the report.
// ───────────────────────────────────────────────────────────────────────────

// VULNERABLE login: username/password spliced directly into the SQL text.
app.post("/login-vulnerable", (req, res) => {
  const { username, password } = req.body;

  const sql = `SELECT id, username, role FROM users
               WHERE username = '${username}' AND password = '${password}'`;

  console.log("[vulnerable /login] SQL =>", sql.replace(/\s+/g, " ").trim());

  try {
    const row = db.prepare(sql).get();
    if (row) {
      return res.json({ message: `Welcome, ${row.username}`, role: row.role });
    }
    return res.status(401).json({ error: "invalid credentials" });
  } catch (err) {
    // Error text echoed back -> enables error-based injection.
    return res.status(500).json({ error: err.message });
  }
});

// VULNERABLE product search: `category` spliced directly into the SQL text.
app.get("/products-vulnerable", (req, res) => {
  const category = req.query.category ?? "";

  const sql = `SELECT id, name, category, price FROM products
               WHERE category = '${category}'`;

  console.log("[vulnerable /products] SQL =>", sql.replace(/\s+/g, " ").trim());

  try {
    const rows = db.prepare(sql).all();
    return res.json({ count: rows.length, rows });
  } catch (err) {
    // Error text echoed back -> enables error-based injection.
    return res.status(500).json({ error: err.message });
  }
});

// ───────────────────────────────────────────────────────────────────────────
// SECURE ROUTES — the fix. Input is passed as PARAMETERS, never concatenated,
// so it can only ever be treated as data, never as SQL.
// ───────────────────────────────────────────────────────────────────────────

// SECURE login: placeholders (?) bind the values as data.
app.post("/login-secure", (req, res) => {
  const { username, password } = req.body;

  // Lightweight input validation (defence in depth) — reject obviously bad input.
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "username and password must be strings" });
  }

  const stmt = db.prepare(
    "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
  );
  const row = stmt.get(username, password);

  if (row) {
    return res.json({ message: `Welcome, ${row.username}`, role: row.role });
  }
  return res.status(401).json({ error: "invalid credentials" });
});

// SECURE product search: parameterised query + an allowlist of valid categories.
const ALLOWED_CATEGORIES = new Set(["electronics", "furniture"]);

app.get("/products-secure", (req, res) => {
  const category = req.query.category ?? "";

  if (!ALLOWED_CATEGORIES.has(category)) {
    return res.status(400).json({ error: "unknown category" });
  }

  const rows = db
    .prepare("SELECT id, name, category, price FROM products WHERE category = ?")
    .all(category);

  return res.json({ count: rows.length, rows });
});

app.listen(PORT, () => {
  console.log(`SQLi lab running on http://localhost:${PORT}`);
});
