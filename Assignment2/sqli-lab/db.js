// db.js — sets up an in-memory SQLite database and seeds it with demo data.
// Uses Node's built-in SQLite (node:sqlite, Node >= 22.5). No external DB driver.
//
// The database is intentionally simple so the SQL injection behaviour is easy to
// read: a `users` table (what an attacker wants to bypass / dump) and a separate
// `secrets` table (what a UNION-based attack can reach even though no route is
// supposed to expose it).

const { DatabaseSync } = require("node:sqlite");

const db = new DatabaseSync(":memory:");

db.exec(`
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,   -- plaintext ON PURPOSE, to make dumped data obvious in the demo
    role     TEXT NOT NULL
  );

  CREATE TABLE products (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    category TEXT NOT NULL,
    price    TEXT NOT NULL
  );

  CREATE TABLE secrets (
    id    INTEGER PRIMARY KEY,
    label TEXT NOT NULL,
    value TEXT NOT NULL
  );

  INSERT INTO products (name, category, price) VALUES
    ('Laptop',   'electronics', '899'),
    ('Phone',    'electronics', '599'),
    ('Desk',     'furniture',   '149'),
    ('Chair',    'furniture',   '89');

  INSERT INTO users (username, password, role) VALUES
    ('pom',   'testpass123',  'user'),
    ('admin', 'S3cr3t-Admin', 'admin'),
    ('guest', 'guest',        'user');

  INSERT INTO secrets (label, value) VALUES
    ('api_key',       'sk_live_9f2b1c4d7e8a'),
    ('db_root_pw',    'r00t-P@ssw0rd!'),
    ('recovery_code', 'ALPHA-BRAVO-2026');
`);

module.exports = db;
