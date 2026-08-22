// ---------------------------------------------------------------------------
// db.js — database setup for the lab app
//
// MODULE 1 READING NOTE:
// This file has ONE job: open a SQLite database and make sure it has a `users`
// table with two accounts in it. Nothing here is a web server. Keeping data
// access in its own file is a habit worth building early — when we later audit
// "where does this app talk to the database?", the answer should be one place.
// ---------------------------------------------------------------------------

// `require` is Node's way of importing another module. sqlite3 is a package we
// installed from npm; it ships a small C library that reads/writes .db files.
// `.verbose()` just turns on nicer stack traces when a query fails.
const sqlite3 = require('sqlite3').verbose();

// SQLite stores an entire database in a single file on disk. No server process,
// no connection string, no credentials. That makes it perfect for a lab and
// completely wrong for production — but the SQL we write is the same either way,
// which is what matters for learning injection.
const db = new sqlite3.Database('./lab.db');

// ---------------------------------------------------------------------------
// VULNERABILITY #2 — Passwords stored in plaintext
// ---------------------------------------------------------------------------
// The `password` column below holds the literal string the user typed.
// Anyone who reads this file — a leaked backup, a SQL injection that dumps the
// table, a curious admin, a stolen laptop — instantly owns every account.
// Worse: people reuse passwords, so a breach here becomes a breach everywhere.
//
// This is CWE-256 (Plaintext Storage of a Password) and it maps to
// OWASP Top 10 A02:2021 – Cryptographic Failures.
//
// We fix this in Module 4 with bcrypt. Do not skip ahead — the point of this
// lab is to see the broken state first, so the fix means something.
// ---------------------------------------------------------------------------

function init() {
  // `serialize` tells sqlite3 to run these statements one after another rather
  // than concurrently. Without it, the INSERTs could fire before CREATE TABLE.
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role     TEXT NOT NULL DEFAULT 'user'
      )
    `);

    // INSERT OR IGNORE means "skip if a row with this UNIQUE username exists",
    // so restarting the app doesn't create duplicates.
    db.run(
      `INSERT OR IGNORE INTO users (username, password, role)
       VALUES ('admin', 'admin123', 'admin')`
    );
    db.run(
      `INSERT OR IGNORE INTO users (username, password, role)
       VALUES ('alice', 'password1', 'user')`
    );
  });
}

module.exports = { db, init };
