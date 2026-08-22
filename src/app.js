// ===========================================================================
//  secure-sdlc-lab — app.js  (VERSION 0: DELIBERATELY VULNERABLE)
// ===========================================================================
//
//  ⚠️  READ THIS FIRST
//
//  This file is broken on purpose. It contains nine planted security flaws.
//  It exists so that, in later modules, each automated scanner has something
//  real to find. Never copy this code into anything that matters, and never
//  run it on a machine reachable from the internet.
//
//  Every flaw below is tagged like this:
//      VULNERABILITY #n — short name
//      CWE-xxx | OWASP A0x:2021 | Caught later by: <tool>  | Fixed in: Module n
//
//  That tag is the spine of this whole course. A "secure SDLC" is not a vibe;
//  it is a claim that for every class of defect you care about, some specific
//  gate catches it at some specific point in the lifecycle. If you can't name
//  the gate, you don't have coverage — you have hope.
// ===========================================================================

const express = require('express');
const session = require('express-session');
const { db, init } = require('./db');

const app = express();
const PORT = 3000;

init(); // create the table + seed users on boot

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
// "Middleware" is Express's name for a function that runs on every request
// before your route handler does. Think of it as a pipeline: the request enters
// on the left, passes through each middleware in the order you registered it,
// and eventually reaches a route. Each one can read the request, change it, or
// stop it dead.
//
// This line adds a parser that reads HTML form submissions (Content-Type:
// application/x-www-form-urlencoded) and hands them to you as `req.body`.
// Without it, `req.body` is undefined and every login attempt crashes.
app.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// VULNERABILITY #3 — Hardcoded secret committed to source control
// CWE-798 | OWASP A07:2021 | Caught later by: Gitleaks | Fixed in: Module 3
// ---------------------------------------------------------------------------
// `secret` is the key used to cryptographically sign the session cookie. Anyone
// who knows it can forge a cookie that says "I am the admin" and the server
// will believe them — no password required.
//
// The deeper problem is not that the value is weak. It is that the value is in
// git. Git never forgets: even if you delete the line in the next commit, the
// secret lives forever in the history, in every clone, in every fork. The only
// real remediation for a committed secret is to ROTATE it — change the value at
// the source — not to delete the line.
//
// This is exactly why secret scanning runs *first* in a pipeline, and ideally
// as a pre-commit hook, before the value ever reaches a remote.
// ---------------------------------------------------------------------------
app.use(
  session({
    secret: 'sk_lab_9f2c4e8a71b3d6f05c8e2a4b7d9f1c3e',
    resave: false,
    saveUninitialized: false,
    // ---------------------------------------------------------------------
    // VULNERABILITY #4 — Insecure session cookie flags
    // CWE-1004, CWE-614 | OWASP A05:2021 | Caught later by: OWASP ZAP
    // Fixed in: Module 6
    // ---------------------------------------------------------------------
    // httpOnly:false means JavaScript running in the page can read the cookie
    // via document.cookie. Combine that with the XSS below (#5) and an attacker
    // steals a live admin session with a single injected <script> tag.
    // secure:false means the cookie is sent over plain HTTP too, so anyone on
    // the same wifi can read it off the wire.
    cookie: { httpOnly: false, secure: false },
  })
);

// ---------------------------------------------------------------------------
// Tiny HTML helper.
// We are deliberately NOT using a template engine yet. Building HTML by hand
// with string concatenation is how injection bugs are born, and you should see
// that mechanism clearly before a framework hides it from you.
// ---------------------------------------------------------------------------
function page(title, body) {
  return `<!doctype html>
<html>
  <head><title>${title}</title></head>
  <body style="font-family: system-ui, sans-serif; max-width: 640px; margin: 40px auto;">
    <h1>${title}</h1>
    ${body}
    <hr>
    <p style="color:#888;font-size:13px;">secure-sdlc-lab &mdash; v0, deliberately vulnerable</p>
  </body>
</html>`;
}

// ---------------------------------------------------------------------------
// GET /  — the login form
// ---------------------------------------------------------------------------
// `app.get(path, handler)` registers a handler for HTTP GET requests to `path`.
// GET means "give me a representation of this thing" and must not change state.
// The form below POSTs, because submitting credentials *does* change state (it
// creates a session) — and because GET parameters end up in browser history,
// server logs, and Referer headers.
app.get('/', (req, res) => {
  res.send(
    page(
      'Login',
      `<form method="POST" action="/login">
         <p><input name="username" placeholder="username" autocomplete="off"></p>
         <p><input name="password" type="password" placeholder="password"></p>
         <p><button type="submit">Log in</button></p>
       </form>
       <p style="font-size:13px;color:#666;">Lab accounts: <code>alice / password1</code></p>`
    )
  );
});

// ---------------------------------------------------------------------------
// POST /login
// ---------------------------------------------------------------------------
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // -------------------------------------------------------------------------
  // VULNERABILITY #1 — SQL injection via string concatenation
  // CWE-89 | OWASP A03:2021 | Caught later by: Semgrep (SAST) | Fixed in: Module 4
  // -------------------------------------------------------------------------
  // The bug is that we are building a *program* (SQL) by gluing together a
  // trusted template and untrusted user input. The database has no way to tell
  // which characters came from the developer and which came from the attacker —
  // it just sees one string and parses all of it as code.
  //
  // Type this into the username box:      ' OR '1'='1' --
  // ...and the query the database actually receives becomes:
  //
  //   SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = ''
  //
  // `'1'='1'` is always true, `--` comments out the rest of the line, and the
  // WHERE clause now matches every row. You are logged in as the first user in
  // the table without knowing a single password.
  //
  // The fix is NOT "escape the quotes" or "block the word OR". It is to stop
  // concatenating: send the query and the data over separate channels so the
  // parser is finished before user input is ever attached. That is what a
  // parameterized query does, and we do it in Module 4.
  // -------------------------------------------------------------------------
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  console.log('[SQL]', query); // logged so you can watch the injection happen

  db.get(query, (err, user) => {
    if (err) {
      // ---------------------------------------------------------------------
      // VULNERABILITY #6 — Verbose error disclosure
      // CWE-209 | OWASP A05:2021 | Caught later by: OWASP ZAP | Fixed in: Module 6
      // ---------------------------------------------------------------------
      // Returning the raw database error hands an attacker a free map: table
      // names, column names, SQL dialect, driver version. Injection attacks are
      // enormously easier when the target narrates its own internals.
      return res.status(500).send(page('Error', `<pre>${err.message}</pre>`));
    }

    if (!user) {
      return res.status(401).send(page('Login failed', '<p><a href="/">Try again</a></p>'));
    }

    // -----------------------------------------------------------------------
    // VULNERABILITY #7 — No session regeneration after privilege change
    // CWE-384 (Session Fixation) | OWASP A07:2021 | Fixed in: Module 6
    // -----------------------------------------------------------------------
    // The visitor already had a session ID before logging in. We keep it and
    // simply staple an identity onto it. If an attacker planted that session ID
    // in the victim's browser beforehand, the attacker's session is now an
    // authenticated one. The rule: whenever the privilege level of a session
    // changes, issue a brand-new session ID.
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect('/dashboard');
  });
});

// ---------------------------------------------------------------------------
// GET /dashboard — requires being logged in
// ---------------------------------------------------------------------------
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/');
  const u = req.session.user;
  res.send(
    page(
      'Dashboard',
      `<p>Signed in as <b>${u.username}</b> (role: ${u.role})</p>
       <ul>
         <li><a href="/search?q=hello">Search</a></li>
         <li><a href="/admin">Admin panel</a></li>
         <li><a href="/logout">Log out</a></li>
       </ul>`
    )
  );
});

// ---------------------------------------------------------------------------
// GET /admin
// ---------------------------------------------------------------------------
app.get('/admin', (req, res) => {
  // -------------------------------------------------------------------------
  // VULNERABILITY #8 — Broken access control (authentication ≠ authorization)
  // CWE-862 | OWASP A01:2021 | Caught later by: manual review + threat model
  // Fixed in: Module 6
  // -------------------------------------------------------------------------
  // We check that *somebody* is logged in. We never check *who*. `alice` has
  // role 'user' and can still read every account in the system just by typing
  // the URL. This is the single most common serious flaw in real applications,
  // and note carefully: no scanner reliably finds it. A SAST tool does not know
  // your business rules. This one is caught by threat modelling and code review,
  // which is precisely why a secure SDLC is more than a pile of scanners.
  // -------------------------------------------------------------------------
  if (!req.session.user) return res.redirect('/');

  db.all('SELECT id, username, password, role FROM users', (err, rows) => {
    if (err) return res.status(500).send(page('Error', `<pre>${err.message}</pre>`));
    const table = rows
      .map((r) => `<tr><td>${r.id}</td><td>${r.username}</td><td>${r.password}</td><td>${r.role}</td></tr>`)
      .join('');
    res.send(
      page(
        'Admin panel',
        `<table border="1" cellpadding="6">
           <tr><th>id</th><th>username</th><th>password</th><th>role</th></tr>
           ${table}
         </table>
         <p><a href="/dashboard">Back</a></p>`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// GET /search
// ---------------------------------------------------------------------------
app.get('/search', (req, res) => {
  const q = req.query.q || '';

  // -------------------------------------------------------------------------
  // VULNERABILITY #5 — Reflected cross-site scripting (XSS)
  // CWE-79 | OWASP A03:2021 | Caught later by: Semgrep + OWASP ZAP
  // Fixed in: Module 6
  // -------------------------------------------------------------------------
  // Same root cause as the SQL injection: user input is pasted straight into a
  // program. Here the program is HTML rather than SQL, and the interpreter is
  // the victim's browser rather than the database.
  //
  // Try:  /search?q=<script>alert(document.cookie)</script>
  //
  // Because the session cookie above is httpOnly:false, that script can read it
  // and ship it to an attacker's server. Chain #5 + #4 and you have full account
  // takeover from a single link.
  //
  // The fix is contextual output encoding: escape the input for the context it
  // lands in, at the moment it lands there. Not on input — on output.
  // -------------------------------------------------------------------------
  res.send(
    page(
      'Search',
      `<p>You searched for: ${q}</p>
       <form method="GET" action="/search">
         <input name="q" value="${q}">
         <button>Search</button>
       </form>
       <p><a href="/dashboard">Back</a></p>`
    )
  );
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ---------------------------------------------------------------------------
// VULNERABILITY #9 — No security headers
// CWE-693 | OWASP A05:2021 | Caught later by: OWASP ZAP | Fixed in: Module 6
// ---------------------------------------------------------------------------
// A default Express response carries no Content-Security-Policy, no
// X-Content-Type-Options, no X-Frame-Options, no Strict-Transport-Security, and
// helpfully advertises `X-Powered-By: Express` so attackers know what to target.
// These headers are defence in depth: a good CSP can neuter the XSS above even
// if the encoding bug survives review. Module 6 adds Helmet.
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`\n  secure-sdlc-lab v0 (VULNERABLE) running at http://localhost:${PORT}`);
  console.log(`  Try logging in as:  alice / password1`);
  console.log(`  Then try username:  ' OR '1'='1' --   with any password\n`);
});
