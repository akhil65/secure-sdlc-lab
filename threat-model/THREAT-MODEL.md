# Threat Model — secure-sdlc-lab

Method: Shostack's 4 questions + STRIDE per element.

## 1. What are we building?

Browser → Express server → SQLite (users table).
Two trust boundaries:
- TB#1 (network): everything crossing it is attacker-controlled.
- TB#2 (data layer): where queries hit the database.

## 2. What can go wrong? (STRIDE per flow)

### Flow A — Search (browser → Express, crosses TB#1)
| STRIDE | Threat? | Notes |
|---|---|---|
| Spoofing | NA | no authentication at this flow |
| Tampering | YES | no HTTPS in transit; reflected XSS rewrites the victim's page |
| Repudiation | NA | read-only; nothing state-changing to repudiate |
| Info disclosure | YES | `q` reflected unescaped (XSS) → steals session cookie (flaw #5, #4) |
| Denial of service | LOW | no rate limiting, but search is cheap |
| Elevation | YES | stolen admin cookie elevates anonymous → admin (flaw #4 → #8) |

### Flow B — DB query (Express → SQLite, crosses TB#2)
| STRIDE | Threat? | Notes |
|---|---|---|
| Spoofing | YES | SQL injection impersonates any user (flaw #1) |
| Tampering | NA* | UI only reads; injection primitive could write in principle |
| Repudiation | YES | no audit logging — injected login leaves no trace (UNPLANTED) |
| Info disclosure | YES | full table readable, passwords in plaintext (flaw #2) |
| Denial of service | YES | no account lockout → brute force + resource exhaustion (UNPLANTED) |
| Elevation | YES | injection returns admin row → full admin (flaw #1 → #8) |

### Flow C — Login (browser → Express, crosses TB#1)
| STRIDE | Threat? | Notes |
|---|---|---|
| Spoofing | YES | SQLi auth bypass; weak password check (flaw #1) |
| Tampering | YES | no HTTPS; request modifiable in transit (flaw #4) |
| Repudiation | YES | no logging of auth events (UNPLANTED) |
| Info disclosure | YES | verbose DB errors leak schema (flaw #6); stealable cookie (flaw #4) |
| Denial of service | YES | no rate limiting on login attempts (UNPLANTED) |
| Elevation | YES | admin panel checks logged-in, not is-admin (flaw #8); no session regen (flaw #7) |

## 3. What are we going to do about it?

| Threat | Mitigation | Module |
|---|---|---|
| SQL injection | parameterized queries | 4 |
| Plaintext passwords | bcrypt hashing | 4 |
| Hardcoded secret | env vars + Gitleaks | 3 |
| XSS | output encoding + CSP | 6 |
| Insecure cookies | httpOnly, secure, sameSite | 6 |
| Verbose errors | generic error responses | 6 |
| No session regen | regenerate on login | 6 |
| Broken access control | RBAC middleware | 6 |
| Missing headers | Helmet | 6 |
| No audit logging | (backlog — future work) | — |
| No rate limiting | (backlog — future work) | — |

## 4. Did we do a good job?

Revisit after Module 9 (DAST): every YES above should be either fixed or a
documented, owned, accepted risk.