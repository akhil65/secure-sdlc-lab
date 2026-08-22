# secure-sdlc-lab

A hands-on Secure SDLC / DevSecOps lab, built from scratch.

The approach: start with a **deliberately vulnerable** Node.js application, then
harden it one control at a time — each fix paired with the automated gate that
catches that class of defect, wired into a real CI/CD pipeline.

The application is intentionally trivial. It is a crash-test dummy. The pipeline
is the actual subject.

> ⚠️ **The `v0` application in this repo is insecure on purpose.** Nine security
> flaws are planted and documented in the source. Run it locally only. Never
> expose it to a network you don't control.

---

## The idea

> For every class of security defect you care about, you should be able to name
> the specific gate that catches it, and the specific phase it catches it in.
> If you can't name the gate, you don't have coverage — you have hope.

This lab builds that mapping end to end:

| SDLC phase | Security activity | Tool | Module |
|---|---|---|---|
| Design | Threat modelling (STRIDE) | — | 2 |
| Implement | Secret scanning | Gitleaks | 3 |
| Implement | Static analysis (SAST) | Semgrep | 4 |
| Build | Dependency analysis (SCA) | Trivy, `npm audit` | 5 |
| Implement | Secure coding fixes | bcrypt, Helmet, RBAC | 6 |
| Build | Container image scanning | Trivy | 7 |
| Deploy | IaC / config scanning | Trivy config | 8 |
| Test | Dynamic analysis (DAST) | OWASP ZAP | 9 |
| Deploy | Runtime hardening | Kubernetes `securityContext` | 10 |
| All | Gates & governance | Branch protection, policy | 11 |
| Build | Supply chain integrity | SBOM, cosign, SLSA | 12 |

---

## Curriculum

Lessons live in [`docs/`](docs/) and are meant to be read in order.

- [Module 0 — Foundations](docs/00-foundations.md) — what a Secure SDLC is, what each tool category actually does and where it's blind, vocabulary, environment setup, git
- [Module 1 — The vulnerable app](docs/01-the-vulnerable-app.md) — the app line by line, then exploit it yourself
- Module 2 — Threat modelling with STRIDE *(next)*
- Modules 3–12 — see [CURRICULUM.md](CURRICULUM.md)

---

## The nine planted flaws

| # | Flaw | CWE | OWASP | Found by | Fixed in |
|---|---|---|---|---|---|
| 1 | SQL injection | CWE-89 | A03 | Semgrep | Module 4 |
| 2 | Plaintext passwords | CWE-256 | A02 | threat model | Module 4 |
| 3 | Hardcoded secret | CWE-798 | A07 | Gitleaks | Module 3 |
| 4 | Insecure cookie flags | CWE-1004/614 | A05 | ZAP | Module 6 |
| 5 | Reflected XSS | CWE-79 | A03 | Semgrep + ZAP | Module 6 |
| 6 | Verbose error disclosure | CWE-209 | A05 | ZAP | Module 6 |
| 7 | No session regeneration | CWE-384 | A07 | code review | Module 6 |
| 8 | Broken access control | CWE-862 | A01 | **threat model only** | Module 6 |
| 9 | Missing security headers | CWE-693 | A05 | ZAP | Module 6 |

Three of the nine are found by humans, not tools. That ratio is the honest
answer to "can we just buy a scanner?"

---

## Running it

```bash
npm install
npm start
# → http://localhost:3000
```

Lab account: `alice` / `password1`

Then try logging in with username `' OR '1'='1' --` and any password, and see
[Module 1 §1.7](docs/01-the-vulnerable-app.md#17--lab-break-it-yourself) for the
rest of the exploits.

---

## Tech stack

**App** — Node.js, Express, SQLite
**Pipeline** — GitHub Actions
**Security tooling** — Gitleaks, Semgrep, Trivy, OWASP ZAP
**Packaging & deploy** — Docker, Kubernetes

---

## Credit

The structure of this lab was inspired by
[LocxZ/SecureSDLC-Lab](https://github.com/LocxZ/SecureSDLC-Lab). This repo is an
independent rebuild-from-scratch with a written curriculum, deliberately planted
and documented vulnerabilities, and expanded coverage of supply-chain controls.

## License

MIT
