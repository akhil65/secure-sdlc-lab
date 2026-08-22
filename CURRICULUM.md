# Curriculum

Twelve modules, beginner → advanced. Each one adds a control to the pipeline and
closes at least one row on the vulnerability scoreboard.

Progress: **2 / 13 complete**

---

### ✅ Module 0 — Foundations
[`docs/00-foundations.md`](docs/00-foundations.md)

What an SDLC is; what makes it *secure*; shift-left and where it's oversold;
each tool category explained with its blind spot; CWE vs CVE vs CVSS vs EPSS;
environment setup; the amount of git you actually need.

### ✅ Module 1 — The vulnerable app
[`docs/01-the-vulnerable-app.md`](docs/01-the-vulnerable-app.md)

HTTP, sessions and cookies from zero. `package.json`, `db.js` and `app.js` line
by line. Nine planted flaws, each tagged with CWE / OWASP / catching tool.
Hands-on lab: authentication bypass via SQL injection, reflected XSS session
theft, broken access control, missing headers, and a `npm audit` that already
reports a critical CVE.

---

### ⬜ Module 2 — Threat modelling (STRIDE)
Data-flow diagrams, trust boundaries, and the STRIDE walkthrough. Prove that a
30-minute structured conversation predicts most of the nine flaws — including
the one no scanner finds. Output: `threat-model/THREAT-MODEL.md`.

### ⬜ Module 3 — Secrets & the first pipeline
Why committed secrets are forever. `.env` and `process.env`. **Gitleaks** — regex
vs entropy detection. Your first GitHub Actions workflow, explained field by
field: triggers, runners, jobs, steps, exit codes. Pre-commit hooks. Secret
rotation as the only real remediation. *Closes flaw #3.*

### ⬜ Module 4 — SAST with Semgrep
How static analysis works: tokens → AST → pattern matching → taint tracking
(source, sink, sanitizer). Writing a custom Semgrep rule. Fix SQL injection with
parameterized queries and passwords with **bcrypt** (salting, work factor, why
not SHA-256). Triage: true positive, false positive, and how to suppress
honestly. *Closes flaws #1 and #2.*

### ⬜ Module 5 — SCA and dependency risk
Direct vs transitive dependencies. Lockfiles. NVD / OSV / GitHub Advisory. CVSS
vs EPSS vs reachability — how to prioritise without drowning. `npm audit`,
**Trivy fs**, Dependabot. Pinning strategies and the cost of upgrading.

### ⬜ Module 6 — Secure coding: the remaining app flaws
Session regeneration and fixation. Cookie flags (`httpOnly`, `secure`,
`sameSite`). RBAC middleware and why authorization must be enforced server-side,
per-request. Contextual output encoding for XSS. **Helmet** and what each header
actually does. Safe error handling. *Closes flaws #4–#9.*

### ⬜ Module 7 — Docker and image scanning
Images, layers, and the union filesystem. Why `USER root` is the default and why
that's bad. Multi-stage builds. `.dockerignore` and how secrets leak into layers.
**Trivy image** — OS packages vs language packages. Distroless and minimal bases.

### ⬜ Module 8 — IaC and config scanning
Infrastructure as code as an attack surface. Dockerfile and Kubernetes manifest
scanning with **Trivy config**. Policy-as-code with Rego/OPA basics. Why most
cloud breaches are misconfiguration, not code.

### ⬜ Module 9 — DAST with OWASP ZAP
Spidering, passive vs active scanning, baseline vs full scan. Running ZAP against
the app inside CI with service containers. Authenticated scanning. Tuning
`.zap/rules.tsv` and the discipline of documenting an accepted finding rather
than silencing it.

### ⬜ Module 10 — Kubernetes hardening
Pods, deployments, services. `securityContext`: `runAsNonRoot`,
`readOnlyRootFilesystem`, dropped capabilities, seccomp profiles. Resource limits
as a security control. Network policies. Admission control and Pod Security
Standards.

### ⬜ Module 11 — Gates, governance and metrics
Turning findings into gates: required status checks, branch protection, CODEOWNERS.
Severity thresholds and exit codes. Risk acceptance with an owner and an expiry
date. Metrics that aren't theatre: mean time to remediate, escape rate, coverage
— and what data source each one actually comes from.

### ⬜ Module 12 — Supply chain integrity
SBOM generation (CycloneDX / SPDX) and what to do with one. Artifact signing with
**cosign** / Sigstore. Provenance and SLSA levels. Dependency confusion and
typosquatting. Securing the pipeline itself: pinning actions by SHA, `permissions:`
scoping, and why `pull_request_target` is a footgun.
