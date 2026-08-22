# Module 0 — Foundations

> **Goal of this module:** understand what a "Secure SDLC" actually *is*, why
> the industry moved to it, what each category of tool does, and how to set up
> your machine. No code yet. Read this once, then come back to it whenever a
> later module makes you ask "wait, why are we doing this here?"

---

## 0.1 — What is an SDLC?

**SDLC** = Software Development Life Cycle. It is just a name for the sequence
of things that happen between "someone has an idea" and "the software is running
and being maintained." Almost every team, however chaotic, goes through these
phases:

| Phase | What happens | Typical artifacts |
|---|---|---|
| **Plan / Requirements** | Decide what to build and for whom | tickets, user stories |
| **Design / Architecture** | Decide how it's structured | diagrams, ADRs |
| **Implement** | Write the code | source files, commits |
| **Build** | Turn source into a runnable thing | binaries, container images |
| **Test** | Verify it works | test suites, CI runs |
| **Deploy / Release** | Put it where users can reach it | manifests, pipelines |
| **Operate / Monitor** | Keep it running, watch it | logs, metrics, alerts |

That's it. Nothing security-specific yet.

---

## 0.2 — So what makes it a *Secure* SDLC?

A Secure SDLC is the same lifecycle with a security activity deliberately
attached to **each** phase — and, critically, with those activities **automated
and enforced** rather than left to good intentions.

The core claim is simple and worth stating precisely:

> For every class of security defect you care about, you should be able to name
> the specific gate that catches it, and the specific phase it catches it in.

If you can't name the gate, you don't have coverage. You have hope.

Here is the mapping this lab builds, end to end:

| SDLC phase | Security activity | Tool we use | Module |
|---|---|---|---|
| Design | Threat modelling (STRIDE) | pen + paper, diagram | 2 |
| Implement | Secret scanning | **Gitleaks** | 3 |
| Implement | Static analysis (SAST) | **Semgrep** | 4 |
| Build | Dependency analysis (SCA) | **Trivy**, `npm audit` | 5 |
| Implement | Secure coding fixes | bcrypt, Helmet, RBAC | 6 |
| Build | Container image scanning | **Trivy** | 7 |
| Deploy | IaC / config scanning | **Trivy config**, Checkov | 8 |
| Test | Dynamic analysis (DAST) | **OWASP ZAP** | 9 |
| Deploy | Runtime hardening | Kubernetes `securityContext` | 10 |
| All | Gates & governance | branch protection, policy | 11 |
| Build | Supply chain integrity | SBOM, cosign, SLSA | 12 |

---

## 0.3 — "Shift left" — what it means and where it's overused

Picture the lifecycle as a line running left (planning) to right (production).
**Shifting left** means moving a security check earlier along that line.

The argument is economic. A flaw found while you're typing costs a minute. The
same flaw found in production costs an incident bridge, a patch, a customer
notification, and possibly a regulator. The exact multipliers people quote
(10x, 100x) come from studies old enough to vote and you should treat them as
directional, not measured — but the direction is real and uncontroversial.

**Where "shift left" is oversold:** some defects genuinely cannot be found early.
You cannot find a misconfigured load balancer by reading source code. You cannot
find broken access control with a linter, because a linter doesn't know that
alice shouldn't see the admin page. Left-shifting is a strategy, not a religion —
which is why this lab also does DAST (Module 9) and runtime hardening
(Module 10). The modern framing is "shift left **and** extend right."

---

## 0.4 — The tool categories, explained properly

This is the section most people skim and then stay confused for a year. Don't.

### Secret scanning
**Question it answers:** "Did someone commit a credential?"
**How it works:** regex + entropy analysis over files *and over git history*.
High-entropy strings (`sk_live_4eC39...`) and known provider formats (AWS keys,
GitHub tokens) get flagged.
**Blind spot:** it finds secrets that *look* like secrets. A password that looks
like a normal word sails right past.
**Key insight:** git is append-only. Deleting a secret in a later commit does
not remove it from history. The only real fix is **rotation** — invalidate the
value at its source.

### SAST — Static Application Security Testing
**Question it answers:** "Are there dangerous patterns in the source code?"
**How it works:** parses your code into an **AST** (Abstract Syntax Tree — a tree
structure representing the code's grammar, not its text), then matches rules
against that tree. Better tools add **data-flow / taint analysis**: they track a
value from a *source* (user input) to a *sink* (a database query, an HTML
response) and flag the path if no *sanitizer* sits between them.
**Strength:** runs without executing anything; finds bugs in code paths tests
never hit; fast enough for every commit.
**Blind spot:** no runtime context. It sees `db.get(query)` and knows `query`
came from `req.body`; it does *not* know whether your business rules permit
alice to reach that route at all. Famous for false positives.

### SCA — Software Composition Analysis
**Question it answers:** "Do the libraries I depend on have known vulnerabilities?"
**How it works:** reads your lockfile (`package-lock.json`), resolves the full
dependency tree, and matches each package@version against vulnerability
databases (NVD, GitHub Advisory Database, OSV).
**Why it matters more than SAST for most teams:** you wrote 500 lines. You
shipped 195 packages. Most of your attack surface is other people's code.
**Key concepts:** *direct* vs *transitive* dependencies; **CVE** (the identifier),
**CVSS** (the severity score 0–10), **EPSS** (the probability it'll actually be
exploited), and **reachability** (does your code even call the vulnerable
function?). A "critical" CVE in a code path you never execute is often less
urgent than a "medium" one you call on every request.

### DAST — Dynamic Application Security Testing
**Question it answers:** "What can an attacker do to the app while it's running?"
**How it works:** it's a robot attacker. It spiders the running app to discover
URLs, then fires crafted requests at them and studies the responses. Sees the
app exactly as the outside world does — no source code needed.
**Strength:** zero false positives on things like missing headers (it either got
the header or it didn't); finds config and deployment issues SAST structurally
cannot.
**Blind spot:** it can only test what it can reach. Anything behind a login it
can't perform, or a form it can't fill, is invisible. Slow — minutes to hours.

### IaC / config scanning
**Question it answers:** "Is the infrastructure definition insecure?"
**How it works:** parses Dockerfiles, Kubernetes YAML, Terraform, etc. and checks
them against policy rules — running as root, no resource limits, privileged
containers, public S3 buckets.
**Why it's a big deal:** most cloud breaches are misconfigurations, not code
bugs. And because infrastructure is now code, it can be reviewed and scanned
like code.

### The one nobody automates: threat modelling
**Question it answers:** "What could go wrong with this *design*?"
No tool does this for you. It's a structured conversation, done in Module 2. It
is the only activity that catches design-level flaws — like the broken access
control we plant in Module 1, which **no scanner in this lab will find**.

---

## 0.5 — The mental model to carry through the whole course

```
        ┌──────────────────────────────────────────────────────────┐
        │  Every security control is a FILTER on a PIPELINE.        │
        │  Each filter has:                                         │
        │    • a class of defect it catches                         │
        │    • a phase where it runs                                │
        │    • a blind spot                                         │
        │    • a decision: warn, or BLOCK the merge?                │
        └──────────────────────────────────────────────────────────┘
```

That last point is where most "DevSecOps programmes" quietly fail. A scanner
that reports findings nobody blocks on is a dashboard, not a control. Module 11
is entirely about turning findings into gates — and about the equally important
question of how you *accept* a risk on purpose, with a name and a date attached.

---

## 0.6 — Vocabulary you'll see constantly

| Term | Meaning |
|---|---|
| **CWE** | Common Weakness Enumeration — a catalogue of *bug types*. "CWE-89: SQL Injection." Describes a class. |
| **CVE** | Common Vulnerabilities and Exposures — a specific *instance* in a specific product. "CVE-2024-1234 in tar 6.2.1." |
| **CVSS** | A 0–10 severity score for a CVE. Base score ignores your context. |
| **EPSS** | Probability a CVE will be exploited in the wild in 30 days. Often more useful than CVSS for prioritising. |
| **OWASP Top 10** | The industry's consensus list of the ten most critical web app risk categories. A01 = Broken Access Control, A03 = Injection, etc. |
| **SBOM** | Software Bill of Materials — a machine-readable inventory of everything in your build. Module 12. |
| **False positive** | Tool says vulnerable; it isn't. Kills adoption if unmanaged. |
| **False negative** | Tool says fine; it isn't. Kills you. |
| **Gate** | A check that can *block* progress, as opposed to merely reporting. |
| **Shift left** | Move a check earlier in the lifecycle. |

---

## 0.7 — Environment setup

You need four things. Check each:

```bash
node --version     # need v18 or newer
npm --version      # ships with node
git --version      # any recent version
docker --version   # needed from Module 7 onward
```

**If Node is missing (macOS):**
```bash
brew install node
```

**If Docker is missing:** install Docker Desktop from docker.com. From Module 7
we build container images; until then you can skip it.

You'll also want a GitHub account (you have one: `akhil65`) because the entire
pipeline runs on **GitHub Actions**, which is free for public repositories.

---

## 0.8 — Git, in the amount you actually need

Git tracks *snapshots* of your project. Three areas to keep straight:

```
  working directory  →  staging area  →  repository (commits)
       (your files)      (git add)         (git commit)
```

```bash
git status                 # what changed?
git add src/app.js         # stage a specific file
git add .                  # stage everything (careful — this is how secrets leak)
git commit -m "message"    # snapshot the staged files
git log --oneline          # history
git push                   # send commits to GitHub
```

**Branches** let you work without touching the main line:

```bash
git checkout -b security/password-hashing   # create + switch
# ...make changes, commit...
git push -u origin security/password-hashing
```

Then you open a **Pull Request (PR)** on GitHub. A PR is where the whole secure
SDLC actually bites: it's the moment your pipeline runs, posts its findings, and
either lets the merge through or blocks it. **This lab does every single change
on a branch, through a PR.** That is not ceremony — the gate literally cannot
exist without it.

One rule to internalise now, before Module 3:

> Never `git add .` without looking at `git status` first. That single habit
> prevents most accidental secret commits in the world.

---

## What's next

**Module 1** — we build the deliberately vulnerable application, line by line,
and then break it ourselves. Seeing the exploit work with your own hands is what
makes every later fix mean something.
