# Sentinel — Enterprise Cybersecurity Assessment & Security Operations Platform

A professional, offline-first security assessment platform for Windows Server,
Active Directory, LDAP, Kerberos, SMB, RDP, WinRM, ADCS, Linux/SSH, network
exposure, vulnerability management, identity security and AWS — with a
centralized **MITRE ATT&CK** mapping engine, transparent security scoring,
attack-path analysis, compliance mapping, evidence and a remediation workflow.

> This is an evolution of the original *Outil d'Audit Cyber*. The existing real
> audit engine (LDAP/SSH/AD/AWS collectors) and CLI are **preserved and
> extended** — nothing was thrown away. A new core layer, data model, MITRE
> engine, SQLite store, RBAC and a white enterprise dashboard were added on top.

---

## Quick start (fully offline, ~10 seconds)

```bash
# 1. Minimal install — the whole platform runs on just Flask + Jinja2
pip install -r requirements-core.txt          # or: pip install Flask Jinja2

# 2. (optional) load representative DEMO data so the dashboard is populated
python -m src.seed_demo

# 3. run the web dashboard
python -m src.webapp                           # http://localhost:5000
```

Default accounts are created on first run (change immediately):

| User | Password | Role |
|------|----------|------|
| `admin` | `admin` | ADMIN |
| `analyst` | `analyst` | SECURITY_ANALYST |
| `auditor` | `auditor` | AUDITOR |
| `viewer` | `viewer` | VIEWER |

To run **real** assessments against your lab/estate, install the optional
collectors (`pip install -r requirements.txt`), copy `.env.example` to `.env`,
fill in the targets, and click **Run Assessment** (or use the CLI).

---

## 1. Architecture summary

```
                    ┌──────────────────────────────────────────────┐
   Web dashboard ──▶│                                              │
   (Flask, RBAC)    │            core.engine (orchestrator)        │◀── CLI (src/main.py)
                    │                                              │
                    └───┬───────────────┬───────────────┬─────────┘
                        │               │               │
              collectors (real)   normalize + MITRE   scoring / compliance
                        │           (config-driven)     attack-paths
        ┌───────────────┼───────────────┐               │
   auditors/*      core/collectors/   (optional AWS)     ▼
   (ldap3/paramiko)  network_exposure                core.store (SQLite,
                     (stdlib sockets)                 optional DynamoDB)
```

* **`src/core/`** — framework-agnostic engine (no Flask dependency):
  `models.py` (Finding/Asset/Evidence/Remediation/AuditRun), `registry.py`
  (module catalogue + nav + finding classification), `mitre.py` (ATT&CK engine),
  `scoring.py` (transparent score), `compliance.py`, `attack_paths.py`,
  `normalize.py`, `engine.py` (orchestrator), `store.py` (SQLite + optional
  DynamoDB), `reporting.py`, `collectors/network_exposure.py` (real scanner).
* **`src/auditors/`** — the original LDAP/SSH/AD/Kerberos/ACL/Potato/AWS
  collectors, kept intact and wrapped by the engine.
* **`src/webapp/`** — Flask app factory, blueprints (`auth`, `ui`), RBAC/CSRF,
  server-side SVG charts, offline templates + bundled CSS/JS.
* **`src/data/`** — `mitre_attack.json`, `mitre_mappings.json`, `compliance.json`.

Design principles: **offline-first** (no CDN, no external fonts/JS, SVG charts),
**AWS optional** (lazy imports, never blocks startup), and **no fabricated
findings** (unavailable collectors and planned modules are shown honestly).

## 2. Modified files

| File | Change |
|------|--------|
| `src/webapp/__init__.py` | Replaced with an app factory (`create_app`) mounting the new blueprints, RBAC bootstrap, context/filters. |
| `src/webapp/__main__.py` | Runs the new app (`python -m src.webapp`). |
| `src/webapp/winrm_exec.py` | `import winrm` made lazy so the app starts without pywinrm. |
| `src/utils/dynamodb.py` | Made fully optional/lazy — no boto3 at import, no-op unless `DYNAMODB_ENABLED`. |
| `src/utils/cloudwatch.py` | boto3 import made lazy; no-op unless `CLOUDWATCH_ENABLED`. |
| `src/main.py` | Rewritten as a subcommand CLI on the shared engine (legacy flags still work). Original saved as `src/main_legacy.py`. |
| `requirements.txt` / `.env.example` | Reorganised to mark the core vs. optional split. |
| `README.md` | This document. |

Legacy templates/routes (`routes.py`, `templates/details.html`, etc.) are left
in place unused for reference; the new UI supersedes them.

## 3. New files

```
src/core/__init__.py
src/core/models.py               src/core/registry.py       src/core/mitre.py
src/core/scoring.py              src/core/compliance.py     src/core/normalize.py
src/core/attack_paths.py         src/core/engine.py         src/core/store.py
src/core/reporting.py            src/core/collectors/network_exposure.py
src/data/mitre_attack.json       src/data/mitre_mappings.json
src/data/compliance.json
src/webapp/auth.py               src/webapp/routes_ui.py    src/webapp/remediation.py
src/webapp/svg.py                src/webapp/icons.py        src/webapp/registry_ctx.py
src/webapp/static/css/app.css    src/webapp/static/js/app.js
src/webapp/templates/*.html      (base, login, dashboard, findings, finding_detail,
                                  assets, module, network, attack_surface, mitre,
                                  mitre_technique, attack_paths, evidence, remediation,
                                  compliance, reports, history, history_detail,
                                  assessment, automation, settings, audit_running,
                                  report, error)
src/seed_demo.py                 requirements-core.txt
```

## 4. New modules implemented

* **58 catalogued modules** across Windows/AD, Identity, LDAP, Kerberos, SMB,
  RDP, WinRM, ADCS, Linux, Network, Vulnerability Management and Cloud
  (`src/core/registry.py`). Each has a data model, MITRE mapping, compliance
  mapping and a UI page. **30 have live collectors today** — the AD/LDAP/Kerberos/Privilege/ACL/
  Windows/SSH/AWS auditors, the **Network Exposure Scanner**, and the new
  **ADCS (ESC1-ESC3)** and **AD Policy/DC** LDAP collectors; the rest are `PLANNED` and show an honest empty
  state instead of fabricated results.
* **New real collector:** `network_exposure.py` — a dependency-free concurrent
  TCP connect scanner that produces genuine findings (open ports, exposed
  RDP/WinRM/SSH/SMB) and works offline against any reachable target.

## 5. MITRE ATT&CK integration details

* Curated ATT&CK catalogue of **14 tactics / 67 techniques** relevant to the
  findings this tool produces (`src/data/mitre_attack.json`).
* A **centralized, config-driven mapping engine** (`src/core/mitre.py` +
  `src/data/mitre_mappings.json`): findings resolve to techniques by exact
  *signature* match and by keyword patterns, each with a **confidence** and a
  **rationale**. New mappings are added by editing the JSON — no module code
  changes. OK/informational findings are never mapped, and techniques are only
  assigned where the finding technically supports the relationship.
* Every finding carries `MitreRef`s (technique id/name, tactic, sub-technique,
  confidence, source, reference URL, rationale). The **MITRE page** renders a
  tactic-column matrix with observed techniques highlighted by severity, plus a
  drill-down per technique (related findings, affected assets).

## 6. Database changes

* New **SQLite** store (`src/core/store.py`, `data/platform.db`, created
  automatically) with tables: `users`, `audits`, `findings`, `assets`,
  `audit_logs`, `exceptions`. Findings are stored as indexed rows + a JSON blob.
* **DynamoDB** remains an *optional* backend (off by default); the original
  `save_audit` still works when `DYNAMODB_ENABLED=true` with credentials.
* No existing data is destroyed — the legacy `outputs/` and `mes_*` folders are
  untouched.

## 7. API changes

New routes (blueprint `ui`, all require auth): `/` `/assessment` `/assets`
`/module/<key>` `/network` `/attack-surface` `/mitre` `/mitre/<tid>`
`/attack-paths` `/findings` `/finding/<id>` `/evidence` `/remediation`
`/compliance` `/reports` `/report/<audit_id>.<fmt>` `/history` `/history/<id>`
`/automation` `/settings`. Actions: `POST /run-audit` (bg) + `/audit/status/<t>`,
`POST /finding/<id>/status`, `POST /remediation/execute`. Auth: `/login`
`/logout`. All state-changing POSTs are CSRF-protected and RBAC-gated.

## 8. How to run the project

```bash
pip install -r requirements-core.txt      # core, offline
python -m src.seed_demo                    # optional demo data
python -m src.webapp                       # dashboard on :5000
# full collectors:  pip install -r requirements.txt  &&  cp .env.example .env
```

## 9. How to run an audit

* **Web:** click **Run Assessment**, choose a target and modules; watch the
  live pipeline; results land on the dashboard.
* **CLI (shares the same engine):**
  ```bash
  python src/main.py audit --all --target 10.0.0.10
  python src/main.py audit --module network --module ad
  python src/main.py findings --severity CRITICAL
  python src/main.py mitre
  python src/main.py report --format both
  python src/main.py remediate --finding FND-xxxx          # preview
  # legacy form still works:
  python src/main.py --all --report both
  ```

## 10. How to test the Windows vulnerable lab

1. Stand up a Windows Server DC (a deliberately-weak AD lab such as *GOAD* or
   *DetectionLab* works well) and, if testing SSH/WinRM checks, enable OpenSSH
   Server / WinRM on it.
2. `pip install -r requirements.txt`, copy `.env.example` → `.env`, set
   `LDAP_HOST`/`AD_*`/`SSH_*`/`WINRM_*` to the DC.
3. Run `python src/main.py audit --all --target <DC_IP>` **or** use the web
   **Run Assessment** dialog. The **Network Exposure Scanner** needs no
   credentials and will immediately report reachable RDP/WinRM/SMB/LDAP.
4. Inspect findings, MITRE matrix, attack paths and the remediation center;
   export a report from **Reports**.

*No lab handy?* `python -m src.seed_demo` loads a representative, clearly
**DEMO-labelled** dataset so every screen is populated for evaluation.

## 11. Remaining limitations

* 28 of the 58 modules are catalogued with full data model / MITRE / compliance
  / UI but do **not yet have a live collector** (marked `PLANNED`). They never
  fabricate data.
* Deeper Windows checks (firewall, Defender, event logging, scheduled tasks,
  ADCS/ESC templates, SMB signing, password policy) require an agent or
  WinRM/PowerShell collector that is scaffolded but not implemented.
* PDF export needs the optional `weasyprint`; HTML/CSV/JSON always work.
* Remediation execution requires WinRM/SSH configured; only allow-listed,
  idempotent commands run, and only for ADMIN after confirmation.
* The AI advisory (Gemini) and SNS/CloudWatch/DynamoDB are optional and off by
  default.

## 12. Recommended next development steps

1. Build a **WinRM/PowerShell collector** to light up the planned Windows/ADCS
   modules (firewall, Defender, event logging, SMB/LDAP signing, ADCS ESC).
2. Add a **CVE feed** to Vulnerability Management (map versions → CVE/CVSS).
3. Add per-asset **historical diffing** and finding lifecycle (first/last seen
   already stored) with trend charts per asset.
4. Add scheduled assessments in-app and richer notification routing.
5. Package as a container image and add automated tests around collectors.

---

### Security notes

Authentication + RBAC (ADMIN / SECURITY_ANALYST / AUDITOR / VIEWER), CSRF on all
POSTs, PBKDF2 password hashing, an immutable-style audit log, allow-listed
remediation, no secrets in logs, and no arbitrary command execution from web
requests. Compliance mappings are **assistive only** and do not assert formal
certification.
