"""
Persistence layer (offline-first).

Primary backend is SQLite (Python standard library) so the platform runs fully
offline with durable history. AWS DynamoDB remains an *optional* backend for
teams that want it — it is only touched when explicitly enabled and never
blocks startup.

Entities: users, assets, audits, findings, evidence, remediations,
audit_logs, security_exceptions. Findings/evidence are stored as JSON blobs
inside the row plus indexed scalar columns for fast filtering.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from .models import (Asset, AuditRun, Evidence, Finding, FindingStatus,
                     Severity, utcnow_iso)

_DEFAULT_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "platform.db"
)


def _pbkdf2(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()


class Store:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("PLATFORM_DB", _DEFAULT_DB)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    # -- connection (thread-local) ----------------------------------------- #
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        c = self._conn()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                username TEXT PRIMARY KEY, role TEXT NOT NULL,
                salt TEXT NOT NULL, pwd_hash TEXT NOT NULL,
                created_at TEXT, last_login TEXT
            );
            CREATE TABLE IF NOT EXISTS audits(
                audit_id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT,
                target TEXT, status TEXT, modules_used TEXT, summary TEXT,
                security_score INTEGER, demo INTEGER DEFAULT 0, triggered_by TEXT
            );
            CREATE TABLE IF NOT EXISTS findings(
                id TEXT, audit_id TEXT, title TEXT, severity TEXT, category TEXT,
                module TEXT, asset TEXT, asset_ip TEXT, status TEXT, signature TEXT,
                data TEXT, first_seen TEXT, last_seen TEXT,
                PRIMARY KEY(id, audit_id)
            );
            CREATE INDEX IF NOT EXISTS idx_find_audit ON findings(audit_id);
            CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_find_mod ON findings(module);
            CREATE TABLE IF NOT EXISTS assets(
                id TEXT PRIMARY KEY, hostname TEXT, ip TEXT, data TEXT,
                last_audit TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT,
                action TEXT, detail TEXT, ip TEXT
            );
            CREATE TABLE IF NOT EXISTS exceptions(
                finding_id TEXT PRIMARY KEY, reason TEXT, owner TEXT,
                created_at TEXT, expires_at TEXT
            );
            """
        )
        c.commit()

    # -- users / auth ------------------------------------------------------ #
    def create_user(self, username: str, password: str, role: str) -> None:
        salt = os.urandom(12).hex()
        c = self._conn()
        c.execute(
            "INSERT OR REPLACE INTO users(username, role, salt, pwd_hash, created_at)"
            " VALUES(?,?,?,?,?)",
            (username, role, salt, _pbkdf2(password, salt), utcnow_iso()),
        )
        c.commit()

    def verify_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        row = self._conn().execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        if not row:
            return None
        if _pbkdf2(password, row["salt"]) != row["pwd_hash"]:
            return None
        self._conn().execute(
            "UPDATE users SET last_login=? WHERE username=?", (utcnow_iso(), username)
        )
        self._conn().commit()
        return {"username": row["username"], "role": row["role"]}

    def list_users(self) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT username, role, created_at, last_login FROM users ORDER BY username"
        ).fetchall()
        return [dict(r) for r in rows]

    def user_count(self) -> int:
        return self._conn().execute("SELECT COUNT(*) c FROM users").fetchone()["c"]

    # -- audits & findings ------------------------------------------------- #
    def save_audit(self, run: AuditRun, findings: List[Finding],
                   assets: Optional[List[Asset]] = None) -> None:
        c = self._conn()
        c.execute(
            "INSERT OR REPLACE INTO audits(audit_id, started_at, finished_at, target,"
            " status, modules_used, summary, security_score, demo, triggered_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (run.audit_id, run.started_at, run.finished_at, run.target, run.status,
             json.dumps(run.modules_used), json.dumps(run.summary),
             run.security_score, 1 if run.demo else 0, run.triggered_by),
        )
        for f in findings:
            f.audit_id = run.audit_id
            c.execute(
                "INSERT OR REPLACE INTO findings(id, audit_id, title, severity, category,"
                " module, asset, asset_ip, status, signature, data, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f.id, run.audit_id, f.title, f.severity, f.category, f.module,
                 f.asset, f.asset_ip, f.status, f.signature,
                 json.dumps(f.to_dict()), f.first_seen, f.last_seen),
            )
        for a in (assets or []):
            c.execute(
                "INSERT OR REPLACE INTO assets(id, hostname, ip, data, last_audit)"
                " VALUES(?,?,?,?,?)",
                (a.id, a.hostname, a.ip, json.dumps(a.to_dict()), run.finished_at or run.started_at),
            )
        c.commit()

    def latest_audit_id(self) -> Optional[str]:
        row = self._conn().execute(
            "SELECT audit_id FROM audits ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return row["audit_id"] if row else None

    def get_audit(self, audit_id: str) -> Optional[AuditRun]:
        row = self._conn().execute(
            "SELECT * FROM audits WHERE audit_id=?", (audit_id,)
        ).fetchone()
        if not row:
            return None
        return AuditRun(
            audit_id=row["audit_id"], started_at=row["started_at"],
            finished_at=row["finished_at"], target=row["target"], status=row["status"],
            modules_used=json.loads(row["modules_used"] or "[]"),
            summary=json.loads(row["summary"] or "{}"),
            security_score=row["security_score"] or 0, demo=bool(row["demo"]),
            triggered_by=row["triggered_by"] or "system",
        )

    def list_audits(self, limit: int = 100) -> List[AuditRun]:
        rows = self._conn().execute(
            "SELECT * FROM audits ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for row in rows:
            out.append(AuditRun(
                audit_id=row["audit_id"], started_at=row["started_at"],
                finished_at=row["finished_at"], target=row["target"], status=row["status"],
                modules_used=json.loads(row["modules_used"] or "[]"),
                summary=json.loads(row["summary"] or "{}"),
                security_score=row["security_score"] or 0, demo=bool(row["demo"]),
                triggered_by=row["triggered_by"] or "system"))
        return out

    def get_findings(self, audit_id: str) -> List[Finding]:
        rows = self._conn().execute(
            "SELECT data FROM findings WHERE audit_id=?", (audit_id,)
        ).fetchall()
        return [Finding.from_dict(json.loads(r["data"])) for r in rows]

    def get_finding(self, audit_id: str, finding_id: str) -> Optional[Finding]:
        row = self._conn().execute(
            "SELECT data FROM findings WHERE audit_id=? AND id=?", (audit_id, finding_id)
        ).fetchone()
        return Finding.from_dict(json.loads(row["data"])) if row else None

    def update_finding_status(self, audit_id: str, finding_id: str, status: str) -> bool:
        f = self.get_finding(audit_id, finding_id)
        if not f:
            return False
        f.status = FindingStatus(status).value
        c = self._conn()
        c.execute(
            "UPDATE findings SET status=?, data=? WHERE audit_id=? AND id=?",
            (f.status, json.dumps(f.to_dict()), audit_id, finding_id),
        )
        c.commit()
        return True

    def get_assets(self, audit_id: Optional[str] = None) -> List[Asset]:
        rows = self._conn().execute(
            "SELECT data FROM assets ORDER BY last_audit DESC"
        ).fetchall()
        return [Asset.from_dict(json.loads(r["data"])) for r in rows]

    # -- audit log --------------------------------------------------------- #
    def log(self, actor: str, action: str, detail: str = "", ip: str = "") -> None:
        c = self._conn()
        c.execute(
            "INSERT INTO audit_logs(ts, actor, action, detail, ip) VALUES(?,?,?,?,?)",
            (utcnow_iso(), actor, action, detail, ip),
        )
        c.commit()

    def get_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # -- exceptions -------------------------------------------------------- #
    def add_exception(self, finding_id: str, reason: str, owner: str,
                      expires_at: str = "") -> None:
        c = self._conn()
        c.execute(
            "INSERT OR REPLACE INTO exceptions(finding_id, reason, owner, created_at, expires_at)"
            " VALUES(?,?,?,?,?)", (finding_id, reason, owner, utcnow_iso(), expires_at))
        c.commit()

    def get_exceptions(self) -> List[Dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT * FROM exceptions ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


# module-level singleton
_STORE: Optional[Store] = None


def get_store() -> Store:
    global _STORE
    if _STORE is None:
        _STORE = Store()
    return _STORE
