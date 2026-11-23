"""SQLite 数据访问层。UI 与 API 不直接写 SQL。"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init(self) -> None:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with self._lock:
            conn = self.connect()
            try:
                conn.executescript(schema)
                self._migrate(conn)
                conn.commit()
            finally:
                conn.close()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        # 已有库的 CREATE IF NOT EXISTS 不会补列，这里按实际表结构增量升级。
        user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        if "is_active" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        if "updated_at" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN updated_at TEXT")
        self._add_columns(conn, "projects", {
            "whitelist_cidrs_json": "TEXT NOT NULL DEFAULT '[]'",
            "forbidden_cidrs_json": "TEXT NOT NULL DEFAULT '[\"192.168.1.250/32\"]'",
            "max_concurrency": "INTEGER NOT NULL DEFAULT 2",
            "nuclei_rate_limit": "INTEGER NOT NULL DEFAULT 50",
            "status": "TEXT NOT NULL DEFAULT 'active'",
            "started_at": "TEXT",
            "archived_at": "TEXT",
            "updated_at": "TEXT",
            "enabled_extensions_json": "TEXT NOT NULL DEFAULT '[\"GENERAL\"]'",
        })
        conn.execute(
            """UPDATE projects SET status='active'
               WHERE status IS NULL OR status=''"""
        )
        conn.execute(
            """UPDATE projects SET started_at=created_at
               WHERE status='active' AND (started_at IS NULL OR started_at='')"""
        )
        self._add_columns(conn, "normalized_evidences", {
            "dojo_finding_id": "TEXT",
            "dojo_status": "TEXT",
        })
        self._add_columns(conn, "clause_assessments", {
            "owner_department": "TEXT NOT NULL DEFAULT ''",
            "compensation_status": "TEXT NOT NULL DEFAULT 'none'",
            "compensation_note": "TEXT NOT NULL DEFAULT ''",
        })
        conn.execute(
            """CREATE TABLE IF NOT EXISTS job_delivery (
                job_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                dojo_product_id TEXT,
                dojo_product_name TEXT,
                dojo_engagement_id TEXT,
                dojo_url TEXT,
                ciso_assessment_id TEXT,
                ciso_url TEXT,
                leak_passed INTEGER,
                updated_at TEXT
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS system_prompts (
                prompt_key TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_by TEXT NOT NULL DEFAULT 'system',
                updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS report_narratives (
                job_id TEXT PRIMARY KEY,
                prompt_key TEXT NOT NULL,
                prompt_version INTEGER NOT NULL DEFAULT 1,
                model_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'fallback',
                sections_json TEXT NOT NULL,
                generated_at TEXT NOT NULL
            )"""
        )
        self._add_columns(conn, "assets", {
            "object_type": "TEXT NOT NULL DEFAULT 'host_os'",
            "ssh_port": "INTEGER NOT NULL DEFAULT 22",
            "ssh_user": "TEXT NOT NULL DEFAULT ''",
            "ssh_auth_mode": "TEXT NOT NULL DEFAULT 'env_ref'",
            "ssh_secret_env": "TEXT NOT NULL DEFAULT ''",
            "ssh_key_env": "TEXT NOT NULL DEFAULT ''",
            "ssh_secret_encrypted": "TEXT NOT NULL DEFAULT ''",
            "is_enabled": "INTEGER NOT NULL DEFAULT 1",
            "notes": "TEXT NOT NULL DEFAULT ''",
            "updated_at": "TEXT",
        })

    def _add_columns(self, conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def _one(self, sql: str, params: tuple = ()) -> dict | None:
        conn = self.connect()
        try:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _all(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = self.connect()
        try:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def _write(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            conn = self.connect()
            try:
                conn.execute(sql, params)
                conn.commit()
            finally:
                conn.close()

    def create_user(self, email: str, password_hash: str, display_name: str, role: str) -> dict:
        user = {
            "user_id": new_id("usr"),
            "email": email.lower().strip(),
            "password_hash": password_hash,
            "display_name": display_name,
            "role": role,
            "theme_preference": "classic_red",
            "created_at": utcnow(),
        }
        self._write(
            """INSERT INTO users(user_id,email,password_hash,display_name,role,theme_preference,is_active,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                user["user_id"],
                user["email"],
                user["password_hash"],
                user["display_name"],
                user["role"],
                user["theme_preference"],
                1,
                user["created_at"],
                user["created_at"],
            ),
        )
        return self.get_user_by_email(user["email"])  # type: ignore[return-value]

    def get_user_by_email(self, email: str) -> dict | None:
        return self._one("SELECT * FROM users WHERE email=?", (email.lower().strip(),))

    def get_user(self, user_id: str) -> dict | None:
        return self._one("SELECT * FROM users WHERE user_id=?", (user_id,))

    def list_users(self) -> list[dict]:
        rows = self._all(
            "SELECT user_id,email,display_name,role,theme_preference,is_active,created_at,updated_at FROM users ORDER BY created_at"
        )
        for row in rows:
            row["is_active"] = bool(row.get("is_active", 1))
        return rows

    def update_user(self, user_id: str, display_name: str, role: str, is_active: bool) -> dict | None:
        self._write(
            "UPDATE users SET display_name=?, role=?, is_active=?, updated_at=? WHERE user_id=?",
            (display_name, role, 1 if is_active else 0, utcnow(), user_id),
        )
        user = self.get_user(user_id)
        if user:
            user.pop("password_hash", None)
            user["is_active"] = bool(user.get("is_active", 1))
        return user

    def set_password(self, user_id: str, password_hash: str) -> None:
        self._write("UPDATE users SET password_hash=?, updated_at=? WHERE user_id=?", (password_hash, utcnow(), user_id))

    def delete_user(self, user_id: str) -> None:
        self._write("DELETE FROM users WHERE user_id=?", (user_id,))

    def count_active_admins(self, exclude_user_id: str = "") -> int:
        row = self._one(
            "SELECT COUNT(*) AS c FROM users WHERE role='admin' AND is_active=1 AND user_id<>?",
            (exclude_user_id,),
        )
        return int(row["c"]) if row else 0

    def promote_bootstrap_admin(self, email: str) -> None:
        self._write(
            "UPDATE users SET role='admin', is_active=1, updated_at=? WHERE email=?",
            (utcnow(), email.lower().strip()),
        )

    def update_theme(self, user_id: str, theme: str) -> None:
        self._write("UPDATE users SET theme_preference=? WHERE user_id=?", (theme, user_id))

    def user_count(self) -> int:
        row = self._one("SELECT COUNT(*) AS c FROM users")
        return int(row["c"]) if row else 0

    def upsert_project(self, project: dict) -> None:
        """配置文件只在项目或资产还是空的时候写入。之后以数据库里的资产和扫描模式为准。"""
        with self._lock:
            conn = self.connect()
            try:
                existing = conn.execute(
                    "SELECT project_id, whitelist_cidrs_json FROM projects WHERE project_id=?",
                    (project["project_id"],),
                ).fetchone()
                if existing is None:
                    whitelist = project.get("whitelist_cidrs") or []
                    forbidden = project.get("forbidden_cidrs") or ["192.168.1.250/32"]
                    if "192.168.1.250/32" not in forbidden:
                        forbidden.append("192.168.1.250/32")
                    conn.execute(
                        """INSERT INTO projects(project_id,name,summary,env_tier,llm_profile,stage_label,classification,
                           whitelist_cidrs_json,forbidden_cidrs_json,max_concurrency,nuclei_rate_limit,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            project["project_id"],
                            project["name"],
                            project["summary"],
                            project["env_tier"],
                            project["llm_profile"],
                            project["stage_label"],
                            project["classification"],
                            json.dumps(whitelist, ensure_ascii=False),
                            json.dumps(forbidden, ensure_ascii=False),
                            int(project.get("max_concurrency") or 2),
                            int(project.get("nuclei_rate_limit") or 50),
                            project.get("created_at") or utcnow(),
                        ),
                    )
                else:
                    current = json.loads(existing["whitelist_cidrs_json"] or "[]")
                    if not current and project.get("whitelist_cidrs"):
                        forbidden = project.get("forbidden_cidrs") or ["192.168.1.250/32"]
                        if "192.168.1.250/32" not in forbidden:
                            forbidden.append("192.168.1.250/32")
                        conn.execute(
                            """UPDATE projects SET name=?, summary=?, stage_label=?, classification=?,
                               whitelist_cidrs_json=?, forbidden_cidrs_json=? WHERE project_id=?""",
                            (
                                project["name"],
                                project["summary"],
                                project["stage_label"],
                                project["classification"],
                                json.dumps(project["whitelist_cidrs"], ensure_ascii=False),
                                json.dumps(forbidden, ensure_ascii=False),
                                project["project_id"],
                            ),
                        )
                count = conn.execute(
                    "SELECT COUNT(*) AS c FROM assets WHERE project_id=?",
                    (project["project_id"],),
                ).fetchone()["c"]
                if count == 0:
                    for asset in project.get("assets", []):
                        self._insert_asset(conn, project["project_id"], asset)
                else:
                    for asset in project.get("assets", []):
                        self._backfill_ssh(conn, asset)
                conn.commit()
            finally:
                conn.close()

    def _insert_asset(self, conn: sqlite3.Connection, project_id: str, asset: dict) -> None:
        ssh = asset.get("ssh_config") or {}
        now = utcnow()
        conn.execute(
            """INSERT INTO assets(asset_id,project_id,host,security_zone,os_type,scan_mode,scanners_json,
               ssh_port,ssh_user,ssh_auth_mode,ssh_secret_env,ssh_key_env,ssh_secret_encrypted,is_enabled,notes,updated_at,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                asset["asset_id"],
                project_id,
                asset["host"],
                asset["security_zone"],
                asset["os_type"],
                asset.get("scan_mode") or "READONLY_AUDIT",
                json.dumps(asset.get("scanners") or ["nmap", "nuclei", "trivy", "ssh_baseline", "db_mw_baseline"], ensure_ascii=False),
                int(ssh.get("port") or asset.get("ssh_port") or 22),
                asset.get("ssh_user") or "",
                asset.get("ssh_auth_mode") or "env_ref",
                ssh.get("password_env") or asset.get("ssh_secret_env") or "",
                ssh.get("key_env") or asset.get("ssh_key_env") or "",
                asset.get("ssh_secret_encrypted") or "",
                1 if asset.get("is_enabled", True) else 0,
                asset.get("notes") or "",
                now,
                now,
            ),
        )

    def _backfill_ssh(self, conn: sqlite3.Connection, asset: dict) -> None:
        ssh = asset.get("ssh_config") or {}
        if not ssh and not asset.get("ssh_user"):
            return
        row = conn.execute("SELECT ssh_user, ssh_secret_env FROM assets WHERE asset_id=?", (asset["asset_id"],)).fetchone()
        if row is None or (row["ssh_user"] or row["ssh_secret_env"]):
            return
        conn.execute(
            """UPDATE assets SET ssh_port=?, ssh_user=?, ssh_auth_mode=?, ssh_secret_env=?, ssh_key_env=?, updated_at=?
               WHERE asset_id=?""",
            (
                int(ssh.get("port") or asset.get("ssh_port") or 22),
                asset.get("ssh_user") or "",
                asset.get("ssh_auth_mode") or "env_ref",
                ssh.get("password_env") or asset.get("ssh_secret_env") or "",
                ssh.get("key_env") or asset.get("ssh_key_env") or "",
                utcnow(),
                asset["asset_id"],
            ),
        )

    def list_projects(self) -> list[dict]:
        return [self._decorate_project(row) for row in self._all("SELECT * FROM projects ORDER BY created_at")]

    def get_project(self, project_id: str) -> dict | None:
        row = self._one("SELECT * FROM projects WHERE project_id=?", (project_id,))
        return self._decorate_project(row) if row else None

    def _decorate_project(self, row: dict) -> dict:
        from core.clause_catalog import load_clauses, normalize_extensions

        row["whitelist_cidrs"] = json.loads(row.get("whitelist_cidrs_json") or "[]")
        row["forbidden_cidrs"] = json.loads(row.get("forbidden_cidrs_json") or "[]")
        if "192.168.1.250/32" not in row["forbidden_cidrs"]:
            row["forbidden_cidrs"].append("192.168.1.250/32")
        raw_exts = json.loads(row.get("enabled_extensions_json") or '["GENERAL"]')
        row["enabled_extensions"] = normalize_extensions(raw_exts)
        row["clause_count"] = len(load_clauses(row["enabled_extensions"]))
        row["max_concurrency"] = int(row.get("max_concurrency") or 2)
        row["nuclei_rate_limit"] = int(row.get("nuclei_rate_limit") or 50)
        row["status"] = row.get("status") or "active"
        return row

    def create_project(self, payload: dict) -> dict:
        from core.clause_catalog import normalize_extensions

        project_id = payload.get("project_id") or new_id("prj")
        now = utcnow()
        forbidden = list(payload.get("forbidden_cidrs") or ["192.168.1.250/32"])
        if "192.168.1.250/32" not in forbidden:
            forbidden.append("192.168.1.250/32")
        extensions = normalize_extensions(payload.get("enabled_extensions"))
        self._write(
            """INSERT INTO projects(project_id,name,summary,env_tier,llm_profile,stage_label,classification,
               whitelist_cidrs_json,forbidden_cidrs_json,enabled_extensions_json,max_concurrency,nuclei_rate_limit,status,started_at,archived_at,updated_at,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                project_id,
                payload["name"],
                payload.get("summary") or "",
                payload.get("env_tier") or "L1_TEST",
                payload.get("llm_profile") or "local_rules",
                payload.get("stage_label") or "进场前差距核查",
                payload.get("classification") or "内部",
                json.dumps(payload.get("whitelist_cidrs") or [], ensure_ascii=False),
                json.dumps(forbidden, ensure_ascii=False),
                json.dumps(extensions, ensure_ascii=False),
                int(payload.get("max_concurrency") or 2),
                int(payload.get("nuclei_rate_limit") or 50),
                "draft",
                None,
                None,
                now,
                now,
            ),
        )
        return self.get_project(project_id)  # type: ignore[return-value]

    def update_project(self, project_id: str, payload: dict) -> dict | None:
        from core.clause_catalog import normalize_extensions

        current = self.get_project(project_id)
        if not current:
            return None
        forbidden = list(current.get("forbidden_cidrs") or ["192.168.1.250/32"])
        if "192.168.1.250/32" not in forbidden:
            forbidden.append("192.168.1.250/32")
        whitelist = payload.get("whitelist_cidrs", current.get("whitelist_cidrs") or [])
        extensions = normalize_extensions(payload.get("enabled_extensions", current.get("enabled_extensions")))
        self._write(
            """UPDATE projects SET name=?, summary=?, env_tier=?, llm_profile=?, stage_label=?, classification=?,
               whitelist_cidrs_json=?, forbidden_cidrs_json=?, enabled_extensions_json=?, updated_at=? WHERE project_id=?""",
            (
                payload.get("name") or current["name"],
                payload.get("summary", current.get("summary") or ""),
                payload.get("env_tier") or current["env_tier"],
                payload.get("llm_profile") or current["llm_profile"],
                payload.get("stage_label") or current.get("stage_label") or "",
                payload.get("classification") or current.get("classification") or "",
                json.dumps(whitelist, ensure_ascii=False),
                json.dumps(forbidden, ensure_ascii=False),
                json.dumps(extensions, ensure_ascii=False),
                utcnow(),
                project_id,
            ),
        )
        return self.get_project(project_id)

    def set_project_status(self, project_id: str, status: str) -> dict | None:
        now = utcnow()
        if status == "active":
            self._write(
                """UPDATE projects SET status=?, started_at=COALESCE(started_at, ?), archived_at=NULL, updated_at=?
                   WHERE project_id=?""",
                (status, now, now, project_id),
            )
        elif status == "archived":
            self._write(
                "UPDATE projects SET status=?, archived_at=?, updated_at=? WHERE project_id=?",
                (status, now, now, project_id),
            )
        else:
            self._write(
                "UPDATE projects SET status=?, updated_at=? WHERE project_id=?",
                (status, now, project_id),
            )
        return self.get_project(project_id)

    def count_jobs(self, project_id: str) -> int:
        row = self._one("SELECT COUNT(*) AS c FROM scan_jobs WHERE project_id=?", (project_id,))
        return int(row["c"]) if row else 0

    def delete_project_if_empty(self, project_id: str) -> None:
        if self.count_jobs(project_id) > 0:
            raise ValueError("这个项目已经有扫描任务，改为归档可以保留历史结果")
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("DELETE FROM assets WHERE project_id=?", (project_id,))
                conn.execute("DELETE FROM manual_evidence WHERE project_id=?", (project_id,))
                conn.execute("DELETE FROM projects WHERE project_id=?", (project_id,))
                conn.commit()
            finally:
                conn.close()

    def count_assessments(self, job_id: str) -> int:
        row = self._one("SELECT COUNT(*) AS c FROM clause_assessments WHERE job_id=?", (job_id,))
        return int(row["c"]) if row else 0

    def list_project_cards(self) -> list[dict]:
        cards = []
        for project in self.list_projects():
            assets = self.list_assets(project["project_id"])
            latest = self.latest_job(project["project_id"])
            stats = self.dashboard(project["project_id"])
            project["asset_count"] = len(assets)
            project["enabled_asset_count"] = sum(1 for item in assets if item.get("is_enabled", True))
            project["job_count"] = self.count_jobs(project["project_id"])
            project["latest_job"] = (
                {"job_id": latest["job_id"], "status": latest["status"], "started_at": latest["started_at"]}
                if latest else None
            )
            project["coverage"] = stats["coverage"]
            cards.append(project)
        return cards

    def update_project_scope(
        self,
        project_id: str,
        env_tier: str,
        whitelist: list[str],
        max_concurrency: int,
        nuclei_rate_limit: int,
        enabled_extensions: list[str] | None = None,
    ) -> None:
        from core.clause_catalog import normalize_extensions

        forbidden = ["192.168.1.250/32"]
        if enabled_extensions is None:
            current = self.get_project(project_id) or {}
            extensions = normalize_extensions(current.get("enabled_extensions"))
        else:
            extensions = normalize_extensions(enabled_extensions)
        self._write(
            """UPDATE projects SET env_tier=?, whitelist_cidrs_json=?, forbidden_cidrs_json=?,
               enabled_extensions_json=?, max_concurrency=?, nuclei_rate_limit=? WHERE project_id=?""",
            (
                env_tier,
                json.dumps(whitelist, ensure_ascii=False),
                json.dumps(forbidden, ensure_ascii=False),
                json.dumps(extensions, ensure_ascii=False),
                max_concurrency,
                nuclei_rate_limit,
                project_id,
            ),
        )

    def list_assets(self, project_id: str, *, include_secret: bool = False) -> list[dict]:
        rows = self._all("SELECT * FROM assets WHERE project_id=? ORDER BY host", (project_id,))
        return [self._decorate_asset(row, include_secret) for row in rows]

    def get_asset(self, asset_id: str, *, include_secret: bool = False) -> dict | None:
        row = self._one("SELECT * FROM assets WHERE asset_id=?", (asset_id,))
        return self._decorate_asset(row, include_secret) if row else None

    def _decorate_asset(self, row: dict, include_secret: bool) -> dict:
        row["scanners"] = json.loads(row.pop("scanners_json") or "[]")
        row["object_type"] = row.get("object_type") or "host_os"
        row["is_enabled"] = bool(row.get("is_enabled", 1))
        row["ssh_port"] = int(row.get("ssh_port") or 22)
        encrypted = row.get("ssh_secret_encrypted") or ""
        row["ssh_configured"] = bool(encrypted or row.get("ssh_secret_env") or row.get("ssh_key_env"))
        if not include_secret:
            row.pop("ssh_secret_encrypted", None)
        return row

    def save_asset(self, project_id: str, asset: dict, *, creating: bool) -> None:
        scanners = json.dumps(asset.get("scanners") or [], ensure_ascii=False)
        object_type = asset.get("object_type") or "host_os"
        if creating:
            self._write(
                """INSERT INTO assets(asset_id,project_id,host,security_zone,os_type,object_type,scan_mode,scanners_json,
                   ssh_port,ssh_user,ssh_auth_mode,ssh_secret_env,ssh_key_env,ssh_secret_encrypted,is_enabled,notes,updated_at,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    asset["asset_id"], project_id, asset["host"], asset["security_zone"], asset["os_type"],
                    object_type, asset["scan_mode"], scanners, asset["ssh_port"], asset["ssh_user"], asset["ssh_auth_mode"],
                    asset.get("ssh_secret_env") or "", asset.get("ssh_key_env") or "",
                    asset.get("ssh_secret_encrypted") or "", 1 if asset.get("is_enabled", True) else 0,
                    asset.get("notes") or "", utcnow(), utcnow(),
                ),
            )
            return
        values = [
            asset["host"], asset["security_zone"], asset["os_type"], object_type, asset["scan_mode"], asset["ssh_port"],
            asset["ssh_user"], asset["ssh_auth_mode"], asset.get("ssh_secret_env") or "",
            asset.get("ssh_key_env") or "", 1 if asset.get("is_enabled", True) else 0, asset.get("notes") or "",
        ]
        sql = """UPDATE assets SET host=?, security_zone=?, os_type=?, object_type=?, scan_mode=?, scanners_json=?,
                 ssh_port=?, ssh_user=?, ssh_auth_mode=?, ssh_secret_env=?, ssh_key_env=?, is_enabled=?, notes=?, updated_at=?"""
        params: list[Any] = [*values[:5], scanners, *values[5:], utcnow()]
        if asset.get("ssh_secret_encrypted"):
            sql += ", ssh_secret_encrypted=?"
            params.append(asset["ssh_secret_encrypted"])
        sql += " WHERE asset_id=? AND project_id=?"
        params.extend([asset["asset_id"], project_id])
        self._write(sql, tuple(params))

    def delete_asset(self, project_id: str, asset_id: str) -> None:
        self._write("DELETE FROM assets WHERE project_id=? AND asset_id=?", (project_id, asset_id))

    def update_asset_mode(self, asset_id: str, scan_mode: str) -> None:
        self._write("UPDATE assets SET scan_mode=?, updated_at=? WHERE asset_id=?", (scan_mode, utcnow(), asset_id))

    def set_project_llm_profile(self, project_id: str, profile_key: str) -> None:
        self._write("UPDATE projects SET llm_profile=? WHERE project_id=?", (profile_key, project_id))

    def projects_using_profile(self, profile_key: str) -> list[dict]:
        return self._all("SELECT project_id, name FROM projects WHERE llm_profile=?", (profile_key,))

    def create_job(self, project: dict) -> dict:
        job = {
            "job_id": new_id("job"),
            "project_id": project["project_id"],
            "project_name": project["name"],
            "env_tier": project["env_tier"],
            "llm_profile": project["llm_profile"],
            "status": "queued",
            "progress_pct": 0,
            "current_stage": "queued",
            "started_at": utcnow(),
            "finished_at": None,
            "error_msg": None,
        }
        self._write(
            """INSERT INTO scan_jobs(job_id,project_id,project_name,env_tier,llm_profile,status,progress_pct,current_stage,started_at,finished_at,error_msg)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                job["job_id"], job["project_id"], job["project_name"], job["env_tier"], job["llm_profile"],
                job["status"], 0, "queued", job["started_at"], None, None,
            ),
        )
        return job

    def update_job(self, job_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        self._write(f"UPDATE scan_jobs SET {cols} WHERE job_id=?", (*fields.values(), job_id))

    def get_job(self, job_id: str) -> dict | None:
        return self._one("SELECT * FROM scan_jobs WHERE job_id=?", (job_id,))

    def latest_job(self, project_id: str) -> dict | None:
        return self._one(
            "SELECT * FROM scan_jobs WHERE project_id=? ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (project_id,),
        )

    def list_jobs(self, project_id: str) -> list[dict]:
        return self._all("SELECT * FROM scan_jobs WHERE project_id=? ORDER BY started_at DESC, rowid DESC", (project_id,))

    def add_event(self, job_id: str, stage: str, message: str, progress: int) -> None:
        self._write(
            "INSERT INTO job_events(job_id,stage,message,progress_pct,created_at) VALUES(?,?,?,?,?)",
            (job_id, stage, message, progress, utcnow()),
        )
        self.update_job(job_id, progress_pct=progress, current_stage=stage)

    def list_events(self, job_id: str, after_id: int = 0) -> list[dict]:
        return self._all(
            "SELECT * FROM job_events WHERE job_id=? AND id>? ORDER BY id",
            (job_id, after_id),
        )

    def replace_evidences(self, job_id: str, rows: list[dict]) -> None:
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("DELETE FROM normalized_evidences WHERE job_id=?", (job_id,))
                for row in rows:
                    conn.execute(
                        """INSERT INTO normalized_evidences(evidence_id,job_id,asset_id,source_tool,evidence_type,severity,cve_or_cwe,title,sanitized_detail_json,detected_by_json,origin)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            row["evidence_id"],
                            job_id,
                            row["asset_id"],
                            row["source_tool"],
                            row["evidence_type"],
                            row["severity"],
                            row.get("cve_or_cwe"),
                            row["title"],
                            json.dumps(row.get("detail", {}), ensure_ascii=False),
                            json.dumps(row.get("detected_by", [row["source_tool"]]), ensure_ascii=False),
                            row.get("origin", "live"),
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

    def list_evidences(self, job_id: str) -> list[dict]:
        rows = self._all(
            """SELECT * FROM normalized_evidences
               WHERE job_id=?
               ORDER BY CASE lower(severity)
                   WHEN 'critical' THEN 1
                   WHEN 'high' THEN 2
                   WHEN 'medium' THEN 3
                   WHEN 'low' THEN 4
                   ELSE 5
               END, evidence_id""",
            (job_id,),
        )
        for row in rows:
            detail = json.loads(row.pop("sanitized_detail_json") or "{}")
            row["detail"] = detail
            row["clause_hints"] = list(detail.get("clause_hints") or [])
            if not row.get("port") and detail.get("port"):
                row["port"] = str(detail.get("port") or "")
            row["detected_by"] = json.loads(row.pop("detected_by_json") or "[]")
        return rows

    def save_vault(self, job_id: str, blob: str, passed: bool, preview: dict) -> dict:
        vault = {
            "vault_id": new_id("vault"),
            "job_id": job_id,
            "encrypted_mapping_blob": blob,
            "leak_check_passed": 1 if passed else 0,
            "preview_json": json.dumps(preview, ensure_ascii=False),
            "created_at": utcnow(),
        }
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("DELETE FROM sanitization_vault WHERE job_id=?", (job_id,))
                conn.execute(
                    """INSERT INTO sanitization_vault(vault_id,job_id,encrypted_mapping_blob,leak_check_passed,preview_json,approved_by,approved_at,created_at)
                       VALUES(?,?,?,?,?,NULL,NULL,?)""",
                    (vault["vault_id"], job_id, blob, vault["leak_check_passed"], vault["preview_json"], vault["created_at"]),
                )
                conn.commit()
            finally:
                conn.close()
        return self.get_vault(job_id)  # type: ignore[return-value]

    def get_vault(self, job_id: str) -> dict | None:
        row = self._one("SELECT * FROM sanitization_vault WHERE job_id=?", (job_id,))
        if not row:
            return None
        row["preview"] = json.loads(row.pop("preview_json") or "{}")
        row["leak_check_passed"] = bool(row["leak_check_passed"])
        return row

    def approve_vault(self, job_id: str, reviewer: str) -> None:
        self._write(
            "UPDATE sanitization_vault SET approved_by=?, approved_at=? WHERE job_id=?",
            (reviewer, utcnow(), job_id),
        )

    def replace_assessments(self, job_id: str, rows: list[dict]) -> None:
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("DELETE FROM clause_assessments WHERE job_id=?", (job_id,))
                for row in rows:
                    conn.execute(
                        """INSERT INTO clause_assessments(assessment_id,job_id,clause_id,auto_status,manual_status,final_status,risk_level,is_high_risk,evidence_ids_json,ai_rationale,remediation_script,compensation_status,compensation_note,reviewer,reviewed_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            row["assessment_id"], job_id, row["clause_id"], row["auto_status"], row.get("manual_status"),
                            row["final_status"], row["risk_level"], 1 if row["is_high_risk"] else 0,
                            json.dumps(row.get("evidence_ids", []), ensure_ascii=False),
                            row.get("ai_rationale", ""), row.get("remediation_script", ""),
                            row.get("compensation_status") or "none", row.get("compensation_note") or "",
                            row.get("reviewer"), row.get("reviewed_at"),
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

    def list_assessments(self, job_id: str) -> list[dict]:
        rows = self._all("SELECT * FROM clause_assessments WHERE job_id=? ORDER BY clause_id", (job_id,))
        for row in rows:
            row["evidence_ids"] = json.loads(row.pop("evidence_ids_json") or "[]")
            row["is_high_risk"] = bool(row["is_high_risk"])
            row["compensation_status"] = row.get("compensation_status") or "none"
            row["compensation_note"] = row.get("compensation_note") or ""
        return rows

    def update_assessment(
        self,
        assessment_id: str,
        reviewer: str,
        manual_status: str,
        note: str,
        *,
        compensation_status: str | None = None,
        compensation_note: str | None = None,
    ) -> dict | None:
        row = self._one("SELECT * FROM clause_assessments WHERE assessment_id=?", (assessment_id,))
        if not row:
            return None
        rationale = row["ai_rationale"]
        if note:
            rationale = rationale + f"\n人工复核：{note}"
        comp_status = compensation_status if compensation_status in {"none", "mitigated"} else (row.get("compensation_status") or "none")
        comp_note = compensation_note if compensation_note is not None else (row.get("compensation_note") or "")
        # 若结论已复核为符合或不适用，自动清除降级标记
        if manual_status in {"compliant", "not_applicable"}:
            comp_status = "none"
        self._write(
            """UPDATE clause_assessments
               SET manual_status=?, final_status=?, reviewer=?, reviewed_at=?, ai_rationale=?,
                   compensation_status=?, compensation_note=?
               WHERE assessment_id=?""",
            (manual_status, manual_status, reviewer, utcnow(), rationale, comp_status, comp_note, assessment_id),
        )
        updated = self._one("SELECT * FROM clause_assessments WHERE assessment_id=?", (assessment_id,))
        if updated:
            updated["evidence_ids"] = json.loads(updated.pop("evidence_ids_json") or "[]")
            updated["is_high_risk"] = bool(updated["is_high_risk"])
            updated["compensation_status"] = updated.get("compensation_status") or "none"
            updated["compensation_note"] = updated.get("compensation_note") or ""
        return updated

    def replace_paths(self, job_id: str, rows: list[dict]) -> None:
        with self._lock:
            conn = self.connect()
            try:
                conn.execute("DELETE FROM attack_paths WHERE job_id=?", (job_id,))
                for row in rows:
                    conn.execute(
                        """INSERT INTO attack_paths(path_id,job_id,title,severity,steps_json,mitigation_priority)
                           VALUES(?,?,?,?,?,?)""",
                        (row["path_id"], job_id, row["title"], row["severity"], json.dumps(row["steps"], ensure_ascii=False), row["mitigation_priority"]),
                    )
                conn.commit()
            finally:
                conn.close()

    def list_paths(self, job_id: str) -> list[dict]:
        rows = self._all("SELECT * FROM attack_paths WHERE job_id=?", (job_id,))
        for row in rows:
            row["steps"] = json.loads(row.pop("steps_json") or "[]")
        return rows

    def add_llm_log(self, row: dict) -> None:
        self._write(
            """INSERT INTO llm_audit_logs(log_id,job_id,stage,model_id,prompt_tokens,completion_tokens,cached_tokens,latency_ms,status,error_detail)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                row.get("log_id") or new_id("llm"), row["job_id"], row["stage"], row["model_id"],
                row.get("prompt_tokens", 0), row.get("completion_tokens", 0), row.get("cached_tokens", 0),
                row.get("latency_ms", 0), row["status"], row.get("error_detail"),
            ),
        )

    def list_llm_logs(self, limit: int = 50) -> list[dict]:
        return self._all("SELECT * FROM llm_audit_logs ORDER BY rowid DESC LIMIT ?", (limit,))

    def save_report(self, job_id: str, variant: str, filename: str, content_path: str) -> dict:
        # 同一轮次、同一版本只保留最新一份，避免整改工单重复出现。
        existing = self._one("SELECT report_id FROM reports WHERE job_id=? AND variant=?", (job_id, variant))
        now = utcnow()
        if existing:
            self._write(
                "UPDATE reports SET filename=?, content_path=?, created_at=? WHERE report_id=?",
                (filename, content_path, now, existing["report_id"]),
            )
            return self.get_report(existing["report_id"])  # type: ignore[return-value]
        report_id = new_id("rpt")
        self._write(
            "INSERT INTO reports(report_id,job_id,variant,filename,content_path,created_at) VALUES(?,?,?,?,?,?)",
            (report_id, job_id, variant, filename, content_path, now),
        )
        return self.get_report(report_id)  # type: ignore[return-value]

    def get_report(self, report_id: str) -> dict | None:
        return self._one("SELECT * FROM reports WHERE report_id=?", (report_id,))

    def list_reports(self, job_id: str) -> list[dict]:
        rows = self._all("SELECT * FROM reports WHERE job_id=? ORDER BY created_at DESC", (job_id,))
        seen: set[str] = set()
        unique = []
        for row in rows:
            if row["variant"] in seen:
                continue
            seen.add(row["variant"])
            unique.append(row)
        return unique

    def save_job_delivery(self, job_id: str, project_id: str, fields: dict) -> dict:
        current = self.get_job_delivery(job_id) or {"job_id": job_id, "project_id": project_id}
        for key, value in fields.items():
            if value is not None and key not in {"job_id", "project_id"}:
                current[key] = value
        current["project_id"] = project_id
        current["updated_at"] = utcnow()
        columns = [
            "job_id", "project_id", "dojo_product_id", "dojo_product_name", "dojo_engagement_id", "dojo_url",
            "ciso_assessment_id", "ciso_url", "leak_passed", "updated_at",
        ]
        values = [current.get(column) for column in columns]
        updates = ",".join(f"{column}=excluded.{column}" for column in columns if column != "job_id")
        self._write(
            f"INSERT INTO job_delivery({','.join(columns)}) VALUES({','.join('?' for _ in columns)}) "
            f"ON CONFLICT(job_id) DO UPDATE SET {updates}",
            tuple(values),
        )
        return self.get_job_delivery(job_id) or current

    def get_job_delivery(self, job_id: str) -> dict | None:
        return self._one("SELECT * FROM job_delivery WHERE job_id=?", (job_id,))

    def has_report_variant(self, job_id: str, variant: str) -> bool:
        return self._one("SELECT report_id FROM reports WHERE job_id=? AND variant=? LIMIT 1", (job_id, variant)) is not None

    def get_integration(self, project_id: str) -> dict | None:
        return self._one("SELECT * FROM project_integrations WHERE project_id=?", (project_id,))

    def save_integration(self, project_id: str, fields: dict) -> dict:
        current = self.get_integration(project_id) or {"project_id": project_id}
        for key, value in fields.items():
            if value is not None and key != "project_id":
                current[key] = value
        current["updated_at"] = utcnow()
        columns = [
            "project_id", "dojo_product_id", "dojo_product_name", "dojo_engagement_id", "dojo_url",
            "ciso_folder_id", "ciso_perimeter_id", "ciso_framework_id", "ciso_assessment_id", "ciso_url", "updated_at",
        ]
        values = [current.get(column) for column in columns]
        placeholders = ",".join("?" for _ in columns)
        updates = ",".join(f"{column}=excluded.{column}" for column in columns if column != "project_id")
        self._write(
            f"INSERT INTO project_integrations({','.join(columns)}) VALUES({placeholders}) "
            f"ON CONFLICT(project_id) DO UPDATE SET {updates}",
            tuple(values),
        )
        return self.get_integration(project_id) or current

    def add_sync_record(self, project_id: str, job_id: str | None, target: str, status: str, summary: str, detail: dict) -> dict:
        sync_id = new_id("sync")
        self._write(
            """INSERT INTO sync_records(sync_id,project_id,job_id,target,status,summary,detail_json,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (sync_id, project_id, job_id, target, status, summary, json.dumps(detail, ensure_ascii=False), utcnow()),
        )
        return self._one("SELECT * FROM sync_records WHERE sync_id=?", (sync_id,)) or {"sync_id": sync_id}

    def list_sync_records(self, project_id: str, job_id: str | None = None, limit: int = 30) -> list[dict]:
        if job_id:
            rows = self._all(
                "SELECT * FROM sync_records WHERE project_id=? AND job_id=? ORDER BY created_at DESC LIMIT ?",
                (project_id, job_id, limit),
            )
        else:
            rows = self._all(
                "SELECT * FROM sync_records WHERE project_id=? ORDER BY created_at DESC LIMIT ?",
                (project_id, limit),
            )
        for row in rows:
            row["detail"] = json.loads(row.pop("detail_json") or "{}")
        return rows

    def set_evidence_dojo(self, evidence_id: str, finding_id: str, status: str) -> None:
        self._write(
            "UPDATE normalized_evidences SET dojo_finding_id=?, dojo_status=? WHERE evidence_id=?",
            (finding_id, status, evidence_id),
        )

    def add_manual_doc(self, project_id: str, clause_id: str, filename: str, note: str, reviewer: str) -> dict:
        doc_id = new_id("doc")
        self._write(
            """INSERT INTO manual_evidence(evidence_doc_id,project_id,clause_id,filename,note,reviewer,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            (doc_id, project_id, clause_id, filename, note, reviewer, utcnow()),
        )
        return self._one("SELECT * FROM manual_evidence WHERE evidence_doc_id=?", (doc_id,))  # type: ignore[return-value]

    def list_manual_docs(self, project_id: str) -> list[dict]:
        return self._all("SELECT * FROM manual_evidence WHERE project_id=? ORDER BY created_at DESC", (project_id,))

    def _effective_job(self, project_id: str, job_id: str | None = None) -> dict | None:
        if job_id:
            selected = self.get_job(job_id)
            if selected and selected["project_id"] == project_id and self.list_assessments(job_id):
                return selected
        return self._one(
            """SELECT j.* FROM scan_jobs j
               WHERE j.project_id=? AND EXISTS (
                 SELECT 1 FROM clause_assessments a WHERE a.job_id=j.job_id
               )
               ORDER BY j.started_at DESC, j.rowid DESC LIMIT 1""",
            (project_id,),
        )

    def severity_counts(self, job_id: str) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        rows = self._all(
            "SELECT lower(severity) AS severity, COUNT(*) AS c FROM normalized_evidences WHERE job_id=? GROUP BY lower(severity)",
            (job_id,),
        )
        for row in rows:
            key = row["severity"] if row["severity"] in counts else "info"
            counts[key] += int(row["c"])
        return counts

    def _clause_catalog(self, extensions: list[str] | None = None) -> list[dict]:
        from core.clause_catalog import load_clauses

        return load_clauses(extensions)

    def _assessment_stats(
        self,
        assessments: list[dict],
        extensions: list[str] | None = None,
        assets: list[dict] | None = None,
        evidences: list[dict] | None = None,
    ) -> dict:
        total = len(assessments)
        compliant = len([a for a in assessments if a["final_status"] in ("compliant", "符合")])
        pending = len([a for a in assessments if a["final_status"] in ("pending_manual", "not_assessed")])
        high = [a for a in assessments if a["is_high_risk"]]
        from core.scoring import score_assessments

        catalog = self._clause_catalog(extensions)
        if assessments:
            # 若历史任务仍保存了旧版精简条款集合，则按实际评估记录构建域统计，确保历史数据口径一致
            known_ids = {item["clause_id"] for item in catalog}
            row_ids = {row["clause_id"] for row in assessments}
            if len(row_ids) != len(known_ids) or not row_ids.issubset(known_ids):
                all_meta = {item["clause_id"]: item for item in self._clause_catalog(None)}
                catalog = [all_meta.get(row["clause_id"], {"clause_id": row["clause_id"], "domain": row.get("domain") or "未归类"}) for row in assessments]
        scored = score_assessments(assessments, catalog, assets=assets, evidences=evidences)
        return {
            "clause_total": total or scored["clause_total"],
            "compliant": compliant,
            "pending_manual": pending,
            "coverage": scored["completeness"],
            "high_total": len(high),
            "high_open": scored["high_open"],
            "high_closed_rate": round((len(high) - scored["high_open"]) / len(high) * 100, 1) if high else 0,
            "completeness": scored["completeness"],
            "checked_score": scored["checked_score"],
            "conservative_score": scored["conservative_score"],
            "weighted_checked_score": scored["weighted_checked_score"],
            "weighted_conservative_score": scored["weighted_conservative_score"],
            "direct_high_fail": scored["direct_high_fail"],
            "direct_high_open": scored["direct_high_open"],
            "mitigated_high_count": scored["mitigated_high_count"],
            "risk_breakdown": scored["risk_breakdown"],
            "object_coverage": scored["object_coverage"],
            "verdict": scored["verdict"],
            "verdict_label": scored["verdict_label"],
            "verdict_advice": scored["verdict_advice"],
            "high_fail": scored["high_fail"],
            "score_counts": scored["counts"],
            "domains": scored["domains"],
        }

    def dashboard(self, project_id: str, job_id: str | None = None) -> dict:
        project = self.get_project(project_id)
        extensions = project.get("enabled_extensions") if project else ["GENERAL"]
        latest = self.latest_job(project_id)
        effective = self._effective_job(project_id, job_id)
        assessments = self.list_assessments(effective["job_id"]) if effective else []
        assets = self.list_assets(project_id)
        evidences = self.list_evidences(effective["job_id"]) if effective else []
        stats = self._assessment_stats(assessments, extensions, assets=assets, evidences=evidences)
        return {
            "job": latest,
            "effective_job": effective,
            **stats,
        }

    def dashboard_analytics(self, project_id: str, job_id: str | None = None) -> dict:
        base = self.dashboard(project_id, job_id)
        effective = base.get("effective_job")
        latest = base.get("job")
        assessments = self.list_assessments(effective["job_id"]) if effective else []
        severity = self.severity_counts(effective["job_id"]) if effective else {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        jobs = list(reversed(self._all(
            "SELECT * FROM scan_jobs WHERE project_id=? ORDER BY started_at DESC, rowid DESC LIMIT 10",
            (project_id,),
        )))
        trend = []
        for job in jobs:
            counts = self.severity_counts(job["job_id"])
            trend.append({
                "job_id": job["job_id"],
                "started_at": job["started_at"],
                "status": job["status"],
                "progress_pct": job["progress_pct"],
                "high": counts["critical"] + counts["high"],
                "other": counts["medium"] + counts["low"] + counts["info"],
                "total": sum(counts.values()),
            })
        return {
            **base,
            "awaiting_approval": latest if latest and latest["status"] == "awaiting_approval" else None,
            "severity": severity,
            "domains": base.get("domains") or [],
            "trend": trend,
            "finding_total": sum(severity.values()),
        }

    def llm_profile_count(self) -> int:
        row = self._one("SELECT COUNT(*) AS c FROM llm_profiles")
        return int(row["c"]) if row else 0

    def list_llm_profiles(self) -> list[dict]:
        rows = self._all("SELECT * FROM llm_profiles ORDER BY created_at")
        return [self._public_profile(row) for row in rows]

    def get_llm_profile(self, profile_key: str) -> dict | None:
        return self._one("SELECT * FROM llm_profiles WHERE profile_key=?", (profile_key,))

    def gateway_profiles(self) -> dict[str, dict]:
        profiles: dict[str, dict] = {}
        for row in self._all("SELECT * FROM llm_profiles"):
            profiles[row["profile_key"]] = {
                "display_name": row["display_name"],
                "provider": row["provider"],
                "allowed_env_tiers": json.loads(row["allowed_env_tiers_json"] or "[]"),
                "is_cross_border": bool(row["is_cross_border"]),
                "fast_mapper_model": row["fast_mapper_model"],
                "deep_reasoner_model": row["deep_reasoner_model"],
                "api_base": row["api_base"],
                "proxy_env": row["proxy_env"],
                "auth_mode": row["auth_mode"],
                "api_key_env": row["api_key_env"],
                "api_key_encrypted": row["api_key_encrypted"],
                "enable_context_caching": bool(row["enable_context_caching"]),
                "inject_block_none_safety": bool(row["inject_block_none_safety"]),
                "is_enabled": bool(row["is_enabled"]),
            }
        return profiles

    def save_llm_profile(self, row: dict) -> dict:
        now = utcnow()
        existing = self.get_llm_profile(row["profile_key"])
        encrypted = row.get("api_key_encrypted", "")
        if existing and row.get("keep_secret"):
            encrypted = existing["api_key_encrypted"]
        payload = (
            row["profile_key"],
            row["display_name"],
            row["provider"],
            1 if row.get("is_cross_border") else 0,
            json.dumps(row.get("allowed_env_tiers") or [], ensure_ascii=False),
            row["fast_mapper_model"],
            row.get("deep_reasoner_model") or row["fast_mapper_model"],
            row.get("api_base") or "",
            row.get("proxy_env") or "",
            row.get("auth_mode") or "env_ref",
            row.get("api_key_env") or "",
            encrypted or "",
            1 if row.get("enable_context_caching") else 0,
            1 if row.get("inject_block_none_safety") else 0,
            1 if row.get("is_enabled", True) else 0,
            existing["created_at"] if existing else now,
            now,
        )
        self._write(
            """INSERT INTO llm_profiles(
                 profile_key,display_name,provider,is_cross_border,allowed_env_tiers_json,
                 fast_mapper_model,deep_reasoner_model,api_base,proxy_env,auth_mode,api_key_env,
                 api_key_encrypted,enable_context_caching,inject_block_none_safety,is_enabled,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(profile_key) DO UPDATE SET
                 display_name=excluded.display_name, provider=excluded.provider,
                 is_cross_border=excluded.is_cross_border, allowed_env_tiers_json=excluded.allowed_env_tiers_json,
                 fast_mapper_model=excluded.fast_mapper_model, deep_reasoner_model=excluded.deep_reasoner_model,
                 api_base=excluded.api_base, proxy_env=excluded.proxy_env, auth_mode=excluded.auth_mode,
                 api_key_env=excluded.api_key_env, api_key_encrypted=excluded.api_key_encrypted,
                 enable_context_caching=excluded.enable_context_caching,
                 inject_block_none_safety=excluded.inject_block_none_safety,
                 is_enabled=excluded.is_enabled, updated_at=excluded.updated_at""",
            payload,
        )
        saved = self.get_llm_profile(row["profile_key"])
        return self._public_profile(saved) if saved else {}

    def delete_llm_profile(self, profile_key: str) -> None:
        self._write("DELETE FROM llm_profiles WHERE profile_key=?", (profile_key,))

    def get_system_prompt(self, prompt_key: str) -> dict | None:
        return self._one("SELECT * FROM system_prompts WHERE prompt_key=?", (prompt_key,))

    def ensure_system_prompt(self, prompt_key: str, title: str, default_content: str) -> dict:
        existing = self.get_system_prompt(prompt_key)
        if existing:
            # 仅当管理员尚未手工定制时，随系统版本平滑刷新内置提示词模板
            if existing.get("updated_by") == "系统内置" and (
                existing.get("content") != default_content or existing.get("title") != title
            ):
                now = utcnow()
                next_ver = int(existing.get("version") or 1) + 1
                self._write(
                    "UPDATE system_prompts SET title=?, content=?, version=?, updated_at=? WHERE prompt_key=?",
                    (title, default_content, next_ver, now, prompt_key),
                )
                return self.get_system_prompt(prompt_key) or existing
            return existing
        now = utcnow()
        self._write(
            "INSERT INTO system_prompts(prompt_key,title,content,version,updated_by,updated_at) VALUES(?,?,?,1,'系统内置',?)",
            (prompt_key, title, default_content, now),
        )
        return self.get_system_prompt(prompt_key) or {
            "prompt_key": prompt_key,
            "title": title,
            "content": default_content,
            "version": 1,
            "updated_by": "系统内置",
            "updated_at": now,
        }

    def save_system_prompt(self, prompt_key: str, title: str, content: str, updated_by: str) -> dict:
        existing = self.get_system_prompt(prompt_key)
        next_version = int(existing["version"]) + 1 if existing else 1
        now = utcnow()
        self._write(
            """INSERT INTO system_prompts(prompt_key,title,content,version,updated_by,updated_at)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(prompt_key) DO UPDATE SET
                 title=excluded.title,
                 content=excluded.content,
                 version=excluded.version,
                 updated_by=excluded.updated_by,
                 updated_at=excluded.updated_at""",
            (prompt_key, title, content, next_version, updated_by, now),
        )
        return self.get_system_prompt(prompt_key) or {}

    def get_report_narrative(self, job_id: str) -> dict | None:
        row = self._one("SELECT * FROM report_narratives WHERE job_id=?", (job_id,))
        if not row:
            return None
        row["sections"] = json.loads(row.pop("sections_json") or "{}")
        return row

    def save_report_narrative(
        self,
        job_id: str,
        prompt_key: str,
        prompt_version: int,
        model_id: str,
        status: str,
        sections: dict,
    ) -> dict:
        now = utcnow()
        self._write(
            """INSERT INTO report_narratives(job_id,prompt_key,prompt_version,model_id,status,sections_json,generated_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(job_id) DO UPDATE SET
                 prompt_key=excluded.prompt_key,
                 prompt_version=excluded.prompt_version,
                 model_id=excluded.model_id,
                 status=excluded.status,
                 sections_json=excluded.sections_json,
                 generated_at=excluded.generated_at""",
            (job_id, prompt_key, int(prompt_version), model_id, status, json.dumps(sections, ensure_ascii=False), now),
        )
        return self.get_report_narrative(job_id) or {}

    def _public_profile(self, row: dict) -> dict:
        encrypted = row.get("api_key_encrypted") or ""
        return {
            "profile_key": row["profile_key"],
            "display_name": row["display_name"],
            "provider": row["provider"],
            "is_cross_border": bool(row["is_cross_border"]),
            "allowed_env_tiers": json.loads(row["allowed_env_tiers_json"] or "[]"),
            "fast_mapper_model": row["fast_mapper_model"],
            "deep_reasoner_model": row["deep_reasoner_model"],
            "api_base": row["api_base"],
            "proxy_env": row["proxy_env"],
            "auth_mode": row["auth_mode"],
            "api_key_env": row["api_key_env"],
            "has_api_key": bool(encrypted) or bool(row.get("api_key_env")),
            "api_key_masked": "已配置" if encrypted else "",
            "enable_context_caching": bool(row["enable_context_caching"]),
            "inject_block_none_safety": bool(row["inject_block_none_safety"]),
            "is_enabled": bool(row["is_enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
