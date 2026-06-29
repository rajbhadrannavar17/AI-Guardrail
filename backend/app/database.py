import json
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "guardrail.sqlite3"


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS prompt_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                department TEXT NOT NULL,
                role TEXT NOT NULL,
                prompt_preview TEXT NOT NULL,
                prompt_hash TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                action TEXT NOT NULL,
                model_route TEXT NOT NULL,
                approval_status TEXT NOT NULL,
                findings TEXT NOT NULL,
                policy_matches TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                device TEXT NOT NULL,
                browser TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER NOT NULL,
                requested_by TEXT NOT NULL,
                approver_role TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )


def row_to_prompt_log(row: sqlite3.Row) -> dict[str, Any]:
    log = dict(row)
    log["findings"] = json.loads(log["findings"])
    log["policy_matches"] = json.loads(log["policy_matches"])
    return log


def row_to_approval(row: sqlite3.Row) -> dict[str, Any]:
    return dict(row)
