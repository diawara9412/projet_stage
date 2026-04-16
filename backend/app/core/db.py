import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from app.core.config import settings

UPLOAD_MUTABLE_FIELDS = {"status", "parsed_artifact", "scenario_artifact", "updated_at"}
RUN_MUTABLE_FIELDS = {
    "models",
    "repeats",
    "status",
    "run_dir",
    "result_artifact",
    "metrics_json",
    "metrics_csv",
    "updated_at",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    settings.data_path.mkdir(parents=True, exist_ok=True)
    settings.sqlite_file.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(settings.sqlite_file) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS uploads (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                parsed_artifact TEXT,
                scenario_artifact TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                upload_id TEXT NOT NULL,
                models TEXT NOT NULL,
                repeats INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                run_dir TEXT NOT NULL,
                result_artifact TEXT,
                metrics_json TEXT,
                metrics_csv TEXT
            )
            """
        )
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(settings.sqlite_file)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def insert_upload(record: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO uploads (id, filename, file_type, path, status, created_at, updated_at, parsed_artifact, scenario_artifact)
            VALUES (:id, :filename, :file_type, :path, :status, :created_at, :updated_at, :parsed_artifact, :scenario_artifact)
            """,
            record,
        )
        conn.commit()


def update_upload(upload_id: str, **kwargs) -> None:
    if not kwargs:
        return
    invalid = set(kwargs) - (UPLOAD_MUTABLE_FIELDS - {"updated_at"})
    if invalid:
        raise ValueError(f"Unsupported upload fields for update: {', '.join(sorted(invalid))}")
    kwargs["updated_at"] = now_iso()
    assignments = ", ".join([f"{k}=:{k}" for k in kwargs])
    kwargs["id"] = upload_id
    with get_conn() as conn:
        conn.execute(f"UPDATE uploads SET {assignments} WHERE id=:id", kwargs)
        conn.commit()


def get_upload(upload_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone()
    return dict(row) if row else None


def insert_run(record: dict) -> None:
    payload = {**record, "models": json.dumps(record["models"])}
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO runs (id, upload_id, models, repeats, status, created_at, updated_at, run_dir, result_artifact, metrics_json, metrics_csv)
            VALUES (:id, :upload_id, :models, :repeats, :status, :created_at, :updated_at, :run_dir, :result_artifact, :metrics_json, :metrics_csv)
            """,
            payload,
        )
        conn.commit()


def update_run(run_id: str, **kwargs) -> None:
    if not kwargs:
        return
    invalid = set(kwargs) - (RUN_MUTABLE_FIELDS - {"updated_at"})
    if invalid:
        raise ValueError(f"Unsupported run fields for update: {', '.join(sorted(invalid))}")
    kwargs["updated_at"] = now_iso()
    assignments = ", ".join([f"{k}=:{k}" for k in kwargs])
    kwargs["id"] = run_id
    if "models" in kwargs and isinstance(kwargs["models"], list):
        kwargs["models"] = json.dumps(kwargs["models"])
    with get_conn() as conn:
        conn.execute(f"UPDATE runs SET {assignments} WHERE id=:id", kwargs)
        conn.commit()


def get_run(run_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return None
    record = dict(row)
    record["models"] = json.loads(record["models"])
    return record
