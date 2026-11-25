"""Lưu kết quả phân tích (analysis_run, NFR-REP-01) và nhật ký từng bước (analysis_log, FR-08) vào Postgres."""

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def create_tables(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_run (
            id                bigserial PRIMARY KEY,
            created_at        timestamptz NOT NULL DEFAULT now(),
            request_id        text   NOT NULL UNIQUE,
            alert_ref         text   NOT NULL,
            host              text,
            status            text   NOT NULL CHECK (status IN ('ok', 'invalid', 'error')),
            needs_review      boolean NOT NULL,
            error             text,
            raw               text,
            result            jsonb,
            teacher           jsonb,
            violations        jsonb  NOT NULL,
            pack              jsonb  NOT NULL,
            candidates        text[] NOT NULL,
            config            jsonb  NOT NULL,
            prompt_tokens     int,
            completion_tokens int,
            latency_s         real
        )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS analysis_run_alert ON analysis_run (alert_ref, created_at DESC)"
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_log (
            id          bigserial PRIMARY KEY,
            ts          timestamptz NOT NULL,
            request_id  text NOT NULL REFERENCES analysis_run (request_id) ON DELETE CASCADE,
            alert_ref   text NOT NULL,
            event       text NOT NULL,
            detail      jsonb NOT NULL
        )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS analysis_log_request ON analysis_log (request_id)"
    )


RUN_COLUMNS = [
    "request_id",
    "alert_ref",
    "host",
    "status",
    "needs_review",
    "error",
    "raw",
    "result",
    "teacher",
    "violations",
    "pack",
    "candidates",
    "config",
    "prompt_tokens",
    "completion_tokens",
    "latency_s",
]
JSON_COLUMNS = {"result", "teacher", "violations", "pack", "config"}


def save_run(conn, run: dict) -> int:
    """Ghi một lần chạy + các bước của nó trong CÙNG một giao dịch: hoặc đủ cả hai, hoặc không gì cả."""
    values = [
        Jsonb(run[c]) if c in JSON_COLUMNS and run[c] is not None else run[c]
        for c in RUN_COLUMNS
    ]
    with conn.transaction():
        run_id = conn.execute(
            f"INSERT INTO analysis_run ({', '.join(RUN_COLUMNS)}) "
            f"VALUES ({', '.join(['%s'] * len(RUN_COLUMNS))}) RETURNING id",
            values,
        ).fetchone()[0]
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO analysis_log (ts, request_id, alert_ref, event, detail) "
                "VALUES (%s, %s, %s, %s, %s)",
                [
                    (
                        e["ts"],
                        run["request_id"],
                        run["alert_ref"],
                        e["event"],
                        Jsonb(e["detail"]),
                    )
                    for e in run["events"]
                ],
            )
    return run_id


def get_run(conn, run_id: int) -> dict | None:
    """Một lần chạy đầy đủ, kèm nhật ký các bước theo thứ tự thời gian."""
    with conn.cursor(row_factory=dict_row) as cur:
        run = cur.execute(
            "SELECT * FROM analysis_run WHERE id = %s", (run_id,)
        ).fetchone()
        if run is None:
            return None
        run["events"] = cur.execute(
            "SELECT ts, event, detail FROM analysis_log WHERE request_id = %s ORDER BY ts, id",
            (run["request_id"],),
        ).fetchall()
    return run


def list_runs(conn, alert_ref: str | None = None, limit: int = 20) -> list[dict]:
    """Các lần chạy mới nhất (gọn, không có raw và gói), lọc theo cảnh báo nếu có."""
    with conn.cursor(row_factory=dict_row) as cur:
        return cur.execute(
            """
            SELECT id, created_at, alert_ref, status, needs_review,
                   teacher -> 'ma_attack' AS ma_attack, latency_s
            FROM analysis_run
            WHERE %(a)s::text IS NULL OR alert_ref = %(a)s
            ORDER BY created_at DESC, id DESC
            LIMIT %(n)s""",
            {"a": alert_ref, "n": limit},
        ).fetchall()
