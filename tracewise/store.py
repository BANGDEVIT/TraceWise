"""Lưu kết quả phân tích (analysis_run, NFR-REP-01), nhãn của người phân tích (analyst_label, FR-05)
và nhật ký (analysis_log, FR-08: mã cảnh báo, mã mô hình, mã người lưu, thời điểm) vào Postgres."""

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SYSTEM_ACTOR = "tracewise"  # "người lưu" của các bước do hệ thống tự chạy


def create_tables(conn) -> None:
    """Tạo bảng nếu chưa có"""
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
    # Ngày 6–7: thêm cột vào bảng đã có (database của bạn đã tạo bảng ở Ngày 5)
    # attemps: Số lần thử gọi LLM cho lần chạy này (lần đầu JSON hỏng thì gọi lại)
    conn.execute(
        "ALTER TABLE analysis_run ADD COLUMN IF NOT EXISTS attempts int NOT NULL DEFAULT 1"
    )
    # actor: Ai ghi bước này.
    conn.execute(
        f"ALTER TABLE analysis_log ADD COLUMN IF NOT EXISTS actor text NOT NULL "
        f"DEFAULT '{SYSTEM_ACTOR}'"
    )
    conn.execute("ALTER TABLE analysis_log ADD COLUMN IF NOT EXISTS model text")
    conn.execute("""
        UPDATE analysis_log l SET model = coalesce(r.config ->> 'llm_model_served',  
                                                   r.config ->> 'llm_model_requested')
        FROM analysis_run r
        WHERE l.model IS NULL AND l.request_id = r.request_id""")  # điền mô hình cho dòng cũ, coalesce(a, b): Lấy a; nếu a rỗng thì lấy b
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyst_label (
            id          bigserial PRIMARY KEY,
            created_at  timestamptz NOT NULL DEFAULT now(),
            run_id      bigint NOT NULL REFERENCES analysis_run (id),
            alert_ref   text   NOT NULL,
            nguoi_luu   text   NOT NULL,
            du_can_cu   boolean NOT NULL,
            ma_attack   text[] NOT NULL,
            ghi_chu     text   NOT NULL DEFAULT '',
            CHECK (du_can_cu = (cardinality(ma_attack) > 0))
        )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS analyst_label_alert ON analyst_label (alert_ref, created_at DESC)"
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
    "attempts",
]
JSON_COLUMNS = {"result", "teacher", "violations", "pack", "config"}


def _model_of(config: dict) -> str | None:
    """Mã mô hình của một lần chạy: tên máy chủ trả về, không có thì tên trong cấu hình."""
    return config.get("llm_model_served") or config.get("llm_model_requested")


def save_run(conn, run: dict) -> int:
    """Ghi một lần chạy + các bước của nó trong CÙNG một giao dịch: hoặc đủ cả hai, hoặc không gì cả."""
    values = [
        Jsonb(run[c]) if c in JSON_COLUMNS and run[c] is not None else run[c]
        for c in RUN_COLUMNS
    ]
    values[RUN_COLUMNS.index("attempts")] = max(run.get("attempts") or 0, 1)
    model = _model_of(run["config"])
    with conn.transaction():
        run_id = conn.execute(
            f"INSERT INTO analysis_run ({', '.join(RUN_COLUMNS)}) "
            f"VALUES ({', '.join(['%s'] * len(RUN_COLUMNS))}) RETURNING id",
            values,
        ).fetchone()[0]
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO analysis_log (ts, request_id, alert_ref, event, detail, actor, model) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                [
                    (
                        e["ts"],
                        run["request_id"],
                        run["alert_ref"],
                        e["event"],
                        Jsonb(e["detail"]),
                        SYSTEM_ACTOR,
                        model,
                    )
                    for e in run["events"]
                ],
            )
    return run_id


def save_label(
    conn,
    run_id: int,
    nguoi_luu: str,
    du_can_cu: bool,
    ma_attack: list[str],
    ghi_chu: str = "",
) -> dict | None:
    """FR-05: lưu nhãn của người phân tích vào bảng RIÊNG, không sửa kết quả của mô hình.

    Mỗi lần lưu là một dòng mới (giữ lịch sử); nhãn hiện hành của cảnh báo là dòng mới nhất.
    Cùng giao dịch, ghi một dòng nhật ký 'label_saved' đủ 4 trường của FR-08.
    Không có lần chạy run_id thì trả None.
    """
    with conn.transaction():
        with conn.cursor(row_factory=dict_row) as cur:
            run = cur.execute(
                "SELECT request_id, alert_ref, config FROM analysis_run WHERE id = %s",
                (run_id,),
            ).fetchone()
            if run is None:
                return None
            label = cur.execute(
                """
                INSERT INTO analyst_label (run_id, alert_ref, nguoi_luu, du_can_cu, ma_attack, ghi_chu)
                VALUES (%s, %s, %s, %s, %s, %s) RETURNING *""",
                (run_id, run["alert_ref"], nguoi_luu, du_can_cu, ma_attack, ghi_chu),
            ).fetchone()
            cur.execute(
                """
                INSERT INTO analysis_log (ts, request_id, alert_ref, event, detail, actor, model)
                VALUES (now(), %s, %s, 'label_saved', %s, %s, %s)""",
                (
                    run["request_id"],
                    run["alert_ref"],
                    Jsonb(
                        {
                            "label_id": label["id"],
                            "run_id": run_id,
                            "du_can_cu": du_can_cu,
                            "ma_attack": ma_attack,
                        }
                    ),
                    nguoi_luu,
                    _model_of(run["config"]),
                ),
            )
    return label


def labels_of(conn, alert_ref: str) -> list[dict]:
    """Các nhãn người phân tích đã lưu cho một cảnh báo, mới nhất trước."""
    with conn.cursor(row_factory=dict_row) as cur:
        return cur.execute(
            "SELECT * FROM analyst_label WHERE alert_ref = %s "
            "ORDER BY created_at DESC, id DESC",
            (alert_ref,),
        ).fetchall()


def get_run(conn, run_id: int) -> dict | None:
    """Một lần chạy đầy đủ, kèm nhật ký các bước và các nhãn người phân tích gắn với nó."""
    with conn.cursor(row_factory=dict_row) as cur:
        run = cur.execute(
            "SELECT * FROM analysis_run WHERE id = %s", (run_id,)
        ).fetchone()
        if run is None:
            return None
        run["events"] = cur.execute(
            "SELECT ts, event, actor, model, detail FROM analysis_log WHERE request_id = %s "
            "ORDER BY ts, id",
            (run["request_id"],),
        ).fetchall()
        run["labels"] = cur.execute(
            "SELECT * FROM analyst_label WHERE run_id = %s ORDER BY created_at DESC, id DESC",
            (run_id,),
        ).fetchall()
    return run


def list_runs(conn, alert_ref: str | None = None, limit: int = 20) -> list[dict]:
    """Các lần chạy mới nhất (gọn, không có raw và gói), lọc theo cảnh báo nếu có."""
    with conn.cursor(row_factory=dict_row) as cur:
        return cur.execute(
            """
            SELECT id, created_at, alert_ref, status, needs_review, attempts,
                   teacher -> 'ma_attack' AS ma_attack, latency_s
            FROM analysis_run
            WHERE %(a)s::text IS NULL OR alert_ref = %(a)s
            ORDER BY created_at DESC, id DESC
            LIMIT %(n)s""",
            {"a": alert_ref, "n": limit},
        ).fetchall()
