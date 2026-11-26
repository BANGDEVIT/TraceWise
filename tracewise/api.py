"""API của TraceWise (FastAPI).

Chạy:  uvicorn tracewise.api:app --host 127.0.0.1 --port 8000
Xem và thử các endpoint: http://127.0.0.1:8000/docs
"""

import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from . import pipeline, srs, store


class LabelIn(BaseModel):
    """Nhãn người phân tích gửi lên (FR-05). Cùng khuôn với nhãn của thầy: du_can_cu, ma_attack, ghi_chu."""

    model_config = ConfigDict(extra="forbid")
    nguoi_luu: str = Field(
        pattern=r"^[a-z0-9._-]{2,32}$", examples=["bang"]
    )  # mã người lưu (FR-08)
    du_can_cu: bool
    ma_attack: list[str] = Field(default=[], max_length=3, examples=[["T1003.001"]])
    ghi_chu: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def codes_match_flag(self):
        self.ma_attack = list(dict.fromkeys(c.strip().upper() for c in self.ma_attack))
        if self.du_can_cu != bool(self.ma_attack):
            raise ValueError(
                "du_can_cu = true thì phải có ít nhất 1 mã; false thì ma_attack rỗng"
            )
        return self


def create_app(services_factory=pipeline.load_services) -> FastAPI:
    """Tạo app. Test truyền services_factory riêng (LLM giả, schema database riêng)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # FR-07: host LLM ngoài allowlist -> load_services ném lỗi -> dịch vụ KHÔNG khởi động
        svc = services_factory()  # Tạo bộ dịch vụ: kết nối DB, client LLM, nạp ATT&CK…
        store.create_tables(svc.conn)  # Tạo bảng analysis_run, analysis_log nếu chưa có
        app.state.svc = svc  # Cất bộ dịch vụ vào app
        app.state.alerts = {a["id"]: a for a in srs.load_alerts()}
        app.state.lock = threading.Lock()  # CPU chỉ chạy nổi một lần gọi LLM mỗi lúc
        yield
        svc.client.close()

    app = FastAPI(title="TraceWise", version="0.1.0", lifespan=lifespan)

    @app.get("/health")
    def health():
        s = app.state.svc.settings
        return {
            "status": "ok",
            "model": s.llm.model,
            "attack_version": app.state.svc.attack_version,
            "rag": s.analysis.rag,
            "k": s.analysis.k,
            "query_mode": s.analysis.query_mode,
        }

    @app.get("/alerts")
    def list_alerts():
        """Các cảnh báo lab của thầy (35 cảnh báo)."""
        return [
            {
                "id": a["id"],
                "host": a["agent"]["name"],
                "level": a["rule"]["level"],
                "rule": a["rule"]["description"],
            }
            for a in app.state.alerts.values()
        ]

    @app.post("/alerts/{alert_id}/analyze")
    def analyze(alert_id: str):
        """Phân tích một cảnh báo, lưu kết quả và nhật ký, trả về lần chạy vừa lưu."""
        alert = app.state.alerts.get(alert_id)
        if alert is None:
            raise HTTPException(404, f"Không có cảnh báo {alert_id}")
        svc = app.state.svc
        with app.state.lock:
            run = pipeline.analyze(alert, svc)
            run_id = store.save_run(svc.conn, run)
        if run["status"] == "error":
            raise HTTPException(502, {"run_id": run_id, "error": run["error"]})
        return store.get_run(svc.conn, run_id)

    @app.post("/runs/{run_id}/labels", status_code=201)
    def save_label(run_id: int, label: LabelIn):
        """Người phân tích lưu nhãn của mình cho một lần chạy. Kết quả của mô hình giữ nguyên."""
        unknown = [c for c in label.ma_attack if c not in app.state.svc.attack]
        if unknown:
            raise HTTPException(
                422,
                f"Mã không có trong ATT&CK {app.state.svc.attack_version}: {unknown}",
            )

        with app.state.lock:
            saved = store.save_label(
                app.state.svc.conn,
                run_id,
                label.nguoi_luu,
                label.du_can_cu,
                label.ma_attack,
                label.ghi_chu,
            )

        if saved is None:
            raise HTTPException(404, f"Không có lần chạy {run_id}")
        return saved

    @app.get("/alerts/{alert_id}/labels")
    def alert_labels(alert_id: str):
        """Các nhãn người phân tích đã lưu cho một cảnh báo, mới nhất trước."""
        if alert_id not in app.state.alerts:
            raise HTTPException(404, f"Không có cảnh báo {alert_id}")
        return store.labels_of(app.state.svc.conn, alert_id)

    @app.get("/runs")
    def list_runs(alert_id: str | None = None, limit: int = 20):
        return store.list_runs(app.state.svc.conn, alert_id, limit)

    @app.get("/runs/{run_id}")
    def get_run(run_id: int):
        run = store.get_run(app.state.svc.conn, run_id)
        if run is None:
            raise HTTPException(404, f"Không có lần chạy {run_id}")
        return run

    return app


app = create_app()
