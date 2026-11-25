"""API của TraceWise (FastAPI).

Chạy:  uvicorn tracewise.api:app --host 127.0.0.1 --port 8000
Xem và thử các endpoint: http://127.0.0.1:8000/docs
"""

import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from . import pipeline, srs, store


def create_app(services_factory=pipeline.load_services) -> FastAPI:
    """Tạo app. Test truyền services_factory riêng (LLM giả, schema database riêng)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # FR-07: host LLM ngoài allowlist -> load_services ném lỗi -> dịch vụ KHÔNG khởi động
        svc = services_factory()
        store.create_tables(svc.conn)
        app.state.svc = svc
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
