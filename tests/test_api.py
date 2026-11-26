"""API FastAPI: endpoint, mã lỗi HTTP, lưu kết quả; FR-07 chặn ngay lúc khởi động."""

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.fakes import FakeLLM
from tracewise import pipeline, srs
from tracewise.api import create_app
from tracewise.settings import load_settings

S = load_settings()


@pytest.fixture
def api(db):
    """(TestClient, LLM giả). 'with' chạy phần khởi động (lifespan) như uvicorn."""
    fake = FakeLLM()
    app = create_app(
        lambda: pipeline.load_services(S, conn=db, transport=fake.transport())
    )
    with TestClient(app) as client:
        yield client, fake


def test_health(api):
    client, _ = api
    body = client.get("/health").json()
    assert body == {
        "status": "ok",
        "model": "qwen3.5:4b",
        "attack_version": "18.1",
        "rag": True,
        "k": 5,
        "query_mode": "pack",
    }


def test_alerts_lists_the_35_lab_alerts(api):
    client, _ = api
    alerts = client.get("/alerts").json()
    assert (
        len(alerts) == 35
        and alerts[28]["id"] == "LAB-0029"
        and alerts[28]["host"] == "lab-win02"
    )


def test_analyze_saves_and_returns_the_run(api):
    client, _ = api
    r = client.post("/alerts/LAB-0029/analyze")
    assert r.status_code == 200
    run = r.json()
    assert (
        run["status"] == "ok"
        and run["alert_ref"] == "LAB-0029"
        and len(run["candidates"]) == 5
    )
    assert [e["event"] for e in run["events"]] == [
        "pack",
        "candidates",
        "llm",
        "validate",
    ]
    assert client.get(f"/runs/{run['id']}").json()["request_id"] == run["request_id"]
    assert (
        client.get("/runs", params={"alert_id": "LAB-0029"}).json()[0]["id"]
        == run["id"]
    )


def test_unknown_alert_and_run_are_404(api):
    client, _ = api
    assert client.post("/alerts/LAB-9999/analyze").status_code == 404
    assert client.get("/runs/999999999").status_code == 404


def test_llm_down_is_502_but_run_is_saved(api):
    client, fake = api
    fake.replies.append(httpx.Response(500, json={"error": "boom"}))
    r = client.post("/alerts/LAB-0030/analyze")
    assert r.status_code == 502
    run_id = r.json()["detail"]["run_id"]
    assert client.get(f"/runs/{run_id}").json()["status"] == "error"


def test_startup_refuses_llm_host_outside_allowlist(db):
    bad = S.model_copy(
        update={
            "llm": S.llm.model_copy(update={"base_url": "https://api.example.com/v1"})
        }
    )
    app = create_app(lambda: pipeline.load_services(bad, conn=db))
    with pytest.raises(srs.HostNotAllowed):
        with TestClient(app):
            pass


def test_label_endpoint_saves_and_lists(api):
    client, _ = api
    run = client.post("/alerts/LAB-0029/analyze").json()
    r = client.post(
        f"/runs/{run['id']}/labels",
        json={"nguoi_luu": "bang", "du_can_cu": True, "ma_attack": ["t1003.001"]},
    )
    assert r.status_code == 201 and r.json()["ma_attack"] == [
        "T1003.001"
    ]  # chuẩn hóa chữ hoa
    assert client.get("/alerts/LAB-0029/labels").json()[0]["id"] == r.json()["id"]
    again = client.get(f"/runs/{run['id']}").json()
    assert again["result"] == run["result"] and len(again["labels"]) == 1


@pytest.mark.parametrize(
    "body, code",
    [
        (
            {"nguoi_luu": "bang", "du_can_cu": True, "ma_attack": ["T9999"]},
            422,
        ),  # mã không có
        (
            {"nguoi_luu": "bang", "du_can_cu": True, "ma_attack": []},
            422,
        ),  # có căn cứ, không mã
        (
            {"nguoi_luu": "bang", "du_can_cu": False, "ma_attack": ["T1003.001"]},
            422,
        ),  # ngược lại
        ({"nguoi_luu": "Bằng Bùi", "du_can_cu": False}, 422),  # mã người lưu sai dạng
        ({"nguoi_luu": "bang", "du_can_cu": False, "role": "admin"}, 422),  # trường lạ
    ],
)
def test_bad_label_is_rejected(api, body, code):
    client, _ = api
    run = client.post("/alerts/LAB-0029/analyze").json()
    assert client.post(f"/runs/{run['id']}/labels", json=body).status_code == code


def test_label_for_unknown_run_or_alert_is_404(api):
    client, _ = api
    body = {"nguoi_luu": "bang", "du_can_cu": False}
    assert client.post("/runs/999999999/labels", json=body).status_code == 404
    assert client.get("/alerts/LAB-9999/labels").status_code == 404
