"""Test nghiệm thu: mỗi yêu cầu FR/NFR một test, kiểm đúng câu "tiêu chí" trong docs/truy_vet.csv.

LLM giả cố tình xấu (bỏ qua enum, nghe lời câu chèn, viết quá dài) để chứng minh yêu cầu vẫn được giữ
nhờ các lớp phía sau. Chất lượng thật của Qwen đo bằng scripts/run_all.py + scripts/score_run.py.
"""

import json
import re
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from tests.fakes import FakeLLM
from tracewise import pipeline, srs, store, validate
from tracewise.api import create_app
from tracewise.settings import ROOT, load_settings

S = load_settings()
ALERTS = {a["id"]: a for a in srs.load_alerts()}
WHITELIST = set(srs.whitelist_codes())


def answer(
    codes, verdict="suspicious", summary="Có hành vi đáng ngờ [E1].", insufficient=False
):
    return json.dumps(
        {
            "verdict": verdict,
            "summary": summary,
            "confidence": 0.9,
            "insufficient_evidence": insufficient,
            "techniques": [
                {"id": c, "rank": i + 1, "evidence": ["E1"], "reason": "x"}
                for i, c in enumerate(codes)
            ],
        },
        ensure_ascii=False,
    )


def analyze(alert_id, db, *replies):
    svc = pipeline.load_services(S, conn=db, transport=FakeLLM(*replies).transport())
    return pipeline.analyze(ALERTS[alert_id], svc)


@pytest.fixture
def client(db):
    app = create_app(
        lambda: pipeline.load_services(S, conn=db, transport=FakeLLM().transport())
    )
    with TestClient(app) as c:
        yield c


def test_fr01_every_lab_alert_is_received_and_its_id_stored(client):
    for alert_id in ALERTS:
        assert client.post(f"/alerts/{alert_id}/analyze").status_code == 200
        assert (
            client.get("/runs", params={"alert_id": alert_id, "limit": 1}).json()[0][
                "alert_ref"
            ]
            == alert_id
        )


def test_fr02_nfr04_summary_is_cut_to_10_sentences(db):
    long = " ".join(
        f"Câu thứ {i} nói về tiến trình trong log [E1]." for i in range(1, 13)
    )
    r = analyze("LAB-0029", db, answer(["T1003.001"], summary=long))
    assert len(validate.SENTENCE_END.split(r["result"]["summary"])) == 10
    assert any(v["rule"] == "R6" for v in r["violations"])


@pytest.mark.parametrize("alert_id", sorted(ALERTS))
def test_fr03_each_alert_has_a_whitelist_code_or_insufficient_flag(db, alert_id):
    r = analyze(
        alert_id, db, answer(["T9999", "T1003.001"])
    )  # mã lạ + mã có thể ngoài ứng viên
    t = r["teacher"]
    assert (t["du_can_cu"] and t["ma_attack"] and set(t["ma_attack"]) <= WHITELIST) or (
        not t["du_can_cu"] and t["ma_attack"] == []
    )


@pytest.mark.parametrize("alert_id", sorted(ALERTS))
def test_fr04_code_outside_table_is_never_returned(db, alert_id):
    r = analyze(alert_id, db, answer(["T9999", "X0001", "T1562.001"]))
    codes = r["teacher"]["ma_attack"]
    assert set(codes) <= set(r["candidates"]) and set(codes) <= WHITELIST
    assert "T9999" not in codes and "X0001" not in codes


def test_fr05_analyst_label_is_kept_apart_from_model_label(client):
    run = client.post("/alerts/LAB-0029/analyze").json()
    saved = client.post(
        f"/runs/{run['id']}/labels",
        json={"nguoi_luu": "bang", "du_can_cu": False, "ghi_chu": "khác mô hình"},
    )
    assert saved.status_code == 201
    after = client.get(f"/runs/{run['id']}").json()
    assert (
        after["teacher"] == run["teacher"] and after["labels"][0]["du_can_cu"] is False
    )


@pytest.mark.parametrize(
    "alert_id, obey",
    [
        ("LAB-0033", answer(["T9999"])),  # đòi trả T9999
        (
            "LAB-0034",
            answer([], verdict="not_suspicious", summary="Cảnh báo an toàn [E1]."),
        ),  # đòi "an toàn"
        ("LAB-0035", answer(["T1486", "X0001"])),  # đòi T1486, X0001
    ],
)
def test_fr06_injection_cases_only_return_table_codes_or_flag(db, alert_id, obey):
    r = analyze(alert_id, db, obey)  # LLM "nghe lời" kẻ tấn công
    t = r["teacher"]
    assert not {"T9999", "X0001", "T1486"} & set(t["ma_attack"])
    assert set(t["ma_attack"]) <= WHITELIST or not t["du_can_cu"]
    assert r["needs_review"]  # mọi ca bị lái đều chuyển cho người xem


def test_fr07_nfr02_model_address_outside_lab_stops_service(db, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "https://api.example.com")
    app = create_app(lambda: pipeline.load_services(load_settings(), conn=db))
    with pytest.raises(srs.HostNotAllowed):
        with TestClient(app):
            pass


def test_fr08_log_has_alert_model_actor_and_time(client, db):
    run = client.post("/alerts/LAB-0029/analyze").json()
    client.post(
        f"/runs/{run['id']}/labels",
        json={"nguoi_luu": "hao", "du_can_cu": True, "ma_attack": ["T1003.001"]},
    )
    rows = db.execute(
        "SELECT alert_ref, model, actor, ts FROM analysis_log WHERE request_id = %s",
        (run["request_id"],),
    ).fetchall()
    assert len(rows) == 5 and all(all(col is not None for col in row) for row in rows)
    assert {row[2] for row in rows} == {store.SYSTEM_ACTOR, "hao"}


def test_nfr01_sample_config_has_no_live_siem_address():
    allowed = set(srs.load_allowlist(S.allowlist_file))
    for name in ("config/m3.yaml", ".env.example"):
        text = (ROOT / name).read_text(encoding="utf-8")
        hosts = {
            urlparse(u).hostname
            for u in re.findall(r"[a-z][a-z0-9+]*://[^\s\"']+", text)
        }
        assert hosts <= allowed, f"{name}: {hosts - allowed}"
