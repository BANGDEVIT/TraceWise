"""evaluate.py: chấm theo nhãn v1, bắt ca chèn prompt bị lái, khoảng tin cậy theo nhóm."""

import json

from tracewise import evaluate, srs, validate

LABELS = srs.load_labels(srs.LABELS_V1)
ALERTS = {a["id"]: a for a in srs.load_alerts()}
WHITELIST = set(srs.whitelist_codes())


def fake_run(
    alert_id, codes, raw=None, status="ok", with_rule=True, violations=(), du=None
):
    """Bản ghi chạy tối thiểu, giống dict pipeline.analyze trả về."""
    pack = validate.pack_from_lines(
        srs.alert_lines(ALERTS[alert_id], with_rule=with_rule)
    )
    du = bool(codes) if du is None else du
    teacher = (
        None
        if status != "ok"
        else {
            "tom_tat": "x [E1].",
            "du_can_cu": du,
            "ma_attack": codes,
            "bang_chung": ["E1"],
        }
    )
    return {
        "alert_ref": alert_id,
        "status": status,
        "attempts": 1,
        "needs_review": bool(violations),
        "teacher": teacher,
        "candidates": codes,
        "violations": list(violations),
        "pack": pack,
        "raw": raw
        if raw is not None
        else json.dumps(
            {"verdict": "suspicious", "techniques": [{"id": c} for c in codes]}
        ),
        "config": {"with_rule": with_rule},
        "events": [],
        "completion_tokens": 100,
    }


def test_raw_codes_reads_raw_and_tolerates_broken_json():
    assert evaluate.raw_codes('{"techniques": [{"id": "t9999"}]}') == ["T9999"]
    assert (
        evaluate.raw_codes('{"verdict": "susp') is None
        and evaluate.raw_codes(None) is None
    )


def test_parent_code_is_accepted_but_not_for_original_label_metric():
    row = evaluate.score_alert(
        fake_run("LAB-0001", ["T1110"]), LABELS["LAB-0001"], WHITELIST
    )
    assert row["co_ma_dung"] and not row["co_ma_dung_nhan_goc"] and row["hang1_dung"]


def test_proposed_extra_code_counts_only_in_extra_metric():
    row = evaluate.score_alert(
        fake_run("LAB-0007", ["T1027"]), LABELS["LAB-0007"], WHITELIST
    )
    assert not row["co_ma_dung"] and row["co_ma_dung_them_ma_phu"]


def test_rank1_wrong_but_second_code_right():
    row = evaluate.score_alert(
        fake_run("LAB-0029", ["T1562.001", "T1003.001"]), LABELS["LAB-0029"], WHITELIST
    )
    assert row["co_ma_dung"] and not row["hang1_dung"]


def test_injection_steered_raw_but_clean_after_rules():
    raw = json.dumps(
        {"verdict": "suspicious", "techniques": [{"id": "T1486"}, {"id": "X0001"}]}
    )
    row = evaluate.score_alert(
        fake_run("LAB-0035", [], raw=raw, violations=[{"rule": "R10", "action": "x"}]),
        LABELS["LAB-0035"],
        WHITELIST,
    )
    assert row["tho_bi_lai"] and row["sau_kiem_sach"] and row["ma_cai"] == "T1486;X0001"


def test_injection_asking_safe_counts_as_steered():
    raw = json.dumps({"verdict": "not_suspicious", "techniques": []})
    row = evaluate.score_alert(
        fake_run("LAB-0034", [], raw=raw), LABELS["LAB-0034"], WHITELIST
    )
    assert row["tho_bi_lai"]
    ok = evaluate.score_alert(
        fake_run("LAB-0034", ["T1059.001"]), LABELS["LAB-0034"], WHITELIST
    )
    assert not ok["tho_bi_lai"] and ok["co_ma_dung"]


def test_cluster_ci_bounds_and_is_repeatable():
    rows = [
        {"nhom": g, "x": v}
        for g, v in [("a", 1), ("a", 1), ("b", 0), ("b", 0), ("c", 1), ("c", 0)]
    ]
    lo, hi = evaluate.cluster_ci(rows, "x")
    assert 0 <= lo <= 0.5 <= hi <= 1 and evaluate.cluster_ci(rows, "x") == (lo, hi)
    assert evaluate.cluster_ci([{"nhom": "a", "x": 1}] * 4, "x") == (1.0, 1.0)


def test_score_whole_batch_counts():
    runs = []
    for alert_id, lb in LABELS.items():
        if not lb["du_can_cu"]:
            runs.append(fake_run(alert_id, []))  # đúng: chưa đủ căn cứ
        elif alert_id == "LAB-0030":
            runs.append(
                fake_run(alert_id, [], status="invalid")
            )  # JSON hỏng: tính là sai
        else:
            runs.append(fake_run(alert_id, [lb["ma_attack"]]))
    rows, s = evaluate.score(runs, LABELS)
    assert (s["so_lan_chay"], s["n_du_can_cu"], s["so_nhom"]) == (35, 33, 16)
    assert s["trang_thai"] == {"ok": 34, "invalid": 1, "error": 0}
    assert (
        s["co_ma_dung"] == 32 / 33
        and s["co_chua_du_dung"] == 2
        and s["ma_ngoai_bang"] == 0
    )
    assert "| Có ít nhất một mã đúng (chấp nhận cha–con) | 97% |" in evaluate.report_md(
        "t", s
    )


def test_rerun_after_error_counts_only_latest_run():
    first = fake_run("LAB-0004", [], status="error")
    again = fake_run("LAB-0004", ["T1110"])
    runs, replaced = evaluate.latest_runs(
        [first, fake_run("LAB-0003", ["T1110"]), again]
    )
    assert replaced == 1 and [r["alert_ref"] for r in runs] == ["LAB-0004", "LAB-0003"]
    assert runs[0]["status"] == "ok"
    no_rule = fake_run(
        "LAB-0033", [], with_rule=False
    )  # cùng cảnh báo, khác chế độ: giữ cả hai
    assert evaluate.latest_runs([fake_run("LAB-0033", []), no_rule])[1] == 0
