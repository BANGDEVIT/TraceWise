"""Nhãn đã rà (nhan_chuyen_gia_v1.csv): không đổi nhãn gốc của thầy, cột thêm vào đúng quy tắc."""

import csv
import runpy

from tracewise import srs
from tracewise.settings import ROOT

V0 = srs.load_labels(srs.LABELS_V0)
V1 = srs.load_labels(srs.LABELS_V1)
WHITELIST = set(srs.whitelist_codes())


def test_teacher_labels_are_unchanged():
    assert V1.keys() == V0.keys()
    for aid in V0:
        for key in ("ma_attack", "du_can_cu", "ghi_chu", "kich_ban"):
            assert V1[aid][key] == V0[aid][key], (aid, key)


def test_every_alert_was_reviewed():
    states = {lb["trang_thai_ra_soat"] for lb in V1.values()}
    assert states <= {"dong_y", "de_xuat_them_ma", "can_ban"} and None not in states
    assert all(lb["ly_do_ra_soat"] for lb in V1.values())


def test_accepted_codes_follow_the_rule():
    for aid, lb in V1.items():
        if lb["ma_attack"]:
            assert lb["ma_attack"] in lb["ma_chap_nhan"], aid
        assert set(lb["ma_chap_nhan"]) <= WHITELIST, aid
        assert set(lb["ma_phu_de_xuat"]) <= WHITELIST, aid
    assert V1["LAB-0003"]["ma_chap_nhan"] == ["T1110", "T1110.001"]  # cha nhận con
    assert V1["LAB-0001"]["ma_chap_nhan"] == ["T1110", "T1110.001"]  # con nhận cha
    assert V1["LAB-0031"]["ma_chap_nhan"] == []


def test_proposals_are_kept_apart_until_approved():
    assert V1["LAB-0007"]["ma_phu_de_xuat"] == ["T1027"]
    assert "T1027" not in V1["LAB-0007"]["ma_chap_nhan"]


def test_v1_file_matches_build_script():
    """File trong repo phải đúng bằng kết quả của script (không sửa tay)."""
    build_rows = runpy.run_path(str(ROOT / "scripts" / "build_labels_v1.py"))[
        "build_rows"
    ]
    with open(srs.LABELS_V1, encoding="utf-8", newline="") as f:
        assert list(csv.DictReader(f)) == build_rows()


def test_v0_still_loads_with_default_columns():
    assert V0["LAB-0001"]["ma_chap_nhan"] == ["T1110.001"]
    assert (
        V0["LAB-0001"]["ma_phu_de_xuat"] == []
        and V0["LAB-0001"]["trang_thai_ra_soat"] is None
    )
