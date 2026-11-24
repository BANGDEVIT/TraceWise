"""Tạo data/srs/nhan_chuyen_gia_v1.csv từ nhãn gốc của thầy + bảng rà soát.

Chạy lại được bất cứ lúc nào (kết quả giống nhau):
    python scripts/build_labels_v1.py

- Giữ nguyên 4 cột gốc (alert_id, ma_attack_ky_vong, du_can_cu, ghi_chu) — không sửa nhãn của thầy.
- Thêm kich_ban, ma_chap_nhan (mã đó + cha + con, chỉ trong 24 mã của bảng), và kết quả rà soát
  (trang_thai_ra_soat, ma_phu_de_xuat, ly_do_ra_soat) đọc từ data/srs/ra_soat_nhan.csv.
"""

import csv

from tracewise import srs
from tracewise.attack import family, load_attack

REVIEW = srs.SRS_DIR / "ra_soat_nhan.csv"
COLUMNS = [
    "alert_id",
    "ma_attack_ky_vong",
    "du_can_cu",
    "ghi_chu",
    "kich_ban",
    "ma_chap_nhan",
    "trang_thai_ra_soat",
    "ma_phu_de_xuat",
    "ly_do_ra_soat",
]
STATES = {"dong_y", "de_xuat_them_ma", "can_ban"}


def load_review() -> dict[str, dict]:
    """{alert_id: dòng rà soát}; một dòng có thể áp cho nhiều cảnh báo (alert_ids ngăn bằng ';')."""
    review = {}
    with open(REVIEW, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if r["trang_thai"] not in STATES:
                raise ValueError(
                    f"Trạng thái lạ {r['trang_thai']!r} ở {r['alert_ids']}"
                )
            for aid in r["alert_ids"].split(";"):
                review[aid.strip()] = r
    return review


# {
#   "LAB-0001": {"alert_ids": "LAB-0001;LAB-0002", "trang_thai": "can_ban", ...},
#   "LAB-0002": {"alert_ids": "LAB-0001;LAB-0002", "trang_thai": "can_ban", ...},
#   "LAB-0003": {"alert_ids": "LAB-0003;LAB-0004", "trang_thai": "dong_y", ...},
#   ...
#   "LAB-0033": {"alert_ids": "LAB-0033", "trang_thai": "dong_y", ...},
#   ...
# }


def build_rows() -> list[dict]:
    """Các dòng của nhan_chuyen_gia_v1.csv (chưa ghi file)."""
    table, _ = load_attack()
    whitelist = set(srs.whitelist_codes())
    review = load_review()
    with open(srs.LABELS_V0, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    missing = {r["alert_id"] for r in rows} - set(review)
    if missing:
        raise SystemExit(f"Chưa rà soát: {sorted(missing)}")

    out = []
    for r in rows:
        code = r["ma_attack_ky_vong"].strip()
        rv = review[r["alert_id"]]
        extra = [c.strip() for c in rv["ma_phu_de_xuat"].split(";") if c.strip()]
        bad = [c for c in extra if c not in whitelist]
        if bad:
            raise SystemExit(f"{r['alert_id']}: mã đề xuất ngoài bảng 24 mã {bad}")
        accepted = sorted(family(code, table) & whitelist) if code else []
        out.append(
            {
                **r,
                "kich_ban": srs.scenario_of(r["ghi_chu"], r["du_can_cu"] == "co"),
                "ma_chap_nhan": ";".join(accepted),
                "trang_thai_ra_soat": rv["trang_thai"],
                "ma_phu_de_xuat": ";".join(extra),
                "ly_do_ra_soat": rv["ly_do"],
            }
        )
    return out


def main():
    out = build_rows()
    with open(srs.LABELS_V1, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(out)
    counts = {s: sum(r["trang_thai_ra_soat"] == s for r in out) for s in sorted(STATES)}
    widened = sum(
        r["ma_chap_nhan"] != r["ma_attack_ky_vong"]
        for r in out
        if r["ma_attack_ky_vong"]
    )
    print(f"{len(out)} nhãn -> {srs.LABELS_V1.relative_to(srs.ROOT)}")
    print(f"Trạng thái rà soát: {counts}")
    print(
        f"Nhãn có ma_chap_nhan rộng hơn mã gốc (quan hệ cha-con trong bảng): {widened}"
    )


if __name__ == "__main__":
    main()
