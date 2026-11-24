"""Ứng viên RAG cho 35 cảnh báo của thầy: hạng của mã đúng, hit@1/3/5, MRR, có và không lọc nền tảng.

CHỈ để báo cáo. Không dùng kết quả này để chọn k hay sửa câu truy vấn (đó là "nhìn đề";
chọn k phải dùng tập phát triển riêng).
    python scripts/check_candidates.py
Ghi chi tiết vào results/candidates_lab.csv.
"""

import csv

from tracewise import rag, srs
from tracewise.adapter import OpenAICompatClient
from tracewise.settings import ROOT, load_settings

K = 5
OUT = ROOT / "results" / "candidates_lab.csv"


def rank_of(found: list[str], accepted: list[str]) -> int | None:
    """Hạng (1..k) của mã chấp nhận được đầu tiên trong danh sách ứng viên; không có thì None."""
    return next((i + 1 for i, c in enumerate(found) if c in accepted), None)


def summarize(ranks: list[int | None]) -> str:
    n = len(ranks)
    hit = {k: sum(r is not None and r <= k for r in ranks) / n for k in (1, 3, 5)}
    mrr = sum(1 / r for r in ranks if r) / n
    return f"hit@1 {hit[1]:.2f} | hit@3 {hit[3]:.2f} | hit@5 {hit[5]:.2f} | MRR {mrr:.2f} (n={n})"


def main():
    s = load_settings()
    client = OpenAICompatClient(s.llm, s.embed, s.allowlist_file)
    conn = rag.connect(s.db.dsn)
    labels = srs.load_labels(srs.LABELS_V1)
    alerts = [
        a for a in srs.load_alerts() if labels[a["id"]]["ma_attack"]
    ]  # bỏ 2 ca không đủ căn cứ

    queries = [rag.alert_query(srs.alert_lines(a)) for a in alerts]
    vectors, served = client.embed([rag.as_query(q, s.embed) for q in queries])

    rows, ranks = [], {"khong_loc": [], "loc_nen_tang": []}
    for a, q, vec in zip(alerts, queries, vectors):
        accepted = labels[a["id"]]["ma_chap_nhan"]
        host = a["agent"]["name"]
        for mode, platform in (
            ("khong_loc", None),
            ("loc_nen_tang", s.host_platform.get(host)),
        ):
            found = [c for c, _, _ in rag.search(conn, vec, K, platform)]
            r = rank_of(found, accepted)
            ranks[mode].append(r)
            rows.append(
                {
                    "alert_id": a["id"],
                    "may": host,
                    "che_do": mode,
                    "nen_tang": platform or "",
                    "ma_dung": ";".join(accepted),
                    "hang": r or "",
                    "ung_vien": ";".join(found),
                    "cau_truy_van": q.replace("\n", " | "),
                }
            )

    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"Mô hình embedding: {served}; k = {K}")
    for mode, r in ranks.items():
        print(f"{mode:13} {summarize(r)}")
    missed = sorted(
        {
            row["alert_id"]
            for row in rows
            if row["che_do"] == "loc_nen_tang" and not row["hang"]
        }
    )
    print(f"Không có mã đúng trong top {K} (lọc nền tảng): {missed}")
    print(f"Chi tiết: {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
