"""Chấm một lượt chạy theo nhãn v1, ghi báo cáo Markdown, bảng từng cảnh báo và phiếu chấm tay FR-02.

    python scripts/score_run.py results/runs/<batch>.jsonl
Ghi: results/<batch>_score.md, results/<batch>_per_alert.csv, results/<batch>_cham_tay.csv
"""

import csv
import json
import random
import sys
from pathlib import Path

from tracewise import evaluate
from tracewise.settings import ROOT

SAMPLE = 10  # FR-02: chấm tay 10 tóm tắt


def write_csv(path: Path, rows: list[dict]) -> None:
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with open(
        path, "w", encoding="utf-8-sig", newline=""
    ) as f:  # utf-8-sig: Excel đọc đúng tiếng Việt
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def main(path: str) -> None:
    src = Path(path) if Path(path).is_absolute() else ROOT / path
    with open(src, encoding="utf-8") as f:
        runs = [json.loads(line) for line in f if line.strip()]
    rows, summary = evaluate.score(runs)
    batch = src.stem
    out = ROOT / "results"
    (out / f"{batch}_score.md").write_text(
        evaluate.report_md(batch, summary), encoding="utf-8"
    )
    write_csv(out / f"{batch}_per_alert.csv", rows)

    ok = sorted(
        (r for r in runs if r["status"] == "ok" and r["config"].get("with_rule", True)),
        key=lambda r: r["alert_ref"],
    )
    picked = sorted(
        random.Random(0).sample(ok, min(SAMPLE, len(ok))), key=lambda r: r["alert_ref"]
    )
    write_csv(
        out / f"{batch}_cham_tay.csv",
        [
            {
                "alert_id": r["alert_ref"],
                "run_id": r.get("run_id"),
                "tom_tat": r["result"]["summary"],
                "goi_bang_chung": " | ".join(f"{k}: {v}" for k, v in r["pack"].items()),
                "dung_su_that_0_2": "",
                "du_y_chinh_0_2": "",
                "tieng_viet_ro_rang_0_2": "",
                "ghi_chu": "",
            }
            for r in picked
        ],
    )

    print((out / f"{batch}_score.md").read_text(encoding="utf-8"))
    print(
        f"Đã ghi results/{batch}_score.md, results/{batch}_per_alert.csv, results/{batch}_cham_tay.csv"
    )


if __name__ == "__main__":
    main(sys.argv[1])
