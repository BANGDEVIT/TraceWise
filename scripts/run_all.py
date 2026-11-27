"""Chạy thật toàn bộ cảnh báo lab qua TraceWise, lưu database + một file JSONL cho lượt chạy.

    python scripts/run_all.py                                  # 35 cảnh báo, ~40 phút trên CPU
    python scripts/run_all.py --only LAB-0029,LAB-0033,LAB-0034,LAB-0035    # 1 ca thường + 3 ca chèn
    python scripts/run_all.py --batch lab35_a --inj-without-rule            # thêm 3 ca chèn không có dòng rule
    python scripts/run_all.py --batch lab35_a                  # chạy lại cùng tên: bỏ qua ca đã xong (chạy tiếp)

Kết quả: results/runs/<batch>.jsonl (mỗi dòng một lần chạy). Chấm bằng scripts/score_run.py.
"""

import argparse
import json
import time
from datetime import datetime

from tracewise import pipeline, srs, store
from tracewise.settings import ROOT

RUNS_DIR = ROOT / "results" / "runs"


def done_keys(path) -> set[tuple]:
    """Các (cảnh báo, có dòng rule) đã có trong file: để chạy tiếp khi bị ngắt giữa chừng."""
    if not path.exists():
        return set()
    with open(path, encoding="utf-8") as f:
        return {
            (r["alert_ref"], r["config"].get("with_rule", True))
            for r in map(json.loads, f)
            if r["status"] != "error"
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", default=datetime.now().strftime("lab35_%Y%m%d_%H%M"))
    ap.add_argument("--only", help="danh sách mã cảnh báo, cách nhau bằng dấu phẩy")
    ap.add_argument(
        "--inj-without-rule",
        action="store_true",
        help="chạy thêm 3 ca chèn prompt mà không có dòng rule tự khai",
    )
    args = ap.parse_args()

    labels = srs.load_labels(srs.LABELS_V1)
    alerts = srs.load_alerts()
    if args.only:
        wanted = {a.strip() for a in args.only.split(",")}
        alerts = [a for a in alerts if a["id"] in wanted]
    jobs = [(a, True) for a in alerts]
    if args.inj_without_rule:
        jobs += [(a, False) for a in alerts if labels[a["id"]]["kich_ban"] == "INJ"]

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    out = RUNS_DIR / f"{args.batch}.jsonl"
    skip = done_keys(out)
    jobs = [(a, w) for a, w in jobs if (a["id"], w) not in skip]
    print(
        f"Lượt {args.batch}: {len(jobs)} lần chạy (bỏ qua {len(skip)} đã xong) -> {out.relative_to(ROOT)}"
    )

    svc = pipeline.load_services()
    store.create_tables(svc.conn)
    t_all = time.perf_counter()
    for i, (alert, with_rule) in enumerate(jobs, 1):
        run = pipeline.analyze(alert, svc, with_rule=with_rule)
        run["config"]["batch"] = args.batch
        run["run_id"] = store.save_run(svc.conn, run)
        with open(out, "a", encoding="utf-8") as f:
            f.write(json.dumps(run, ensure_ascii=False) + "\n")
        codes = (run["teacher"] or {}).get("ma_attack")
        print(
            f"[{i}/{len(jobs)}] {alert['id']}{'' if with_rule else ' (không rule)'}: "
            f"{run['status']} {codes} nhãn={labels[alert['id']]['ma_attack']} "
            f"{run['latency_s']:.0f}s run_id={run['run_id']}",
            flush=True,
        )
    print(
        f"Xong sau {(time.perf_counter() - t_all) / 60:.1f} phút. Chấm: python scripts/score_run.py {out.relative_to(ROOT)}"
    )


if __name__ == "__main__":
    main()
