"""Phân tích MỘT cảnh báo lab qua toàn bộ hệ thống (không cần bật API), lưu vào database và evidence/.

    python scripts/analyze_one.py LAB-0029
Cần: Postgres đang chạy, Ollama đang chạy, đã chạy scripts/setup_db.py.
"""

import json
import sys

from tracewise import pipeline, srs, store
from tracewise.settings import ROOT

OUT_DIR = ROOT / "evidence" / "runs"


def main(alert_id: str) -> None:
    alerts = {a["id"]: a for a in srs.load_alerts()}
    if alert_id not in alerts:
        sys.exit(f"Không có cảnh báo {alert_id}")
    svc = pipeline.load_services()
    store.create_tables(svc.conn)
    label = srs.load_labels(srs.LABELS_V1)[alert_id]

    print(f"Đang phân tích {alert_id} (trên CPU mất khoảng 1–3 phút)...")
    run = pipeline.analyze(alerts[alert_id], svc)
    run_id = store.save_run(svc.conn, run)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{alert_id}_run{run_id}.json"
    out.write_text(json.dumps(run, ensure_ascii=False, indent=2), encoding="utf-8")

    print(
        f"\nLần chạy #{run_id} | trạng thái {run['status']} | cần người xem: {run['needs_review']} "
        f"| {run['latency_s']} giây"
    )
    for e in run["events"]:
        print(f"  {e['event']:10} {e['detail']['seconds']:>8.2f} s")
    print(f"Ứng viên:   {run['candidates']}")
    print(f"Nhãn (v1):  {label['ma_attack']}  (chấp nhận: {label['ma_chap_nhan']})")
    if run["status"] == "error":
        print(f"LỖI: {run['error']}")
    elif run["result"] is None:
        print(f"JSON hỏng. Đầu ra thô:\n{run['raw']}")
    else:
        res = run["result"]
        for t in res["techniques"]:
            print(
                f"  #{t['rank']} {t['id']} {t['name']}  bằng chứng {t['evidence']}  - {t['reason']}"
            )
        print(f"Tóm tắt:    {res['summary']}")
        print(
            f"Tin cậy:    {res['confidence']}  | token ra: {run['completion_tokens']}"
        )
        for v in run["violations"]:
            print(f"  [{v['rule']}] {v['detail']} -> {v['action']}")
    print(f"\nĐã lưu database (analysis_run id {run_id}) và {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "LAB-0029")
