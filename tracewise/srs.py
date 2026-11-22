"""Bộ dữ liệu SRS-TTTN-M3 của thầy (cảnh báo, bảng mã, nhãn) và kiểm host LLM theo allowlist (FR-07)."""

import csv
import json
from pathlib import Path
from urllib.parse import (
    urlparse,
)  # tách một URL thành từng phần để đọc riêng: giao thức, tên máy, cổng, đường dẫn…

import yaml
from .settings import ROOT

SRS_DIR = ROOT / "data" / "srs"


# ---------- dữ liệu của thầy ----------
def load_alerts(path: Path = SRS_DIR / "canh_bao_lab.jsonl") -> list[dict]:
    """35 cảnh báo lab, mỗi phần tử là một cảnh báo Wazuh (dict), giữ đúng thứ tự trong file."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def load_whitelist(path: Path = SRS_DIR / "attack_subset.csv") -> list[dict]:
    """24 kỹ thuật được phép: {"ma", "ten", "chien_thuat": [tactic, ...]}."""
    with open(path, encoding="utf-8", newline="") as f:
        return [
            {
                "ma": r["ma"],
                "ten": r["ten"],
                "chien_thuat": [t.strip() for t in r["chien_thuat"].split(",")],
            }
            for r in csv.DictReader(f)
        ]


# scenario_of gom nhãn về 17 nhóm độc lập: 15 kịch bản (tên nhóm là số rule, ví dụ "5710") + "INJ" + "khong_du"
# Mỗi kịch bản có 2 cảnh báo gần giống hệt nhau. Khi tính khoảng tin cậy, phải lấy mẫu theo nhóm chứ không theo từng cảnh báo
def scenario_of(note: str, du_can_cu: bool) -> str:
    """Nhóm độc lập của một nhãn: số rule của kịch bản, 'INJ' (chèn prompt) hoặc 'khong_du'."""
    if "CHÈN PROMPT" in note:
        return "INJ"
    if not du_can_cu:
        return "khong_du"
    return note.removeprefix("Kịch bản").strip()


def load_labels(path: Path = SRS_DIR / "nhan_chuyen_gia.csv") -> dict[str, dict]:
    """Nhãn chuyên gia theo alert_id: {"ma_attack": mã hoặc None, "du_can_cu": bool, "kich_ban", "ghi_chu"}."""
    labels = {}
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            du = r["du_can_cu"].strip() == "co"
            labels[r["alert_id"]] = {
                "ma_attack": r["ma_attack_ky_vong"].strip() or None,
                "du_can_cu": du,
                "kich_ban": scenario_of(r["ghi_chu"], du),
                "ghi_chu": r["ghi_chu"],
            }
    return labels


# ---------- FR-07: chỉ gọi LLM ở host trong allowlist ----------
class HostNotAllowed(RuntimeError):
    """Địa chỉ LLM nằm ngoài allowlist: dừng, không gửi dữ liệu đi."""


def load_allowlist(path: Path = SRS_DIR / "allowlist_llm.yaml") -> set[str]:
    with open(path, encoding="utf-8") as f:
        return {str(h).lower() for h in yaml.safe_load(f)["hosts"]}


def check_host(raw: str, allowlist_file: Path = SRS_DIR / "allowlist_llm.yaml") -> str:
    """Trả về URL đã chuẩn hóa nếu host thuộc allowlist; ngược lại ném HostNotAllowed.

    So sánh hostname sau khi phân tích URL (không so chuỗi con), nên các bẫy như
    'localhost.evil.com', 'localhost@evil.com', 'evil.com/localhost' đều bị chặn.
    URL có kèm tên đăng nhập hoặc mật khẩu cũng bị chặn.
    """
    url = raw.strip() if "://" in raw else f"http://{raw.strip()}"
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if p.username or p.password or host not in load_allowlist(allowlist_file):
        raise HostNotAllowed(f"Địa chỉ LLM ngoài allowlist: {raw!r} (host={host!r})")
    return url.rstrip("/")
