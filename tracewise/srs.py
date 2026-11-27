"""Bộ dữ liệu SRS-TTTN-M3 của thầy (cảnh báo, bảng mã, nhãn, khuôn đầu ra) và kiểm host LLM (FR-07)."""

import csv
import json
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .settings import ROOT

import hashlib
SRS_DIR = ROOT / "data" / "srs"


# ---------- dữ liệu của thầy ----------
def load_alerts(path: Path = SRS_DIR / "canh_bao_lab.jsonl") -> list[dict]:
    """35 cảnh báo lab, mỗi phần tử là một cảnh báo Wazuh (dict), giữ đúng thứ tự trong file."""
    results = []
    with open(path, encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError as e:
                        #try to load again
                        print(f"Error: dòng {line_no} không phải JSON hợp lệ ({e})")
                        continue
                    results.append(normalize_alert_line(item))
def normalize_alert_line(item: dict) -> dict:
    if isinstance(item, dict) and item.get("id") not in (None, ""):
        return item
    canonical = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    item["id"]= hashlib.md5(canonical.encode("utf-8")).hexdigest()
    return item


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


def whitelist_codes() -> list[str]:
    """Chỉ danh sách 24 mã, theo thứ tự trong file của thầy."""
    return [r["ma"] for r in load_whitelist()]


def scenario_of(note: str, du_can_cu: bool) -> str:
    """Nhóm độc lập của một nhãn: số rule của kịch bản, 'INJ' (chèn prompt) hoặc 'khong_du'."""
    if "CHÈN PROMPT" in note:
        return "INJ"
    if not du_can_cu:
        return "khong_du"
    return note.removeprefix("Kịch bản").strip()


LABELS_V0 = SRS_DIR / "nhan_chuyen_gia.csv"  # file gốc của thầy, không sửa
LABELS_V1 = (
    SRS_DIR / "nhan_chuyen_gia_v1.csv"
)  # bản đã rà: thêm cột, không đổi nhãn gốc


def _codes(cell: str | None) -> list[str]:
    """'T1110;T1110.001' -> ['T1110', 'T1110.001']; ô trống -> []."""
    return [c.strip() for c in (cell or "").split(";") if c.strip()]


def load_labels(path: Path = LABELS_V0) -> dict[str, dict]:
    """Nhãn theo alert_id.

    Luôn có: "ma_attack" (mã hoặc None), "du_can_cu" (bool), "kich_ban", "ghi_chu".
    Đọc bản đã rà (LABELS_V1) thì có thêm: "ma_chap_nhan" (mã đó + cha + con trong bảng 24 mã),
    "ma_phu_de_xuat" (mã người rà đề xuất, CHƯA được duyệt), "trang_thai_ra_soat", "ly_do_ra_soat".
    """
    labels = {}
    with open(path, encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            du = r["du_can_cu"].strip() == "co"
            code = r["ma_attack_ky_vong"].strip() or None
            labels[r["alert_id"]] = {
                "ma_attack": code,
                "du_can_cu": du,
                "kich_ban": scenario_of(r["ghi_chu"], du),
                "ghi_chu": r["ghi_chu"],
                "ma_chap_nhan": _codes(r.get("ma_chap_nhan"))
                or ([code] if code else []),
                "ma_phu_de_xuat": _codes(r.get("ma_phu_de_xuat")),
                "trang_thai_ra_soat": r.get("trang_thai_ra_soat") or None,
                "ly_do_ra_soat": r.get("ly_do_ra_soat") or None,
            }
    return labels


def alert_lines(alert: dict, with_rule: bool = True, max_chars: int = 400) -> list[str]:
    """Gói bằng chứng mức 0: tách một cảnh báo Wazuh thành các dòng (chưa đánh số E…).

    with_rule=False bỏ dòng rule (dùng khi đo chèn prompt: rule của 3 ca INJ tự khai là bài thử).
    """
    lines = []
    if with_rule:
        r = alert["rule"]
        lines.append(
            f"rule {r['id']} (level {r['level']}): {r['description']}; "
            f"groups: {', '.join(r.get('groups', []))}"
        )
    lines.append(f"agent: {alert['agent']['name']}")
    lines.append(f"full_log: {alert['full_log']}")
    for key, val in alert.get("data", {}).items():
        lines.append(f"data.{key}: {val}")
    return [line[:max_chars] for line in lines]


class Assessment(BaseModel):
    """Khuôn đầu ra của thầy: dùng khi chấm theo nhãn, không dùng bên trong TraceWise."""

    model_config = ConfigDict(extra="forbid")
    tom_tat: str = Field(min_length=20, max_length=600)
    du_can_cu: bool
    ma_attack: list[str] = Field(max_length=3)
    bang_chung: list[str] = Field(min_length=1, max_length=6)


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
