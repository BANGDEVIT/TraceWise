"""Đọc MITRE ATT&CK Enterprise (STIX 2.1) ở MỘT chỗ duy nhất: tên, tactic, nền tảng, nguồn dữ liệu, mô tả."""

import json
import re
from dataclasses import (
    dataclass,
)  # : tạo class chứa dữ liệu mà không phải viết __init__
from functools import lru_cache
from pathlib import Path

from .settings import load_settings


@dataclass(frozen=True)
class Technique:
    id: str  # T1059.001
    name: str  # PowerShell
    tactics: tuple[str, ...]  # ("execution",)
    platforms: tuple[str, ...]  # ("Windows",)
    data_components: tuple[str, ...]
    description: str


# Chỉ khai báo tên trường và kiểu, @dataclass tự sinh các hàm sau:
# Hàm tự sinh  	Làm gì	                                    Ví dụ
# __init__	    Hàm khởi tạo nhận đủ các trường	            Context(id , name, tactics)
# __repr__	    In object ra dễ đọc	                        Context(id)
# __eq__	      So sánh hai object theo giá trị các trường	ctx1 == ctx2


def clean(text: str) -> str:
    """Bỏ trích dẫn, link markdown, thẻ <code> và khoảng trắng thừa trong mô tả ATT&CK."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"</?code>", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _live(o: dict) -> bool:
    """Đối tượng còn hiệu lực: không bị thu hồi (revoked), không bị bỏ (deprecated)."""
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def _data_components(objects: list[dict]) -> dict[str, set[str]]:
    # muốn phát hiện mỗi kỹ thuật ATT&CK thì cần loại log nào
    # Hàm này cho biết muốn thấy kỹ thuật X thì cần loại log Y
    """{id attack-pattern: tên data component}, theo chuỗi detection strategy -> analytic -> log source.

    Từ ATT&CK v18 kỹ thuật không còn trường x_mitre_data_sources.
    """
    by_id = {o["id"]: o for o in objects}
    out: dict[str, set[str]] = {}
    for r in objects:
        if (
            r["type"] != "relationship"
            or r.get("relationship_type") != "detects"
            or not _live(r)
        ):
            continue
        strategy = by_id.get(r["source_ref"])
        if strategy is None or not _live(strategy):
            continue
        names = out.setdefault(r["target_ref"], set())
        for a in strategy.get("x_mitre_analytic_refs", []):
            for ls in by_id[a].get("x_mitre_log_source_references", []):
                names.add(by_id[ls["x_mitre_data_component_ref"]]["name"])
    return out


@lru_cache(maxsize=2)
def _load(path: str) -> tuple[dict[str, Technique], str]:
    with open(path, encoding="utf-8") as f:
        objects = json.load(f)["objects"]
    version = next(
        o["x_mitre_version"] for o in objects if o["type"] == "x-mitre-collection"
    )
    detect = _data_components(objects)
    table = {}
    for o in objects:
        if o["type"] != "attack-pattern" or not _live(o):
            continue
        tid = next(
            r["external_id"]
            for r in o["external_references"]
            if r["source_name"] == "mitre-attack"
        )
        table[tid] = Technique(
            id=tid,
            name=o["name"],
            tactics=tuple(p["phase_name"] for p in o.get("kill_chain_phases", [])),
            platforms=tuple(o.get("x_mitre_platforms", [])),
            data_components=tuple(sorted(detect.get(o["id"], ()))),
            description=clean(o.get("description", "")),
        )
    return table, version


def load_attack(path: str | Path | None = None) -> tuple[dict[str, Technique], str]:
    """({mã: Technique} của mọi kỹ thuật còn hiệu lực, số phiên bản ATT&CK).

    Đọc file 50 MB mất cỡ nửa giây đến vài giây, nên kết quả được giữ lại (cache): gọi lại không đọc file nữa.
    """
    if path is None:
        path = load_settings().attack_stix
    return _load(str(Path(path).resolve()))


def tactic_slug(name: str) -> str:
    """'Command and Control' -> 'command-and-control' (cách viết tactic trong STIX)."""
    return name.strip().lower().replace(" ", "-")
