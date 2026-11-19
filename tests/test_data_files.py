"""Ngày 1: bộ dữ liệu của thầy và file ATT&CK đúng như README. Không cần Ollama hay Postgres."""

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRS = ROOT / "data" / "srs"
STIX = ROOT / "data" / "attack" / "enterprise-attack-18.1.json"
STIX_MD5 = "4be6b501abe1fa6c7616f3666be5ac3f"


def read_csv(name):
    with open(SRS / name, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def alert_ids():
    lines = (SRS / "canh_bao_lab.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line)["id"] for line in lines if line.strip()]


def test_35_alerts_with_unique_ids():
    ids = alert_ids()
    assert len(ids) == 35 and len(set(ids)) == 35


def test_whitelist_has_24_unique_codes():
    codes = [r["ma"] for r in read_csv("attack_subset.csv")]
    assert len(codes) == 24 and len(set(codes)) == 24


def test_every_alert_has_one_label():
    labels = read_csv("nhan_chuyen_gia.csv")
    assert sorted(r["alert_id"] for r in labels) == sorted(alert_ids())
    assert {r["du_can_cu"] for r in labels} <= {"co", "khong"}


def test_attack_file_is_version_18_1():
    assert hashlib.md5(STIX.read_bytes()).hexdigest() == STIX_MD5
