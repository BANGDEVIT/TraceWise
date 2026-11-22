"""settings.py: đọc cấu hình đúng, sai khóa thì báo lỗi, thiếu mật khẩu DB thì báo rõ, OLLAMA_HOST ghi đè được."""

import pytest
from pydantic import ValidationError

from tracewise.settings import ROOT, load_settings


def test_default_config_follows_b6_decision():
    s = load_settings()
    assert s.llm.model == "qwen3.5:4b"
    assert s.llm.response_format == "json_schema"
    assert s.llm.reasoning_effort == "none"  # chuỗi "none", không phải None
    assert s.attack_stix == ROOT / "data" / "attack" / "enterprise-attack-18.1.json"
    assert s.host_platform["lab-win02"] == "Windows"


# gõ sai tên khóa trong YAML phải báo lỗi, không được lặng lẽ bỏ qua.
def test_unknown_key_is_rejected(tmp_path):
    text = (ROOT / "config" / "m3.yaml").read_text(encoding="utf-8")
    cfg = tmp_path / "typo.yaml"
    cfg.write_text(text.replace("max_tokens:", "max_token:"), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_settings(cfg)


# thiếu biến M3_PG_DSN thì phải báo lỗi dễ hiểu, có nhắc tên biến.
def test_missing_dsn_gives_clear_error(monkeypatch):
    monkeypatch.delenv("M3_PG_DSN", raising=False)
    with pytest.raises(RuntimeError, match="M3_PG_DSN"):
        load_settings().db.dsn


# chạy cùng một test 3 lần, mỗi lần một cặp (host, expected)
@pytest.mark.parametrize(
    "host, expected",
    [
        ("http://lab-llm:8000", "http://lab-llm:8000/v1"),
        ("localhost:11434", "http://localhost:11434/v1"),
        ("https://api.example.com/", "https://api.example.com/v1"),
    ],
)
#  biến OLLAMA_HOST phải ghi đè địa chỉ trong YAML và được chuẩn hóa đúng, với nhiều kiểu viết khác nhau.
def test_ollama_host_overrides_base_url(monkeypatch, host, expected):
    monkeypatch.setenv("OLLAMA_HOST", host)
    s = load_settings()
    assert s.llm.base_url == expected and s.embed.base_url == expected
