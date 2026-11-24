"""Đọc cấu hình TraceWise từ config/m3.yaml và .env. Mọi thứ thay đổi theo máy nằm ở đây, không nằm trong code."""

import os
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = ROOT / "config" / "m3.yaml"
load_dotenv(
    ROOT / ".env"
)  # đọc .env nếu có; không ghi đè biến đã đặt sẵn (vd. trong CI)


class Strict(BaseModel):  # định nghĩa class, phần trong ngoặc là class cha
    # BaseModel:  khai báo kiểu (model: str, max_tokens: int)
    model_config = ConfigDict(
        extra="forbid"
    )  # gõ sai tên khóa trong YAML là báo lỗi ngay


class LLMConf(Strict):
    base_url: str
    model: str
    api_key_env: str | None = None
    temperature: float = Field(0.0, ge=0, le=2)
    seed: int = 42
    max_tokens: int = Field(800, gt=0)
    timeout_s: float = Field(900, gt=0)
    response_format: Literal["json_schema", "json_object", "none"] = "json_schema"
    reasoning_effort: str | None = None


class EmbedConf(Strict):
    base_url: str
    model: str
    dim: int = Field(768, gt=0)
    query_prefix: str = ""
    doc_template: str = "{text}"  # có thể dùng {title} và {text}


class AnalysisConf(Strict):
    prompt: str = "analyze_v1"
    summary_prompt: str = "summary_v1"
    rag: bool = True
    k: int = Field(5, gt=0)
    platform_filter: bool = True  # Tóm lại một câu: bật platform_filter thì khi tìm ứng viên, TraceWise tra bảng xem máy phát cảnh báo chạy hệ điều hành gì, rồi chỉ giữ những kỹ thuật ATT&CK có ghi hệ điều hành đó.
    query_mode: Literal["pack", "summary"] = "pack"


class DBConf(Strict):
    dsn_env: str = "M3_PG_DSN"  # chỉ ghi TÊN biến; mật khẩu nằm trong .env

    @property  # biến một hàm thành thứ dùng như một thuộc tính: gọi mà không cần dấu ngoặc ().
    def dsn(self) -> str:
        value = os.environ.get(self.dsn_env)
        if not value:
            raise RuntimeError(
                f"Thiếu biến môi trường {self.dsn_env}. "
                "Copy .env.example thành .env ở thư mục gốc rồi điền mật khẩu Postgres."
            )
        return value


# cách gọi DBConf.dsn # đúng: có @property nên gọi như thuộc tính @property trong Python chính là getter (get) trong TypeScript:


class Settings(Strict):
    llm: LLMConf
    embed: EmbedConf
    allowlist_file: Path
    attack_stix: Path
    analysis: AnalysisConf = AnalysisConf()
    host_platform: dict[str, str] = {}
    db: DBConf = DBConf()


def _ollama_base(host: str) -> str:
    """'localhost:11434' hoặc 'http://localhost:11434/' -> 'http://localhost:11434/v1'."""
    host = host.strip().rstrip("/")
    if "://" not in host:
        host = "http://" + host
    return host if host.endswith("/v1") else host + "/v1"


def load_settings(path: str | Path | None = None) -> Settings:
    """Đọc cấu hình: tham số path, hoặc biến M3_CONFIG, hoặc config/m3.yaml.

    Nếu có biến OLLAMA_HOST thì nó ghi đè địa chỉ LLM và embedding (cách README của thầy dùng để thử FR-07).
    """
    path = Path(path or os.environ.get("M3_CONFIG") or DEFAULT_CONFIG)
    if (
        not path.is_absolute()
    ):  # True nếu đường dẫn là tuyệt đối, False nếu là tương đối.
        path = ROOT / path
    with open(path, encoding="utf-8") as f:  # ← ra khỏi khối with, file f đã tự đóng
        s = Settings.model_validate(yaml.safe_load(f))
    host = os.environ.get("OLLAMA_HOST")
    if host:
        # s.llm.base_url = s.embed.base_url = _ollama_base(host)
        url = _ollama_base(host)
        s.llm.base_url = url  # Ollama dùng cho Qwen (chat)
        s.embed.base_url = url  # Ollama dùng cho embeddinggemma (embed
    s.allowlist_file = (
        s.allowlist_file if s.allowlist_file.is_absolute() else ROOT / s.allowlist_file
    )
    s.attack_stix = (
        s.attack_stix if s.attack_stix.is_absolute() else ROOT / s.attack_stix
    )
    return s
