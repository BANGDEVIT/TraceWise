"""Gọi máy chủ mô hình theo chuẩn OpenAI (/v1): embedding (Ngày 4) và chat (Ngày 5).

Đổi Ollama sang vLLM, LM Studio… chỉ cần đổi base_url trong cấu hình.
"""

import os
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import numpy as np

from .settings import EmbedConf, LLMConf
from .srs import check_host


class LLMError(RuntimeError):
    """Máy chủ mô hình lỗi, quá thời gian hoặc trả dữ liệu không đọc được."""


@dataclass
class ChatReply:
    """Một câu trả lời của LLM kèm số liệu để lưu (NFR-REP-01) và đo tốc độ."""

    content: str  # chữ mô hình viết (JSON khi có schema)
    model: str  # tên mô hình MÁY CHỦ trả về, không phải tên trong cấu hình
    finish_reason: str | None  # "stop" là xong; "length" là bị cắt vì hết max_tokens
    prompt_tokens: int | None
    completion_tokens: int | None
    seconds: float


class OpenAICompatClient:
    def __init__(
        self,
        llm: LLMConf,
        embed: EmbedConf,
        allowlist_file: Path,
        transport: httpx.BaseTransport | None = None,
    ):
        # FR-07: kiểm host NGAY khi tạo client, trước khi có bất kỳ dữ liệu nào được gửi đi
        self.llm_url = check_host(llm.base_url, allowlist_file)
        self.embed_url = check_host(embed.base_url, allowlist_file)
        self.llm, self.embed_conf = llm, embed
        key = os.environ.get(llm.api_key_env) if llm.api_key_env else None
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        self.http = httpx.Client(
            timeout=llm.timeout_s, transport=transport, headers=headers
        )

    def close(self) -> None:
        self.http.close()

    def _post(self, url: str, body: dict) -> dict:
        try:
            r = self.http.post(url, json=body)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise LLMError(f"{url}: {e}") from e

    # ---------- embedding ----------
    def embed(self, texts: list[str], batch: int = 8) -> tuple[np.ndarray, str]:
        """(mảng vector đã chuẩn hóa độ dài 1, tên mô hình máy chủ trả về)."""
        vectors, served = [], self.embed_conf.model
        for i in range(0, len(texts), batch):
            d = self._post(
                f"{self.embed_url}/embeddings",
                {"model": self.embed_conf.model, "input": texts[i : i + batch]},
            )
            served = d.get("model", served)
            vectors += [
                item["embedding"]
                for item in sorted(d["data"], key=lambda x: x["index"])
            ]
        arr = np.array(vectors, dtype=np.float32)
        if arr.ndim != 2 or arr.shape[1] != self.embed_conf.dim:
            raise LLMError(
                f"vector có {arr.shape[-1]} chiều, cấu hình ghi {self.embed_conf.dim}"
            )
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        return arr / np.where(norms == 0, 1, norms), served

    # ---------- chat ----------
    def chat(
        self,
        messages: list[dict],
        schema: dict | None = None,
        max_tokens: int | None = None,
    ) -> ChatReply:
        """Gọi /chat/completions. Có schema thì máy chủ ép đầu ra theo schema (enum áp lúc sinh, B6)."""
        body = {
            "model": self.llm.model,
            "messages": messages,
            "temperature": self.llm.temperature,
            "seed": self.llm.seed,
            "max_tokens": max_tokens or self.llm.max_tokens,
        }
        if schema is not None and self.llm.response_format == "json_schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "analysis", "strict": True, "schema": schema},
            }
        elif schema is not None and self.llm.response_format == "json_object":
            body["response_format"] = {"type": "json_object"}
        if self.llm.reasoning_effort:
            body["reasoning_effort"] = (
                self.llm.reasoning_effort
            )  # B6: "none" để Qwen không "suy nghĩ"

        t0 = time.perf_counter()
        d = self._post(f"{self.llm_url}/chat/completions", body)
        seconds = time.perf_counter() - t0
        try:
            choice = d["choices"][0]
            content = choice["message"].get("content") or ""
        except (KeyError, IndexError, TypeError, AttributeError) as e:
            raise LLMError(
                f"câu trả lời không đúng chuẩn OpenAI: {str(d)[:200]}"
            ) from e
        usage = d.get("usage") or {}
        return ChatReply(
            content=content,
            model=d.get("model", self.llm.model),
            finish_reason=choice.get("finish_reason"),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            seconds=round(seconds, 2),
        )


# d = self._post(f"{self.llm_url}/chat/completions", body)
# {
#     "id": "chatcmpl-123",
#     "model": "qwen3.5:4b",
#     "choices": [
#         {
#             "index": 0,
#             "message": {
#                 "role": "assistant",
#                 "content": '{"verdict": "suspicious", ...}',
#             },
#             "finish_reason": "stop",
#         }
#     ],
#     "usage": {"prompt_tokens": 812, "completion_tokens": 142, "total_tokens": 954},
# }
