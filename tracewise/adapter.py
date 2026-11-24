"""Gọi máy chủ mô hình theo chuẩn OpenAI (/v1). Ngày 4: embedding; Ngày 5 thêm chat.

Đổi Ollama sang vLLM, LM Studio… chỉ cần đổi base_url trong cấu hình.
"""

import os
from pathlib import Path

import httpx
import numpy as np

from .settings import EmbedConf, LLMConf
from .srs import check_host


class LLMError(RuntimeError):
    """Máy chủ mô hình lỗi, quá thời gian hoặc trả dữ liệu không đọc được."""


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

    def _post(self, url: str, body: dict) -> dict:
        try:
            r = self.http.post(url, json=body)
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise LLMError(f"{url}: {e}") from e

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
