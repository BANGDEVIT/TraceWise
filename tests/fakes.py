"""Máy chủ Ollama GIẢ cho test: embedding "túi từ" + chat trả lời theo kịch bản test đặt sẵn.

Không hiểu nghĩa, chỉ để kiểm đường ống (gọi đúng địa chỉ, đúng khuôn, lưu đúng chỗ).
"""

import json
import re
import zlib

import httpx


def bag_of_words(text, dim=768):
    v = [0.0] * dim
    for w in re.findall(r"\w+", text.lower()):
        v[zlib.crc32(w.encode()) % dim] += 1
    return v


def first_candidate_answer(body):
    """Câu trả lời 'ngoan': chọn ứng viên đầu tiên trong enum, trích dòng E1."""
    tech = body["response_format"]["json_schema"]["schema"]["$defs"]["Technique"][
        "properties"
    ]
    return json.dumps(
        {
            "verdict": "suspicious",
            "summary": "Cảnh báo cho thấy hành vi đáng ngờ trên máy [E1].",
            "techniques": [
                {
                    "id": tech["id"]["enum"][0],
                    "rank": 1,
                    "evidence": [tech["evidence"]["items"]["enum"][0]],
                    "reason": "Dòng E1.",
                }
            ],
            "confidence": 0.6,
            "insufficient_evidence": False,
        },
        ensure_ascii=False,
    )


class FakeLLM:
    """replies: mỗi lần gọi chat lấy một phần tử: chuỗi (nội dung), hàm(body) -> chuỗi, hoặc httpx.Response.
    Hết danh sách thì trả first_candidate_answer."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []  # [(path, body)]

    def __call__(self, request):
        body = json.loads(request.content)
        self.requests.append((request.url.path, body))
        if request.url.path.endswith("/embeddings"):
            return httpx.Response(
                200,
                json={
                    "model": "embeddinggemma:latest",
                    "data": [
                        {"index": i, "embedding": bag_of_words(t)}
                        for i, t in enumerate(body["input"])
                    ],
                },
            )
        reply = self.replies.pop(0) if self.replies else first_candidate_answer
        if isinstance(reply, httpx.Response):
            return reply
        content = reply(body) if callable(reply) else reply
        return httpx.Response(
            200,
            json={
                "model": "qwen3.5:4b",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": content},
                    }
                ],
                "usage": {"prompt_tokens": 900, "completion_tokens": 120},
            },
        )

    def transport(self):
        return httpx.MockTransport(self)

    def chats(self):
        return [b for p, b in self.requests if p.endswith("/chat/completions")]

    def embed_inputs(self):
        return [
            t for p, b in self.requests if p.endswith("/embeddings") for t in b["input"]
        ]
