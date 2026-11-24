"""rag.py + adapter.embed: câu truy vấn đã làm sạch, gọi embedding chuẩn OpenAI, kho pgvector có lọc nền tảng.

Không cần Ollama: máy chủ embedding giả (httpx.MockTransport) trả vector "túi từ" để kiểm đường ống.
Phần cơ sở dữ liệu dùng schema riêng tw_test, xong thì xóa.
"""

import json
import os
import re
import zlib

import httpx
import numpy as np
import pytest

from tracewise import rag, srs
from tracewise.adapter import LLMError, OpenAICompatClient
from tracewise.attack import load_attack
from tracewise.settings import load_settings

S = load_settings()
ATTACK, VERSION = load_attack()
ALERTS = {a["id"]: a for a in srs.load_alerts()}
SEEN = []


def bag_of_words(text, dim=768):
    v = np.zeros(dim)
    for w in re.findall(r"\w+", text.lower()):
        v[zlib.crc32(w.encode()) % dim] += 1
    return v.tolist()


def fake_server(request):
    body = json.loads(request.content)
    SEEN.append((request.url.host, request.url.path, body))
    return httpx.Response(
        200,
        json={
            "object": "list",
            "model": "embeddinggemma:latest",
            "data": [
                {"object": "embedding", "index": i, "embedding": bag_of_words(t)}
                for i, t in enumerate(body["input"])
            ],
        },
    )


def client(transport=fake_server):
    return OpenAICompatClient(
        S.llm, S.embed, S.allowlist_file, transport=httpx.MockTransport(transport)
    )


# ---------- câu truy vấn ----------
def query_of(alert_id):
    return rag.alert_query(srs.alert_lines(ALERTS[alert_id]))


def test_query_removes_injection_and_planted_codes():
    q33, q35 = query_of("LAB-0033"), query_of("LAB-0035")
    assert "T9999" not in q33 and "ignore" not in q33.lower()
    assert "T1486" not in q35 and "X0001" not in q35 and "debug mode" not in q35
    assert "sshd" in q33 and "php" in q35  # phần hành vi thật vẫn còn


def test_query_keeps_behaviour_and_drops_host_line():
    q = query_of("LAB-0029")
    assert "lsass" in q and "agent" not in q and "lab-win02" not in q


def test_doc_and_query_follow_model_templates():
    doc = rag.as_doc(ATTACK["T1003.001"], S.embed)
    assert doc.startswith("title: T1003.001 LSASS Memory | text: ")
    assert rag.as_query("abc", S.embed) == "task: search result | query: abc"


# ---------- máy chủ embedding ----------
def test_embed_calls_openai_endpoint_and_normalizes():
    SEEN.clear()
    vecs, served = client().embed(["một", "hai ba"])
    host, path, body = SEEN[-1]
    assert (host, path, body["model"]) == (
        "localhost",
        "/v1/embeddings",
        "embeddinggemma",
    )
    assert vecs.shape == (2, 768) and np.allclose(np.linalg.norm(vecs, axis=1), 1)
    assert served == "embeddinggemma:latest"


def test_embed_wrong_dimension_is_an_error():
    def short(request):
        return httpx.Response(
            200, json={"data": [{"index": 0, "embedding": [1.0, 0.0]}]}
        )

    with pytest.raises(LLMError, match="chiều"):
        client(short).embed(["x"])


def test_embed_http_error_becomes_llm_error():
    with pytest.raises(LLMError):
        client(lambda r: httpx.Response(500, json={"error": "model not found"})).embed(
            ["x"]
        )


def test_client_refuses_host_outside_allowlist():
    embed = S.embed.model_copy(update={"base_url": "https://api.example.com/v1"})
    with pytest.raises(srs.HostNotAllowed):
        OpenAICompatClient(S.llm, embed, S.allowlist_file)


# ---------- kho pgvector ----------
@pytest.fixture(scope="module")
def kb():
    try:
        conn = rag.connect(S.db.dsn)
    except Exception as e:  # noqa: BLE001
        if os.environ.get("CI"):
            raise
        pytest.skip(f"không kết nối được Postgres: {e}")
    conn.execute("DROP SCHEMA IF EXISTS tw_test CASCADE")
    conn.execute("CREATE SCHEMA tw_test")
    conn.execute("SET search_path TO tw_test, public")
    techs = [ATTACK[c] for c in srs.whitelist_codes()]
    vecs, served = client().embed([rag.as_doc(t, S.embed) for t in techs])
    rag.create_table(conn, S.embed.dim)
    rag.upsert(conn, techs, vecs, VERSION, served)
    yield conn
    conn.execute("DROP SCHEMA tw_test CASCADE")
    conn.close()


def test_upsert_twice_keeps_one_row_per_code(kb):
    techs = [ATTACK[c] for c in srs.whitelist_codes()]
    vecs, served = client().embed([rag.as_doc(t, S.embed) for t in techs])
    rag.upsert(kb, techs, vecs, VERSION, served)
    n, models = kb.execute(
        "SELECT count(*), array_agg(DISTINCT embed_model) FROM attack_kb"
    ).fetchone()
    assert n == 24 and models == [
        "embeddinggemma:latest"
    ]  # lưu tên mô hình máy chủ trả về


def test_search_returns_k_with_scores(kb):
    vec, _ = client().embed([rag.as_query("dump lsass memory credentials", S.embed)])
    found = rag.search(kb, vec[0], 5)
    assert len(found) == 5 and all(-1 <= score <= 1 for _, _, score in found)


def test_platform_filter_drops_windows_only_codes_for_linux(kb):
    vec, _ = client().embed([rag.as_query("powershell encoded command", S.embed)])
    linux = {c for c, _, _ in rag.search(kb, vec[0], 24, "Linux")}
    assert len(linux) == 18 and "T1059.001" not in linux and "T1059.004" in linux
    assert len(rag.search(kb, vec[0], 24, None)) == 24


def test_lab0034_loses_its_answer_when_filtered(kb):
    """Bẫy đã biết: LAB-0034 ở máy Linux nhưng nhãn là T1059.001 (chỉ Windows)."""
    platform = rag.platform_of(ALERTS["LAB-0034"]["agent"]["name"], S)
    assert platform == "Linux"
    found = rag.candidates(kb, client(), S.embed, query_of("LAB-0034"), 24, platform)
    assert "T1059.001" not in {c for c, _, _ in found}
