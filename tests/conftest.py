"""Fixture dùng chung: database thật trong schema riêng tw_api (xong thì xóa), kho attack_kb embed bằng máy giả."""

import os

import pytest

from tests.fakes import FakeLLM
from tracewise import rag, srs, store
from tracewise.adapter import OpenAICompatClient
from tracewise.attack import load_attack
from tracewise.settings import load_settings


@pytest.fixture(scope="session")
def db():
    s = load_settings()
    try:
        conn = rag.connect(s.db.dsn)
    except Exception as e:  # noqa: BLE001
        if os.environ.get("CI"):
            raise
        pytest.skip(f"không kết nối được Postgres: {e}")
    conn.execute("DROP SCHEMA IF EXISTS tw_api CASCADE")
    conn.execute("CREATE SCHEMA tw_api")
    conn.execute("SET search_path TO tw_api, public")
    attack, version = load_attack()
    techs = [attack[c] for c in srs.whitelist_codes()]
    client = OpenAICompatClient(
        s.llm, s.embed, s.allowlist_file, transport=FakeLLM().transport()
    )
    vecs, served = client.embed([rag.as_doc(t, s.embed) for t in techs])
    rag.create_table(conn, s.embed.dim)
    rag.upsert(conn, techs, vecs, version, served)
    store.create_tables(conn)
    yield conn
    conn.execute("DROP SCHEMA tw_api CASCADE")
    conn.close()
