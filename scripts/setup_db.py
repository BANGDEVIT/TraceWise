"""Tạo bảng attack_kb và embed 24 kỹ thuật của thầy (chạy một lần; chạy lại sẽ ghi đè, không nhân đôi).

Cần: Postgres đang chạy (M3_PG_DSN trong .env), Ollama đang chạy và đã pull embeddinggemma.
    python scripts/setup_db.py
"""

import time

from tracewise import rag, srs
from tracewise.adapter import OpenAICompatClient
from tracewise.attack import load_attack
from tracewise.settings import load_settings


def main():
    s = load_settings()
    client = OpenAICompatClient(
        s.llm, s.embed, s.allowlist_file
    )  # kiểm FR-07 trước khi gửi gì
    conn = rag.connect(s.db.dsn)
    table, version = load_attack(s.attack_stix)
    techniques = [table[c] for c in srs.whitelist_codes()]

    t0 = time.perf_counter()
    vectors, served = client.embed([rag.as_doc(t, s.embed) for t in techniques])
    seconds = time.perf_counter() - t0

    rag.create_table(conn, s.embed.dim)
    rag.upsert(conn, techniques, vectors, version, served)
    n, models = conn.execute(
        "SELECT count(*), array_agg(DISTINCT embed_model) FROM attack_kb"
    ).fetchone()
    print(
        f"attack_kb: {n} kỹ thuật, ATT&CK {version}, mô hình embedding {models}, "
        f"{vectors.shape[1]} chiều, embed mất {seconds:.1f} giây"
    )


if __name__ == "__main__":
    main()
