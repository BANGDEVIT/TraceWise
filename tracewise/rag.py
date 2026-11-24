"""RAG: kho kỹ thuật ATT&CK trong Postgres + pgvector, tìm k kỹ thuật ứng viên cho một cảnh báo."""

import re

import numpy as np
import psycopg
from pgvector.psycopg import register_vector

from . import injection
from .attack import Technique
from .settings import EmbedConf, Settings


# ---------- văn bản đưa vào mô hình embedding ----------
def as_doc(t: Technique, embed: EmbedConf, desc_chars: int = 1500) -> str:
    """Tài liệu của một kỹ thuật theo khuôn của mô hình embedding (EmbeddingGemma: 'title: … | text: …')."""
    return embed.doc_template.format(
        title=f"{t.id} {t.name}", text=t.description[:desc_chars]
    )


def as_query(text: str, embed: EmbedConf) -> str:
    """Câu truy vấn kèm tiền tố của mô hình embedding."""
    return embed.query_prefix + text


def alert_query(lines: list[str]) -> str:
    """Câu truy vấn tìm ứng viên từ gói bằng chứng, đã làm sạch (FR-06).

    Bỏ dòng 'agent:' (tên máy không mang nghĩa hành vi), đổi '_' '-' thành dấu cách,
    xóa cụm trông như mệnh lệnh cho AI và chuỗi trông như mã kỹ thuật (T9999, X0001, T1486…),
    để kẻ tấn công không cài từ khóa hay mã vào log mà kéo được ứng viên hắn muốn.
    """
    keep = [line for line in lines if not line.startswith("agent:")]
    text = injection.normalize("\n".join(keep))
    text = injection.INJECTION.sub(" ", text)
    text = injection.CODE_LIKE.sub(" ", text)
    return re.sub(r"[ \t]+", " ", text).strip()


# ---------- Postgres + pgvector ----------
def connect(dsn: str) -> psycopg.Connection:
    """Mở kết nối, bật extension vector, đăng ký kiểu vector cho psycopg, làm việc theo giờ UTC."""
    conn = psycopg.connect(dsn, autocommit=True)
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    register_vector(conn)
    conn.execute("SET TIME ZONE 'UTC'")
    return conn


def create_table(conn, dim: int) -> None:
    """Bảng attack_kb: mỗi dòng một kỹ thuật + vector embedding của nó."""
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS attack_kb (
            ma            text PRIMARY KEY,
            ten           text   NOT NULL,
            chien_thuat   text[] NOT NULL,
            nen_tang      text[] NOT NULL,
            nguon_du_lieu text[] NOT NULL,
            mo_ta         text   NOT NULL,
            attack_ver    text   NOT NULL,
            embed_model   text   NOT NULL,
            embedding     vector({dim}) NOT NULL
        )""")


def upsert(
    conn,
    techniques: list[Technique],
    vectors: np.ndarray,
    version: str,
    embed_model: str,
) -> None:
    """Ghi (hoặc ghi đè) từng kỹ thuật cùng vector. Chạy lại nhiều lần vẫn chỉ một dòng mỗi mã."""
    if len(techniques) != len(vectors):
        raise ValueError(f"{len(techniques)} kỹ thuật nhưng {len(vectors)} vector")
    sql = """
        INSERT INTO attack_kb (ma, ten, chien_thuat, nen_tang, nguon_du_lieu, mo_ta,
                               attack_ver, embed_model, embedding)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (ma) DO UPDATE SET
            ten = EXCLUDED.ten, chien_thuat = EXCLUDED.chien_thuat, nen_tang = EXCLUDED.nen_tang,
            nguon_du_lieu = EXCLUDED.nguon_du_lieu, mo_ta = EXCLUDED.mo_ta,
            attack_ver = EXCLUDED.attack_ver, embed_model = EXCLUDED.embed_model,
            embedding = EXCLUDED.embedding"""
    with conn.cursor() as cur:
        for t, vec in zip(techniques, vectors):
            cur.execute(
                sql,
                (
                    t.id,
                    t.name,
                    list(t.tactics),
                    list(t.platforms),
                    list(t.data_components),
                    t.description,
                    version,
                    embed_model,
                    vec,
                ),
            )


def search(
    conn, vec: np.ndarray, k: int = 5, platform: str | None = None
) -> list[tuple]:
    """k kỹ thuật gần nhất: [(mã, tên, độ giống cosine)]; platform (vd 'Linux') lọc theo nen_tang."""
    return conn.execute(
        """
        SELECT ma, ten, 1 - (embedding <=> %(v)s) AS do_giong
        FROM attack_kb
        WHERE %(p)s::text IS NULL OR %(p)s = ANY(nen_tang)
        ORDER BY embedding <=> %(v)s
        LIMIT %(k)s""",
        {"v": vec, "p": platform, "k": k},
    ).fetchall()


def platform_of(host: str, settings: Settings) -> str | None:
    """Nền tảng ATT&CK của máy (từ cấu hình) nếu bật lọc nền tảng; máy lạ hoặc tắt lọc -> None (không lọc)."""
    if not settings.analysis.platform_filter:
        return None
    return settings.host_platform.get(host)


def candidates(
    conn, client, embed: EmbedConf, query: str, k: int = 5, platform: str | None = None
) -> list[tuple]:
    """Embed câu truy vấn rồi tìm k ứng viên."""
    vec, _ = client.embed([as_query(query, embed)])
    return search(conn, vec[0], k, platform)
