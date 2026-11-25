"""Ghép các bước phân tích MỘT cảnh báo: gói bằng chứng → câu truy vấn → ứng viên → prompt → LLM → 10 luật.

Không ghi database ở đây (việc của store.py). analyze() trả về một dict đủ để lưu và hiển thị,
kể cả khi máy chủ LLM lỗi (status "error"), để nhật ký vẫn ghi lại lần thử đó (FR-08).
"""

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from . import prompts, rag, srs, validate
from .adapter import LLMError, OpenAICompatClient
from .attack import Technique, load_attack
from .settings import Settings, load_settings

SUMMARY_MAX_TOKENS = 120  # câu tóm tắt cho RAG chỉ 1–2 câu


@dataclass
class Services:
    """Những thứ tạo MỘT lần khi khởi động, dùng lại cho mọi cảnh báo."""

    settings: Settings
    client: OpenAICompatClient
    conn: object
    attack: dict[str, Technique]
    attack_version: str


def check_kb(conn, settings: Settings, attack_version: str) -> None:
    """Dừng sớm, báo rõ, nếu kho attack_kb chưa có hoặc không khớp cấu hình hiện tại."""
    try:
        n, models, versions = conn.execute(
            "SELECT count(*), array_agg(DISTINCT embed_model), array_agg(DISTINCT attack_ver) "
            "FROM attack_kb"
        ).fetchone()
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(
            "Chưa có bảng attack_kb. Chạy: python scripts/setup_db.py"
        ) from e
    if not n:
        raise RuntimeError("Bảng attack_kb rỗng. Chạy: python scripts/setup_db.py")
    base = settings.embed.model.split(":")[0]
    if not any(m.split(":")[0] == base for m in models):
        raise RuntimeError(
            f"attack_kb được embed bằng {models}, cấu hình dùng {settings.embed.model}. "
            "Chạy lại scripts/setup_db.py"
        )
    if versions != [attack_version]:
        raise RuntimeError(
            f"attack_kb là ATT&CK {versions}, file đang nạp là {attack_version}"
        )


def load_services(
    settings: Settings | None = None,
    conn=None,
    transport: httpx.BaseTransport | None = None,
) -> Services:
    """Đọc cấu hình, tạo client (kiểm FR-07), mở database, nạp ATT&CK, kiểm kho kỹ thuật."""
    s = settings or load_settings()
    client = OpenAICompatClient(s.llm, s.embed, s.allowlist_file, transport=transport)
    conn = conn or rag.connect(s.db.dsn)
    attack, version = load_attack(s.attack_stix)
    if s.analysis.rag:
        check_kb(conn, s, version)
    return Services(s, client, conn, attack, version)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def analyze(alert: dict, svc: Services) -> dict:
    """Phân tích một cảnh báo Wazuh (dict). Trả về bản ghi chạy, chưa lưu."""
    s = svc.settings
    run = {
        "request_id": uuid.uuid4().hex,
        "alert_ref": alert["id"],
        "host": alert["agent"]["name"],
        "status": "error",
        "needs_review": True,
        "error": None,
        "raw": None,
        "result": None,
        "teacher": None,
        "violations": [],
        "pack": {},
        "candidates": [],
        "config": {},
        "prompt_tokens": None,
        "completion_tokens": None,
        "latency_s": None,  # thời gian từ lúc gửi request tới Ollama cho tới lúc nhận đủ câu trả lời
        "events": [],
    }
    config = {
        "llm_model_requested": s.llm.model,
        "attack_version": svc.attack_version,
        "settings": s.model_dump(
            mode="json"
        ),  # đổi object Pydantic thành dict chép toàn bộ cấu hình đang dùng vào báo cáo
    }
    t_start = time.perf_counter()

    def event(name: str, t0: float, **detail) -> None:
        """Ghi một bước vào nhật ký của lần chạy (FR-08)."""
        run["events"].append(
            {
                "ts": _now(),
                "event": name,
                "detail": {"seconds": round(time.perf_counter() - t0, 3), **detail},
            }
        )

    try:
        # 1. gói bằng chứng mức 0
        t0 = time.perf_counter()
        lines = srs.alert_lines(alert)
        pack = validate.pack_from_lines(lines)
        run["pack"] = pack
        event("pack", t0, level=0, lines=len(pack))

        # 2. ứng viên
        t0 = time.perf_counter()
        if s.analysis.rag:
            if s.analysis.query_mode == "summary":
                msgs, sha = prompts.summary_messages(pack, s.analysis.summary_prompt)
                reply = svc.client.chat(msgs, max_tokens=SUMMARY_MAX_TOKENS)
                query = rag.alert_query(
                    [reply.content]
                )  # đầu ra của Qwen cũng phải làm sạch
                config["summary_prompt_sha"] = sha
                event(
                    "summary",
                    t0,
                    text=reply.content,
                    model=reply.model,
                    completion_tokens=reply.completion_tokens,
                )
                t0 = time.perf_counter()
            else:
                query = rag.alert_query(lines)
            platform = rag.platform_of(run["host"], s)
            vec, served_embed = svc.client.embed([rag.as_query(query, s.embed)])
            found = rag.search(svc.conn, vec[0], s.analysis.k, platform)
            config["embed_model_served"] = served_embed
            event(
                "candidates",
                t0,
                query=query,
                platform=platform,
                found=[
                    {"ma": c, "do_giong": round(float(score), 4)}
                    for c, _, score in found
                ],
            )
            codes = [c for c, _, _ in found]
        else:
            codes = srs.whitelist_codes()
            event(
                "candidates",
                t0,
                query=None,
                platform=None,
                found=[{"ma": c} for c in codes],
            )
        run["candidates"] = codes

        # 3. LLM phân tích, enum = ứng viên
        t0 = time.perf_counter()
        msgs, sha = prompts.analysis_messages(
            pack, codes, svc.attack, s.analysis.prompt
        )
        reply = svc.client.chat(msgs, validate.output_schema(codes, list(pack)))
        run["raw"] = reply.content
        run["prompt_tokens"], run["completion_tokens"] = (
            reply.prompt_tokens,
            reply.completion_tokens,
        )
        config.update(
            prompt=s.analysis.prompt, prompt_sha=sha, llm_model_served=reply.model
        )
        event(
            "llm",
            t0,
            model=reply.model,
            finish_reason=reply.finish_reason,
            prompt_tokens=reply.prompt_tokens,
            completion_tokens=reply.completion_tokens,
        )

        # 4. 10 luật
        t0 = time.perf_counter()
        report = validate.validate(
            reply.content, validate.make_context(pack, codes, svc.attack)
        )
        run.update(
            status="ok" if report["valid"] else "invalid",
            needs_review=report["needs_review"],
            result=report["result"],
            violations=report["violations"],
            teacher=validate.to_teacher(report),
        )
        event(
            "validate",
            t0,
            valid=report["valid"],
            violations=len(report["violations"]),
            needs_review=report["needs_review"],
        )
    except LLMError as e:
        run["error"] = str(e)
        event("error", t0, message=str(e))

    run["config"] = config
    run["latency_s"] = round(time.perf_counter() - t_start, 2)
    return run
