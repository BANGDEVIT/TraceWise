"""FR-06: nhận diện dòng bằng chứng có câu trông như mệnh lệnh cho AI (chèn prompt gián tiếp qua log)."""

import re  # biểu thức chính quy Nó dùng để tìm, kiểm tra, tách hoặc thay chuỗi theo một mẫu, thay vì so chính xác từng chữ.

INJECTION = re.compile(
    r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?"
    r"(previous\s+|prior\s+|above\s+|earlier\s+)?(instructions?|rules?|prompts?)"
    r"|\b(bỏ qua|quên|phớt lờ)\s+(mọi\s+|tất cả\s+|các\s+)?(quy tắc|chỉ dẫn|hướng dẫn)"
    r"|\byou are now\b|\bfrom now on\b|\bact as\b|\b(debug|developer) mode\b"
    r"|\b(system|assistant)\s*:"
    r"|</?\s*(evidence|alert)\b"
    r"|\b(output|return|respond with|reply with)\s+(only\s+)?(technique|tactic|ma_attack)"
    r"|\btrả lời rằng\b",
    re.I,
)
CODE_LIKE = re.compile(r"\b[A-Z]\d{4}(?:\.\d{3})?\b", re.I)  # T9999, X0001, T1059.001
SAFE_REQUEST = re.compile(r"an toàn|không có kỹ thuật|safe|benign|not suspicious", re.I)


def normalize(line: str) -> str:
    """Đổi '_' và '-' thành dấu cách: 'ignore_all_previous_instructions' -> 'ignore all previous instructions'."""
    return re.sub(r"[_\-]+", " ", line)


def suspicious(pack: dict[str, str]) -> list[str]:
    """Mã E của các dòng có câu trông như mệnh lệnh cho AI."""
    return [e for e, line in pack.items() if INJECTION.search(normalize(line))]


def injected_codes(pack: dict[str, str]) -> set[str]:
    """Các chuỗi trông như mã kỹ thuật nằm trong dòng nghi chèn lệnh (mã mà kẻ tấn công muốn ta trả)."""
    return {
        c.upper()
        for e in suspicious(pack)
        for c in CODE_LIKE.findall(normalize(pack[e]))
    }


def asks_safe(pack: dict[str, str]) -> bool:
    """Dòng nghi chèn lệnh có đòi kết luận 'an toàn / không có kỹ thuật' không."""
    return any(SAFE_REQUEST.search(pack[e]) for e in suspicious(pack))
