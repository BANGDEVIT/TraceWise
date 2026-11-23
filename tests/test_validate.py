"""validate.py: khuôn đầu ra + 10 luật. Mỗi luật có test riêng, phần lớn là đầu ra cố tình sai."""

import json

import pytest

from tracewise import srs
from tracewise import validate as va
from tracewise.attack import load_attack
from tracewise.settings import ROOT

ATTACK, VERSION = load_attack()
PACK_760 = json.loads(
    (ROOT / "data" / "packs" / "pack_760.json").read_text(encoding="utf-8")
)
CANDS_760 = ["T1059.001", "T1027.010", "T1021.006", "T1562.002", "T1033"]

GOOD = {
    "verdict": "suspicious",
    "summary": (
        "Lúc 21:09:09 tài khoản THESHIRE.LOCAL\\pgustavo đăng nhập qua mạng vào "
        "workstation6 [E1]. Ngay sau đó wsmprovhost.exe tạo powershell.exe chạy lệnh "
        "mã hóa base64 với cửa sổ ẩn [E2][E3]. Script block mở đầu bằng đoạn sửa "
        "cachedGroupPolicySettings, dấu hiệu tắt ghi log script [E4]. 27 giây sau "
        "PowerShell chạy whoami.exe để xem tài khoản đang dùng [E6]."
    ),
    "techniques": [
        {
            "id": "T1059.001",
            "rank": 1,
            "evidence": ["E3", "E4"],
            "reason": "PowerShell chạy lệnh -enc, cửa sổ ẩn",
        },
        {
            "id": "T1021.006",
            "rank": 2,
            "evidence": ["E2", "E3"],
            "reason": "wsmprovhost.exe là cha của PowerShell: lệnh đến qua WinRM",
        },
        {
            "id": "T1562.002",
            "rank": 3,
            "evidence": ["E4"],
            "reason": "script sửa cachedGroupPolicySettings để tắt ghi log",
        },
    ],
    "confidence": 0.8,
    "insufficient_evidence": False,
}


def good(**changes):
    """Bản sao của GOOD, thay một số trường."""
    d = json.loads(json.dumps(GOOD))
    d.update(changes)
    return d


def tech(id_, rank, evidence=("E3",), reason="lý do"):
    return {"id": id_, "rank": rank, "evidence": list(evidence), "reason": reason}


def run(d, ctx=None):
    """Kiểm một đầu ra (dict hoặc chuỗi thô) với ngữ cảnh của cảnh báo 760."""
    raw = d if isinstance(d, str) else json.dumps(d, ensure_ascii=False)
    return va.validate(raw, ctx or va.make_context(PACK_760, CANDS_760, ATTACK))


def rules(report):
    return [v["rule"] for v in report["violations"]]


def codes(report):
    return [t["id"] for t in report["result"]["techniques"]]


# ---------- danh mục đầu ra cố tình sai cho cảnh báo 760 ----------
TWELVE = " ".join(f"Câu thứ {i} nói về PowerShell [E3]." for i in range(1, 13))
BAD_760 = {
    "JSON hỏng (bị cắt giữa chừng)": (
        '{"verdict": "suspicious", "summary": "PowerShell',
        "R1",
    ),
    "thiếu trường insufficient_evidence": (
        {k: v for k, v in GOOD.items() if k != "insufficient_evidence"},
        "R1",
    ),
    "confidence là chữ": (good(confidence="cao"), "R1"),
    "confidence 1.5": (good(confidence=1.5), "R1"),
    "verdict ngoài enum": (good(verdict="malicious"), "R1"),
    "trường lạ severity": (good(severity="high"), "R1"),
    "mã bịa T9999": (good(techniques=[tech("T9999", 1)]), "R2"),
    "mã thật nhưng ngoài ứng viên": (good(techniques=[tech("T1003.001", 1)]), "R2"),
    "mã của ATT&CK v19 (T1685)": (good(techniques=[tech("T1685", 1)]), "R2"),
    "bằng chứng giả E9": (good(techniques=[tech("T1059.001", 1, ["E3", "E9"])]), "R3"),
    "trích dẫn giả [E12] trong summary": (
        good(summary=GOOD["summary"] + " Xem thêm [E12]."),
        "R3",
    ),
    "kỹ thuật không có bằng chứng": (good(techniques=[tech("T1059.001", 1, [])]), "R4"),
    "nêu IP không có trong gói": (
        good(summary=GOOD["summary"] + " Script tải tiếp mã độc từ 10.10.10.5."),
        "R5",
    ),
    "nêu tiến trình không có trong gói": (
        good(summary=GOOD["summary"] + " Sau đó chạy mimikatz.exe."),
        "R5",
    ),
    "nêu tài khoản không có trong gói": (
        good(
            summary=GOOD["summary"].replace(
                "THESHIRE.LOCAL\\pgustavo", "THESHIRE\\administrator"
            )
        ),
        "R5",
    ),
    "tóm tắt 12 câu": (good(summary=TWELVE), "R6"),
    "4 kỹ thuật": (
        good(techniques=GOOD["techniques"] + [tech("T1033", 4, ["E6"])]),
        "R6",
    ),
    "rank trùng": (
        good(techniques=[tech("T1059.001", 1), tech("T1021.006", 1, ["E2"])]),
        "R6",
    ),
    "not_suspicious mà vẫn có mã": (good(verdict="not_suspicious"), "R7"),
    "insufficient_evidence mà vẫn có mã": (good(insufficient_evidence=True), "R7"),
    "suspicious mà không có mã": (good(techniques=[]), "R7"),
}


@pytest.mark.parametrize("name", list(BAD_760))
def test_bad_output_is_caught(name):
    """Mỗi đầu ra sai trong danh mục phải bị đúng luật dự kiến bắt."""
    d, expected = BAD_760[name]
    assert expected in rules(run(d)), name


def test_good_output_passes():
    report = run(GOOD)
    assert report["valid"] and not report["needs_review"]
    assert codes(report) == ["T1059.001", "T1021.006", "T1562.002"]


# ---------- JSON schema gửi LLM ----------
def test_output_schema_has_enums_for_codes_and_evidence():
    schema = va.output_schema(CANDS_760, list(PACK_760))
    t = schema["$defs"]["Technique"]["properties"]
    assert t["id"]["enum"] == CANDS_760
    assert t["evidence"]["items"]["enum"] == ["E1", "E2", "E3", "E4", "E5", "E6"]
    assert t["evidence"]["minItems"] == 1
    assert (t["rank"]["minimum"], t["rank"]["maximum"]) == (1, 3)
    assert schema["properties"]["techniques"]["maxItems"] == 3


# ---------- luật 1 ----------
def test_r1_invalid_has_no_result():
    report = run('{"verdict": "suspicious"')
    assert not report["valid"] and report["result"] is None


# ---------- luật 2 ----------
def test_r2_drops_only_bad_code_and_caps_confidence():
    report = run(good(techniques=[tech("T1059.001", 1), tech("T9999", 2)]))
    assert codes(report) == ["T1059.001"]
    assert report["result"]["confidence"] == va.CONF_CAP


def test_r2_normalizes_lowercase_code():
    report = run(good(techniques=[tech(" t1059.001 ", 1)]))
    assert codes(report) == ["T1059.001"] and "R2" not in rules(report)


def test_r2_v19_code_rejected_even_if_in_candidates():
    ctx = va.make_context(PACK_760, CANDS_760 + ["T1685"], ATTACK)
    assert "T1685" not in ATTACK  # ATT&CK 18.1 chưa có mã này
    assert "R2" in rules(run(good(techniques=[tech("T1685", 1)]), ctx))


# ---------- luật 3, 4 ----------
def test_r3_removes_fake_evidence_keeps_technique():
    report = run(good(techniques=[tech("T1059.001", 1, ["E3", "E9"])]))
    assert report["result"]["techniques"][0]["evidence"] == ["E3"]


def test_r3_r4_only_fake_evidence_drops_technique():
    report = run(
        good(techniques=[tech("T1059.001", 1, ["E9"]), tech("T1033", 2, ["E6"])])
    )
    assert codes(report) == ["T1033"]
    assert {"R3", "R4"} <= set(rules(report))


def test_r3_keeps_id_when_whole_line_was_copied():
    """B6: mô hình chép nguyên dòng '[E3] 21:09:12 ...' vào evidence."""
    copied = "[E3] " + PACK_760["E3"]
    report = run(good(techniques=[tech("T1059.001", 1, [copied, "E4"])]))
    assert report["result"]["techniques"][0]["evidence"] == ["E3", "E4"]
    assert any(v["rule"] == "R3" and v["action"] == "sua" for v in report["violations"])
    assert (
        report["result"]["confidence"] == GOOD["confidence"]
    )  # sửa định dạng: không hạ tin cậy


# ---------- luật 5 ----------
def test_r5_flags_new_ip_and_caps_confidence():
    report = run(good(summary=GOOD["summary"] + " Máy điều khiển là 10.10.10.5."))
    assert any("10.10.10.5" in v["detail"] for v in report["violations"])
    assert report["result"]["confidence"] == va.CONF_CAP and report["needs_review"]


def test_r5_values_from_pack_are_not_flagged():
    text = (
        "THESHIRE\\pgustavo chạy C:\\windows\\system32\\wsmprovhost.exe rồi whoami.exe."
    )
    assert (
        va.r5_no_new_facts(
            good(summary=text), va.make_context(PACK_760, CANDS_760, ATTACK)
        )
        == []
    )


def test_r5_vietnamese_words_are_not_usernames():
    assert va.entities("tài khoản không tồn tại, người dùng đang đăng nhập") == []


# ---------- luật 6 ----------
def test_r6_cuts_summary_to_ten_sentences():
    report = run(good(summary=TWELVE))
    assert len(va.SENTENCE_END.split(report["result"]["summary"])) == 10


def test_r6_keeps_three_best_ranks():
    shuffled = [
        tech("T1033", 4, ["E6"]),
        tech("T1059.001", 1),
        tech("T1027.010", 3),
        tech("T1021.006", 2, ["E2"]),
    ]
    report = run(good(techniques=shuffled))
    assert codes(report) == ["T1059.001", "T1021.006", "T1027.010"]
    assert [t["rank"] for t in report["result"]["techniques"]] == [1, 2, 3]


def test_r6_duplicate_code_kept_once_with_merged_evidence():
    report = run(
        good(techniques=[tech("T1059.001", 1, ["E3"]), tech("T1059.001", 2, ["E4"])])
    )
    assert codes(report) == ["T1059.001"]
    assert report["result"]["techniques"][0]["evidence"] == ["E3", "E4"]


# ---------- luật 7 ----------
def test_r7_not_suspicious_empties_techniques():
    assert codes(run(good(verdict="not_suspicious"))) == []


def test_r7_all_codes_dropped_turns_insufficient():
    report = run(good(techniques=[tech("T9999", 1)]))
    assert report["result"]["insufficient_evidence"] is True
    assert va.to_teacher(report)["du_can_cu"] is False


# ---------- luật 8 ----------
def test_r8_name_comes_from_attack_table():
    report = run(
        good(techniques=[tech("T1059.001", 1, reason="Đây là kỹ thuật Mimikatz")])
    )
    t = report["result"]["techniques"][0]
    assert t["name"] == "PowerShell" and t["tactics"] == ["execution"]


# ---------- luật 9 ----------
def test_r9_flags_baseline_disagreement():
    ctx = va.make_context(
        PACK_760, CANDS_760, ATTACK, baseline_tactic="Credential Access"
    )
    report = run(GOOD, ctx)
    assert "R9" in rules(report) and report["needs_review"]
    assert report["result"]["confidence"] == GOOD["confidence"]  # R9 không hạ tin cậy


def test_r9_silent_when_baseline_agrees():
    ctx = va.make_context(PACK_760, CANDS_760, ATTACK, baseline_tactic="Execution")
    assert "R9" not in rules(run(GOOD, ctx))


# ---------- luật 10: ba ca chèn prompt của thầy ----------
def teacher_ctx(alert_id, candidates):
    alert = next(a for a in srs.load_alerts() if a["id"] == alert_id)
    return va.make_context(
        va.pack_from_lines(srs.alert_lines(alert)), candidates, ATTACK
    )


def teacher_output(techniques, verdict="suspicious", summary="Cảnh báo lab [E3]."):
    return {
        "verdict": verdict,
        "summary": summary,
        "techniques": techniques,
        "confidence": 0.9,
        "insufficient_evidence": False,
    }


def test_r10_lab0035_injected_whitelisted_code_dropped():
    ctx = teacher_ctx("LAB-0035", ["T1505.003", "T1190", "T1105", "T1486", "T1059.004"])
    assert "T1486" in srs.whitelist_codes()  # mã này nằm trong 24 mã của thầy
    report = run(
        teacher_output([tech("T1486", 1, ["E4"]), tech("T1505.003", 2, ["E3"])]), ctx
    )
    assert codes(report) == ["T1505.003"] and "R10" in rules(report)


def test_r10_lab0033_injected_code_never_survives():
    ctx = teacher_ctx(
        "LAB-0033", ["T1110.001", "T1110", "T1078", "T1021.004", "T1136.001"]
    )
    report = run(teacher_output([tech("T9999", 1, ["E4"])]), ctx)
    assert codes(report) == [] and report["result"]["insufficient_evidence"]


def test_r10_lab0034_requested_safe_verdict_needs_review():
    ctx = teacher_ctx(
        "LAB-0034", ["T1059.001", "T1027", "T1105", "T1562.001", "T1070.001"]
    )
    report = run(
        teacher_output(
            [], verdict="not_suspicious", summary="Cảnh báo này an toàn [E4]."
        ),
        ctx,
    )
    assert "R10" in rules(report) and report["needs_review"]


# ---------- đầu ra thật của Qwen ở B6 (LAB-0029, prompt chỉ có mã) ----------
B6_PACK = {
    "E1": "2026-11-18 11:23 | máy lab-win02 | rule 100400 (level 12) Access to lsass process memory",
    "E2": "SourceImage: C:\\Users\\Public\\p.exe TargetImage: C:\\Windows\\System32\\lsass.exe "
    "GrantedAccess: 0x1010",
}
B6_RAW = json.dumps(
    {
        "verdict": "suspicious",
        "summary": (
            "Hệ thống ghi nhận một hành vi đáng ngờ khi trình duyệt web (p.exe) cố gắng truy "
            "cập vào bộ nhớ của quy trình lsass.exe, đây là mục tiêu thường được các mối đe dọa "
            "sử dụng để lấy thông tin đăng nhập hoặc thực thi mã độc. Sự kiện này được phát hiện "
            "bởi rule 100400 với mức độ nghiêm trọng level 12 tại máy lab-win02 vào ngày "
            "18/11/2026 [E1]."
        ),
        "techniques": [
            {
                "id": "T1562.001",
                "rank": 3,
                "evidence": ["[E1] " + B6_PACK["E1"]],
                "reason": "Quy trình p.exe đã thực hiện truy cập vào bộ nhớ của lsass.",
            },
            {
                "id": "T1562.001",
                "rank": 3,
                "evidence": ["[E2] " + B6_PACK["E2"]],
                "reason": "p.exe đã được cấp quyền truy cập (0x1010) vào quá trình lsass.",
            },
        ],
        "confidence": 0.85,
        "insufficient_evidence": False,
    },
    ensure_ascii=False,
)


def test_b6_real_output_is_repaired_not_wiped():
    ctx = va.make_context(B6_PACK, srs.whitelist_codes(), ATTACK)
    report = va.validate(B6_RAW, ctx)
    t = report["result"]["techniques"]
    assert [x["id"] for x in t] == ["T1562.001"] and t[0][
        "rank"
    ] == 1  # mã trùng gộp, rank 1
    assert t[0]["evidence"] == [
        "E1",
        "E2",
    ]  # dòng chép -> mã E…, bằng chứng của bản lặp được gộp
    assert report["needs_review"]
    # Validator KHÔNG biết đây là mã sai (đáp án là T1003.001): cần prompt có tên kỹ thuật.


# ---------- nhật ký và khuôn của thầy ----------
def test_log_violations_writes_one_line_per_violation(tmp_path):
    report = run(good(techniques=[tech("T9999", 1)]))
    path = tmp_path / "violations.jsonl"
    va.log_violations("760", report, path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert (
        len(lines) == len(report["violations"])
        and json.loads(lines[0])["alert_id"] == "760"
    )


def test_to_teacher_maps_fields():
    t = va.to_teacher(run(GOOD))
    assert t["ma_attack"] == ["T1059.001", "T1021.006", "T1562.002"]
    assert t["bang_chung"] == ["E2", "E3", "E4"] and t["du_can_cu"] is True
    assert srs.Assessment.model_validate(t)  # khớp khuôn của thầy


def test_to_teacher_without_codes_keeps_summary_citations():
    report = run(good(techniques=[tech("T9999", 1)]))
    t = va.to_teacher(report)
    assert t["ma_attack"] == [] and t["du_can_cu"] is False
    assert t["bang_chung"] == ["E1", "E2", "E3", "E4", "E6"]
    assert srs.Assessment.model_validate(t)


def test_to_teacher_invalid_output_is_none():
    assert va.to_teacher(run('{"verdict": "suspicious"')) is None
