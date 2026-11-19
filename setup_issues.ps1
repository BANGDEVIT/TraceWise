# Tạo nhãn, mốc và issue cho TraceWise (chạy MỘT lần, ở thư mục gốc repo, đã gh auth login).

# ---------- 1. Nhãn ----------
$labels = @(
  @("type:feature", "1D76DB", "Chức năng mới"),
  @("type:bug",     "D73A4A", "Lỗi cần sửa"),
  @("type:test",    "0E8A16", "Kiểm thử, đo đạc, bằng chứng"),
  @("type:docs",    "5319E7", "Tài liệu, báo cáo"),
  @("type:chore",   "BFD4F2", "Cấu hình, công cụ, dọn dẹp"),
  @("type:data",    "FBCA04", "Dữ liệu, nhãn")
)
foreach ($r in "FR-01","FR-02","FR-03","FR-04","FR-05","FR-06","FR-07","FR-08","NFR-01","NFR-02","NFR-03","NFR-04") {
  $labels += ,@($r, "C5DEF5", "Yêu cầu SRS $r")
}
foreach ($l in $labels) { gh label create $l[0] --color $l[1] --description $l[2] --force }

# ---------- 2. Mốc (milestone) — sửa ngày cho khớp lịch của bạn ----------
gh api "repos/{owner}/{repo}/milestones" -f title="Tuần 1" -f due_on="2026-11-25T23:59:59Z" -f description="Ngày 1-5: khung, B6, module lõi, thiết kế, rà nhãn, dịch vụ"
gh api "repos/{owner}/{repo}/milestones" -f title="Tuần 2 - Mốc HD" -f due_on="2026-12-02T23:59:59Z" -f description="Ngày 6-10: FR-05, B5, chạy thật 35 cảnh báo, bằng chứng"
gh api "repos/{owner}/{repo}/milestones" -f title="Sau mốc HD" -f description="Lab Wazuh, gói mức 1, đánh giá, React, SRS"

# ---------- 3. Issue ----------
$issues = @(
  @{ t = "Dựng khung dự án (Ngày 1)"; l = "type:chore"; m = "Tuần 1"; close = $true; b = @'
- [x] Repo, venv, requirements.txt, pyproject.toml
- [x] .env.example, .gitignore, database tracewise, docker-compose.yml
- [x] Dữ liệu của thầy, ATT&CK 18.1 + MD5, 4 test dữ liệu, CI
- [x] docs/truy_vet.csv, evidence/nghiem_thu.md, README, nhật ký
'@ },
  @{ t = "B6: chốt cách gọi Ollama (json_schema, enum, reasoning_effort)"; l = "type:test,FR-04"; m = "Tuần 1"; b = @'
- [x] scripts/check_ollama_schema.py có ca bẫy
- [ ] Lưu kết quả vào evidence/FR-04/check_ollama_schema.json
- [ ] Ghi phiên bản Ollama, digest, mức lượng tử hóa vào README
- [ ] Ghi quyết định vào docs/nhat_ky.md

Xong khi: biết rõ /v1 hay /api/chat có áp enum, có tắt được thinking không.
'@ },
  @{ t = "tracewise/settings.py + config/m3.yaml"; l = "type:feature"; m = "Tuần 1"; b = @'
- [ ] Đọc YAML + .env, Pydantic extra="forbid"
- [ ] Cấu hình LLM theo kết quả B6
- [ ] Test: thiếu M3_PG_DSN thì báo lỗi rõ ràng; gõ sai khóa YAML thì báo lỗi

Xong khi: test qua trên CI.
'@ },
  @{ t = "tracewise/srs.py: nạp dữ liệu của thầy + check_host"; l = "type:feature,FR-01,FR-07,NFR-02"; m = "Tuần 1"; b = @'
- [ ] load_alerts, load_whitelist, load_labels
- [ ] check_host bằng urlparse, đọc allowlist_llm.yaml
- [ ] Test: chặn api.example.com, localhost.evil.com, localhost@evil.com, evil.com/localhost

Xong khi: test qua trên CI.
'@ },
  @{ t = "tracewise/attack.py: đọc ATT&CK 18.1 một chỗ duy nhất"; l = "type:feature,FR-04"; m = "Tuần 1"; b = @'
- [ ] load_attack (mã -> tên, tactic), build_kb (mô tả, nền tảng, nguồn dữ liệu)
- [ ] Bỏ đối tượng revoked / deprecated
- [ ] Test: 691 kỹ thuật còn hiệu lực, 24 mã của thầy khớp tên

Xong khi: test qua trên CI.
'@ },
  @{ t = "tracewise/validate.py: khuôn Analysis + 10 luật"; l = "type:feature,FR-02,FR-03,FR-04,FR-06,NFR-04"; m = "Tuần 1"; b = @'
- [ ] Khuôn Technique, Analysis; output_schema(candidates)
- [ ] 10 luật, mỗi luật một hàm; validate(); to_teacher()
- [ ] tests/test_validate.py (45 test) + data/packs/pack_760.json
- [ ] validate chỉ phụ thuộc srs và attack (không import rag)

Xong khi: 45 test qua trên CI.
'@ },
  @{ t = "docs/thiet_ke.md"; l = "type:docs"; m = "Tuần 1"; b = @'
- [ ] Kiến trúc và luồng dữ liệu
- [ ] Bảng quyết định thiết kế, mỗi dòng có lý do
- [ ] ERD (attack_tactic, attack_technique_tactic; giải thích vì sao code dùng text[])
- [ ] Quyết định B6
'@ },
  @{ t = "B7: rà nhãn, thêm ma_chap_nhan"; l = "type:data,FR-03"; m = "Tuần 1"; b = @'
- [ ] data/srs/nhan_chuyen_gia_v1.csv (giữ nguyên file gốc)
- [ ] Cột ma_chap_nhan: mã đó + mã cha + mã con (không gồm mã anh em)
- [ ] Biên bản thay đổi nhãn, mỗi dòng có lý do
- [ ] Gửi Hào / thầy duyệt
'@ },
  @{ t = "tracewise/prompts.py + prompts/*.md"; l = "type:feature,FR-02,FR-06"; m = "Tuần 1"; b = @'
- [ ] load_prompt + sha256 (12 ký tự)
- [ ] wrap: thẻ ngẫu nhiên alert-xxxxxx, gỡ thẻ giả trong dữ liệu
- [ ] prompts/analyze_v1.md, prompts/summary_v1.md
- [ ] Test: thẻ khác nhau mỗi lần, dữ liệu chứa thẻ giả bị gỡ
'@ },
  @{ t = "tracewise/rag.py + scripts/setup_db.py"; l = "type:feature"; m = "Tuần 1"; b = @'
- [ ] Bảng attack_kb (text[] cho tactic, nền tảng, nguồn dữ liệu), embed 24 mã bằng EmbeddingGemma
- [ ] search có lọc nền tảng; candidates với truy vấn đã làm sạch
- [ ] setup_db.py chạy một lần là đủ, chạy lại không lỗi
- [ ] Ghi lại: ứng viên top 5 của LAB-0029 có T1003.001 không
'@ },
  @{ t = "Dịch vụ: adapter, pipeline, store, api"; l = "type:feature,FR-01,FR-07,FR-08"; m = "Tuần 1"; b = @'
- [ ] adapter chuẩn OpenAI (hoặc /api/chat theo B6), kiểm host lúc khởi động
- [ ] pipeline: gói -> ứng viên -> LLM -> kiểm tra, lưu config + prompt_sha
- [ ] store: analysis_run, analysis_log
- [ ] api: /health, POST /alerts/{id}/analysis, GET /analyses/{id}
- [ ] tests/test_api.py (máy chủ LLM giả, schema m3_test)
- [ ] Gọi thật LAB-0029 với Qwen
'@ },
  @{ t = "Báo cáo tuần 1"; l = "type:docs"; m = "Tuần 1"; b = @'
- [ ] Khuôn đầu ra, kết quả B6, nhãn cần duyệt, việc tuần 2
'@ },
  @{ t = "FR-05: analyst lưu nhãn riêng"; l = "type:feature,FR-05"; m = "Tuần 2 - Mốc HD"; b = @'
- [ ] Bảng nhãn của analyst, tách khỏi nhãn mô hình
- [ ] API lưu nhãn, xem nhãn người + nhãn mô hình
- [ ] tests/test_fr05.py, bằng chứng trong evidence/FR-05/

Xong khi: lưu nhãn người xong vẫn xem được nhãn mô hình (SRS 4.1-3).
'@ },
  @{ t = "FR-08: nhật ký có mã người lưu"; l = "type:feature,FR-08"; m = "Tuần 2 - Mốc HD"; b = @'
- [ ] Nhật ký: mã cảnh báo, mã mô hình, mã người lưu, thời điểm
- [ ] tests/test_fr08.py
'@ },
  @{ t = "B5: gọi lại một lần khi JSON hỏng"; l = "type:feature,FR-03"; m = "Tuần 2 - Mốc HD"; b = @'
- [ ] pipeline.run gọi lại đúng một lần khi JSON không đọc được
- [ ] Test: lần 1 hỏng, lần 2 đúng -> status ok; hai lần hỏng -> invalid
'@ },
  @{ t = "Chạy thật 35 cảnh báo của thầy (B1-B4)"; l = "type:test,FR-03,FR-04,FR-06,FR-07"; m = "Tuần 2 - Mốc HD"; b = @'
- [ ] Lưu đầu ra thô + sau hậu kiểm
- [ ] Tỷ lệ có ít nhất 1 mã đúng; cờ chưa đủ căn cứ cho 2 cảnh báo hệ thống
- [ ] Bảng 3 ca chèn prompt: thô có bị lái không, sau kiểm còn T9999/X0001 không
- [ ] Ảnh FR-07: host ngoài allowlist thì dừng
'@ },
  @{ t = "Test theo từng yêu cầu: test_fr01..08, test_nfr04"; l = "type:test"; m = "Tuần 2 - Mốc HD"; b = @'
- [ ] Mỗi FR/NFR có ít nhất một test hoặc bằng chứng
'@ },
  @{ t = "Hoàn thiện truy_vet.csv và nghiem_thu.md"; l = "type:docs"; m = "Tuần 2 - Mốc HD"; b = @'
- [ ] Mỗi dòng có đường dẫn code, test, bằng chứng
'@ },
  @{ t = "Mốc HD ngày 10 + báo cáo tuần 2"; l = "type:docs"; m = "Tuần 2 - Mốc HD"; b = @'
- [ ] Bộ dữ liệu + bảng mã được duyệt
- [ ] README cập nhật, bảng tự kiểm điền đủ
'@ },
  @{ t = "Lab Wazuh 3 nguồn"; l = "type:feature"; m = "Sau mốc HD"; b = @'
- [ ] Bật lưu log thô (logall_json), agent thu Sysmon, Security, PowerShell/Operational
- [ ] normalize cho tên trường Wazuh, kiểm trên mẫu log thật
- [ ] Nối cảnh báo với dòng log trong bảng events
'@ },
  @{ t = "tracewise/evidence.py: gói bằng chứng mức 1"; l = "type:feature"; m = "Sau mốc HD"; b = @'
- [ ] Bảng events chia theo ngày (UTC), cây tiến trình, 4624, 4104
- [ ] Cách nối cho cảnh báo không phải Sysmon EID 1 (4625, sshd, web)
'@ },
  @{ t = "Ma trận đánh giá (có/không RAG x mức gói x 3 seed)"; l = "type:test"; m = "Sau mốc HD"; b = @'
- [ ] Khoảng tin cậy bootstrap theo kịch bản, McNemar, hit@k, MRR, p95
'@ },
  @{ t = "Giao diện React cho analyst"; l = "type:feature"; m = "Sau mốc HD"; b = @'
- [ ] Danh sách cảnh báo, tóm tắt, mã + tên ATT&CK, bấm [E...] xem log, cờ cần người xem
- [ ] Form lưu nhãn của analyst (FR-05)
'@ },
  @{ t = "SRS theo ISO/IEC/IEEE 29148 bản đầy đủ"; l = "type:docs"; m = "Sau mốc HD"; b = @'
- [ ] Đủ các mục theo chuẩn, khớp truy_vet.csv
'@ }
)

foreach ($i in $issues) {
  $url = gh issue create --title $i.t --label $i.l --milestone $i.m --body $i.b
  Write-Host $url
  if ($i.close) { gh issue close $url --reason completed }
}