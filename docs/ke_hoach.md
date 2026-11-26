# Kế hoạch TraceWise

Đánh dấu `[x]` khi xong và ghi ngày hoàn thành. Chi tiết từng ngày ở [nhat_ky.md](nhat_ky.md).
Mốc HD: ngày 10 — bộ dữ liệu + bảng mã được duyệt, bảng tự kiểm nghiệm thu điền đủ.

## Tuần 1

### Ngày 1 — Khung dự án
- [x] Repo, môi trường ảo, `requirements.txt`, `pyproject.toml` (19/11)
- [x] `.env.example`, `.gitignore`, database `tracewise`, `docker-compose.yml` (19/11)
- [x] Dữ liệu của thầy, ATT&CK 18.1 + MD5, 4 test dữ liệu, CI (19/11)
- [x] `docs/truy_vet.csv`, `evidence/nghiem_thu.md`, thư mục `evidence/` (19/11)
- [x] README, nhật ký (19/11)
- [x] Chuyển CI sang GitHub Actions (19/11)

### Ngày 1–2 — B6: Ollama có áp JSON schema + enum
- [x] `scripts/check_ollama_schema.py` có ca bẫy (19/11)
- [x] Ghi kết quả vào `evidence/FR-04/`, phiên bản Ollama + digest vào README (19/11)
- [x] Chốt cách gọi LLM: `/v1` + `json_schema` + `reasoning_effort: none` (19/11)

### Ngày 2 — Cấu hình và dữ liệu
- [x] `tracewise/settings.py` + `config/m3.yaml` (theo quyết định B6): thiếu `.env` thì báo lỗi rõ ràng (19/11)
- [x] `tracewise/srs.py`: nạp dữ liệu của thầy, `check_host` (FR-07) (19/11)
- [x] `tracewise/attack.py`: đọc STIX một chỗ duy nhất (691 kỹ thuật, 24 mã khớp tên) (19/11)
- [x] Test cho cả ba module (19/11)

### Ngày 2–3 — Kiểm tra chặt đầu ra
- [x] `tracewise/validate.py`: khuôn `Analysis` + 10 luật (22/11)
- [x] Thêm luật bắt mã trùng (B6: mô hình trả cùng một mã hai lần) — luật 6 có sẵn, nay gộp bằng chứng (22/11)
- [x] `tests/test_validate.py` (45 test + test mã trùng) + `data/packs/pack_760.json` (22/11)

### Ngày 3 — Thiết kế
- [x] `docs/thiet_ke.md`: kiến trúc, quyết định + lý do, ERD, quyết định B6 (23/11)
### Ngày 3–4 — Rà nhãn (B7)
- [x] `data/srs/nhan_chuyen_gia_v1.csv` có cột `ma_chap_nhan` (file gốc giữ nguyên) (23/11)
- [x] Biên bản thay đổi nhãn, kèm lý do từng dòng — `docs/ra_soat_nhan.md`, chờ Hào/thầy duyệt (23/11)

### Ngày 4 — Prompt và RAG
- [x] `tracewise/prompts.py` + `prompts/analyze_v1.md`, `prompts/summary_v1.md` (24/11)
- [x] `tracewise/rag.py` + `scripts/setup_db.py` (tạo `attack_kb`, embed 24 mã) (24/11)

### Ngày 5 — Dịch vụ
- [x] `tracewise/adapter.py`, `pipeline.py`, `store.py`, `api.py`
- [x] `tests/test_api.py` (máy chủ LLM giả, schema `m3_test`)
- [x] Gọi thật `POST /alerts/LAB-0029/analysis` với Qwen
- [x] Báo cáo tuần 1 gửi thầy: khuôn đầu ra, kết quả B6, nhãn cần duyệt

## Tuần 2

### Ngày 6–7 — Nhãn analyst, nhật ký, gọi lại
- [x] FR-05: bảng `analyst_label`, POST /runs/{id}/labels, GET /alerts/{id}/labels
- [x] FR-08: `analysis_log` có `actor` (mã người lưu) và `model`; nâng cấp bảng cũ bằng ALTER TABLE
- [x] B5: JSON hỏng gọi lại 1 lần, bị cắt thì gấp đôi max_tokens
- [x] Luật 3: mỗi câu tóm tắt phải trích dòng E…; lưu tên thẻ ngẫu nhiên vào nhật ký

<!-- ### Ngày 6–7 — FR-05 + FR-08
- [ ] Bảng nhãn của analyst, tách khỏi nhãn mô hình; API lưu và xem
- [ ] Nhật ký có "mã người lưu"
- [ ] `tests/test_fr05.py`, bằng chứng trong `evidence/FR-05/`

### Ngày 7 — B5
- [ ] Gọi lại một lần khi JSON hỏng trong `pipeline.py` + test -->

### Ngày 8–9 — Chạy thật 35 cảnh báo (B1–B4)
Lưu ý: mỗi cảnh báo ~2–3 phút trên CPU → mỗi cấu hình ~1–2 giờ; chạy lúc không dùng máy.
- [x] Lưu đầu ra thô + sau hậu kiểm
- [x] Chấm theo nhãn: tỷ lệ có ≥ 1 mã đúng, cờ chưa đủ căn cứ cho 2 cảnh báo hệ thống
- [x] Bảng 3 ca chèn prompt (đầu ra thô có bị lái không, sau kiểm có còn T9999/X0001 không)
- [x] Ảnh FR-07: đổi host ra ngoài allowlist thì dừng

### Ngày 6–9 — Test và bằng chứng theo yêu cầu
- [x] `test_fr01.py` … `test_fr08.py`, `test_nfr04.py`
- [x] Điền `docs/truy_vet.csv`, `evidence/nghiem_thu.md`

### Ngày 10 — Mốc
- [x] Báo cáo mốc `docs/bao_cao/Bao_cao_moc_TraceWise.docx`
- [x] Kịch bản demo `docs/demo_moc.md`
- [x] Tag `v0.1.0`
- [ ] Gửi báo cáo cho thầy; demo; ghi lại ý kiến thầy vào `docs/nhat_ky.md`

## Sau mốc ngày 10
- [ ] Lab Wazuh 3 nguồn: lưu log thô, chuẩn hóa tên trường Wazuh, nối cảnh báo với log
- [ ] `tracewise/evidence.py`: gói bằng chứng mức 1
- [ ] Ma trận đánh giá (có/không RAG × seed) — giảm số lần chạy vì mỗi lần gọi ~1,5–2 phút
- [ ] Giao diện React cho analyst
- [ ] SRS theo ISO/IEC/IEEE 29148 bản đầy đủ

## Sau mốc (thứ tự ưu tiên chờ thầy cho ý kiến)
- [ ] Giới hạn thời gian tổng mỗi lần gọi Qwen; tìm nguyên nhân LAB-0004, 0012 chờ ~1 giờ
- [ ] Sửa nhãn v1 theo trả lời của thầy cho 4 câu hỏi; chấm lại lab35_a (không chạy lại Qwen)
- [ ] Tập phát triển riêng (không dùng 35 cảnh báo của thầy) để thử prompt, k, query_mode summary
- [ ] Lab Wazuh 3 nguồn (Sysmon, Windows Security, PowerShell); gói bằng chứng mức 1
- [ ] Giao diện React: xem kết quả, lưu nhãn, đăng nhập (nguoi_luu lấy từ tài khoản)
- [ ] SRS theo ISO/IEC/IEEE 29148; nhờ Hào chấm tay độc lập 10 tóm tắt


