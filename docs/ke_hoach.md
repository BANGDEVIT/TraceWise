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

### Ngày 1–2 — B6: Ollama có áp JSON schema + enum
- [x] `scripts/check_ollama_schema.py` có ca bẫy (19/11)
- [ ] Ghi kết quả vào `evidence/FR-04/`, phiên bản Ollama + digest vào README
- [ ] Chốt cách gọi LLM (`/v1` hay `/api/chat`, `reasoning_effort`) trong `config/m3.yaml`

### Ngày 2 — Cấu hình và dữ liệu
- [ ] `tracewise/settings.py` + `config/m3.yaml`: thiếu `.env` thì báo lỗi rõ ràng
- [ ] `tracewise/srs.py`: nạp dữ liệu của thầy, `check_host` (FR-07)
- [ ] `tracewise/attack.py`: đọc STIX một chỗ duy nhất (691 kỹ thuật, 24 mã khớp tên)
- [ ] Test cho cả ba module

### Ngày 2–3 — Kiểm tra chặt đầu ra
- [ ] `tracewise/validate.py`: khuôn `Analysis` + 10 luật
- [ ] `tests/test_validate.py` (45 test) + `data/packs/pack_760.json`

### Ngày 3 — Thiết kế
- [ ] `docs/thiet_ke.md`: kiến trúc, quyết định + lý do, ERD, quyết định B6

### Ngày 3–4 — Rà nhãn (B7)
- [ ] `data/srs/nhan_chuyen_gia_v1.csv` có cột `ma_chap_nhan` (file gốc giữ nguyên)
- [ ] Biên bản thay đổi nhãn, kèm lý do từng dòng

### Ngày 4 — Prompt và RAG
- [ ] `tracewise/prompts.py` + `prompts/analyze_v1.md`, `prompts/summary_v1.md`
- [ ] `tracewise/rag.py` + `scripts/setup_db.py` (tạo `attack_kb`, embed 24 mã)

### Ngày 5 — Dịch vụ
- [ ] `tracewise/adapter.py`, `pipeline.py`, `store.py`, `api.py`
- [ ] `tests/test_api.py` (máy chủ LLM giả, schema `m3_test`)
- [ ] Gọi thật `POST /alerts/LAB-0029/analysis` với Qwen
- [ ] Báo cáo tuần 1 gửi thầy: khuôn đầu ra, kết quả B6, nhãn cần duyệt

## Tuần 2

### Ngày 6–7 — FR-05 + FR-08
- [ ] Bảng nhãn của analyst, tách khỏi nhãn mô hình; API lưu và xem
- [ ] Nhật ký có "mã người lưu"
- [ ] `tests/test_fr05.py`, bằng chứng trong `evidence/FR-05/`

### Ngày 7 — B5
- [ ] Gọi lại một lần khi JSON hỏng trong `pipeline.py` + test

### Ngày 8–9 — Chạy thật 35 cảnh báo (B1–B4)
- [ ] Lưu đầu ra thô + sau hậu kiểm
- [ ] Chấm theo nhãn: tỷ lệ có ≥ 1 mã đúng, cờ chưa đủ căn cứ cho 2 cảnh báo hệ thống
- [ ] Bảng 3 ca chèn prompt (đầu ra thô có bị lái không, sau kiểm có còn T9999/X0001 không)
- [ ] Ảnh FR-07: đổi host ra ngoài allowlist thì dừng

### Ngày 6–9 — Test và bằng chứng theo yêu cầu
- [ ] `test_fr01.py` … `test_fr08.py`, `test_nfr04.py`
- [ ] Điền `docs/truy_vet.csv`, `evidence/nghiem_thu.md`

### Ngày 10 — Mốc HD
- [ ] Bộ dữ liệu + bảng mã được duyệt
- [ ] Báo cáo tuần 2, README cập nhật

## Sau mốc ngày 10
- [ ] Lab Wazuh 3 nguồn: lưu log thô, chuẩn hóa tên trường Wazuh, nối cảnh báo với log
- [ ] `tracewise/evidence.py`: gói bằng chứng mức 1
- [ ] Ma trận đánh giá (có/không RAG × 3 seed), khoảng tin cậy, McNemar, hit@k
- [ ] Giao diện React cho analyst
- [ ] SRS theo ISO/IEC/IEEE 29148 bản đầy đủ