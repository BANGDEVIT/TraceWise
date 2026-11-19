# Nhật ký dự án TraceWise

Mục mới nhất ở trên cùng. Mỗi mục: đã làm, quyết định (kèm lý do), vấn đề gặp phải, việc tiếp theo.

## Ngày 1: dựng khung dự án

**Đã làm**
- Tạo repo, môi trường ảo Python 3.13.1, `requirements.txt`, `pyproject.toml` (cài editable `pip install -e .`).
- Cấu trúc thư mục: `tracewise/`, `tests/`, `scripts/`, `config/`, `prompts/`, `data/`, `docs/`, `evidence/FR-01…NFR-04/`.
- Database `tracewise` trong container `m3-pg` (Postgres 16 + pgvector), đổi mật khẩu, chuỗi kết nối nằm trong `.env`.
- `docker-compose.yml` để máy khác dựng lại Postgres giống hệt.
- Chép dữ liệu của thầy vào `data/srs/`, tải ATT&CK 18.1 và kiểm MD5.
- 4 test đầu tiên (`tests/test_data_files.py`): 35 cảnh báo, 24 mã whitelist, nhãn đủ cho mọi cảnh báo, MD5 ATT&CK → 4 passed.
- CI: `pyflakes` + `pytest` mỗi lần push.
- `docs/truy_vet.csv`, `evidence/nghiem_thu.md`.
- Viết `scripts/check_ollama_schema.py` cho B6.

**Quyết định**
- Code chính đặt trong package `tracewise/` (thay cho `src/` của giai đoạn học): import rõ nguồn gốc, cài editable được.
- Giữ tiền tố biến môi trường `M3_` (gắn với mã đề), không đổi sang tên khác.
- Dùng Python 3.13 cả trên máy và CI (thư viện đều hỗ trợ), không hạ xuống 3.12.
- Không dùng Postgres trên cloud: dữ liệu log và kết quả phải ở lại máy lab.
- Postgres chỉ mở ở `127.0.0.1` để máy khác trong mạng không kết nối được.
- Test đầu tiên không cần Ollama hay Postgres, nên CI xanh ngay từ ngày đầu.
- Script B6 thêm ca bẫy (enum không chứa đáp án đúng); ca thường không chứng minh được enum có được áp.

**Tiếp theo**
- Chạy B6 trên máy lab, ghi phiên bản Ollama và digest mô hình vào README, chốt `config/m3.yaml`.
- Ngày 2: chuyển `settings`, `srs`, `attack`, `validate` sang `tracewise/`, mỗi module kèm test.