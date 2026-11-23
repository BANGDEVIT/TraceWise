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

## Ngày 2 — 19/11/2026: cấu hình, dữ liệu của thầy, ATT&CK

**Đã làm**
- `config/m3.yaml` + `tracewise/settings.py`: cấu hình theo kết quả B6 (`json_schema`, `reasoning_effort: none`).
- `tracewise/srs.py`: nạp 35 cảnh báo, 24 mã, nhãn (kèm nhóm kịch bản); `check_host` cho FR-07.
- `tracewise/attack.py`: đọc ATT&CK 18.1 một lần (691 kỹ thuật), có tên, tactic, nền tảng, nguồn dữ liệu, mô tả.
- 24 test mới → tổng 28 passed.

**Quyết định**
- `max_tokens` 500 → 800: B6 cho thấy câu trả lời 290–390 token, có 3 kỹ thuật dễ vượt 500 và bị cắt.
- `OLLAMA_HOST` ghi đè địa chỉ LLM, để thử FR-07 đúng như README của thầy.
- `host_platform` chuyển vào cấu hình (trước ghi cứng trong code đánh giá).
- Nhãn được gom theo kịch bản ngay khi nạp: 17 nhóm độc lập (15 kịch bản + INJ + khong_du), dùng cho bootstrap sau này.
- Gộp hai chỗ đọc STIX (validate và rag) thành `attack.py`; dùng `lru_cache` nên chỉ đọc file một lần.

**Kiểm chứng**
- 24 mã của thầy khớp cả tên lẫn tactic với ATT&CK 18.1.
- `check_host` chặn 6 bẫy: api.example.com, localhost.evil.com, localhost@evil.com, evil.com/localhost, URL có user:pass, 0.0.0.0.

**Tiếp theo**
- Ngày 2–3: `tracewise/validate.py` + 45 test, thêm enum cho `evidence`, giới hạn `rank` 1–3, luật bắt mã trùng.

## Ngày 3 — 22/11/2026: kiểm tra chặt đầu ra

**Đã làm**
- `tracewise/validate.py`: khuôn `Analysis` + 10 luật, chỉ phụ thuộc `attack` và `injection`.
- `tracewise/injection.py` (mới, FR-06): nhận diện dòng chèn prompt, mã bị cài, yêu cầu "an toàn".
- `srs.py` thêm `alert_lines` (gói mức 0), `whitelist_codes`, `Assessment` (khuôn của thầy).
- `data/packs/pack_760.json` làm dữ liệu cố định cho test.
- 53 test mới → tổng 81 passed.

**Quyết định (từ kết quả B6)**
- `output_schema` thêm enum cho `evidence` (chỉ E1…En của gói) và giới hạn `rank` 1–3.
- Luật 3: chuỗi bắt đầu bằng mã E (mô hình chép nguyên dòng log) thì giữ mã E, ghi vi phạm "sửa", không hạ tin cậy.
- Luật 6: mã lặp thì gộp bằng chứng vào lần xuất hiện đầu (trước đây vứt luôn bằng chứng của bản lặp).
- `to_teacher` trả `None` cho kết quả hỏng, không ép vào khuôn của thầy.
- Đóng băng câu trả lời thật của Qwen ở B6 thành regression test.

**Kiểm chứng**
- Bộ nhận diện chèn prompt bắt đúng 3/3 ca của thầy, không báo nhầm 32 cảnh báo còn lại.
- Câu trả lời B6: trước đây bị xóa sạch mã ("chưa đủ căn cứ"), nay giữ T1562.001 với bằng chứng E1, E2 và gắn cờ cần người xem.

**Giới hạn còn lại**
- Validator không biết mã sai về nghĩa (T1562.001 thay vì T1003.001) → sửa bằng prompt có tên kỹ thuật (Ngày 4) và đo ở lần chạy 35 cảnh báo.

**Tiếp theo**
- Ngày 3: `docs/thiet_ke.md`. Ngày 3–4: rà nhãn (B7).