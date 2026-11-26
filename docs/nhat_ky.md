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

## Ngày 4 — 23/11/2026: rà nhãn chuyên gia (B7)

**Đã làm**
- Rà 35 nhãn: 22 đồng ý, 6 đề xuất thêm mã phụ, 7 cần bàn với thầy (LAB-0001/02, 0005/06, 0017/18, 0034).
- `attack.family`: mã + cha + con (không gồm anh em).
- `data/srs/ra_soat_nhan.csv` (ý kiến rà) → `scripts/build_labels_v1.py` → `data/srs/nhan_chuyen_gia_v1.csv`.
- `docs/ra_soat_nhan.md`: biên bản gửi Hào và thầy duyệt.
- 7 test mới → tổng 88 passed.

**Quyết định**
- Không sửa nhãn gốc; ba lớp: nhãn gốc / chấp nhận (tự động theo quy tắc) / đề xuất (chờ duyệt).
- `ma_chap_nhan` chỉ tính trong 24 mã của bảng, vì TraceWise không trả được mã ngoài bảng.
- File v1 sinh bằng script; test bảo đảm file khớp script và nhãn gốc không đổi.

**Phát hiện**
- Trong 24 mã, quan hệ cha–con chỉ có ở T1110 / T1110.001 → "chấp nhận được" chỉ khác "đúng mã" ở 5 cảnh báo.
- Ba kịch bản có thể là hoạt động bình thường (đăng nhập thành công, sudo của quản trị viên, một lần đăng nhập sai) → cần thầy xác nhận ý đồ.

**Tiếp theo**
- Gửi biên bản cho Hào và thầy (kèm báo cáo tuần 1).
- Ngày 4: `prompts.py`, `rag.py` + `scripts/setup_db.py`.

## Ngày 5 — 24/11/2026: prompt và RAG

**Đã làm**
- `prompts/analyze_v1.md`: bảng tên kỹ thuật + 8 quy tắc rút từ lỗi thật ở B6; `summary_v1.md` cho câu truy vấn.
- `tracewise/prompts.py`: SHA của prompt, thẻ ngẫu nhiên, gỡ thẻ giả, bảng kỹ thuật.
- `tracewise/adapter.py` (phần embedding): kiểm FR-07 khi tạo client, lưu tên mô hình máy chủ trả về.
- `tracewise/rag.py`: bảng `attack_kb`, tìm k ứng viên, lọc nền tảng, làm sạch câu truy vấn.
- `scripts/setup_db.py`, `scripts/check_candidates.py`. 17 test mới → 105 passed.

**Kết quả thật (EmbeddingGemma)**
- setup_db: … giây cho 24 kỹ thuật.
- Không lọc: hit@1 … | hit@3 … | hit@5 … | MRR …
- Lọc nền tảng: hit@1 … | hit@3 … | hit@5 … | MRR …
- Trượt khi lọc: …   (LAB-0029 có/không có T1003.001 trong top 5: …)

**Quyết định**
- System prompt cố định, bảng kỹ thuật đặt trong tin nhắn user (dùng lại phần đã tính trên CPU).
- Khuôn tài liệu/truy vấn của EmbeddingGemma đưa vào cấu hình.
- Không chỉnh câu truy vấn hay k theo kết quả trên bộ của thầy.

**Tiếp theo**
- Ngày 5: phần chat của adapter, `pipeline.py`, `store.py`, `api.py`; gọi thật LAB-0029.

## …/11/2026 — Kế hoạch Ngày 6–7: nhãn analyst, nhật ký, gọi lại

**Đã làm**
- FR-05: nhãn analyst ở bảng riêng `analyst_label`, chỉ thêm không sửa, nối với lần chạy (run_id).
- FR-08: mỗi dòng nhật ký có alert_ref, model, actor, ts; dòng cũ được điền model.
- B5: gọi lại khi JSON hỏng; bị cắt thì 800 → 1600 token.
- Luật 3 bắt câu tóm tắt không trích dẫn (lỗi thật của LAB-0029 ngày 25/11). 15 test mới → 139 passed.

**Kết quả thật**
- LAB-0029 chạy lại: trạng thái …, cần người xem …, gọi Qwen … lần, vi phạm …
- Lưu nhãn qua /docs: 201; nhãn sai: 422.

**Quyết định**
- Mã analyst được kiểm trong 691 kỹ thuật ATT&CK 18.1, không giới hạn trong 5 ứng viên.
- Câu không trích dẫn: đánh dấu cần xem, không hạ tin cậy.
- Chưa có đăng nhập: nguoi_luu gõ tay; sẽ lấy từ tài khoản khi có giao diện.

**Tiếp theo**
- Ngày 8–9: chạy thật 35 cảnh báo, chấm theo nhãn, báo cáo 3 ca chèn lệnh.