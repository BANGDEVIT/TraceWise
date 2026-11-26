# Kịch bản demo mốc 2 tuần (10 phút)

## Chuẩn bị (15 phút trước buổi demo)
- [ ] Cắm sạc, tắt ngủ: `powercfg /change standby-timeout-ac 0`
- [ ] `docker ps` thấy Postgres chạy; `ollama ps` (nếu trống thì chạy bước làm nóng dưới đây)
- [ ] Làm nóng mô hình (lần gọi đầu nạp mô hình vào RAM, chậm hơn): `python scripts/analyze_one.py LAB-0030`
- [ ] Cửa sổ 1: `uvicorn tracewise.api:app --host 127.0.0.1 --port 8000`, trình duyệt mở `http://127.0.0.1:8000/docs`
- [ ] Cửa sổ 2: PowerShell ở thư mục dự án, đã bật venv
- [ ] Mở sẵn: `docs/thiet_ke.md` (hình mục 2 và 2.1), `results/lab35_a_score.md`, báo cáo mốc
- [ ] Dự phòng nếu Qwen chậm hoặc lỗi: `evidence/runs/LAB-0029_run3.json` và `results/runs/lab35_a.jsonl`

## Trình tự
| Phút | Nội dung | Thao tác |
|---|---|---|
| 0–1 | Bài toán và kiến trúc 5 bước | Hình mục 2 trong `thiet_ke.md` |
| 1–4 | Phân tích thật LAB-0029 | /docs → POST `/alerts/LAB-0029/analyze` → Execute. Trong ~60 giây chờ Qwen: giải thích enum = 5 ứng viên, 10 luật. Kết quả: T1003.001, bằng chứng E3, `events` có thời gian từng bước |
| 4–6 | Chèn prompt LAB-0034 | Cửa sổ 2: `python scripts/analyze_one.py LAB-0034` (~35 giây). Chỉ: đầu ra thô "không có dấu hiệu tấn công", luật 10 → cần người xem |
| 6–7 | FR-07: chặn địa chỉ lạ | Cửa sổ 2: `$env:OLLAMA_HOST = "https://api.example.com"` rồi `uvicorn tracewise.api:app --port 8001` → `Application startup failed`; sau đó `Remove-Item Env:OLLAMA_HOST` |
| 7–8 | FR-05: analyst lưu nhãn riêng | /docs → POST `/runs/{id}/labels` cho lần chạy LAB-0029 vừa xong → 201; GET `/runs/{id}` thấy `result` giữ nguyên, có `labels` |
| 8–9 | Kết quả 35 cảnh báo | `results/lab35_a_score.md` hoặc hình phễu trong báo cáo: 79% / 67% / trần RAG 91%; mất 3 ở RAG, 4 ở Qwen |
| 9–10 | Kiểm thử và câu hỏi | Cửa sổ 2: `python -m pytest -q` → 228 passed (~7 giây). Hỏi thầy 4 câu về nhãn |

## Nếu có sự cố
- Qwen quá 3 phút không trả lời: dừng, mở `evidence/runs/LAB-0029_run3.json`, nói rõ "đây là kết quả lần chạy thật hôm 26/11".
- Database lỗi: `docker start m3-pg` rồi chạy lại uvicorn.