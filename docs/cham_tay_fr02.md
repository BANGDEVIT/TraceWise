# Tiêu chí chấm tay tóm tắt (FR-02)

10 tóm tắt chọn ngẫu nhiên bằng `random.Random(0)` trong `scripts/score_run.py`
(file `results/<lượt>_cham_tay.csv`). Mỗi tóm tắt chấm 3 tiêu chí, mỗi tiêu chí 0–2 điểm.

| Tiêu chí | 0 | 1 | 2 |
|---|---|---|---|
| Đúng sự thật | Có chi tiết sai hoặc bịa | Đúng nhưng có suy diễn, gọi tên đoán mò | Mọi câu khớp với log |
| Đủ ý chính | Bỏ sót hành vi chính | Thiếu chi tiết quan trọng (máy, tài khoản, tiến trình) | Đủ: cái gì, làm gì, trên máy nào |
| Tiếng Việt rõ ràng | Khó hiểu, sai ngữ pháp | Hiểu được nhưng gượng | Rõ ràng, tự nhiên |

Người chấm: … | Ngày chấm: … | Kết quả: đúng sự thật …/20, đủ ý …/20, tiếng Việt …/20