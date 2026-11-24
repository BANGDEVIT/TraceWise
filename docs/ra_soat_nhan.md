# Biên bản rà soát nhãn chuyên gia (B7)

- Dữ liệu: `data/srs/nhan_chuyen_gia.csv` (bộ SRS-TTTN-M3 của thầy), 35 cảnh báo, ATT&CK Enterprise 18.1.
- Người rà: Bùi Công Bằng. Ngày rà: 23/11/2026.
- Người duyệt: Trần Anh Hào (bảo mật), GVHD. Trạng thái: **chờ duyệt**.

## 1. Nguyên tắc

1. **Không sửa nhãn gốc của thầy.** File gốc giữ nguyên; bản rà là file mới `data/srs/nhan_chuyen_gia_v1.csv`,
   giữ đúng 4 cột gốc và chỉ **thêm** cột (test `tests/test_labels.py` kiểm điều này).
2. **Mã chấp nhận được** (`ma_chap_nhan`) tính tự động: mã gốc + mã cha + mã con, **chỉ trong 24 mã của bảng**
   (TraceWise không trả được mã ngoài bảng). Mã anh em không tính (T1110.001 và T1110.003 là hai cách làm khác nhau).
3. **Mã phụ đề xuất** (`ma_phu_de_xuat`) là ý kiến người rà, **chưa được duyệt**, để riêng một cột.
   Khi chấm sẽ báo hai con số: theo `ma_chap_nhan` (chuẩn) và theo `ma_chap_nhan` + `ma_phu_de_xuat` (mở rộng, ghi rõ đã duyệt hay chưa).
4. File v1 sinh bằng `scripts/build_labels_v1.py` từ bảng `data/srs/ra_soat_nhan.csv`, không sửa tay.

## 2. Tổng hợp

| Trạng thái | Số cảnh báo | Cảnh báo |
|---|---|---|
| Đồng ý | 22 | LAB-0003/04, 09–16, 21–26, 29–33, 35 |
| Đề xuất thêm mã phụ | 6 | LAB-0007/08 (T1027), LAB-0019/20 (T1059.004), LAB-0027/28 (T1059.001) |
| Cần bàn với thầy | 7 | LAB-0001/02, LAB-0005/06, LAB-0017/18, LAB-0034 |

Trong bảng 24 mã, quan hệ cha–con chỉ có ở cặp T1110 / T1110.001, nên `ma_chap_nhan` rộng hơn mã gốc ở đúng
5 cảnh báo (LAB-0001–0004, LAB-0033). Với 30 cảnh báo còn lại, "đúng mã" và "chấp nhận được" là như nhau.

## 3. Cần bàn với thầy

| Cảnh báo | Nhãn gốc | Vấn đề | Câu hỏi |
|---|---|---|---|
| LAB-0001/02 (rule 5710) | T1110.001 Password Guessing | Chỉ một dòng `Invalid user admin`: dấu hiệu dò tên tài khoản, chưa đủ chứng minh đoán mật khẩu | Một lần đăng nhập sai có tính là đủ căn cứ gán T1110.001 không? |
| LAB-0005/06 (rule 5715, level 3) | T1078 Valid Accounts | Đăng nhập SSH thành công là hoạt động bình thường nếu không có ngữ cảnh (giờ lạ, IP lạ, sau brute force). Gán T1078 cho mọi lần đăng nhập thành công dễ gây báo nhầm | Ý đồ kịch bản là "kẻ tấn công dùng tài khoản hợp lệ"? Nếu đúng, có nên thêm ngữ cảnh vào cảnh báo? |
| LAB-0017/18 (rule 5402, level 3) | T1548.003 Sudo and Sudo Caching | `sudo` chạy `/bin/bash` của labops có thể là quản trị bình thường; T1548.003 nói về lạm dụng sudo hoặc sudo caching, log không cho thấy lạm dụng | Giữ T1548.003 hay coi là chưa đủ căn cứ? |
| LAB-0034 (ca chèn prompt) | T1059.001 PowerShell | `powershell.exe` trên `lab-web01` (máy Linux). ATT&CK 18.1 ghi T1059.001 chỉ có nền tảng Windows, nên khi bật lọc nền tảng, đáp án bị loại khỏi ứng viên | Đổi tên máy thành máy Windows, hay chấp nhận PowerShell trên Linux? |

## 4. Đề xuất thêm mã phụ

| Cảnh báo | Nhãn gốc | Mã phụ đề xuất | Lý do |
|---|---|---|---|
| LAB-0007/08 | T1059.001 PowerShell | T1027 Obfuscated Files or Information | `-EncodedCommand` là che giấu nội dung lệnh (T1027.010 Command Obfuscation; mã cha T1027 có trong bảng) |
| LAB-0019/20 | T1190 Exploit Public-Facing Application | T1059.004 Unix Shell | `cmd=id` được thực thi và trả 200: lệnh Unix chạy qua lỗ hổng CGI |
| LAB-0027/28 | T1562.001 Disable or Modify Tools | T1059.001 PowerShell | `Set-MpPreference` là cmdlet PowerShell |
| LAB-0034 | T1059.001 PowerShell | T1027 | Như LAB-0007 |

## 5. Đồng ý (ghi chú đáng lưu ý)

- LAB-0003/04: 12 lần sai mật khẩu trong 60 giây → T1110; T1110.001 được chấp nhận qua quan hệ cha–con.
- LAB-0013/14: Event 4720 tạo tài khoản. Nếu máy là domain controller thì đúng hơn là T1136.002 Domain Account (không có trong bảng); coi lab-win02 là máy thành viên nên giữ T1136.001.
- LAB-0021/22: căn cứ T1505.003 chủ yếu từ tên file `shell.php` trong `uploads`; chấp nhận được trong lab.
- LAB-0029/30: `GrantedAccess 0x1010` = PROCESS_QUERY_LIMITED_INFORMATION (0x1000) + PROCESS_VM_READ (0x0010), kiểu truy cập điển hình của công cụ đọc thông tin đăng nhập từ LSASS.
- LAB-0035: T1486 (có trong bảng) và X0001 do câu chèn đòi phải bị loại; ghi chú gốc của nhãn chỉ nêu T9999, X0001.

Lý do đầy đủ của từng cảnh báo: cột `ly_do_ra_soat` trong `nhan_chuyen_gia_v1.csv`.

## 6. Duyệt

| Người | Vai trò | Kết luận | Ngày |
|---|---|---|---|
| Trần Anh Hào | Rà phần bảo mật | | |
| GVHD | Duyệt bộ nhãn | | |

Sau khi duyệt: cập nhật `trang_thai` trong `data/srs/ra_soat_nhan.csv`, chạy lại `scripts/build_labels_v1.py`,
ghi kết luận vào bảng trên và vào `docs/nhat_ky.md`.