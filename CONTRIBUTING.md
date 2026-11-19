# Quy trình làm việc TraceWise

Mỗi việc là một issue. Không commit thẳng vào `main`; mọi thay đổi đi qua Pull Request và CI phải xanh.

## Mỗi buổi

1. **Chọn issue** trên bảng Project (cột *Todo*), gán cho mình, kéo sang *In Progress*.
2. **Cập nhật main và tạo branch gắn với issue**
   ```powershell
   git switch main
   git pull
   gh issue develop <số> --checkout --name <loại>/<số>-<mô-tả-ngắn>
   ```
   Loại: `feat`, `fix`, `test`, `docs`, `chore`. Ví dụ: `feat/3-settings-module`.
3. **Làm từng bước nhỏ, commit thường xuyên** (tiếng Anh, dạng `<loại>: <việc đã làm>`)
   ```powershell
   python -m pytest -q
   python -m pyflakes tracewise tests
   git add <file>
   git commit -m "feat: load settings from YAML and .env"
   ```
4. **Cập nhật tài liệu** trong cùng branch: `docs/nhat_ky.md`, README nếu cách chạy đổi, `docs/truy_vet.csv` nếu liên quan FR/NFR.
5. **Push và mở Pull Request**
   ```powershell
   git push -u origin HEAD
   gh pr create --base main --web
   ```
   Điền mẫu PR, dòng đầu `Closes #<số>`.
6. **Chờ CI và tự review**: `gh pr checks --watch`, đọc lại tab *Files changed* như người khác đọc.
7. **Merge và dọn dẹp**
   ```powershell
   gh pr merge --squash --delete-branch
   git switch main
   git pull
   ```
   Issue tự đóng, thẻ trên bảng tự sang *Done*.

## Quy ước
- Branch và commit message bằng tiếng Anh.
- Không commit `.env` hoặc mật khẩu.
- Phát hiện việc mới hoặc lỗi giữa chừng: tạo issue mới, không nhét vào PR đang làm.