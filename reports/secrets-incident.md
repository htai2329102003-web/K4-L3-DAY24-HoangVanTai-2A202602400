# Secret giả trong lịch sử Git

- Scanner và phiên bản: Gitleaks v8.30.1.
- Commit chứa token giả: `1bdd849922156c868a5ee9293d68f5b72e242d2c`.
- File, rule và kết quả quét lịch sử: `lab-fake-secret.txt`, rule `lab24-synthetic-token`; `gitleaks git --config .gitleaks.toml --redact --verbose .` tìm đúng một finding và trả exit code 1 như dự kiến. Đây là token synthetic, vô hiệu của lab.
- Kết quả quét file hiện tại: quét 112 file working tree (không gồm `.git`) bằng `gitleaks dir --config .gitleaks.toml` trả exit code 0, không có leak.
- Nếu đây là credential thật, cần thu hồi/rotate ngay, vô hiệu hoá phiên hoặc key liên quan, điều tra phạm vi lộ lọt và cập nhật hệ thống đang dùng credential đó.
- Xoá file khỏi HEAD không loại được credential khỏi lịch sử hay bản sao đã bị tải về. Pin dependency và hook Gitleaks chỉ giúp giảm rủi ro về sau; chúng không thay thế rotate một secret đã lộ.
