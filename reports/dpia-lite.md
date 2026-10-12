# DPIA-lite

1. Loại dữ liệu và phân loại: corpus là input không tin cậy; customer record có CCCD, điện thoại, tài khoản ngân hàng và email là synthetic nhưng được xử lý như `restricted`.
2. Mục đích xử lý và principal: tóm tắt ticket và hỗ trợ phản hồi; `support_l1` chỉ search, còn `dpo` chỉ đọc customer gắn với ticket hợp lệ theo policy.
3. Dữ liệu đi qua những run/tool nào, endpoint nào: Run A dùng `search_docs`; Run B nhận ticket ID từ tên file, tra `related_tickets` rồi mới gọi `read_customer`. Egress chỉ là sink lab `http://127.0.0.1:10024`; replay sau containment không gọi POST thật.
4. Bằng chứng deny/allow và giới hạn của mock: `reports/ledger.jsonl:23` là deny `http_post` với `on_behalf_of=dpo`; `reports/attack-after.log` 0 byte. Mock LLM, principals, corpus và sink đều là môi trường lab synthetic, không chứng minh kiểm soát sản xuất hay tuân thủ pháp lý.
