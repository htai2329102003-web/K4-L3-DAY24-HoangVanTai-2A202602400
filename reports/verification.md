# Verification

- OS / Python / Gitleaks version: Windows 10.0.26200; Python 3.11.9; Gitleaks 8.30.1.
- `python -m pytest tests/ -q`: 33 passed in 4.76s.
- `pre-commit run --all-files`: `Detect hardcoded secrets` passed.
- Ledger verify: `verify(Path("reports/ledger.jsonl"))` trả `True` sau replay DPO; dòng 23 là `http_post` deny có reason.
- Các lỗi còn lại: không có test failure tại thời điểm chạy. Gitleaks được chạy từ binary v8.30.1 trong thư mục tạm của phiên kiểm tra này; cần bảo đảm binary đó có trong PATH ở môi trường chấm lặp lại.
