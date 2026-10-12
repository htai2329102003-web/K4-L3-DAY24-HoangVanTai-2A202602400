# Compliance mapping

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| [Luật 91/2025/QH15](https://vanban.chinhphu.vn/?docid=214590&pageid=27160) | Phân loại restricted và chặn egress của dữ liệu đó. | `agent/policy.py:62`; `reports/ledger.jsonl:23` | Mapping kỹ thuật, không khẳng định đáp ứng điều khoản pháp lý cụ thể. |
| [NĐ 356/2025/NĐ-CP](https://vanban.chinhphu.vn/?classid=1&docid=216387&pageid=27160&typegroupid=4) | Audit quyết định allow/deny có reason và hash-chain. | `agent/ledger.py:74`; `reports/ledger.jsonl:23` | Ledger lab không thay thế quy trình tuân thủ hoặc lưu trữ audit production. |
| [Luật AI 134/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=216334&pageid=27160) | Tách untrusted corpus khỏi Run B và giới hạn quyền theo principal. | `agent/runner.py:96`; `agent/runner.py:110` | Không đánh giá phân loại/rủi ro AI theo luật; đây chỉ là minh chứng control kỹ thuật. |
| [OWASP ASI01, ASI03, ASI04](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) | Containment chống goal hijack, OBO scope/TTL, và Gitleaks + hash lock. | `agent/runner.py:105`; `agent/policy.py:62`; `.pre-commit-config.yaml:1` | Không bao phủ toàn bộ ASI; scanner/hook không thay thế review dependency và vận hành an toàn. |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
