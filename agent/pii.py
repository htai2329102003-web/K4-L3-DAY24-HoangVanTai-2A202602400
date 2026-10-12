"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)0(?:[ -]?\d){9,10}(?!\d)")
_BANK_RE = re.compile(
    r"(?i)\b(?:stk|số\s+tài\s+khoản)\b\s*[:#-]?\s*(\d{8,16})(?!\d)"
)


def _overlaps(left: dict, right: dict) -> bool:
    return left["start"] < right["end"] and right["start"] < left["end"]


def detect(text: str) -> list[dict]:
    """Return non-overlapping PII spans with offsets into ``text``.

    A 12-digit bank account can also resemble a CCCD, so labelled bank-account
    spans take precedence over the generic numeric recognizers.
    """
    candidates: list[tuple[int, dict]] = []

    for match in _EMAIL_RE.finditer(text):
        candidates.append((3, {"type": "EMAIL", "start": match.start(), "end": match.end()}))
    for match in _BANK_RE.finditer(text):
        candidates.append((0, {"type": "VN_BANK_ACCOUNT", "start": match.start(1), "end": match.end(1)}))
    for match in _CCCD_RE.finditer(text):
        candidates.append((1, {"type": "VN_CCCD", "start": match.start(), "end": match.end()}))
    for match in _PHONE_RE.finditer(text):
        candidates.append((2, {"type": "VN_PHONE", "start": match.start(), "end": match.end()}))

    selected: list[dict] = []
    for _, entity in sorted(candidates, key=lambda item: (item[0], item[1]["start"], item[1]["end"])):
        if not any(_overlaps(entity, existing) for existing in selected):
            selected.append(entity)
    return sorted(selected, key=lambda entity: (entity["start"], entity["end"]))


def redact(text: str) -> str:
    redacted = text
    for entity in reversed(detect(text)):
        replacement = f"[REDACTED_{entity['type']}]"
        redacted = redacted[: entity["start"]] + replacement + redacted[entity["end"] :]
    return redacted
