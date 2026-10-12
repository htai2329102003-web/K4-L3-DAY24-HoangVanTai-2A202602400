"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from uuid import uuid4

from agent import tools
from agent.policy import PolicyContext, check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
_TICKET_ID_RE = re.compile(r"^ticket-(\d+)(?:[a-z]+)?\.md$", re.IGNORECASE)


def _customer_ids_for_tickets(ticket_ids: set[int]) -> list[str]:
    """Map trusted filename IDs to customers without inspecting ticket text."""
    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    return [str(record["customer_id"]) for record in customers
            if ticket_ids.intersection(record.get("related_tickets", []))]


def _append_audit(entry: dict, path: Path) -> None:
    """CP3c audit record; CP3e will make this append-only and hash-chained."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as audit_file:
        audit_file.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")


def _args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _run_a(message: str, llm, call_tool) -> tuple[str, set[int]]:
    """Read untrusted tickets and emit only typed filename IDs to Run B."""
    docs = call_tool(
        "search_docs", "internal", "lab24-agent/run-a", ("search_docs",),
        {"query": message}, lambda: tools.search_docs(message),
    ) or []
    llm.find_injection("\n\n".join(str(doc.get("text", "")) for doc in docs))
    ticket_ids = {int(match.group(1)) for doc in docs
                  if (match := _TICKET_ID_RE.fullmatch(str(doc.get("id", ""))))}
    return llm.summarize(docs), ticket_ids


def _run_b(ticket_ids: set[int], call_tool) -> None:
    """Resolve only trusted ticket IDs; it never receives ticket free text."""
    for customer_id in _customer_ids_for_tickets(ticket_ids):
        call_tool(
            "read_customer", "restricted", "lab24-agent/run-b", ("read_customer",),
            {"customer_id": customer_id},
            lambda customer_id=customer_id: tools.read_customer(customer_id),
        )


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = log_dir / "ledger.jsonl" if log_dir else DEFAULT_LEDGER_PATH
    run_id = str(uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def call_tool(tool_name: str, classification: str, agent_id: str,
                  agent_scopes: tuple[str, ...], args: dict, invoke):
        allowed, reason = check(PolicyContext(
            data_classification=classification, request_purpose="support-reply",
            agent_owner=agent_id, delegation_depth=0, egress_enabled=False,
            principal_id=principal_id, requested_tool=tool_name,
            agent_scopes=agent_scopes, expires_at=expires_at,
        ))
        _append_audit({
            "ts": datetime.now(timezone.utc).isoformat(), "agent_id": agent_id,
            "run_id": run_id, "tool": tool_name, "args_hash": _args_hash(args),
            "classification": classification, "decision": "allow" if allowed else "deny",
            "reason": reason, "on_behalf_of": principal_id, "expires_at": expires_at,
        }, ledger_path)
        return invoke() if allowed else None

    summary, ticket_ids = _run_a(message, llm, call_tool)
    _run_b(ticket_ids, call_tool)
    return summary
