from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class MemoryImageInfo:
    path: str = ""
    size: int = 0
    sha256: str = ""
    verified: bool = False


@dataclass(slots=True)
class ExecutionRecord:
    plugin: str
    version: str
    parameters: dict[str, Any]
    timestamp: str
    raw_output: str
    parsed_header: list[str] = field(default_factory=list)
    parsed_rows: list[list[str]] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    title: str
    details: str
    tags: list[str] = field(default_factory=list)
    bookmarked: bool = False
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass(slots=True)
class CaseData:
    case_number: str = ""
    investigator: str = ""
    evidence_id: str = ""
    notes: str = ""
    memory_image: MemoryImageInfo = field(default_factory=MemoryImageInfo)
    custody_log: list[str] = field(default_factory=list)
    executions: list[ExecutionRecord] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


class CaseManager:
    def __init__(self) -> None:
        self.current_case = CaseData()

    def new_case(self, case_number: str, investigator: str, evidence_id: str) -> CaseData:
        self.current_case = CaseData(
            case_number=case_number,
            investigator=investigator,
            evidence_id=evidence_id,
        )
        self.add_custody_event("Case created")
        return self.current_case

    def add_custody_event(self, event: str) -> None:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.current_case.custody_log.append(f"[{timestamp}] {event}")

    def save_case(self, path: str | Path) -> None:
        file_path = Path(path)
        payload = asdict(self.current_case)
        file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load_case(self, path: str | Path) -> CaseData:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        memory = MemoryImageInfo(**payload.get("memory_image", {}))

        executions = [ExecutionRecord(**item) for item in payload.get("executions", [])]
        findings = [Finding(**item) for item in payload.get("findings", [])]

        self.current_case = CaseData(
            case_number=payload.get("case_number", ""),
            investigator=payload.get("investigator", ""),
            evidence_id=payload.get("evidence_id", ""),
            notes=payload.get("notes", ""),
            memory_image=memory,
            custody_log=payload.get("custody_log", []),
            executions=executions,
            findings=findings,
        )
        return self.current_case

    def add_execution(self, record: ExecutionRecord) -> None:
        self.current_case.executions.append(record)
        self.add_custody_event(f"Executed plugin: {record.plugin} (Volatility {record.version})")

    def add_finding(self, title: str, details: str, tags: list[str] | None = None, bookmarked: bool = False) -> None:
        self.current_case.findings.append(
            Finding(title=title, details=details, tags=tags or [], bookmarked=bookmarked)
        )

    def diff_last_two(self, plugin: str) -> tuple[str, str] | None:
        filtered = [e for e in self.current_case.executions if e.plugin == plugin]
        if len(filtered) < 2:
            return None
        return filtered[-2].raw_output, filtered[-1].raw_output
