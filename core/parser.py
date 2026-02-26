from __future__ import annotations

import re
from typing import Any


NOISE_PREFIXES = (
    "Progress:",
    "Volatility 3 Framework",
)


def _is_noise_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    return any(stripped.startswith(prefix) for prefix in NOISE_PREFIXES)


def sanitize_output(raw_text: str) -> str:
    kept = [ln for ln in raw_text.splitlines() if not _is_noise_line(ln)]
    return "\n".join(kept)


def _split_ascii_table(lines: list[str]) -> tuple[list[str], list[list[str]]] | None:
    data_lines = [ln for ln in lines if ln.strip()]
    if len(data_lines) < 2:
        return None
    if not any("---" in ln for ln in data_lines[:3]):
        return None

    header = re.split(r"\s{2,}", data_lines[0].strip())
    rows: list[list[str]] = []
    for ln in data_lines[2:]:
        cols = re.split(r"\s{2,}", ln.strip())
        if len(cols) < 1:
            continue
        if len(cols) < len(header):
            cols = cols + [""] * (len(header) - len(cols))
        rows.append(cols[: len(header)])

    if not header or not rows:
        return None
    return header, rows


def parse_output_to_table(raw_text: str) -> tuple[list[str], list[list[str]]]:
    lines = sanitize_output(raw_text).splitlines()

    pipe_lines = [ln.strip() for ln in lines if "|" in ln and ln.strip()]
    if pipe_lines:
        rows = [
            [cell.strip() for cell in ln.strip("|").split("|")]
            for ln in pipe_lines
            if not ln.startswith("+-") and not set(ln).issubset(set("|-+"))
        ]
        if len(rows) > 1:
            return rows[0], rows[1:]

    ascii_table = _split_ascii_table(lines)
    if ascii_table:
        return ascii_table

    return ["Output"], [[ln] for ln in lines if ln.strip()]


def parse_timeline_entries(raw_text: str) -> list[dict[str, Any]]:
    header, rows = parse_output_to_table(raw_text)
    entries: list[dict[str, Any]] = []
    lower = [h.lower() for h in header]
    date_idx = next((i for i, h in enumerate(lower) if "time" in h or "date" in h), -1)

    for row in rows:
        row_map = {header[i]: row[i] if i < len(row) else "" for i in range(len(header))}
        timestamp = row[date_idx] if 0 <= date_idx < len(row) else ""
        entries.append({"timestamp": timestamp, "fields": row_map})
    return entries
