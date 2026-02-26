from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import QDate
from PyQt6.QtWidgets import (
    QDateEdit,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


class TimelineView(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.entries: list[dict] = []

        self.from_date = QDateEdit()
        self.from_date.setCalendarPopup(True)
        self.from_date.setDate(QDate.currentDate().addYears(-10))

        self.to_date = QDateEdit()
        self.to_date.setCalendarPopup(True)
        self.to_date.setDate(QDate.currentDate().addYears(1))

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp", "Source", "Artifact", "Details"])

        filters = QHBoxLayout()
        filters.addWidget(QLabel("From"))
        filters.addWidget(self.from_date)
        filters.addWidget(QLabel("To"))
        filters.addWidget(self.to_date)
        filters.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addLayout(filters)
        layout.addWidget(self.table)

        self.from_date.dateChanged.connect(self._refresh)
        self.to_date.dateChanged.connect(self._refresh)

    def add_entries(self, records: list[dict]) -> None:
        self.entries.extend(records)
        self._refresh()

    def set_entries(self, records: list[dict]) -> None:
        self.entries = records
        self._refresh()

    def _refresh(self) -> None:
        start = self.from_date.date().toPyDate()
        end = self.to_date.date().toPyDate()

        filtered = []
        for item in self.entries:
            stamp = item.get("timestamp", "")
            dt = self._to_datetime(stamp)
            if dt and start <= dt.date() <= end:
                filtered.append((dt, item))
            elif not dt:
                filtered.append((datetime.min, item))

        filtered.sort(key=lambda x: x[0])

        self.table.setRowCount(len(filtered))
        for r, (_, entry) in enumerate(filtered):
            self.table.setItem(r, 0, QTableWidgetItem(entry.get("timestamp", "")))
            self.table.setItem(r, 1, QTableWidgetItem(entry.get("source", "")))
            self.table.setItem(r, 2, QTableWidgetItem(entry.get("artifact", "")))
            self.table.setItem(r, 3, QTableWidgetItem(entry.get("details", "")))

    @staticmethod
    def _to_datetime(value: str) -> datetime | None:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value[:19], fmt)
            except ValueError:
                continue
        return None
