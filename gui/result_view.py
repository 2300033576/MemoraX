from __future__ import annotations

from PyQt6.QtCore import Qt, QPoint, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


class ResultView(QWidget):
    bookmark_requested = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter rows...")

        self.table = QTableWidget(0, 0)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_table_context_menu)

        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)

        tabs = QTabWidget()
        tabs.addTab(self.table, "Structured")
        tabs.addTab(self.raw, "Raw Console")

        top = QHBoxLayout()
        top.addWidget(self.search_input)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(tabs)

        self.search_input.textChanged.connect(self._filter_rows)

    def set_result(self, headers: list[str], rows: list[list[str]], raw_text: str) -> None:
        self.table.setSortingEnabled(False)
        self.table.clear()
        self.table.setColumnCount(len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setRowCount(len(rows))

        for r_idx, row in enumerate(rows):
            for c_idx, value in enumerate(row):
                item = QTableWidgetItem(value)
                if "suspicious" in value.lower() or "malfind" in value.lower():
                    item.setBackground(Qt.GlobalColor.darkRed)
                    item.setForeground(Qt.GlobalColor.white)
                self.table.setItem(r_idx, c_idx, item)

        self.table.setSortingEnabled(True)
        self.raw.setPlainText(raw_text)

    def _filter_rows(self, text: str) -> None:
        query = text.strip().lower()
        for row in range(self.table.rowCount()):
            visible = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and query in item.text().lower():
                    visible = True
                    break
            self.table.setRowHidden(row, bool(query) and not visible)

    def _show_table_context_menu(self, pos: QPoint) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return

        self.table.selectRow(index.row())
        menu = QMenu(self.table)
        bookmark_action = menu.addAction("Add to Bookmarks")
        selected_action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if selected_action == bookmark_action:
            self.bookmark_requested.emit()
