from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)


class NewCaseDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Case")

        self.case_number = QLineEdit()
        self.investigator = QLineEdit()
        self.evidence_id = QLineEdit()

        form = QFormLayout()
        form.addRow("Case Number", self.case_number)
        form.addRow("Investigator", self.investigator)
        form.addRow("Evidence ID", self.evidence_id)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)


class NotesDialog(QDialog):
    def __init__(self, initial_text: str = "", parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Investigator Notes")

        self.notes = QTextEdit()
        self.notes.setPlainText(initial_text)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.notes)
        layout.addWidget(buttons)


class MemoryImageDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Load Memory Image")

        self.path = QLineEdit()
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)

        form = QFormLayout()
        form.addRow("Image Path", self.path)
        form.addRow("", browse)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _browse(self) -> None:
        target, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Image",
            "",
            "Memory Images (*.raw *.mem *.dmp *.lime *.bin *.img *.mddramimage);;All Files (*)",
        )
        if target:
            self.path.setText(target)
