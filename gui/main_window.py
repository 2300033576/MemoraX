from __future__ import annotations

import difflib
import subprocess
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QInputDialog,
)

from core.case_manager import CaseManager, ExecutionRecord
from core.hashing import file_sha256, file_size
from core.parser import parse_output_to_table, parse_timeline_entries, sanitize_output
from core.volatility_runner import VolatilityCommandBuilder, command_to_str, ensure_volatility_installed
from gui.dialogs import MemoryImageDialog, NewCaseDialog, NotesDialog
from gui.plugin_panel import PluginPanel
from gui.result_view import ResultView
from gui.timeline_view import TimelineView
from plugins.plugin_definitions import CATEGORY_DESCRIPTIONS, PluginDefinition, category_plugin_counts
from reports.report_generator import ReportGenerator
from utils.logger import setup_logger


class ExecutionWorker(QObject):
    output_line = pyqtSignal(str)
    finished = pyqtSignal(int, str, str)

    def __init__(self, command: list[str]) -> None:
        super().__init__()
        self.command = command

    def run(self) -> None:
        raw_stdout: list[str] = []
        try:
            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            assert process.stdout is not None
            for line in process.stdout:
                line = line.rstrip("\n")
                raw_stdout.append(line)
                self.output_line.emit(line)

            exit_code = process.wait()
            self.finished.emit(exit_code, "\n".join(raw_stdout), "")
        except Exception as exc:
            self.finished.emit(1, "", str(exc))


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MemoraX - Volatility Forensic Suite")
        self.resize(1600, 950)

        self.logger = setup_logger()
        self.case_manager = CaseManager()
        self.env, install_messages = ensure_volatility_installed()
        self.command_builder = VolatilityCommandBuilder(self.env)

        self.current_version = "3"
        self.current_profile = ""
        self.current_theme = "dark"
        self.current_plugin: PluginDefinition | None = None
        self.last_executed_plugin_name: str | None = None
        self._thread: QThread | None = None
        self._worker: ExecutionWorker | None = None

        self._init_ui()
        self._apply_theme()
        for msg in install_messages:
            self.log(msg)
        self._refresh_env_status()

    def _init_ui(self) -> None:
        toolbar = QToolBar("Main")
        self.addToolBar(toolbar)
        self.toolbar = toolbar

        new_case_act = QAction("New Case", self)
        new_case_act.triggered.connect(self.new_case)
        open_case_act = QAction("Open Case", self)
        open_case_act.triggered.connect(self.open_case)
        save_case_act = QAction("Save Case", self)
        save_case_act.triggered.connect(self.save_case)

        load_image_act = QAction("Load Memory Image", self)
        load_image_act.triggered.connect(self.load_memory_image)
        verify_hash_act = QAction("Verify Hash", self)
        verify_hash_act.triggered.connect(self.verify_hash)

        self.run_act = QAction("Run Analysis", self)
        self.run_act.triggered.connect(self.run_analysis)
        export_act = QAction("Export Report", self)
        export_act.triggered.connect(self.export_report)

        notes_act = QAction("Notes", self)
        notes_act.triggered.connect(self.edit_notes)

        bookmark_act = QAction("Bookmark Selected Row", self)
        bookmark_act.triggered.connect(self.bookmark_selected_result)
        self.console_logs_toggle_act = QAction("Show Console/Logs", self)
        self.console_logs_toggle_act.setCheckable(True)
        self.console_logs_toggle_act.toggled.connect(
            lambda checked: self._set_console_logs_visible(checked, announce=True)
        )
        self.theme_toggle_act = QAction("Light Theme", self)
        self.theme_toggle_act.setCheckable(True)
        self.theme_toggle_act.toggled.connect(self.toggle_theme)

        for action in (
            new_case_act,
            open_case_act,
            save_case_act,
            load_image_act,
            verify_hash_act,
            self.run_act,
            export_act,
            notes_act,
            bookmark_act,
            self.console_logs_toggle_act,
            self.theme_toggle_act,
        ):
            toolbar.addAction(action)
        run_btn = toolbar.widgetForAction(self.run_act)
        if run_btn is not None:
            run_btn.setObjectName("runAnalysisButton")

        self.version_label = QLabel("Volatility Version")
        self.version_selector = QInputDialog(self)

        self.plugin_panel = PluginPanel()
        self.plugin_panel.plugin_selected.connect(self._set_current_plugin)

        self.result_view = ResultView()
        self.result_view.bookmark_requested.connect(self.bookmark_selected_result)
        self.timeline_view = TimelineView()

        self.findings_box = QTextEdit()
        self.findings_box.setReadOnly(True)
        self.docs_box = QTextEdit()
        self.docs_box.setReadOnly(True)
        self.docs_box.setHtml(self._documentation_html())

        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels(["Process", "PID", "PPID", "Details"])

        center_tabs = QTabWidget()
        center_tabs.addTab(self.result_view, "Analysis Results")
        center_tabs.addTab(self.timeline_view, "Timeline")
        center_tabs.addTab(self.process_tree, "Process Tree")
        center_tabs.addTab(self.findings_box, "Findings / Bookmarks")
        center_tabs.addTab(self.docs_box, "Documentation")
        self.extract_progress = QProgressBar()
        self.extract_progress.setFixedWidth(130)
        self.extract_progress.setFixedHeight(12)
        self.extract_progress.setTextVisible(False)
        self.extract_progress.setRange(0, 1)
        self.extract_progress.setValue(0)
        self.extract_progress.setVisible(False)
        self.extract_progress.setToolTip("Extraction progress")
        corner_wrap = QWidget()
        corner_layout = QHBoxLayout(corner_wrap)
        corner_layout.setContentsMargins(0, 0, 12, 0)
        corner_layout.setSpacing(0)
        corner_layout.addWidget(self.extract_progress)
        center_tabs.setCornerWidget(corner_wrap, Qt.Corner.TopRightCorner)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(5000)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(120)

        bottom_tabs = QTabWidget()
        bottom_tabs.addTab(self.console, "Live Console")
        bottom_tabs.addTab(self.log_view, "Log Output")
        self.bottom_tabs = bottom_tabs

        top_split = QSplitter(Qt.Orientation.Horizontal)
        top_split.addWidget(self.plugin_panel)
        top_split.addWidget(center_tabs)
        top_split.setSizes([540, 1050])

        main_split = QSplitter(Qt.Orientation.Vertical)
        main_split.addWidget(top_split)
        main_split.addWidget(bottom_tabs)
        main_split.setSizes([780, 170])
        self.main_split = main_split

        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)

        info_row = QHBoxLayout()
        self.case_label = QLabel("Case: N/A")
        self.image_label = QLabel("Image: Not loaded")
        self.hash_label = QLabel("SHA256: N/A")
        self.env_label = QLabel("Env: Pending detection")
        self.version_switch = QLabel("Version: 3")
        self.auto_clear_checkbox = QCheckBox("Auto-clear results on plugin change")
        self.auto_clear_checkbox.setChecked(True)

        info_row.addWidget(self.case_label)
        info_row.addWidget(self.image_label)
        info_row.addWidget(self.hash_label)
        info_row.addWidget(self.env_label)
        info_row.addWidget(self.version_switch)
        info_row.addWidget(self.auto_clear_checkbox)
        info_row.addStretch(1)

        switch_v3 = QAction("Use Volatility 3", self)
        switch_v3.triggered.connect(lambda: self.set_version("3"))
        toolbar.addSeparator()
        toolbar.addAction(switch_v3)

        wrapper_layout.addLayout(info_row)
        wrapper_layout.addWidget(main_split)
        self.setCentralWidget(wrapper)

        self.progress = QProgressBar()
        self.progress.setVisible(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)

        status = QStatusBar()
        status.addPermanentWidget(self.progress)
        self.setStatusBar(status)
        self._set_console_logs_visible(False, announce=False)

    def _apply_theme(self) -> None:
        dark_theme = """
            QMainWindow, QWidget { background-color: #10151b; color: #d1d5db; font-family: 'Segoe UI'; font-size: 12px; }
            QToolBar { background: #111827; border-bottom: 1px solid #2b3442; spacing: 6px; }
            QToolButton#runAnalysisButton { background: #f59e0b; color: #111827; font-weight: 700; border: 1px solid #fbbf24; border-radius: 4px; padding: 4px 8px; }
            QToolButton#runAnalysisButton:disabled { background: #6b7280; color: #d1d5db; border-color: #6b7280; }
            QPushButton, QLineEdit, QPlainTextEdit, QTextEdit, QListWidget, QTableWidget, QTreeWidget, QTabWidget, QDateEdit {
                background-color: #16202b; border: 1px solid #2b3442; border-radius: 4px; color: #e5e7eb;
            }
            QHeaderView::section { background-color: #1f2937; color: #e5e7eb; border: 1px solid #2b3442; }
            QTabBar::tab { background: #1f2937; color: #d1d5db; padding: 6px 10px; }
            QTabBar::tab:selected { background: #2563eb; }
            QProgressBar { background: #16202b; border: 1px solid #2b3442; }
            QProgressBar::chunk { background-color: #0ea5e9; }
        """
        light_theme = """
            QMainWindow, QWidget { background-color: #f3f6fb; color: #0f172a; font-family: 'Segoe UI'; font-size: 12px; }
            QToolBar { background: #e5ebf5; border-bottom: 1px solid #cbd5e1; spacing: 6px; }
            QToolButton#runAnalysisButton { background: #2563eb; color: #ffffff; font-weight: 700; border: 1px solid #1d4ed8; border-radius: 4px; padding: 4px 8px; }
            QToolButton#runAnalysisButton:disabled { background: #93c5fd; color: #f8fafc; border-color: #93c5fd; }
            QPushButton, QLineEdit, QPlainTextEdit, QTextEdit, QListWidget, QTableWidget, QTreeWidget, QTabWidget, QDateEdit {
                background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 4px; color: #0f172a;
            }
            QHeaderView::section { background-color: #dbe7f7; color: #0f172a; border: 1px solid #cbd5e1; }
            QTabBar::tab { background: #dbe7f7; color: #0f172a; padding: 6px 10px; }
            QTabBar::tab:selected { background: #3b82f6; color: #ffffff; }
            QProgressBar { background: #ffffff; border: 1px solid #cbd5e1; color: #0f172a; }
            QProgressBar::chunk { background-color: #2563eb; }
        """
        self.setStyleSheet(light_theme if self.current_theme == "light" else dark_theme)

    def toggle_theme(self, checked: bool) -> None:
        self.current_theme = "light" if checked else "dark"
        self.theme_toggle_act.setText("Dark Theme" if checked else "Light Theme")
        self._apply_theme()
        self.log(f"Theme switched to {self.current_theme}")

    def _set_console_logs_visible(self, visible: bool, announce: bool = True) -> None:
        self.bottom_tabs.setVisible(visible)
        if visible:
            self.console_logs_toggle_act.setText("Hide Console/Logs")
            self.main_split.setSizes([780, 170])
        else:
            self.console_logs_toggle_act.setText("Show Console/Logs")
            self.main_split.setSizes([950, 0])
        if announce:
            self.log(
                "Live console and log output shown"
                if visible
                else "Live console and log output hidden"
            )

    def _refresh_env_status(self) -> None:
        versions = self.command_builder.available_versions()
        if not versions:
            self.env_label.setText("Env: No Volatility detected in PATH")
            self.log("Volatility executables not detected in PATH")
        else:
            self.env_label.setText(f"Env: Volatility {', '.join(versions)} available")
            if self.current_version not in versions:
                self.set_version(versions[0])
        self.docs_box.setHtml(self._documentation_html())

    def set_version(self, version: str) -> None:
        ok, message = self.command_builder.validate(version)
        if not ok:
            QMessageBox.warning(self, "Environment Validation", message)
            self.log(message)
            return
        self.current_version = version
        self.version_switch.setText(f"Version: {version}")
        self.plugin_panel.set_version(version)
        self.docs_box.setHtml(self._documentation_html())
        self.log(f"Switched to Volatility {version}")

    def _set_current_plugin(self, plugin: PluginDefinition) -> None:
        self.current_plugin = plugin

    def new_case(self) -> None:
        dlg = NewCaseDialog(self)
        if dlg.exec():
            self.case_manager.new_case(
                case_number=dlg.case_number.text().strip(),
                investigator=dlg.investigator.text().strip(),
                evidence_id=dlg.evidence_id.text().strip(),
            )
            self.case_label.setText(f"Case: {self.case_manager.current_case.case_number or 'N/A'}")
            self.image_label.setText("Image: Not loaded")
            self.hash_label.setText("SHA256: N/A")
            self._reset_analysis_views()
            self.log("New case initialized")

    def open_case(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Case", "", "Case Files (*.json)")
        if not path:
            return
        case_data = self.case_manager.load_case(path)
        self._reset_analysis_views()
        self.case_label.setText(f"Case: {case_data.case_number or 'N/A'}")
        self.image_label.setText(f"Image: {Path(case_data.memory_image.path).name if case_data.memory_image.path else 'Not loaded'}")
        self.hash_label.setText(f"SHA256: {case_data.memory_image.sha256 or 'N/A'}")
        self._refresh_findings_view()
        self.log(f"Case loaded: {path}")

    def save_case(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Case", "case.json", "Case Files (*.json)")
        if not path:
            return
        self.case_manager.save_case(path)
        self.log(f"Case saved: {path}")

    def load_memory_image(self) -> None:
        dlg = MemoryImageDialog(self)
        if not dlg.exec():
            return

        image_path = dlg.path.text().strip()
        if not image_path or not Path(image_path).exists():
            QMessageBox.warning(self, "Invalid Path", "Memory image path does not exist")
            return

        self.extract_progress.setVisible(True)
        self.extract_progress.setRange(0, 0)
        self.statusBar().showMessage("Loading memory image...")
        QApplication.processEvents()
        try:
            self.case_manager.current_case.memory_image.path = image_path
            self.case_manager.current_case.memory_image.size = file_size(image_path)
            self.case_manager.current_case.memory_image.sha256 = file_sha256(image_path)
            self.case_manager.current_case.memory_image.verified = True
            self.case_manager.add_custody_event(f"Memory image loaded: {image_path}")
        finally:
            self.extract_progress.setRange(0, 1)
            self.extract_progress.setValue(1)
            self.extract_progress.setVisible(False)

        self.image_label.setText(f"Image: {Path(image_path).name}")
        self.hash_label.setText(f"SHA256: {self.case_manager.current_case.memory_image.sha256[:20]}...")
        self.log(f"Loaded image: {image_path}")

    def verify_hash(self) -> None:
        image_path = self.case_manager.current_case.memory_image.path
        if not image_path:
            QMessageBox.information(self, "No Image", "Load a memory image first")
            return

        current_hash = file_sha256(image_path)
        verified = current_hash == self.case_manager.current_case.memory_image.sha256
        self.case_manager.current_case.memory_image.verified = verified
        self.case_manager.add_custody_event(f"Hash verification {'passed' if verified else 'failed'}")
        QMessageBox.information(self, "Hash Verification", f"SHA256 {'matches' if verified else 'does NOT match'}")
        self.log(f"Hash verification status: {verified}")

    def run_analysis(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            QMessageBox.information(self, "Analysis Running", "An analysis job is already running.")
            return

        image_path = self.case_manager.current_case.memory_image.path
        if not image_path:
            QMessageBox.warning(self, "Missing Image", "Load a memory image before analysis")
            return

        plugin = self.plugin_panel.current_plugin()
        if not plugin:
            QMessageBox.warning(self, "Missing Plugin", "Select a plugin to execute")
            return

        params = self.plugin_panel.current_parameters()
        if self.current_version == "2" and not self.current_profile:
            profile, ok = QInputDialog.getText(self, "Volatility 2 Profile", "Enter profile (optional but recommended):")
            if ok:
                self.current_profile = profile.strip()

        try:
            command = self.command_builder.build_command(
                self.current_version,
                plugin,
                image_path,
                params,
                profile=self.current_profile,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Command Build Error", str(exc))
            self.log(str(exc))
            return

        self.console.clear()
        self.console.appendPlainText(
            "Analysis started. Initial Volatility 3 runs can take time while symbol data is prepared."
        )
        if self.auto_clear_checkbox.isChecked() and self.last_executed_plugin_name != plugin.name:
            self.result_view.set_result([], [], "")
        self.progress.setRange(0, 0)
        self.extract_progress.setVisible(True)
        self.extract_progress.setRange(0, 0)
        self.statusBar().showMessage(f"Running: {plugin.name}")
        self.run_act.setEnabled(False)

        self.log(f"Executing command: {command_to_str(command)}")
        self._worker = ExecutionWorker(command)
        self._thread = QThread(self)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.output_line.connect(self.console.appendPlainText)
        self._worker.finished.connect(
            lambda code, stdout, stderr, p=plugin.name, prm=params: self._on_execution_complete(code, stdout, stderr, p, prm)
        )
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._on_worker_thread_finished)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _on_execution_complete(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
        plugin_name: str,
        params: dict,
    ) -> None:
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.extract_progress.setRange(0, 1)
        self.extract_progress.setValue(1)
        self.extract_progress.setVisible(False)
        self.statusBar().showMessage("Execution complete", 3000)
        self.run_act.setEnabled(True)

        raw_output = stdout if stdout.strip() else stderr
        clean_output = sanitize_output(raw_output)
        header, rows = parse_output_to_table(raw_output)
        self.result_view.set_result(header, rows, clean_output)

        record = ExecutionRecord(
            plugin=plugin_name,
            version=self.current_version,
            parameters=params,
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            raw_output=raw_output,
            parsed_header=header,
            parsed_rows=rows,
        )
        self.case_manager.add_execution(record)
        self.last_executed_plugin_name = plugin_name

        if plugin_name in {"timeliner", "pslist", "netscan"}:
            entries = self._build_timeline_entries(plugin_name, raw_output)
            self.timeline_view.add_entries(entries)

        if plugin_name == "pstree":
            self._populate_process_tree(header, rows)

        if exit_code != 0:
            self.log(f"Plugin {plugin_name} exited with code {exit_code}: {stderr}")
            QMessageBox.warning(self, "Execution Error", stderr or f"Exit code: {exit_code}")
        else:
            self.log(f"Plugin {plugin_name} completed successfully")

    def _build_timeline_entries(self, plugin_name: str, raw_output: str) -> list[dict]:
        parsed = parse_timeline_entries(raw_output)
        result = []
        for entry in parsed:
            fields = entry.get("fields", {})
            artifact = fields.get("PID") or fields.get("Process") or fields.get("Proto") or plugin_name
            details = " | ".join(f"{k}: {v}" for k, v in list(fields.items())[:6])
            result.append(
                {
                    "timestamp": entry.get("timestamp", ""),
                    "source": plugin_name,
                    "artifact": str(artifact),
                    "details": details,
                }
            )
        return result

    def _populate_process_tree(self, header: list[str], rows: list[list[str]]) -> None:
        self.process_tree.clear()

        key_map = {name.lower(): i for i, name in enumerate(header)}
        pid_idx = key_map.get("pid")
        ppid_idx = key_map.get("ppid")
        name_idx = key_map.get("name") if "name" in key_map else key_map.get("imagefilename")

        if pid_idx is None or ppid_idx is None:
            return

        nodes: dict[str, QTreeWidgetItem] = {}
        parent_map: dict[str, str] = {}

        for row in rows:
            pid = row[pid_idx] if pid_idx < len(row) else ""
            ppid = row[ppid_idx] if ppid_idx < len(row) else ""
            name = row[name_idx] if name_idx is not None and name_idx < len(row) else "process"
            item = QTreeWidgetItem([name, pid, ppid, ""])
            nodes[pid] = item
            parent_map[pid] = ppid

        for pid, item in nodes.items():
            parent_pid = parent_map.get(pid, "")
            parent = nodes.get(parent_pid)
            if parent:
                parent.addChild(item)
            else:
                self.process_tree.addTopLevelItem(item)

        self.process_tree.expandAll()

    def compare_last_two_runs(self) -> None:
        plugin = self.plugin_panel.current_plugin()
        if not plugin:
            QMessageBox.information(self, "Select Plugin", "Select a plugin first")
            return

        pair = self.case_manager.diff_last_two(plugin.name)
        if not pair:
            QMessageBox.information(self, "Not Enough Data", "Need at least two executions for this plugin")
            return

        a, b = pair
        diff = "\n".join(
            difflib.unified_diff(
                a.splitlines(),
                b.splitlines(),
                fromfile="previous",
                tofile="latest",
                lineterm="",
            )
        )
        dlg = NotesDialog(diff[:50000], self)
        dlg.setWindowTitle("Diff Comparison")
        dlg.exec()

    def bookmark_selected_result(self) -> None:
        if not self.case_manager.current_case.executions:
            QMessageBox.information(
                self,
                "No Analysis in Current Case",
                "Run analysis for this case before bookmarking result rows.",
            )
            return

        table = self.result_view.table
        row = table.currentRow()
        if row < 0:
            QMessageBox.information(self, "No Selection", "Select a result row first")
            return

        values = []
        for col in range(table.columnCount()):
            item = table.item(row, col)
            values.append(item.text() if item else "")

        title = f"Bookmark: {self.current_plugin.name if self.current_plugin else 'result'} row {row}"
        details = " | ".join(values)

        tags_text, ok = QInputDialog.getText(self, "Tag Artifact", "Enter comma-separated tags")
        tags = [t.strip() for t in tags_text.split(",") if t.strip()] if ok and tags_text else []
        self.case_manager.add_finding(title=title, details=details, tags=tags, bookmarked=True)
        self._refresh_findings_view()
        self.log("Result bookmarked")

    def _reset_analysis_views(self) -> None:
        self.result_view.set_result([], [], "")
        self.timeline_view.set_entries([])
        self.process_tree.clear()
        self._refresh_findings_view()

    def _refresh_findings_view(self) -> None:
        lines: list[str] = []
        for finding in self.case_manager.current_case.findings:
            lines.append(
                f"[{finding.created_at}] {finding.title}\nTags: {', '.join(finding.tags)}\n{finding.details}\n"
            )
        self.findings_box.setPlainText("\n".join(lines))

    def edit_notes(self) -> None:
        dlg = NotesDialog(self.case_manager.current_case.notes, self)
        if dlg.exec():
            self.case_manager.current_case.notes = dlg.notes.toPlainText()
            self.log("Investigator notes updated")

    def export_report(self) -> None:
        path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            "report",
            "PDF Report (*.pdf);;HTML Report (*.html);;CSV Report (*.csv);;JSON Report (*.json)",
        )
        if not path:
            return

        try:
            if "*.pdf" in selected_filter:
                if not path.lower().endswith(".pdf"):
                    path += ".pdf"
                ReportGenerator.export_pdf(self.case_manager.current_case, path)
            elif "*.html" in selected_filter:
                if not path.lower().endswith(".html"):
                    path += ".html"
                ReportGenerator.export_html(self.case_manager.current_case, path)
            elif "*.csv" in selected_filter:
                if not path.lower().endswith(".csv"):
                    path += ".csv"
                ReportGenerator.export_csv(self.case_manager.current_case, path)
            else:
                if not path.lower().endswith(".json"):
                    path += ".json"
                ReportGenerator.export_json(self.case_manager.current_case, path)

            self.log(f"Report exported: {path}")
            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{path}")
        except Exception as exc:
            self.log(f"Report export error: {exc}")
            QMessageBox.critical(self, "Export Error", str(exc))

    def log(self, message: str) -> None:
        self.logger.info(message)
        self.log_view.appendPlainText(message)

    def _on_worker_thread_finished(self) -> None:
        self._thread = None
        self._worker = None

    def _documentation_html(self) -> str:
        counts = category_plugin_counts(self.current_version)
        sections = []
        for category, summary in CATEGORY_DESCRIPTIONS.items():
            count = counts.get(category, 0)
            sections.append(
                f"<h3>{category}</h3><p>{summary}<br><b>Available plugins (Volatility {self.current_version}):</b> {count}</p>"
            )

        return (
            "<h2>MemoraX Plugin Documentation</h2>"
            "<p>This suite organizes Volatility plugins by investigative objective. "
            "Select a category, choose a plugin, configure parameters, and execute analysis to produce structured evidence outputs.</p>"
            "<p><b>Operational note:</b> Use <b>Run Analysis</b> to execute the selected plugin against the loaded memory image.</p>"
            + "".join(sections)
        )


def run_app() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    app.exec()
