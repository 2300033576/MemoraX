from __future__ import annotations

from typing import Any

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from plugins.plugin_definitions import PLUGIN_CATEGORIES, PluginDefinition, get_plugins_for_version


class PluginPanel(QWidget):
    plugin_selected = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self._version = "3"
        self._plugins: list[PluginDefinition] = []
        self._current_plugin: PluginDefinition | None = None
        self._arg_widgets: dict[str, QWidget] = {}

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search plugins...")

        self.category_list = QListWidget()
        self.category_list.addItems(["All"] + PLUGIN_CATEGORIES)
        self.category_list.setCurrentRow(0)

        self.plugin_list = QListWidget()

        self.arg_form = QFormLayout()
        self.arg_form.setLabelAlignment(self.arg_form.labelAlignment())

        sidebar = QWidget()
        side_layout = QVBoxLayout(sidebar)
        side_layout.addWidget(QLabel("Categories"))
        side_layout.addWidget(self.category_list)
        side_layout.addWidget(QLabel("Plugin Search"))
        side_layout.addWidget(self.search_input)
        side_layout.addWidget(QLabel("Plugins"))
        side_layout.addWidget(self.plugin_list)

        config_widget = QWidget()
        self.config_widget = config_widget
        config_layout = QVBoxLayout(config_widget)
        config_layout.addWidget(QLabel("Plugin Parameters"))
        config_layout.addLayout(self.arg_form)
        config_layout.addStretch(1)

        split = QSplitter()
        self.split = split
        split.addWidget(sidebar)
        split.addWidget(config_widget)
        split.setSizes([280, 420])

        layout = QHBoxLayout(self)
        layout.addWidget(split)

        self.search_input.textChanged.connect(self._refresh_list)
        self.category_list.currentTextChanged.connect(self._refresh_list)
        self.plugin_list.currentItemChanged.connect(self._on_plugin_selected)

        self.set_version("3")

    def set_version(self, version: str) -> None:
        self._version = version
        self._plugins = get_plugins_for_version(version)
        self._refresh_list()

    def _refresh_list(self) -> None:
        query = self.search_input.text().strip().lower()
        selected_category = self.category_list.currentItem().text() if self.category_list.currentItem() else "All"

        self.plugin_list.clear()
        for plugin in self._plugins:
            if selected_category != "All" and plugin.category != selected_category:
                continue
            if query and query not in plugin.name.lower() and query not in plugin.description.lower():
                continue

            item = QListWidgetItem(plugin.name)
            item.setToolTip(plugin.description)
            item.setData(256, plugin)
            self.plugin_list.addItem(item)

        if self.plugin_list.count() > 0:
            self.plugin_list.setCurrentRow(0)

    def _clear_form(self) -> None:
        while self.arg_form.rowCount() > 0:
            self.arg_form.removeRow(0)
        self._arg_widgets.clear()

    def _on_plugin_selected(self, item: QListWidgetItem | None) -> None:
        self._clear_form()
        if not item:
            self._current_plugin = None
            self._set_parameter_panel_visible(False)
            return

        plugin = item.data(256)
        self._current_plugin = plugin
        self._set_parameter_panel_visible(bool(plugin.args))

        for arg in plugin.args:
            if arg.arg_type == "bool":
                widget: QWidget = QCheckBox()
                widget.setChecked(bool(arg.default))
            elif arg.arg_type in ("int", "offset"):
                spin = QSpinBox()
                spin.setMaximum(2_147_483_647)
                spin.setValue(int(arg.default) if str(arg.default).isdigit() else 0)
                widget = spin
            elif arg.arg_type == "file":
                holder = QWidget()
                h = QHBoxLayout(holder)
                h.setContentsMargins(0, 0, 0, 0)
                line = QLineEdit(str(arg.default))
                btn = QPushButton("Browse")
                btn.clicked.connect(lambda _, ln=line: self._pick_file(ln))
                h.addWidget(line)
                h.addWidget(btn)
                widget = holder
                self._arg_widgets[f"{arg.key}__line"] = line
            else:
                line = QLineEdit(str(arg.default))
                line.setPlaceholderText(arg.help_text)
                widget = line

            self._arg_widgets[arg.key] = widget
            label = f"{arg.label}{' *' if arg.required else ''}"
            self.arg_form.addRow(label, widget)

        self.plugin_selected.emit(plugin)

    def _set_parameter_panel_visible(self, visible: bool) -> None:
        self.config_widget.setVisible(visible)
        if visible:
            self.split.setSizes([280, 420])
        else:
            self.split.setSizes([700, 0])

    def _pick_file(self, line_edit: QLineEdit) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            line_edit.setText(file_path)

    def current_plugin(self) -> PluginDefinition | None:
        return self._current_plugin

    def current_parameters(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        if not self._current_plugin:
            return values

        for arg in self._current_plugin.args:
            widget = self._arg_widgets.get(arg.key)
            if isinstance(widget, QCheckBox):
                values[arg.key] = widget.isChecked()
            elif isinstance(widget, QSpinBox):
                values[arg.key] = widget.value()
            elif arg.arg_type == "file":
                line = self._arg_widgets.get(f"{arg.key}__line")
                values[arg.key] = line.text().strip() if isinstance(line, QLineEdit) else ""
            elif isinstance(widget, QLineEdit):
                values[arg.key] = widget.text().strip()
            else:
                values[arg.key] = ""

        return values
