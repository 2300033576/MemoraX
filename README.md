# MemoraX - Volatility Desktop Forensic Suite

Native desktop GUI frontend for Volatility 2/3 built with PyQt6.

## Requirements

- Python 3.11+
- PyQt6
- Volatility 2 and/or Volatility 3 installed and available in `PATH`

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```powershell
python main.py
```

## Architecture

- `core/volatility_runner.py`: version detection and command build
- `core/parser.py`: table/timeline parsing helpers
- `core/hashing.py`: file size and SHA256
- `core/case_manager.py`: case/session/custody/finding models
- `plugins/plugin_definitions.py`: plugin catalog + dynamic args
- `gui/main_window.py`: main shell, threading, execution, integration
- `gui/plugin_panel.py`: plugin browser + generated parameter form
- `gui/result_view.py`: structured/raw results viewer
- `gui/timeline_view.py`: unified timeline with date filtering
- `gui/dialogs.py`: case/image/notes dialogs
- `reports/report_generator.py`: PDF/HTML/CSV/JSON exporters
- `utils/logger.py`: forensic activity logging

## Supported workflows

- New/open/save case session
- Memory image load + SHA256 integrity verification
- Volatility 2/3 environment detection and switching
- Visual plugin selection by category/search
- Dynamic plugin parameter entry
- Background execution (non-blocking UI)
- Live console streaming and log output
- Parsed results table + raw view + searching/filtering
- Timeline aggregation (`timeliner`, `pslist`, `netscan`)
- Process tree view (`pstree`)
- Bookmark/tag suspicious artifacts
- Report export (PDF/HTML/CSV/JSON)
- Chain of custody log persistence
- Compare last two plugin runs (diff)
