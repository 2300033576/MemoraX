# MemoraX - Volatility Desktop Forensic Suite

Native desktop GUI frontend for Volatility 2/3 built with PyQt6.

## Requirements

- Python 3.11+
- PyQt6
- Volatility 3

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


## Supported workflows

- New/open/save case session
- Memory image load + SHA256 integrity verification
- Volatility 3 environment detection and switching
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
