# Delete From Internet (GhostTrace) — Tracker

**Last updated:** 2026-05-28  
**Status:** Active — Flask/OSINT project

## Completed
- [x] Core Flask app (`app.py`)
- [x] Search UI (`templates/search-ui.html`)
- [x] GhostTrace core (`ghosttrace/core/`)
- [x] Checkers module (`checkers/`)
- [x] README.md, QUICK_START.md, SEARCH_ENGINE_GUIDE.md, IMPROVEMENTS_SUMMARY.md
- [x] Removed committed `venv/` (2026-05-28)

## Pending
- [ ] Add `.gitignore` with `venv/`, `__pycache__/`, `*.db`, `.env`
- [ ] Validate `app.py` runs and search UI integrates with `search-ui.html`
- [ ] Add automated tests for `checkers/` and `ghosttrace/core/` endpoints
- [ ] Review docs for stale setup instructions
- [ ] Consider Docker support or packaging

## Start Command
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
