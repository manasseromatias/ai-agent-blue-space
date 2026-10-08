"""Connectors. Each source is a folder under data/. If the folder is missing, the source does not respond.

To use your own data, replace `query()` for that source: it only has to return the
records for the user, plus a status (with_data | no_records | no_response).
"""
import json
import time
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"


def query(source, user):
    t0 = time.perf_counter()
    folder = DATA / source
    if not folder.is_dir():
        return {"status": "no_response", "records": [], "ms": _ms(t0)}
    records = []
    for f in sorted(folder.glob("*.json")):
        content = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(content, dict) and "items" in content:   # Admin Reports API shape
            content = content["items"]
        if isinstance(content, list):
            records += [r for r in content if _belongs_to(r, user)]
        else:
            records.append({"_file": f.name, **content})
    return {"status": "with_data" if records else "no_records", "records": records, "ms": _ms(t0)}


def _belongs_to(r, user):
    return user in (r.get("user"), r.get("assigned_to"), r.get("actor", {}).get("email"))


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 1)
