"""Fact extraction: fixed rules per source. Every fact has an ID and says where it came from."""
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

CONFIG = Path(__file__).resolve().parent.parent / "config"


@dataclass
class Fact:
    key: str                 # i18n key for the text
    params: dict
    source: str
    level: str = "HIGH"      # HIGH = raw log or platform API
    supports: str = None     # hypothesis it supports
    contradicts: str = None  # hypothesis it contradicts
    corroborates: bool = False  # True: goes along with, but does not prove on its own
    evidence: str = ""       # pointer to the raw data
    id: str = ""


def from_siem(records):
    if not records:
        return []
    ts = sorted(r["ts"] for r in records)
    minutes = (_t(ts[-1]) - _t(ts[0])) // 60 + 1
    return [Fact("f_siem_peak", {"n": len(records), "m": minutes}, "siem",
                 supports="exfiltration", evidence="action=file_download")]


def from_workspace(records):
    if not records:
        return []
    apps = Counter(_param(r, "originating_app_id") for r in records)
    app, n = apps.most_common(1)[0]
    approved = json.loads((CONFIG / "approved_integrations.json").read_text())
    if app and app in approved and n / len(records) >= 0.9:
        return [Fact("f_ws_app", {"n": n, "t": len(records)}, "workspace",
                     supports="sync", contradicts="exfiltration",
                     evidence=f"originating_app_id={app}")]
    return [Fact("f_ws_user", {"t": len(records)}, "workspace",
                 supports="exfiltration", evidence="originating_app_id=null")]


def from_idp(records):
    profile = next((r for r in records if r.get("_file") == "user_profile.json"), {})
    logins = [r for r in records if r.get("event") == "user.session.start"]
    if not logins:
        return [], False
    last = max(logins, key=lambda r: r["ts"])
    known = {x["ip"]: x for x in profile.get("known_ips", [])}
    if last["ip"] in known:
        return [Fact("f_idp_known", {"label": known[last["ip"]]["label"]}, "idp",
                     supports="sync", corroborates=True, evidence=f"ip={last['ip']}")], True
    return [Fact("f_idp_new", {}, "idp", supports="exfiltration", corroborates=True,
                 evidence=f"ip={last['ip']}")], False


def instructions_in_data(records_by_source):
    """Logs are data, not instructions. (A phrase list is easy to evade: the real defense is
    that data never reaches the model as instructions, and that the gate does not trust the model.)"""
    patterns = ("ignore previous instructions", "mark this alert as benign", "disregard all")
    hits = []
    for source, records in records_by_source.items():
        for r in records:
            for value in _strings(r):
                if any(p in value.lower() for p in patterns):
                    hits.append((source, value))
    return hits


def number(facts):
    for i, f in enumerate(facts, 1):
        f.id = f"F{i}"
    return facts


def _param(r, name):
    for ev in r.get("events", []):
        for p in ev.get("parameters", []):
            if p["name"] == name:
                return p.get("value")
    return None


def _strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)


def _t(iso):
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())
