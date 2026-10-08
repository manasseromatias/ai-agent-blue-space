#!/usr/bin/env python3
"""
A triage agent that learned to say "I don't know". Demo with synthetic data.

    python3 triage.py              # step by step (press enter)
    python3 triage.py --fast       # no pauses
    python3 triage.py --lang en    # English output (default: Spanish)
    python3 triage.py --gate       # print the gate's code

No dependencies. Python 3.8+. No network.
"""
import json
import sys
import time
from pathlib import Path

from agent import confidence, facts as F, gate as G, i18n, sources

ROOT = Path(__file__).resolve().parent
FAST = "--fast" in sys.argv
LANG = "en" if "--lang" in sys.argv and sys.argv[sys.argv.index("--lang") + 1] == "en" else "es"
t = i18n.make(LANG)
NAME = {"siem": "SIEM", "workspace": "Workspace", "idp": "IdP", "edr": "EDR",
        "mdm": "MDM", "threat_intel": "Threat intel"}
HYPOTHESES = ["sync", "exfiltration"]
COL = {"cy": "\033[96m", "mg": "\033[95m", "gr": "\033[90m", "w": "\033[97m",
       "ok": "\033[92m", "b": "\033[1m", "r": "\033[0m"}


def out(text="", c="w", bold=False):
    print(f"{COL['b'] if bold else ''}{COL[c]}{text}{COL['r']}")


def step(key):
    if not FAST:
        input(f"{COL['gr']}  [enter]{COL['r']}")
    print()
    out("─" * 76, "gr")
    out(t(key), "cy", True)
    out("─" * 76, "gr")


def fact_text(f):
    params = dict(f.params)
    if "label" in params:
        params["label"] = t(params["label"])
    return t(f.key, **params)


def investigate(alert):
    """Run the whole pipeline without printing. Used by the CLI and by the tests."""
    plan = json.loads((ROOT / "config" / "required_sources.json").read_text())[alert["rule"]]
    res = {s: sources.query(s, alert["user"]) for s in plan["required"]}
    recs = {s: r["records"] for s, r in res.items()}
    fs = F.from_siem(recs["siem"]) + F.from_workspace(recs["workspace"])
    idp_facts, ip_known = F.from_idp(recs["idp"])
    fs = F.number(fs + idp_facts)
    hyps = {h: confidence.hypothesis(h, fs) for h in HYPOTHESES}
    top = max(hyps, key=lambda h: hyps[h][0])
    statuses = {s: res[s]["status"] for s in plan["required"]}
    trust, tsteps = confidence.trustworthiness(statuses, plan["required"], hyps[top][2])
    risk = 2 if len(hyps[top][2]) >= 2 else 6          # simulated; the model reports it in production
    published, checks = G.gate(hyps[top][2], fs, trust, risk)
    return dict(plan=plan, res=res, facts=fs, ip_known=ip_known, hyps=hyps, top=top,
                trust=trust, tsteps=tsteps, risk=risk, published=published, checks=checks,
                traps=F.instructions_in_data(recs))


def main():
    if "--gate" in sys.argv:
        out((ROOT / "agent" / "gate.py").read_text(encoding="utf-8"))
        return
    alert = json.loads((ROOT / "alerts" / "drive_p1.json").read_text(encoding="utf-8"))
    r = investigate(alert)
    req = r["plan"]["required"]

    out("\n  " + t("banner"), "mg", True)
    step("h1")
    for k, v in alert.items():
        out(f"  {k:<10} {v}")

    step("h2")
    for s in req:
        out(f"  · {NAME[s]}")
    for s in r["plan"]["conditional"]:
        out(f"  · {NAME[s]}  ({t('cond_' + s)})", "gr")

    step("h3")
    for s in req:
        q = r["res"][s]
        if not FAST:
            time.sleep(0.25)
        if q["status"] == "with_data":
            out(f"  ✓ {NAME[s]:<12} {t('records', n=len(q['records'])):>14}   {q['ms']:>6} ms", "ok")
        elif q["status"] == "no_records":
            out(f"  ○ {NAME[s]:<12} {t('no_records'):>14}   {q['ms']:>6} ms", "mg")
        else:
            out(f"  ✕ {NAME[s]:<12} {t('no_response'):>14}", "mg", True)
    if r["ip_known"]:
        out(f"  – {NAME['threat_intel']:<12} {t('ti_skip')}", "gr")
    for src, value in r["traps"]:
        print()
        out("  ⚠ " + t("inj1", src=NAME[src]), "mg", True)
        out(f'    "{value}"', "mg")
        out("    " + t("inj2"))

    step("h4")
    with_data = [s for s in req if r["res"][s]["status"] == "with_data"]
    out("  " + t("card_sum", r=len(req), d=len(with_data), e=len(req) - len(with_data)), "w", True)
    for s in req:
        mine = [f for f in r["facts"] if f.source == s]
        if mine:
            f = mine[0]
            out(f"  ✓ {NAME[s]:<12} {f.id}  {fact_text(f)}", "ok")
            out(f"    {'':<12}     {t('evidence')}: {f.evidence}", "gr")
        elif r["res"][s]["status"] == "no_records":
            out(f"  ○ {NAME[s]:<12} {t('card_empty')}", "mg")
        else:
            out(f"  ✕ {NAME[s]:<12} {t('card_down')}", "mg")

    step("h5")
    for h in HYPOTHESES:
        value, steps, _, _ = r["hyps"][h]
        out("  " + t(h), "w", True)
        for key, kw in steps:
            if "src" in kw:
                kw = dict(kw, src=NAME[kw["src"]])
            out("     " + t(key, **kw), "gr")
        out(f"     {'█' * int(value * 30):<30} {value:.2f}", "cy" if value >= 0.7 else "mg", True)

    step("h6")
    out("  " + t("t_start"), "gr")
    for key, kw in r["tsteps"]:
        if "src" in kw:
            kw = dict(kw, src=NAME[kw["src"]], status=t(kw["status"]))
        out("  " + t(key, **kw), "gr")
    out("  " + t("t_total", v=r["trust"]), "cy" if r["trust"] >= 6 else "mg", True)
    out("  " + t("risk", v=r["risk"]), "gr")

    step("h7")
    for key, ok in r["checks"].items():
        out(f"  {'✓' if ok else '✕'} {t(key)}", "ok" if ok else "mg", not ok)
    print()
    out("  " + t("pass" if r["published"] else "block"), "cy" if r["published"] else "mg", True)

    step("h8")
    missing = [NAME[s] for s in req if s not in with_data]
    lines = [("h", f"{t('o_inv')} · {alert['rule']} ({alert['severity']})"), ("s", "FACTS")]
    lines += [("n", f"{f.id}  {fact_text(f):<54} [{NAME[f.source]}]") for f in r["facts"]]
    if r["traps"]:
        lines.append(("m", f"--  {t('o_inj'):<54} [{t('o_inj_tag')}]"))
    lines += [("s", "EVIDENCE"),
              ("n", f"· {t('o_with')}: {', '.join(NAME[s] for s in with_data)}"),
              ("n", f"· {t('o_without')}: {', '.join(missing) or t('o_none')}"),
              ("s", "HYPOTHESES")]
    for i, h in enumerate(sorted(HYPOTHESES, key=lambda h: -r["hyps"][h][0]), 1):
        v, _, _, cited = r["hyps"][h]
        lvl = "HIGH" if v >= 0.7 else ("MED " if v >= 0.4 else "LOW ")
        lines.append(("n" if i == 1 else "m", f"{i}. [{lvl} {v:.2f}] {t(h)}  ({', '.join(cited) or '—'})"))
    if r["published"]:
        lines += [("k", "CONTRADICTIONS  " + t("o_contra_ok")),
                  ("k", "UNKNOWNS        " + t("o_unk_ok", srcs=f" {t('and')} ".join(missing))),
                  ("k", "NEXT STEPS      " + t("o_next_ok")),
                  ("c", "CLASSIFICATION  " + t("o_class_ok")), ("c", t("o_tags_ok"))]
    else:
        lines += [("k", "CONTRADICTIONS  " + t("o_contra_no")),
                  ("k", "UNKNOWNS        " + t("o_unk_no", srcs=", ".join(missing))),
                  ("k", "NEXT STEPS      " + t("o_next_no")),
                  ("c", "CLASSIFICATION  " + t("o_class_no")),
                  ("c", "CURRENT EVIDENCE DOES NOT SUFFICIENTLY SUPPORT THIS THEORY")]
    lines.append(("f", "Investigated by the agent"))
    for kind, text in lines:
        if not FAST:
            time.sleep(0.06)
        if kind == "k":
            print(f"  {COL['b']}{COL['cy']}{text[:16]}{COL['r']}{COL['w']}{text[16:]}{COL['r']}")
        elif kind == "f":
            print()
            out("  " + text, "gr")
        else:
            out("  " + text, {"h": "gr", "s": "cy", "m": "gr", "c": "mg", "n": "w"}[kind], kind in "hsc")
    print()


if __name__ == "__main__":
    main()
