"""The numbers shown in the talk. Run: python3 -m unittest"""
import json
import shutil
import unittest
from pathlib import Path

import triage

ROOT = Path(__file__).resolve().parent.parent
ALERT = json.loads((ROOT / "alerts" / "drive_p1.json").read_text())


class Scenarios(unittest.TestCase):
    def test_1_all_sources(self):
        r = triage.investigate(ALERT)
        self.assertEqual(r["top"], "sync")
        self.assertEqual(r["hyps"]["sync"][0], 0.85)
        self.assertEqual(r["hyps"]["exfiltration"][0], 0.10)
        self.assertEqual(r["trust"], 8)
        self.assertTrue(r["published"])

    def test_2_workspace_down_says_i_dont_know(self):
        ws, off = ROOT / "data" / "workspace", ROOT / "data" / "workspace.off"
        ws.rename(off)
        try:
            r = triage.investigate(ALERT)
        finally:
            off.rename(ws)
        self.assertEqual(r["top"], "exfiltration")
        self.assertEqual(r["hyps"]["exfiltration"][0], 0.60)
        self.assertEqual(r["hyps"]["sync"][0], 0.30)
        self.assertEqual(r["trust"], 5)
        self.assertFalse(r["published"])

    def test_3_instruction_in_log_does_not_change_the_result(self):
        extra = ROOT / "data" / "siem" / "drive_events_extra.json"
        shutil.copy(ROOT / "scenarios" / "injection" / "drive_events_extra.json", extra)
        try:
            r = triage.investigate(ALERT)
        finally:
            extra.unlink()
        self.assertEqual(len(r["traps"]), 1)
        self.assertEqual(r["top"], "sync")
        self.assertTrue(r["published"])

    def test_every_hypothesis_cites_existing_facts(self):
        r = triage.investigate(ALERT)
        ids = {f.id for f in r["facts"]}
        for _, _, _, cited in r["hyps"].values():
            self.assertTrue(set(cited) <= ids)


if __name__ == "__main__":
    unittest.main()
