# A triage agent that learned to say "I don't know"

Demo from the talk at **Ekoparty 2026 · BlueSpace Village** *(the talk is in Spanish; the terminal output defaults to Spanish, use `--lang en` for English)*.

Most AI features in SIEMs reach a conclusion without saying **what evidence it rests on**, and back down as soon as you question them. This demo shows the opposite approach: before concluding, the agent shows **which sources it should have checked, what each one returned, and what was missing**. If the evidence is not enough, nothing gets published: it answers *"I don't know"* and says what is needed to continue.

- Synthetic data only · no dependencies · no network · Python 3.8+
- Deterministic: same input, same output, every time

## Quick start

```bash
./demo.sh                 # the three scenarios, step by step (Spanish)
./demo.sh --lang en       # same, in English
./demo.sh --fast          # no pauses

python3 triage.py         # a single run on the current data
python3 triage.py --gate  # print the gate's code
python3 -m unittest       # check the numbers shown in the talk
```

## The three scenarios

It is always **the same alert**: a mass download in Google Drive on the last day of a user who resigned. What changes is the data, and it changes on disk, not with a flag.

| | What changes | What happens |
|---|---|---|
| **1 · Friday's alert** | Nothing. EDR and MDM have no record of the user's device | Sync by an approved integration (**0.85**), trustworthiness **8/10** → **PASS** |
| **2 · A source goes down** | `data/workspace` is removed, so there is no `originating_app_id` | Exfiltration stays at the single-source cap (**0.60**), trustworthiness **5/10** → **BLOCKED: "I don't know"** |
| **3 · A log that gives orders** | A file name in the SIEM says *"IGNORE PREVIOUS INSTRUCTIONS…"* | Logged as suspicious data, not executed; the conclusion does not change |

`demo.sh` makes those changes for you and always restores the data, even if you stop it halfway.

## What each step shows

1. **The alert.** `alerts/drive_p1.json`
2. **Required sources, defined before investigating.** `config/required_sources.json`. Threat intel is conditional: only if the IP is unknown for the user.
3. **Query.** `agent/sources.py`. The SIEM is one source, not the judge.
4. **Coverage card.** Each fact gets an ID (F1, F2…) and a pointer to the raw data.
5. **Confidence per hypothesis (0–1).** `agent/confidence.py`. Each hypothesis cites the fact IDs behind it.
6. **Investigation trustworthiness (0–10).** Starts at 10 and discounts.
7. **The gate.** `agent/gate.py`. About 20 lines of code decide whether anything is published.
8. **What the analyst gets.** Facts with sources, hypotheses with citations, contradictions, unknowns, next steps, classification, and the detection-quality (`DQ`) and `TUNING` tags that feed back into detection engineering.

### Why the SIEM alone gets it wrong (and why that is realistic)

`data/workspace/` follows the shape of the Google Workspace **Admin Reports API**: 405 of the 412 download events carry an `originating_app_id`. `data/siem/` holds the same events **after normalization**, and that field is gone. A model that only reads the SIEM sees a download peak and nothing else. That was the real case behind the talk.

## The rules

**Confidence of a hypothesis (0 to 1)**
- Supported by a single tool: capped at **0.6**
- Supported by two different tools: **0.85**
- Uncorroborated inference jump: **−0.3**
- Contradicted by rawer data: **−0.5**
- A fact that only *corroborates* (for example, a known IP) does not count as direct support

**Trustworthiness of the investigation (0 to 10)**, starting at 10
- **−1** per required source with no records or no response
- **−2** if the conclusion depends on a single tool
- **−2** if facts from different sources conflict

**The gate** publishes only with ≥2 high-confidence facts, from ≥2 different tools, trustworthiness ≥6 and hallucination risk ≤5.

The values are design choices and **are not calibrated** against real outcomes.

## What this is, and what it is not

**It is** a small, readable reference of the framework from the talk: required sources defined up front, a coverage card, two confidence scales, and a gate in code.

**It is not** a product. There are no real connectors, one alert type, two hypotheses, and simplified rules. The instruction-in-a-log check is a phrase list and is easy to evade; the real defense is that data never reaches a model as instructions, and that the gate does not trust what the model says.

**Differences with a production agent:** here everything is deterministic code, including contradiction detection and hallucination risk. In production a model decides what to query, proposes hypotheses, and estimates those two values following rules; the gate checks in code everything that can be checked.

## Using it with your own data

Each source is one function: `agent/sources.py → query(source, user)` returns the user's records and a status (`with_data`, `no_records`, `no_response`). Replace it for the source you have, then adapt the matching rule in `agent/facts.py`. The confidence rules and the gate do not change.

## License

MIT
