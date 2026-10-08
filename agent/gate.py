"""The gate. Not decided by the prompt: checked in code before anything is published."""

MIN_HIGH_FACTS = 2
MIN_TOOLS = 2
MIN_TRUSTWORTHINESS = 6
MAX_HALLUCINATION_RISK = 5


def gate(tools, facts, trustworthiness, risk):
    high = [f for f in facts if f.source in tools and f.level == "HIGH"]
    checks = {
        "g_high_facts":  len(high) >= MIN_HIGH_FACTS,
        "g_tools":       len({f.source for f in high}) >= MIN_TOOLS,
        "g_trust":       trustworthiness >= MIN_TRUSTWORTHINESS,
        "g_risk":        risk <= MAX_HALLUCINATION_RISK,
    }
    return all(checks.values()), checks
