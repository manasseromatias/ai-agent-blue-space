"""The two scales. Fixed rules; the values are design choices and are NOT calibrated."""

SINGLE_SOURCE_CAP = 0.6
TWO_TOOLS = 0.85
UNCORROBORATED_JUMP = -0.3
CONTRADICTED = -0.5


def hypothesis(name, facts):
    """Confidence of one hypothesis, 0 to 1. Returns (value, steps, tools, cited_ids)."""
    support = [f for f in facts if f.supports == name]
    direct = [f for f in support if not f.corroborates]
    against = [f for f in facts if f.contradicts == name]
    steps = []
    if not direct:
        value = SINGLE_SOURCE_CAP + UNCORROBORATED_JUMP
        if support:
            steps.append(("s_only_corrob", {"src": support[0].source, "id": support[0].id}))
        steps.append(("s_no_direct", {}))
        tools, cited = set(), [f.id for f in support]
    else:
        tools, cited = {f.source for f in support}, [f.id for f in support]
        if len(tools) >= 2:
            value = TWO_TOOLS
            steps.append(("s_two_tools", {"n": len(tools), "ids": ", ".join(cited)}))
        else:
            value = SINGLE_SOURCE_CAP
            steps.append(("s_one_tool", {"ids": ", ".join(cited)}))
    if against:
        value += CONTRADICTED
        steps.append(("s_contradicted", {"src": against[0].source, "id": against[0].id}))
    return round(max(value, 0.0), 2), steps, tools, cited


def trustworthiness(statuses, required, conclusion_tools, conflicting_facts=0):
    """Trustworthiness of the whole investigation, 0 to 10. Starts at 10 and discounts."""
    value, steps = 10, []
    for s in required:
        if statuses[s] != "with_data":
            value -= 1
            steps.append(("t_missing", {"src": s, "status": statuses[s]}))
    if len(conclusion_tools) < 2:
        value -= 2
        steps.append(("t_one_tool", {}))
    if conflicting_facts:
        value -= 2
        steps.append(("t_conflict", {}))
    return value, steps
