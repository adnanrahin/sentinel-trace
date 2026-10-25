from sentinal_trace.models.enums import Confidence, Severity


def supporting_score(severity: Severity, confidence: Confidence) -> int:
    """Transparent 0-100 helper. Not a substitute for severity/confidence labels."""
    sev = {0: 95, 1: 80, 2: 55, 3: 30, 4: 10}[severity.rank]
    conf = {0: 10, 1: 5, 2: 0, 3: -15}[confidence.rank]
    return max(0, min(100, sev + conf))
