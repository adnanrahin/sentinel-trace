from __future__ import annotations

from sentinal_trace.pipeline import ScanSession, scan_text
from tests.conftest import SYNTHETIC_AWS, SYNTHETIC_GITHUB

LABELED = [
    ("aws", f"aws_access_key_id={SYNTHETIC_AWS}", True, "credential"),
    ("github", f"export TOKEN={SYNTHETIC_GITHUB}", True, "credential"),
    ("benign-ip", "example documentation 192.168.1.1 rfc1918", False, "credential"),
    ("hello", "hello world", False, "credential"),
]


def test_synthetic_corpus_precision_recall(session: ScanSession) -> None:
    tp = fp = fn = tn = 0
    for _name, text, should_hit, category in LABELED:
        result = scan_text(text, session=session)
        hit = any(f.category.value == category for f in result.findings)
        if should_hit and hit:
            tp += 1
        elif should_hit and not hit:
            fn += 1
        elif not should_hit and hit:
            fp += 1
        else:
            tn += 1
    recall = tp / (tp + fn)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    assert recall == 1.0
    assert precision == 1.0
    assert tn >= 1
