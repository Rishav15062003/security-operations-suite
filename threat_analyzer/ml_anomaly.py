from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import List, Optional, Sequence, Tuple

import numpy as np

from .models import EventKind, Finding, ParsedEvent

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:  # pragma: no cover
    IsolationForest = None  # type: ignore
    StandardScaler = None  # type: ignore


def _hour_bucket(ts: Optional[datetime]) -> float:
    if not ts:
        return 12.0
    return float(ts.hour) + ts.minute / 60.0


def build_ip_features(events: Sequence[ParsedEvent]) -> Tuple[np.ndarray, List[str], List[str]]:
    """Per-source-IP features: fail count, success count, hour mean, distinct users."""
    by_ip: dict = defaultdict(lambda: {"fail": 0, "ok": 0, "hours": [], "users": set()})
    for e in events:
        if not e.ip:
            continue
        if e.kind == EventKind.LOGIN_FAILURE:
            by_ip[e.ip]["fail"] += 1
        elif e.kind == EventKind.LOGIN_SUCCESS:
            by_ip[e.ip]["ok"] += 1
            if e.user:
                by_ip[e.ip]["users"].add(e.user)
        if e.ts:
            by_ip[e.ip]["hours"].append(_hour_bucket(e.ts))

    rows = []
    keys = []
    labels = []
    for ip, d in by_ip.items():
        hlist = d["hours"] or [12.0]
        mean_h = float(np.mean(hlist))
        std_h = float(np.std(hlist)) if len(hlist) > 1 else 0.0
        rows.append(
            [
                float(d["fail"]),
                float(d["ok"]),
                mean_h,
                std_h,
                float(len(d["users"])),
            ]
        )
        keys.append(ip)
        labels.append(f"{ip} fail={d['fail']} ok={d['ok']} users={len(d['users'])}")
    return np.array(rows, dtype=np.float64), keys, labels


def detect_anomalies_ml(
    events: Sequence[ParsedEvent],
    *,
    contamination: float = 0.12,
    random_state: int = 42,
) -> List[Finding]:
    """
    Optional Isolation Forest on per-IP behavior. Flags outliers (unusual mix of
    failures, successes, timing, account count). Requires scikit-learn.
    """
    if IsolationForest is None:
        return [
            Finding(
                category="ml_anomaly",
                severity="info",
                title="ML module unavailable",
                detail="Install scikit-learn to enable IsolationForest anomaly scoring.",
                evidence=[],
            )
        ]

    if len(events) > 100_000:
        return [
            Finding(
                category="ml_anomaly",
                severity="info",
                title="ML skipped (large input)",
                detail="Isolation Forest is disabled when there are more than 100,000 parsed rows to avoid long freezes.",
                evidence=[],
            )
        ]

    X, ips, _ = build_ip_features(events)
    if len(X) < 4:
        return []

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    max_contam = max((len(X) - 1) / len(X), 0.01)
    clf = IsolationForest(
        contamination=min(contamination, max_contam),
        random_state=random_state,
    )
    pred = clf.fit_predict(Xs)
    scores = clf.score_samples(Xs)

    findings: List[Finding] = []
    for i, ip in enumerate(ips):
        if pred[i] == -1:
            findings.append(
                Finding(
                    category="ml_anomaly",
                    severity="medium",
                    title=f"Behavioral outlier (IP): {ip}",
                    detail=f"IsolationForest score {scores[i]:.4f} - review alongside rule-based alerts.",
                    evidence=[],
                )
            )
    return findings
