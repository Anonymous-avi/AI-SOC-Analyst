from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from statistics import median
from typing import Any

from app.schemas.detection_result import DetectionResult
from app.schemas.security_alert import AlertSeverity
from app.schemas.security_event import EventOutcome, SecurityEvent

try:  # pragma: no cover - import availability is environment-specific.
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM

    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover - fallback path for deploy safety.
    np = None
    IsolationForest = None
    LocalOutlierFactor = None
    StandardScaler = None
    OneClassSVM = None
    SKLEARN_AVAILABLE = False


SUSPICIOUS_TOKENS = (
    "../",
    "..\\",
    "%2e%2e",
    "%252e%252e",
    "powershell",
    "cmd.exe",
    "reverse shell",
    "curl ",
    "wget ",
    "base64",
    "union select",
    "<script",
    "ransom",
    "beacon",
    "dns",
)


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value)


def _source_group(event: SecurityEvent) -> str:
    return event.source_ip or event.hostname or event.source_type or "unknown"


def _path_depth(path: str) -> int:
    normalized = path.strip("/")
    if not normalized:
        return 0

    return normalized.count("/") + 1


def _suspicious_token_score(text: str) -> float:
    lowered = text.lower()

    return float(
        sum(1 for token in SUSPICIOUS_TOKENS if token in lowered)
    )


def _extract_context(events: list[SecurityEvent]) -> dict[str, dict[str, Any]]:
    context: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "events": [],
            "failures": 0,
            "users": set(),
            "paths": set(),
        }
    )

    for event in events:
        group = _source_group(event)
        group_context = context[group]
        group_context["events"].append(event)

        if event.outcome == EventOutcome.FAILURE:
            group_context["failures"] += 1

        if event.user:
            group_context["users"].add(event.user)

        path = _safe_text(event.raw_event.get("path")).strip()
        if path:
            group_context["paths"].add(path)

    return context


def _build_feature_vector(
    event: SecurityEvent,
    group_context: dict[str, Any],
    total_events: int,
) -> dict[str, float]:
    raw_text = " ".join(
        _safe_text(value)
        for value in event.raw_event.values()
        if value is not None
    )
    path = _safe_text(event.raw_event.get("path")).strip()
    status_code = event.raw_event.get("status_code")
    port = event.raw_event.get("port")

    feature_vector = {
        "hour": event.timestamp.hour / 23 if event.timestamp.hour else 0.0,
        "weekday": event.timestamp.weekday() / 6,
        "minute": event.timestamp.minute / 59 if event.timestamp.minute else 0.0,
        "failure_flag": 1.0 if event.outcome == EventOutcome.FAILURE else 0.0,
        "client_error_flag": 1.0 if event.outcome == EventOutcome.CLIENT_ERROR else 0.0,
        "server_error_flag": 1.0 if event.outcome == EventOutcome.SERVER_ERROR else 0.0,
        "source_type": {
            "ssh": 1.0,
            "apache": 2.0,
            "nginx": 2.5,
            "syslog": 0.8,
        }.get(event.source_type.lower(), 0.0),
        "event_type": {
            "authentication_failure": 1.0,
            "http_request": 2.0,
            "dns_query": 3.0,
            "process_start": 4.0,
            "network_connection": 5.0,
        }.get(event.event_type.lower(), 0.0),
        "source_event_count": min(len(group_context["events"]) / max(total_events, 1), 1.0),
        "source_failure_rate": (
            group_context["failures"] / max(len(group_context["events"]), 1)
        ),
        "source_unique_users": min(len(group_context["users"]) / 5, 1.0),
        "source_unique_paths": min(len(group_context["paths"]) / 10, 1.0),
        "request_length": min(len(path) / 200, 1.0),
        "request_depth": min(_path_depth(path) / 10, 1.0),
        "request_entropy": min(_suspicious_token_score(raw_text) / 4, 1.0),
        "raw_event_size": min(len(raw_text) / 1200, 1.0),
        "user_length": min(len(_safe_text(event.user)) / 32, 1.0),
        "hostname_length": min(len(_safe_text(event.hostname)) / 64, 1.0),
        "service_length": min(len(event.service) / 32, 1.0),
        "status_code": min(float(status_code or 0) / 599, 1.0),
        "port": min(float(port or 0) / 65535, 1.0),
    }

    return feature_vector


def _build_feature_matrix(events: list[SecurityEvent]) -> tuple[list[str], list[dict[str, float]], list[list[float]]]:
    context = _extract_context(events)
    feature_names: list[str] = []
    feature_rows: list[dict[str, float]] = []

    for event in events:
        group_context = context[_source_group(event)]
        feature_row = _build_feature_vector(event, group_context, len(events))

        if not feature_names:
            feature_names = list(feature_row.keys())

        feature_rows.append(feature_row)

    matrix = [
        [feature_row[name] for name in feature_names]
        for feature_row in feature_rows
    ]

    return feature_names, feature_rows, matrix


def _compute_feature_importance(
    feature_names: list[str],
    feature_rows: list[dict[str, float]],
) -> list[list[tuple[str, float]]]:
    if not feature_rows:
        return []

    medians = {
        name: median(row[name] for row in feature_rows)
        for name in feature_names
    }

    deviations = []
    for feature_row in feature_rows:
        row_scores = []
        for name in feature_names:
            row_scores.append(abs(feature_row[name] - medians[name]))

        deviations.append(row_scores)

    importance: list[list[tuple[str, float]]] = []
    for row_scores in deviations:
        ranked = sorted(
            zip(feature_names, row_scores),
            key=lambda item: item[1],
            reverse=True,
        )
        importance.append(ranked)

    return importance


def _normalize_scores(scores: list[float]) -> list[float]:
    if not scores:
        return []

    minimum = min(scores)
    maximum = max(scores)

    if maximum == minimum:
        return [0.5 for _ in scores]

    return [(score - minimum) / (maximum - minimum) for score in scores]


def _build_anomaly_result(
    event: SecurityEvent,
    confidence: float,
    feature_importance: list[tuple[str, float]],
    model_votes: dict[str, str],
    feature_snapshot: dict[str, float],
    source_key: str,
) -> DetectionResult:
    severity = AlertSeverity.LOW
    if confidence >= 0.85:
        severity = AlertSeverity.HIGH
    elif confidence >= 0.7:
        severity = AlertSeverity.MEDIUM

    top_features = [name for name, _ in feature_importance[:3]]

    return DetectionResult(
        attack_type="Anomaly Detection",
        severity=severity,
        attacker_ip=event.source_ip,
        confidence=confidence,
        recommendation=(
            "Review surrounding telemetry, validate whether this pattern is part of an approved change, "
            f"and investigate deviations in {', '.join(top_features) if top_features else 'the observed telemetry'} "
            "before escalating or quarantining the source."
        ),
        evidence_events=[event],
        metadata={
            "source_key": source_key,
            "anomaly_confidence": confidence,
            "model_votes": model_votes,
            "top_contributing_factors": [
                {"feature": name, "deviation": round(score, 4)}
                for name, score in feature_importance[:5]
            ],
            "feature_snapshot": {
                name: round(value, 4)
                for name, value in feature_snapshot.items()
            },
        },
    )


def detect_anomalies(
    events: list[SecurityEvent],
    min_events: int = 8,
) -> list[DetectionResult]:
    if len(events) < min_events:
        return []

    feature_names, feature_rows, matrix = _build_feature_matrix(events)
    feature_importance = _compute_feature_importance(feature_names, feature_rows)

    if not matrix:
        return []

    if SKLEARN_AVAILABLE and len(matrix) > 1:
        scaler = StandardScaler()
        scaled_matrix = scaler.fit_transform(matrix)

        contamination = min(max(1 / len(events), 0.08), 0.2)

        isolation_forest = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
        )
        isolation_forest.fit(scaled_matrix)
        isolation_votes = isolation_forest.predict(scaled_matrix)
        isolation_scores = _normalize_scores(
            (-isolation_forest.decision_function(scaled_matrix)).tolist()
        )

        lof_votes = [1] * len(events)
        lof_scores = [0.5] * len(events)
        if len(events) > 5:
            n_neighbors = min(20, max(2, len(events) - 1))
            lof = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=contamination,
            )
            lof_votes = lof.fit_predict(scaled_matrix).tolist()
            lof_scores = _normalize_scores(
                (-lof.negative_outlier_factor_).tolist()
            )

        svm = OneClassSVM(
            kernel="rbf",
            gamma="scale",
            nu=min(0.25, max(0.05, 1 / len(events))),
        )
        svm.fit(scaled_matrix)
        svm_votes = svm.predict(scaled_matrix).tolist()
        svm_scores = _normalize_scores(
            (-svm.decision_function(scaled_matrix)).tolist()
        )

        scored_events = []
        for index, event in enumerate(events):
            votes = {
                "IsolationForest": "outlier" if isolation_votes[index] == -1 else "inlier",
                "LocalOutlierFactor": "outlier" if lof_votes[index] == -1 else "inlier",
                "OneClassSVM": "outlier" if svm_votes[index] == -1 else "inlier",
            }

            vote_fraction = sum(
                1 for vote in votes.values() if vote == "outlier"
            ) / 3

            model_strength = (
                isolation_scores[index] + lof_scores[index] + svm_scores[index]
            ) / 3

            deviation_strength = min(
                sum(score for _, score in feature_importance[index][:3]) / 2.5,
                1.0,
            )

            confidence = round(
                min(0.99, 0.55 * deviation_strength + 0.25 * vote_fraction + 0.20 * model_strength),
                2,
            )

            if vote_fraction < 0.34 and confidence < 0.55:
                continue

            top_features = feature_importance[index]
            source_key = _source_group(event)

            scored_events.append(
                (
                    confidence,
                    _build_anomaly_result(
                        event=event,
                        confidence=confidence,
                        feature_importance=top_features,
                        model_votes=votes,
                        feature_snapshot=feature_rows[index],
                        source_key=source_key,
                    ),
                )
            )

        scored_events.sort(key=lambda item: item[0], reverse=True)

        return [result for _, result in scored_events[:5]]

    medians = {
        name: median(row[name] for row in feature_rows)
        for name in feature_names
    }

    scored_events = []
    for index, event in enumerate(events):
        scores = [
            abs(feature_rows[index][name] - medians[name])
            for name in feature_names
        ]
        confidence = round(min(0.99, max(scores) if scores else 0.0), 2)

        if confidence < 0.55:
            continue

        source_key = _source_group(event)
        scored_events.append(
            (
                confidence,
                _build_anomaly_result(
                    event=event,
                    confidence=confidence,
                    feature_importance=feature_importance[index],
                    model_votes={"fallback": "heuristic"},
                    feature_snapshot=feature_rows[index],
                    source_key=source_key,
                ),
            )
        )

    scored_events.sort(key=lambda item: item[0], reverse=True)

    return [result for _, result in scored_events[:5]]


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_seconds: int = 60,
):
    failures_by_ip = defaultdict(list)

    for event in events:
        if event.event_type != "authentication_failure":
            continue

        if event.source_ip is None:
            continue

        failures_by_ip[event.source_ip].append((event.timestamp, event))

    alerts = []

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda item: item[0])

        window_start = 0

        for window_end in range(len(failures)):
            current_time = failures[window_end][0]

            while (
                current_time - failures[window_start][0]
                > timedelta(seconds=window_seconds)
            ):
                window_start += 1

            window_size = window_end - window_start + 1

            if window_size >= threshold:
                window_events = failures[window_start:window_end + 1]
                targeted_users = sorted(
                    {
                        event.user
                        for _, event in window_events
                        if event.user
                    }
                )

                start_time = window_events[0][0]
                end_time = window_events[-1][0]

                alerts.append(
                    DetectionResult(
                        attack_type="Brute Force",
                        severity=AlertSeverity.HIGH,
                        attacker_ip=source_ip,
                        confidence=0.95,
                        recommendation=(
                            "Investigate the source IP, review authentication activity around the detection window, "
                            "reset affected credentials if compromise is suspected, and enforce MFA."
                        ),
                        evidence_events=[event for _, event in window_events],
                        metadata={
                            "failed_attempts": window_size,
                            "target_users": targeted_users,
                            "window_start": start_time.isoformat(),
                            "window_end": end_time.isoformat(),
                            "window_seconds": (end_time - start_time).total_seconds(),
                        },
                    )
                )
                break

    return alerts


def detect_path_traversal(
    events: list[SecurityEvent],
):
    suspicious_patterns = [
        "../",
        "..\\",
        "%2e%2e",
        "%252e%252e",
    ]

    alerts = []

    for event in events:
        if event.event_type != "http_request":
            continue

        path = event.raw_event.get("path")

        if not path:
            continue

        normalized_path = path.lower()

        matched_pattern = next(
            (
                pattern
                for pattern in suspicious_patterns
                if pattern in normalized_path
            ),
            None,
        )

        if matched_pattern:
            alerts.append(
                DetectionResult(
                    attack_type="Path Traversal",
                    severity=AlertSeverity.HIGH,
                    attacker_ip=event.source_ip,
                    confidence=0.95,
                    recommendation=(
                        "Investigate the source IP and affected endpoint, review related web requests, "
                        "validate and canonicalize paths, and ensure the web server cannot access files outside intended directories."
                    ),
                    evidence_events=[event],
                    metadata={
                        "request_method": event.action,
                        "requested_path": path,
                        "status_code": event.raw_event.get("status_code"),
                        "evidence": f"Suspicious path pattern detected: {matched_pattern}",
                    },
                )
            )

    return alerts