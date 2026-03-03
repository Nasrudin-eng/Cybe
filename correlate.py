"""Cyber threat correlation prototype."""

from __future__ import annotations

from datetime import datetime
import base64
import hashlib
import hmac
import json
import os
from typing import Dict, List, Optional, Tuple


SEVERITY_SCORES = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

KEYWORDS = ("malware", "credential", "suspicious")

ENGINE_CONFIG = {
    "time_window_minutes": 60,
    "source_time_windows": {
        "identity": 90,
        "endpoint": 90,
        "cloud": 60,
    },
    "default_incident_status": "open",
    "suppression_keywords": ("benign", "false positive", "test event"),
    "correlation_rules": (
        "shared_entities",
        "high_severity_device_repeat",
        "identity_endpoint_link",
    ),
    "required_fields": (
        "id",
        "timestamp",
        "source",
        "user",
        "device",
        "ip",
        "region",
        "severity",
        "description",
    ),
    "source_types": ("identity", "cloud", "endpoint"),
    "severity_levels": ("low", "medium", "high", "critical"),
    "user_aliases": {},
    "device_aliases": {},
    "ip_aliases": {},
    "known_bad_ips": set(),
    "vip_users": set(),
    "critical_devices": set(),
    "clearance_levels": ("public", "analyst", "lead", "admin"),
    "retention_days": 90,
    "sla_hours": {
        "urgent": 4,
        "high": 8,
        "medium": 24,
        "low": 72,
    },
    "sharing": {
        "signing_secret": "rotate-me",
        "token_salt": "rotate-me",
        "tokenize_fields": ("users", "devices", "ips"),
        "encryption_secret": "rotate-me",
        "allowed_recipients": {
            "partner-001": {
                "max_clearance": "public",
            }
        },
    },
    "tenants": {
        "local": {
            "clearance": "admin",
            "allowed_sources": ("identity", "cloud", "endpoint"),
        },
        "tenant-b": {
            "clearance": "analyst",
            "allowed_sources": ("identity", "cloud"),
        },
    },
    "ml": {
        "enabled": False,
        "risk_weight": 0.2,
        "confidence_weight": 0.2,
    },
    "field_visibility": {
        "public": (
            "id",
            "attack_summary",
            "related_events",
            "risk_score",
            "recommended_action",
            "status",
        ),
        "analyst": (
            "id",
            "attack_summary",
            "related_events",
            "risk_score",
            "risk_breakdown",
            "confidence_score",
            "recommended_action",
            "playbook_hints",
            "tactics",
            "response_priority",
            "entity_profile",
            "status",
            "created_at",
            "last_updated",
            "metadata",
            "evidence",
            "actor_attribution",
            "ml_insights",
            "soar_actions",
        ),
        "lead": (
            "id",
            "attack_summary",
            "related_events",
            "risk_score",
            "risk_breakdown",
            "confidence_score",
            "recommended_action",
            "playbook_hints",
            "tactics",
            "response_priority",
            "entity_profile",
            "status",
            "created_at",
            "last_updated",
            "metadata",
            "evidence",
            "rules_evaluated",
            "incident_graph",
            "timeline",
            "automation_recommended",
            "case_workflow",
            "actor_attribution",
            "ml_insights",
            "soar_actions",
        ),
        "admin": (
            "id",
            "attack_summary",
            "related_events",
            "risk_score",
            "risk_breakdown",
            "confidence_score",
            "recommended_action",
            "playbook_hints",
            "tactics",
            "response_priority",
            "entity_profile",
            "status",
            "created_at",
            "last_updated",
            "metadata",
            "evidence",
            "rules_evaluated",
            "incident_graph",
            "timeline",
            "automation_recommended",
            "case_workflow",
            "actor_attribution",
            "ml_insights",
            "soar_actions",
        ),
    },
}

TACTIC_KEYWORDS = {
    "credential_access": ("credential", "password", "login"),
    "malware": ("malware", "ransomware", "trojan"),
    "execution": ("execution", "run", "powershell"),
    "exfiltration": ("exfil", "exfiltration", "data leak"),
    "persistence": ("persistence", "scheduled task", "startup"),
}

ACTOR_PATTERNS = {
    "credential_theft_group": ("credential", "login", "password"),
    "malware_operator": ("malware", "ransomware", "trojan"),
    "cloud_abuse_cell": ("api", "cloud", "exfil"),
    "persistent_threat": ("persistence", "scheduled task", "startup"),
}

CONNECTOR_REGISTRY: dict[str, dict] = {}

PIPELINE_QUEUE: List[dict] = []


def _normalize_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return value.strip().lower()


def _normalize_event(event: dict) -> dict:
    user = _normalize_value(event.get("user"))
    device = _normalize_value(event.get("device"))
    ip = _normalize_value(event.get("ip"))
    user = ENGINE_CONFIG["user_aliases"].get(user, user)
    device = ENGINE_CONFIG["device_aliases"].get(device, device)
    ip = ENGINE_CONFIG["ip_aliases"].get(ip, ip)
    return {
        **event,
        "user": user,
        "device": device,
        "ip": ip,
    }


def _is_suppressed(event: dict) -> bool:
    description = (event.get("description") or "").lower()
    return any(keyword in description for keyword in ENGINE_CONFIG["suppression_keywords"])


def _validate_event(event: dict) -> List[str]:
    errors = []
    for field in ENGINE_CONFIG["required_fields"]:
        if field not in event:
            errors.append(f"missing_field:{field}")
    if "source" in event and event.get("source") not in ENGINE_CONFIG["source_types"]:
        errors.append("invalid_source")
    if "severity" in event and event.get("severity") not in ENGINE_CONFIG["severity_levels"]:
        errors.append("invalid_severity")
    return errors


def _dedupe_events(events: List[dict]) -> List[dict]:
    seen = set()
    deduped = []
    for event in events:
        signature = (
            event.get("id"),
            event.get("timestamp"),
            event.get("source"),
            event.get("user"),
            event.get("device"),
            event.get("ip"),
            event.get("region"),
            event.get("severity"),
            event.get("description"),
        )
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(event)
    return deduped


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M")
    except ValueError:
        return None


def _format_timestamp(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    return value.strftime("%Y-%m-%d %H:%M")


def _shared_entities(event_a: dict, event_b: dict) -> int:
    """Count shared entities between two events."""
    shared = 0
    for key in ("user", "device", "ip"):
        value_a = event_a.get(key)
        value_b = event_b.get(key)
        if value_a is not None and value_a == value_b:
            shared += 1
    return shared


def _relationship_reasons(
    event_a: dict,
    event_b: dict,
    device_high_critical: dict,
) -> List[str]:
    reasons = []
    if _shared_entities(event_a, event_b) >= 2:
        reasons.append("shared_entities")
    if (
        event_a.get("device")
        and event_a.get("device") == event_b.get("device")
        and device_high_critical.get(event_a.get("device"), 0) >= 2
    ):
        reasons.append("high_severity_device_repeat")
    if {
        event_a.get("source"),
        event_b.get("source"),
    } == {"identity", "endpoint"}:
        if (
            event_a.get("user")
            and event_a.get("user") == event_b.get("user")
        ) or (
            event_a.get("device")
            and event_a.get("device") == event_b.get("device")
        ):
            reasons.append("identity_endpoint_link")
    return reasons


def _contains_keyword(event: dict, keywords: tuple[str, ...]) -> bool:
    description = (event.get("description") or "").lower()
    return any(keyword in description for keyword in keywords)


def _identify_action(events: List[dict]) -> str:
    has_identity = any(event.get("source") == "identity" for event in events)
    has_endpoint = any(event.get("source") == "endpoint" for event in events)

    identity_compromise = False
    endpoint_malware = False
    ip_attack = False

    for event in events:
        description = (event.get("description") or "").lower()
        if event.get("source") == "identity" and (
            "credential" in description or "login" in description or "failed" in description
        ):
            identity_compromise = True
        if event.get("source") == "endpoint" and "malware" in description:
            endpoint_malware = True
        if event.get("ip") and ("malicious" in description or "suspicious" in description):
            ip_attack = True

    if endpoint_malware and has_endpoint:
        return "isolate_device"
    if identity_compromise and has_identity:
        return "disable_user"
    if ip_attack:
        return "block_ip"
    return "block_ip"


def _risk_score(events: List[dict]) -> int:
    return _risk_breakdown(events)["total"]


def _risk_breakdown(events: List[dict]) -> dict:
    base = 1
    event_count_score = min(4, max(0, len(events) - 1))

    keyword_hits = sum(1 for event in events if _contains_keyword(event, KEYWORDS))
    keyword_score = min(3, keyword_hits)

    severity_total = sum(SEVERITY_SCORES.get(event.get("severity", ""), 0) for event in events)
    severity_score = min(3, severity_total // 3)

    total = max(1, min(10, base + event_count_score + keyword_score + severity_score))
    return {
        "event_count": event_count_score,
        "keyword_hits": keyword_hits,
        "severity_score": severity_score,
        "total": total,
    }


def _confidence_score(
    risk_breakdown: dict,
    evidence: List[str],
    event_count: int,
) -> int:
    score = 1
    score += min(4, len(set(evidence)))
    score += min(3, event_count - 1)
    score += min(2, risk_breakdown.get("severity_score", 0))
    return max(1, min(10, score))


def _attack_summary(events: List[dict]) -> str:
    sources = sorted({event.get("source") for event in events if event.get("source")})
    user = next((event.get("user") for event in events if event.get("user")), None)
    device = next((event.get("device") for event in events if event.get("device")), None)
    ip = next((event.get("ip") for event in events if event.get("ip")), None)

    keyword_tags = []
    for keyword in KEYWORDS:
        if any(keyword in (event.get("description") or "").lower() for event in events):
            keyword_tags.append(keyword)

    subject = user or device or ip or "shared assets"
    summary = (
        f"Correlated {len(events)} events across {', '.join(sources)} involving {subject}"
    )
    if keyword_tags:
        summary += f" indicating {', '.join(keyword_tags)} activity"
    words = summary.split()
    if len(words) > 25:
        summary = " ".join(words[:25])
    return summary


def _playbook_hints(action: str, events: List[dict]) -> List[str]:
    hints = []
    if action == "disable_user":
        hints = [
            "reset_credentials",
            "require_mfa",
            "review_identity_logs",
        ]
    elif action == "isolate_device":
        hints = [
            "isolate_host",
            "collect_memory",
            "run_endpoint_scan",
        ]
    elif action == "block_ip":
        hints = [
            "block_ip_perimeter",
            "review_firewall_logs",
            "monitor_for_retries",
        ]
    if any("malware" in (event.get("description") or "").lower() for event in events):
        hints.append("preserve_forensics")
    return hints


def _actor_attribution_score(events: List[dict]) -> dict:
    scores = {}
    signals = {}
    for actor, keywords in ACTOR_PATTERNS.items():
        match_count = 0
        matched = []
        for event in events:
            description = (event.get("description") or "").lower()
            for keyword in keywords:
                if keyword in description:
                    match_count += 1
                    matched.append(keyword)
        score = min(100, match_count * 15)
        scores[actor] = score
        signals[actor] = sorted(set(matched))
    primary = max(scores, key=scores.get) if scores else None
    return {
        "primary": primary,
        "scores": scores,
        "signals": signals,
    }


def _ml_layer(events: List[dict]) -> Optional[dict]:
    if not ENGINE_CONFIG["ml"]["enabled"]:
        return None
    severity_total = sum(SEVERITY_SCORES.get(event.get("severity", ""), 0) for event in events)
    keyword_hits = sum(1 for event in events if _contains_keyword(event, KEYWORDS))
    ml_risk_score = min(10, 1 + (severity_total + keyword_hits))
    ml_confidence = min(10, 3 + keyword_hits + (severity_total // 2))
    return {
        "ml_enabled": True,
        "ml_risk_score": ml_risk_score,
        "ml_confidence_score": ml_confidence,
        "ml_notes": "Heuristic ML placeholder (enable when enough data is available).",
    }


def _classify_tactics(events: List[dict]) -> List[str]:
    tactics = set()
    for event in events:
        description = (event.get("description") or "").lower()
        for tactic, keywords in TACTIC_KEYWORDS.items():
            if any(keyword in description for keyword in keywords):
                tactics.add(tactic)
    return sorted(tactics)


def _entity_profile(events: List[dict]) -> dict:
    users = sorted({event.get("user") for event in events if event.get("user")})
    devices = sorted({event.get("device") for event in events if event.get("device")})
    ips = sorted({event.get("ip") for event in events if event.get("ip")})
    regions = sorted({event.get("region") for event in events if event.get("region")})
    known_bad_ips = sorted(set(ips) & ENGINE_CONFIG["known_bad_ips"])
    vip_users = sorted(set(users) & ENGINE_CONFIG["vip_users"])
    critical_devices = sorted(set(devices) & ENGINE_CONFIG["critical_devices"])
    return {
        "users": users,
        "devices": devices,
        "ips": ips,
        "regions": regions,
        "known_bad_ips": known_bad_ips,
        "vip_users": vip_users,
        "critical_devices": critical_devices,
    }


def _response_priority(risk_score: int, confidence_score: int, profile: dict) -> str:
    if profile["vip_users"] or profile["critical_devices"]:
        return "urgent"
    if risk_score >= 8 and confidence_score >= 7:
        return "high"
    if risk_score >= 5:
        return "medium"
    return "low"


def _build_timeline(events: List[dict]) -> List[dict]:
    sortable = []
    for event in events:
        timestamp = _parse_timestamp(event.get("timestamp"))
        sortable.append((timestamp or datetime.min, event))
    sortable.sort(key=lambda item: item[0])
    timeline = []
    for _, event in sortable:
        timeline.append(
            {
                "id": event.get("id"),
                "timestamp": event.get("timestamp"),
                "source": event.get("source"),
                "severity": event.get("severity"),
                "description": event.get("description"),
            }
        )
    return timeline


def _incident_metadata(
    events: List[dict],
    created_at: Optional[str],
    last_updated: Optional[str],
) -> dict:
    sources = sorted({event.get("source") for event in events if event.get("source")})
    severities = sorted({event.get("severity") for event in events if event.get("severity")})
    earliest = created_at
    latest = last_updated
    return {
        "event_count": len(events),
        "sources": sources,
        "severities": severities,
        "first_seen": earliest,
        "last_seen": latest,
        "ingestion_timestamp": _format_timestamp(datetime.utcnow()),
        "data_lineage": {
            "rules": list(ENGINE_CONFIG["correlation_rules"]),
            "suppression_keywords": list(ENGINE_CONFIG["suppression_keywords"]),
        },
    }


def _case_workflow(response_priority: str) -> dict:
    return {
        "owner": None,
        "tags": [],
        "sla_hours": ENGINE_CONFIG["sla_hours"].get(response_priority, 24),
        "retention_days": ENGINE_CONFIG["retention_days"],
    }


def apply_clearance(report: dict, clearance: str) -> dict:
    """Redact incident fields based on security clearance level."""
    if clearance not in ENGINE_CONFIG["clearance_levels"]:
        raise ValueError("Unknown clearance level")
    allowed = set(ENGINE_CONFIG["field_visibility"][clearance])
    filtered_incidents = []
    for incident in report.get("incidents", []):
        filtered = {key: value for key, value in incident.items() if key in allowed}
        filtered_incidents.append(filtered)
    filtered = {
        "incidents": filtered_incidents,
        "uncorrelated": report.get("uncorrelated", []),
    }
    if clearance in {"lead", "admin"} and "validation_errors" in report:
        filtered["validation_errors"] = report["validation_errors"]
    return filtered


def _enforce_sharing_policy(clearance: str, recipient: dict) -> None:
    allowed = ENGINE_CONFIG["sharing"].get("allowed_recipients", {})
    recipient_id = recipient.get("id")
    if allowed:
        if recipient_id not in allowed:
            raise ValueError("Recipient not allowed")
        max_clearance = allowed[recipient_id].get("max_clearance")
        if max_clearance:
            levels = ENGINE_CONFIG["clearance_levels"]
            if levels.index(clearance) > levels.index(max_clearance):
                raise ValueError("Clearance exceeds recipient policy")


def _tokenize_value(value: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()
    return f"tok_{digest[:16]}"


def _tokenize_profile(profile: dict, salt: str, fields: Tuple[str, ...]) -> dict:
    tokenized = dict(profile)
    for field in fields:
        if field in tokenized:
            tokenized[field] = [
                _tokenize_value(value, salt) for value in tokenized.get(field, [])
            ]
    return tokenized


def _xor_encrypt(payload: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(payload))


def _derive_key(secret: str, nonce: bytes, context: str) -> bytes:
    return hashlib.sha256(f"{secret}:{context}".encode("utf-8") + nonce).digest()


def _sign_manifest(manifest: dict) -> str:
    payload = json.dumps(manifest, sort_keys=True).encode("utf-8")
    secret = ENGINE_CONFIG["sharing"]["signing_secret"].encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def apply_sharing_policy(
    report: dict,
    clearance: str,
    recipient: dict,
    sender: Optional[dict] = None,
) -> dict:
    """Apply clearance filtering and tokenization for secure sharing."""
    _enforce_sharing_policy(clearance, recipient)
    filtered = apply_clearance(report, clearance)
    salt = ENGINE_CONFIG["sharing"]["token_salt"]
    tokenize_fields = ENGINE_CONFIG["sharing"]["tokenize_fields"]
    for incident in filtered.get("incidents", []):
        profile = incident.get("entity_profile")
        if profile:
            incident["entity_profile"] = _tokenize_profile(profile, salt, tokenize_fields)
    manifest = {
        "sender_id": (sender or {}).get("id", "local"),
        "recipient_id": recipient.get("id"),
        "clearance": clearance,
        "shared_at": _format_timestamp(datetime.utcnow()),
        "incident_count": len(filtered.get("incidents", [])),
    }
    filtered["sharing_manifest"] = manifest
    filtered["sharing_signature"] = _sign_manifest(manifest)
    return filtered


def export_encrypted_payload(
    report: dict,
    clearance: str,
    recipient: dict,
    sender: Optional[dict] = None,
) -> dict:
    shared = apply_sharing_policy(report, clearance, recipient, sender)
    payload = json.dumps(shared, sort_keys=True).encode("utf-8")
    nonce = os.urandom(16)
    secret = ENGINE_CONFIG["sharing"]["encryption_secret"]
    key = _derive_key(secret, nonce, recipient.get("id", "recipient"))
    encrypted = _xor_encrypt(payload, key)
    return {
        "encrypted_payload": base64.b64encode(encrypted).decode("utf-8"),
        "encryption": {
            "algorithm": "xor-sha256-stream",
            "nonce": base64.b64encode(nonce).decode("utf-8"),
        },
        "sharing_manifest": shared.get("sharing_manifest"),
        "sharing_signature": shared.get("sharing_signature"),
    }


def export_for_storage(report: dict, clearance: str, recipient: dict) -> dict:
    shared = apply_sharing_policy(report, clearance, recipient)
    payload = json.dumps(shared, sort_keys=True).encode("utf-8")
    return {
        "payload": shared,
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "exported_at": _format_timestamp(datetime.utcnow()),
    }


def _incident_fingerprint(incident: dict) -> str:
    profile = incident.get("entity_profile") or {}
    tokens = []
    for field in ("users", "devices", "ips"):
        tokens.extend(profile.get(field, []))
    tactics = incident.get("tactics", [])
    fingerprint = {
        "tokens": sorted(tokens),
        "tactics": sorted(tactics),
    }
    return hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode("utf-8")).hexdigest()


def register_connector(name: str, metadata: dict) -> None:
    CONNECTOR_REGISTRY[name] = metadata


def list_connectors() -> List[str]:
    return sorted(CONNECTOR_REGISTRY.keys())


def get_connector(name: str) -> Optional[dict]:
    return CONNECTOR_REGISTRY.get(name)


def validate_connector_event(event: dict) -> List[str]:
    return _validate_event(event)


def _authorize_tenant(tenant_id: str, source: str) -> dict:
    tenant = ENGINE_CONFIG["tenants"].get(tenant_id)
    if not tenant:
        raise ValueError("Unknown tenant")
    if source not in tenant["allowed_sources"]:
        raise ValueError("Source not allowed for tenant")
    return tenant


def ingest_events(
    events: List[dict],
    tenant_id: str,
    source: str,
) -> dict:
    tenant = _authorize_tenant(tenant_id, source)
    validated = []
    rejected = []
    for event in events:
        errors = _validate_event(event)
        if errors:
            rejected.append({"id": event.get("id"), "errors": errors})
        else:
            validated.append(event)
    report = correlate_events(validated)
    report["tenant"] = {
        "id": tenant_id,
        "clearance": tenant["clearance"],
        "source": source,
    }
    report["rejected_events"] = rejected
    return report


def enqueue_events(events: List[dict], tenant_id: str, source: str) -> None:
    PIPELINE_QUEUE.append(
        {
            "events": events,
            "tenant_id": tenant_id,
            "source": source,
        }
    )


def process_queue() -> List[dict]:
    processed = []
    while PIPELINE_QUEUE:
        batch = PIPELINE_QUEUE.pop(0)
        processed.append(
            ingest_events(
                batch["events"],
                batch["tenant_id"],
                batch["source"],
            )
        )
    return processed


def federate_incidents(shared_reports: List[dict]) -> dict:
    federation = {}
    for report in shared_reports:
        sender_id = report.get("sharing_manifest", {}).get("sender_id", "unknown")
        for incident in report.get("incidents", []):
            fingerprint = _incident_fingerprint(incident)
            federation.setdefault(fingerprint, {"incidents": [], "tenants": set()})
            federation[fingerprint]["incidents"].append(
                {"tenant_id": sender_id, "incident": incident}
            )
            federation[fingerprint]["tenants"].add(sender_id)

    federated_incidents = []
    for index, (fingerprint, data) in enumerate(federation.items(), start=1):
        federated_incidents.append(
            {
                "id": f"FED-{index:03d}",
                "fingerprint": fingerprint,
                "tenant_count": len(data["tenants"]),
                "tenants": sorted(data["tenants"]),
                "contributors": [
                    {
                        "tenant_id": entry["tenant_id"],
                        "incident_id": entry["incident"].get("id"),
                        "summary": entry["incident"].get("attack_summary"),
                    }
                    for entry in data["incidents"]
                ],
            }
        )

    return {
        "federated_incidents": federated_incidents,
        "tenant_count": len({tenant for entry in federation.values() for tenant in entry["tenants"]}),
    }


def build_soar_actions(incident: dict) -> List[dict]:
    action = incident.get("recommended_action")
    playbook_hints = incident.get("playbook_hints", [])
    if not action:
        return []
    return [
        {
            "action": action,
            "priority": incident.get("response_priority"),
            "hints": playbook_hints,
        }
    ]


def emit_webhook(incident: dict, url: str) -> dict:
    return {
        "url": url,
        "payload": incident,
        "delivered": False,
        "queued_at": _format_timestamp(datetime.utcnow()),
    }


def correlate_events(events: List[dict]) -> Dict[str, List[dict] | List[str]]:
    """Correlate security events into incidents using deterministic rules."""
    if not events:
        return {"incidents": [], "uncorrelated": []}

    validation_errors = {}
    for event in events:
        errors = _validate_event(event)
        if errors:
            validation_errors[event.get("id", "unknown")] = errors

    deduped_events = _dedupe_events(events)
    suppressed_ids = [event.get("id") for event in deduped_events if _is_suppressed(event)]
    deduped_events = [event for event in deduped_events if not _is_suppressed(event)]
    normalized_events = [_normalize_event(event) for event in deduped_events]
    timestamps = {
        event["id"]: _parse_timestamp(event.get("timestamp"))
        for event in normalized_events
    }

    device_high_critical = {}
    for event in normalized_events:
        device = event.get("device")
        if device and event.get("severity") in {"high", "critical"}:
            device_high_critical[device] = device_high_critical.get(device, 0) + 1

    adjacency = {event["id"]: set() for event in normalized_events}
    edge_reasons: dict[tuple[str, str], List[str]] = {}

    for i, event_a in enumerate(normalized_events):
        for event_b in normalized_events[i + 1 :]:
            reasons = _relationship_reasons(event_a, event_b, device_high_critical)
            timestamp_a = timestamps.get(event_a["id"])
            timestamp_b = timestamps.get(event_b["id"])
            within_window = True
            if timestamp_a and timestamp_b:
                delta_minutes = abs((timestamp_b - timestamp_a).total_seconds()) / 60
                window_a = ENGINE_CONFIG["source_time_windows"].get(
                    event_a.get("source"),
                    ENGINE_CONFIG["time_window_minutes"],
                )
                window_b = ENGINE_CONFIG["source_time_windows"].get(
                    event_b.get("source"),
                    ENGINE_CONFIG["time_window_minutes"],
                )
                within_window = delta_minutes <= min(window_a, window_b)

            if reasons and within_window:
                adjacency[event_a["id"]].add(event_b["id"])
                adjacency[event_b["id"]].add(event_a["id"])
                edge_key = tuple(sorted((event_a["id"], event_b["id"])))
                edge_reasons[edge_key] = reasons

    visited = set()
    incidents = []
    uncorrelated = []
    incident_index = 1

    event_lookup = {event["id"]: event for event in events}

    for event in events:
        event_id = event["id"]
        if event_id in visited:
            continue

        stack = [event_id]
        component = []
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.append(current)
            stack.extend(adjacency[current] - visited)

        if len(component) < 2:
            uncorrelated.append(event_id)
            continue

        component_events = [event_lookup[event_id] for event_id in component]
        evidence = set()
        for event_id in component:
            for neighbor in adjacency[event_id]:
                edge_key = tuple(sorted((event_id, neighbor)))
                evidence.update(edge_reasons.get(edge_key, []))
        component_timestamps = [
            timestamps.get(event_id) for event_id in component if timestamps.get(event_id)
        ]
        created_at = _format_timestamp(min(component_timestamps)) if component_timestamps else None
        last_updated = (
            _format_timestamp(max(component_timestamps)) if component_timestamps else None
        )
        risk_breakdown = _risk_breakdown(component_events)
        confidence_score = _confidence_score(risk_breakdown, sorted(evidence), len(component))
        recommended_action = _identify_action(component_events)
        tactics = _classify_tactics(component_events)
        profile = _entity_profile(component_events)
        actor_attribution = _actor_attribution_score(component_events)
        ml_insights = _ml_layer(component_events)
        response_priority = _response_priority(
            risk_breakdown["total"], confidence_score, profile
        )
        incident = {
            "id": f"INC-{incident_index:03d}",
            "attack_summary": _attack_summary(component_events),
            "related_events": sorted(component),
            "risk_score": risk_breakdown["total"],
            "risk_breakdown": risk_breakdown,
            "confidence_score": confidence_score,
            "recommended_action": recommended_action,
            "playbook_hints": _playbook_hints(recommended_action, component_events),
            "tactics": tactics,
            "response_priority": response_priority,
            "entity_profile": profile,
            "actor_attribution": actor_attribution,
            "ml_insights": ml_insights,
            "status": ENGINE_CONFIG["default_incident_status"],
            "created_at": created_at,
            "last_updated": last_updated,
            "metadata": _incident_metadata(component_events, created_at, last_updated),
            "evidence": sorted(evidence),
            "rules_evaluated": list(ENGINE_CONFIG["correlation_rules"]),
        }
        incident_graph_edges = []
        for edge_key, reasons in edge_reasons.items():
            if edge_key[0] in component and edge_key[1] in component:
                incident_graph_edges.append(
                    {"source": edge_key[0], "target": edge_key[1], "reasons": reasons}
                )
        incident["incident_graph"] = {
            "nodes": sorted(component),
            "edges": incident_graph_edges,
        }
        incident["timeline"] = _build_timeline(component_events)
        incident["automation_recommended"] = (
            risk_breakdown["total"] >= 7 and confidence_score >= 7
        )
        incident["case_workflow"] = _case_workflow(response_priority)
        incident["soar_actions"] = build_soar_actions(incident)
        incidents.append(incident)
        incident_index += 1

    response = {"incidents": incidents, "uncorrelated": sorted(uncorrelated)}
    response["processing_summary"] = {
        "total_events": len(events),
        "deduped_events": len(deduped_events),
        "suppressed_events": len(suppressed_ids),
        "suppressed_event_ids": sorted([event_id for event_id in suppressed_ids if event_id]),
        "validation_error_count": len(validation_errors),
    }
    if validation_errors:
        response["validation_errors"] = validation_errors
    return response


def _run_attack_scenario() -> None:
    scenario_events = [
        {
            "id": "S1",
            "timestamp": "2025-12-28 18:01",
            "source": "identity",
            "user": "riley",
            "device": "workstation-7",
            "ip": "55",
            "region": "EU",
            "severity": "high",
            "description": "Suspicious login from new device",
        },
        {
            "id": "S2",
            "timestamp": "2025-12-28 18:04",
            "source": "endpoint",
            "user": None,
            "device": "workstation-7",
            "ip": None,
            "region": "EU",
            "severity": "critical",
            "description": "Malware detected: credential dumping attempt",
        },
        {
            "id": "S3",
            "timestamp": "2025-12-28 18:07",
            "source": "identity",
            "user": "riley",
            "device": "workstation-7",
            "ip": "55",
            "region": "EU",
            "severity": "high",
            "description": "Failed login attempts after password change",
        },
        {
            "id": "S4",
            "timestamp": "2025-12-28 18:09",
            "source": "cloud",
            "user": None,
            "device": None,
            "ip": "55",
            "region": "EU",
            "severity": "medium",
            "description": "Suspicious API burst from same IP",
        },
        {
            "id": "S5",
            "timestamp": "2025-12-28 18:12",
            "source": "cloud",
            "user": None,
            "device": None,
            "ip": "200",
            "region": "US",
            "severity": "low",
            "description": "Unusual storage enumeration",
        },
    ]

    print("Attack scenario results:")
    print(correlate_events(scenario_events))


if __name__ == "__main__":
    events = [
        {
            "id": "E1",
            "timestamp": "2025-12-28 14:01",
            "source": "identity",
            "user": "adam",
            "device": "laptop-22",
            "ip": "191",
            "region": "EU",
            "severity": "high",
            "description": "Failed login attempts",
        },
        {
            "id": "E2",
            "timestamp": "2025-12-28 14:05",
            "source": "cloud",
            "user": None,
            "device": None,
            "ip": "8",
            "region": "US",
            "severity": "medium",
            "description": "Unusual API call",
        },
        {
            "id": "E3",
            "timestamp": "2025-12-28 14:07",
            "source": "endpoint",
            "user": None,
            "device": "laptop-22",
            "ip": None,
            "region": None,
            "severity": "critical",
            "description": "Malware detected: credential stealer",
        },
        {
            "id": "E4",
            "timestamp": "2025-12-28 14:10",
            "source": "identity",
            "user": "adam",
            "device": "laptop-22",
            "ip": "191",
            "region": "EU",
            "severity": "high",
            "description": "Login from known malicious IP",
        },
        {
            "id": "E5",
            "timestamp": "2025-12-28 14:11",
            "source": "cloud",
            "user": None,
            "device": None,
            "ip": "10",
            "region": "EU",
            "severity": "low",
            "description": "Storage bucket read",
        },
    ]

    print("Example dataset results:")
    full_report = correlate_events(events)
    print(full_report)
    print("Example dataset results (analyst clearance):")
    print(apply_clearance(full_report, "analyst"))
    print("Example dataset results (shared to partner):")
    shared = apply_sharing_policy(
        full_report,
        "public",
        {"id": "partner-001"},
    )
    print(shared)
    print("Example dataset results (encrypted export):")
    encrypted = export_encrypted_payload(
        full_report,
        "public",
        {"id": "partner-001"},
    )
    print(encrypted)
    print("Example dataset results (federated view):")
    shared_b = apply_sharing_policy(
        full_report,
        "public",
        {"id": "partner-001"},
        sender={"id": "tenant-b"},
    )
    print(federate_incidents([shared, shared_b]))
    register_connector("siem-sentinel", {"version": "1.0"})
    print("Registered connectors:", list_connectors())
    print("Connector metadata:", get_connector("siem-sentinel"))
    print("Tenant ingestion sample:")
    print(ingest_events(events, "local", "identity"))
    enqueue_events(events, "local", "identity")
    print("Queue processed:", process_queue())
    print("SOAR webhook sample:", emit_webhook(full_report["incidents"][0], "https://soar"))
    print("Storage export sample:", export_for_storage(full_report, "public", {"id": "partner-001"}))
    _run_attack_scenario()
