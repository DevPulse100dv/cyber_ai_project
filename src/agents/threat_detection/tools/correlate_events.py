"""
Event Correlation Tool.

Cross-correlates security events from multiple sources to identify
attack patterns, campaigns, or coordinated activities.
"""

from datetime import datetime
from typing import Any


# Correlation rules for detecting attack patterns
CORRELATION_RULES = {
    "brute_force_to_success": {
        "name": "Brute Force Leading to Successful Login",
        "description": "Multiple failed auth attempts followed by successful login",
        "severity": "critical",
        "mitre": "T1110 - Brute Force",
        "sequence": ["auth_failure", "auth_failure", "auth_success"],
    },
    "recon_to_exploit": {
        "name": "Reconnaissance Followed by Exploitation",
        "description": "Port scan or vulnerability scan followed by exploit attempt",
        "severity": "critical",
        "mitre": "TA0043 - Reconnaissance → TA0001 - Initial Access",
        "sequence": ["port_scan", "exploit_attempt"],
    },
    "lateral_movement_chain": {
        "name": "Lateral Movement Chain",
        "description": "Sequential access across multiple systems",
        "severity": "high",
        "mitre": "TA0008 - Lateral Movement",
        "sequence": ["remote_login", "remote_login", "remote_login"],
    },
    "data_staging": {
        "name": "Data Staging for Exfiltration",
        "description": "Data collection followed by compression or encryption",
        "severity": "high",
        "mitre": "T1074 - Data Staged",
        "sequence": ["file_access", "compression", "network_upload"],
    },
    "privilege_escalation_chain": {
        "name": "Privilege Escalation Chain",
        "description": "Normal user activity followed by privilege escalation and admin actions",
        "severity": "critical",
        "mitre": "TA0004 - Privilege Escalation",
        "sequence": ["user_login", "priv_escalation", "admin_action"],
    },
    "malware_installation": {
        "name": "Malware Installation Pattern",
        "description": "File download followed by execution and persistence",
        "severity": "critical",
        "mitre": "T1204 - User Execution",
        "sequence": ["file_download", "file_execution", "persistence"],
    },
}

# Event type mappings for normalization
EVENT_TYPE_MAPPING = {
    # Authentication events
    "failed_login": "auth_failure",
    "failed_password": "auth_failure",
    "authentication_failure": "auth_failure",
    "successful_login": "auth_success",
    "accepted_password": "auth_success",
    "session_opened": "auth_success",
    
    # Reconnaissance events
    "port_scan": "port_scan",
    "vulnerability_scan": "port_scan",
    "network_discovery": "port_scan",
    
    # Exploitation events
    "exploit": "exploit_attempt",
    "attack": "exploit_attempt",
    "injection": "exploit_attempt",
    "overflow": "exploit_attempt",
    
    # Lateral movement
    "ssh": "remote_login",
    "rdp": "remote_login",
    "remote_access": "remote_login",
    "psexec": "remote_login",
    
    # Data events
    "file_read": "file_access",
    "file_open": "file_access",
    "data_access": "file_access",
    "archive": "compression",
    "zip": "compression",
    "tar": "compression",
    "encrypt": "compression",
    "upload": "network_upload",
    "exfil": "network_upload",
    
    # Privilege events
    "sudo": "priv_escalation",
    "runas": "priv_escalation",
    "privilege": "priv_escalation",
    "admin_login": "admin_action",
    "root_command": "admin_action",
    
    # Execution events
    "download": "file_download",
    "wget": "file_download",
    "curl": "file_download",
    "execute": "file_execution",
    "process_create": "file_execution",
    "cron": "persistence",
    "scheduled_task": "persistence",
    "startup": "persistence",
    "registry_run": "persistence",
}


async def correlate_events(
    events: list[dict[str, Any]],
    correlation_rules: list[str] | None = None,
    time_window: str = "1h",
) -> dict[str, Any]:
    """
    Correlate security events to identify attack patterns.
    
    Args:
        events: List of security events to correlate.
        correlation_rules: Specific rules to apply (or None for all).
        time_window: Time window for correlation.
        
    Returns:
        dict: Correlation results with identified patterns.
    """
    # Determine which rules to apply
    rules_to_apply = CORRELATION_RULES
    if correlation_rules:
        rules_to_apply = {k: v for k, v in CORRELATION_RULES.items() if k in correlation_rules}
    
    # Normalize events
    normalized_events = [_normalize_event(e) for e in events]
    
    # Group events by source
    events_by_source: dict[str, list[dict[str, Any]]] = {}
    events_by_user: dict[str, list[dict[str, Any]]] = {}
    
    for event in normalized_events:
        source = event.get("source_ip", event.get("host", "unknown"))
        user = event.get("user", "unknown")
        
        if source not in events_by_source:
            events_by_source[source] = []
        events_by_source[source].append(event)
        
        if user not in events_by_user:
            events_by_user[user] = []
        events_by_user[user].append(event)
    
    # Find pattern matches
    correlations = []
    
    # Check each rule against event sequences
    for rule_name, rule in rules_to_apply.items():
        sequence = rule["sequence"]
        
        # Check by source IP
        for source, source_events in events_by_source.items():
            matches = _find_sequence_matches(source_events, sequence)
            for match in matches:
                correlations.append({
                    "rule": rule_name,
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "mitre": rule["mitre"],
                    "source": source,
                    "matched_events": match,
                    "confidence": _calculate_confidence(match),
                })
        
        # Check by user
        for user, user_events in events_by_user.items():
            matches = _find_sequence_matches(user_events, sequence)
            for match in matches:
                # Avoid duplicates
                if not any(c["matched_events"] == match for c in correlations):
                    correlations.append({
                        "rule": rule_name,
                        "rule_name": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "mitre": rule["mitre"],
                        "user": user,
                        "matched_events": match,
                        "confidence": _calculate_confidence(match),
                    })
    
    # Additional correlation: high-volume activity detection
    for source, source_events in events_by_source.items():
        if len(source_events) >= 10:
            # Check for rapid activity
            event_types = [e.get("normalized_type") for e in source_events]
            unique_types = set(event_types)
            
            if len(unique_types) >= 3:
                correlations.append({
                    "rule": "high_volume_multi_type",
                    "rule_name": "High Volume Multi-Type Activity",
                    "description": f"Source {source} generated {len(source_events)} events of {len(unique_types)} types",
                    "severity": "medium",
                    "mitre": "TA0043 - Reconnaissance",
                    "source": source,
                    "event_count": len(source_events),
                    "event_types": list(unique_types),
                    "confidence": "medium",
                })
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    correlations.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))
    
    # Generate timeline
    timeline = _generate_attack_timeline(correlations, normalized_events)
    
    return {
        "timestamp": datetime.now().isoformat(),
        "time_window": time_window,
        "rules_applied": list(rules_to_apply.keys()),
        "summary": {
            "total_events_analyzed": len(events),
            "normalized_events": len(normalized_events),
            "correlations_found": len(correlations),
            "critical_correlations": sum(1 for c in correlations if c.get("severity") == "critical"),
            "unique_sources": len(events_by_source),
            "unique_users": len(events_by_user),
        },
        "correlations": correlations[:20],  # Limit to top 20
        "attack_timeline": timeline,
        "recommendations": _generate_correlation_recommendations(correlations),
    }


def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize an event to a standard format."""
    normalized = event.copy()
    
    # Get event type
    event_type = event.get("type", event.get("event_type", "unknown")).lower()
    
    # Normalize event type
    normalized_type = EVENT_TYPE_MAPPING.get(event_type)
    
    # If no direct match, try partial matching
    if not normalized_type:
        for key, value in EVENT_TYPE_MAPPING.items():
            if key in event_type:
                normalized_type = value
                break
    
    normalized["normalized_type"] = normalized_type or event_type
    normalized["original_type"] = event_type
    
    return normalized


def _find_sequence_matches(
    events: list[dict[str, Any]],
    sequence: list[str],
) -> list[list[dict[str, Any]]]:
    """Find all occurrences of a sequence in events."""
    matches = []
    
    if len(events) < len(sequence):
        return matches
    
    # Extract normalized types
    event_types = [e.get("normalized_type", "") for e in events]
    
    # Sliding window
    for i in range(len(events) - len(sequence) + 1):
        window_types = event_types[i:i + len(sequence)]
        
        if window_types == sequence:
            matches.append(events[i:i + len(sequence)])
        
        # Also check for partial matches with the sequence pattern
        partial_match = True
        matched_events = []
        seq_idx = 0
        
        for j in range(i, min(i + len(sequence) * 2, len(events))):
            if seq_idx >= len(sequence):
                break
            if event_types[j] == sequence[seq_idx]:
                matched_events.append(events[j])
                seq_idx += 1
        
        if len(matched_events) == len(sequence) and matched_events not in matches:
            matches.append(matched_events)
    
    return matches


def _calculate_confidence(matched_events: list[dict[str, Any]]) -> str:
    """Calculate confidence level for a correlation."""
    # Simple heuristic based on event quality
    if len(matched_events) >= 3:
        return "high"
    elif len(matched_events) >= 2:
        return "medium"
    return "low"


def _generate_attack_timeline(
    correlations: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Generate a timeline of attack activities."""
    timeline = []
    
    for correlation in correlations:
        matched = correlation.get("matched_events", [])
        if matched:
            timeline.append({
                "phase": correlation.get("rule_name", "Unknown"),
                "severity": correlation.get("severity", "medium"),
                "mitre": correlation.get("mitre", "Unknown"),
                "event_count": len(matched),
                "source": correlation.get("source", correlation.get("user", "Unknown")),
            })
    
    return timeline


def _generate_correlation_recommendations(correlations: list[dict[str, Any]]) -> list[str]:
    """Generate recommendations based on correlations."""
    recommendations = []
    
    rule_names = set(c.get("rule") for c in correlations)
    has_critical = any(c.get("severity") == "critical" for c in correlations)
    
    if has_critical:
        recommendations.extend([
            "CRITICAL: Active attack campaign detected",
            "Immediately escalate to incident response team",
            "Consider network isolation of affected systems",
        ])
    
    if "brute_force_to_success" in rule_names:
        recommendations.extend([
            "Reset credentials for compromised account",
            "Review all activity from the authenticated session",
            "Implement additional authentication controls",
        ])
    
    if "lateral_movement_chain" in rule_names:
        recommendations.extend([
            "Map all systems accessed in the chain",
            "Review credentials used for lateral movement",
            "Implement network segmentation",
        ])
    
    if "data_staging" in rule_names:
        recommendations.extend([
            "Investigate data that was accessed and staged",
            "Check for data exfiltration to external destinations",
            "Review DLP policies and alerts",
        ])
    
    if "malware_installation" in rule_names:
        recommendations.extend([
            "Isolate affected systems immediately",
            "Collect and analyze malware samples",
            "Scan all systems with updated signatures",
        ])
    
    if not recommendations:
        recommendations.append("No attack patterns detected - continue monitoring")
    
    return recommendations
