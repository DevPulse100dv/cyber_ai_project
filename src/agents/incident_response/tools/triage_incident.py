"""
Incident Triage Tool.

Classifies and prioritizes security incidents based on
indicators, affected systems, and potential impact.
"""

import re
from datetime import datetime
from typing import Any
from uuid import uuid4


# Incident type patterns and classifications
INCIDENT_PATTERNS = {
    "ransomware": {
        "keywords": ["ransomware", "encrypted files", "ransom note", "locked files", "bitcoin payment"],
        "severity": "critical",
        "category": "malware",
        "priority": 1,
        "response_time": "15 minutes",
    },
    "data_breach": {
        "keywords": ["data breach", "data leak", "exfiltration", "stolen data", "unauthorized access to data"],
        "severity": "critical",
        "category": "data_loss",
        "priority": 1,
        "response_time": "30 minutes",
    },
    "apt": {
        "keywords": ["advanced persistent", "apt", "nation state", "targeted attack", "sophisticated"],
        "severity": "critical",
        "category": "intrusion",
        "priority": 1,
        "response_time": "30 minutes",
    },
    "malware": {
        "keywords": ["malware", "virus", "trojan", "worm", "backdoor", "rootkit"],
        "severity": "high",
        "category": "malware",
        "priority": 2,
        "response_time": "1 hour",
    },
    "phishing": {
        "keywords": ["phishing", "spear phishing", "credential theft", "fake login", "social engineering"],
        "severity": "high",
        "category": "social_engineering",
        "priority": 2,
        "response_time": "1 hour",
    },
    "brute_force": {
        "keywords": ["brute force", "password spray", "credential stuffing", "failed logins"],
        "severity": "medium",
        "category": "authentication",
        "priority": 3,
        "response_time": "2 hours",
    },
    "unauthorized_access": {
        "keywords": ["unauthorized access", "privilege escalation", "lateral movement"],
        "severity": "high",
        "category": "intrusion",
        "priority": 2,
        "response_time": "1 hour",
    },
    "ddos": {
        "keywords": ["ddos", "denial of service", "traffic flood", "service unavailable"],
        "severity": "high",
        "category": "availability",
        "priority": 2,
        "response_time": "30 minutes",
    },
    "insider_threat": {
        "keywords": ["insider", "employee", "internal threat", "data theft by user"],
        "severity": "high",
        "category": "insider",
        "priority": 2,
        "response_time": "1 hour",
    },
    "policy_violation": {
        "keywords": ["policy violation", "compliance", "unauthorized software"],
        "severity": "low",
        "category": "policy",
        "priority": 4,
        "response_time": "24 hours",
    },
}

# Impact factors
IMPACT_FACTORS = {
    "data_sensitivity": {
        "pii": 3,
        "phi": 4,
        "financial": 4,
        "intellectual_property": 4,
        "public": 1,
        "internal": 2,
    },
    "system_criticality": {
        "production": 4,
        "staging": 2,
        "development": 1,
        "test": 1,
        "critical_infrastructure": 5,
    },
    "user_impact": {
        "executive": 4,
        "admin": 4,
        "standard": 2,
        "service_account": 3,
    },
}


async def triage_incident(
    incident_description: str,
    affected_systems: list[str] | None = None,
    indicators: list[dict[str, Any]] | None = None,
    initial_severity: str = "unknown",
) -> dict[str, Any]:
    """
    Triage and classify a security incident.
    
    Args:
        incident_description: Detailed description of the incident.
        affected_systems: List of affected system identifiers.
        indicators: IOCs and other indicators.
        initial_severity: Initial severity assessment.
        
    Returns:
        dict: Triage results with classification and recommendations.
    """
    affected_systems = affected_systems or []
    indicators = indicators or []
    
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{str(uuid4())[:8].upper()}"
    
    # Classify incident type
    incident_type, type_info = _classify_incident_type(incident_description)
    
    # Calculate severity score
    severity_score, severity_factors = _calculate_severity(
        incident_description,
        affected_systems,
        indicators,
        type_info,
        initial_severity,
    )
    
    # Determine final severity
    final_severity = _score_to_severity(severity_score)
    
    # Calculate impact
    impact_assessment = _assess_impact(incident_description, affected_systems)
    
    # Determine response priority
    priority = type_info.get("priority", 3) if type_info else 3
    if severity_score >= 8:
        priority = 1
    elif severity_score >= 6:
        priority = min(priority, 2)
    
    # Generate recommended actions
    recommended_actions = _generate_triage_actions(
        incident_type,
        final_severity,
        affected_systems,
        indicators,
    )
    
    # Determine escalation requirements
    escalation = _determine_escalation(final_severity, incident_type, impact_assessment)
    
    return {
        "incident_id": incident_id,
        "timestamp": datetime.now().isoformat(),
        "classification": {
            "incident_type": incident_type,
            "category": type_info.get("category", "unknown") if type_info else "unknown",
            "severity": final_severity,
            "severity_score": severity_score,
            "priority": priority,
            "response_time_target": type_info.get("response_time", "4 hours") if type_info else "4 hours",
        },
        "severity_factors": severity_factors,
        "impact_assessment": impact_assessment,
        "affected_systems": affected_systems,
        "indicators_count": len(indicators),
        "recommended_actions": recommended_actions,
        "escalation": escalation,
        "next_steps": [
            f"1. Begin incident response within {type_info.get('response_time', '4 hours') if type_info else '4 hours'}",
            "2. Execute containment actions for affected systems",
            "3. Collect and preserve evidence",
            "4. Notify stakeholders per escalation requirements",
            "5. Document all actions in incident ticket",
        ],
    }


def _classify_incident_type(description: str) -> tuple[str, dict[str, Any] | None]:
    """Classify incident based on description keywords."""
    description_lower = description.lower()
    
    best_match = None
    best_score = 0
    
    for incident_type, info in INCIDENT_PATTERNS.items():
        score = sum(1 for keyword in info["keywords"] if keyword in description_lower)
        if score > best_score:
            best_score = score
            best_match = (incident_type, info)
    
    if best_match:
        return best_match
    
    return ("unknown", None)


def _calculate_severity(
    description: str,
    affected_systems: list[str],
    indicators: list[dict[str, Any]],
    type_info: dict[str, Any] | None,
    initial_severity: str,
) -> tuple[float, list[str]]:
    """Calculate severity score based on multiple factors."""
    score = 0.0
    factors = []
    
    # Base score from incident type
    if type_info:
        base_severity = type_info.get("severity", "medium")
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        score += severity_scores.get(base_severity, 2)
        factors.append(f"Incident type base severity: {base_severity}")
    
    # Initial severity input
    if initial_severity in ["critical", "high"]:
        score += 2
        factors.append(f"Initial severity reported as {initial_severity}")
    
    # Number of affected systems
    system_count = len(affected_systems)
    if system_count >= 10:
        score += 3
        factors.append(f"Large scope: {system_count} systems affected")
    elif system_count >= 5:
        score += 2
        factors.append(f"Medium scope: {system_count} systems affected")
    elif system_count >= 1:
        score += 1
        factors.append(f"Limited scope: {system_count} systems affected")
    
    # Number of indicators
    if len(indicators) >= 10:
        score += 2
        factors.append("High number of IOCs suggests sophisticated attack")
    elif len(indicators) >= 5:
        score += 1
        factors.append("Multiple IOCs present")
    
    # Critical keywords in description
    critical_keywords = [
        "executive", "ceo", "cfo", "board", "customer data", "pii",
        "production", "critical system", "database", "payment"
    ]
    description_lower = description.lower()
    for keyword in critical_keywords:
        if keyword in description_lower:
            score += 1
            factors.append(f"Critical asset/data mentioned: {keyword}")
            break
    
    # Normalize score to 1-10 range
    score = min(10, max(1, score))
    
    return (score, factors)


def _score_to_severity(score: float) -> str:
    """Convert numeric score to severity label."""
    if score >= 8:
        return "critical"
    elif score >= 6:
        return "high"
    elif score >= 4:
        return "medium"
    return "low"


def _assess_impact(description: str, affected_systems: list[str]) -> dict[str, Any]:
    """Assess potential impact of the incident."""
    impact = {
        "confidentiality": "unknown",
        "integrity": "unknown",
        "availability": "unknown",
        "business_impact": "unknown",
        "regulatory_implications": [],
    }
    
    description_lower = description.lower()
    
    # Confidentiality impact
    if any(kw in description_lower for kw in ["data breach", "stolen", "exfiltrated", "leaked"]):
        impact["confidentiality"] = "high"
    elif any(kw in description_lower for kw in ["access", "viewed", "read"]):
        impact["confidentiality"] = "medium"
    else:
        impact["confidentiality"] = "low"
    
    # Integrity impact
    if any(kw in description_lower for kw in ["modified", "altered", "changed", "encrypted", "ransomware"]):
        impact["integrity"] = "high"
    elif any(kw in description_lower for kw in ["trojan", "backdoor", "malware"]):
        impact["integrity"] = "medium"
    else:
        impact["integrity"] = "low"
    
    # Availability impact
    if any(kw in description_lower for kw in ["ddos", "denial of service", "unavailable", "down", "crashed"]):
        impact["availability"] = "high"
    elif any(kw in description_lower for kw in ["slow", "degraded", "intermittent"]):
        impact["availability"] = "medium"
    else:
        impact["availability"] = "low"
    
    # Business impact
    high_impact_count = sum(1 for v in [impact["confidentiality"], impact["integrity"], impact["availability"]] if v == "high")
    if high_impact_count >= 2:
        impact["business_impact"] = "severe"
    elif high_impact_count >= 1:
        impact["business_impact"] = "significant"
    else:
        impact["business_impact"] = "limited"
    
    # Regulatory implications
    if any(kw in description_lower for kw in ["pii", "personal data", "customer", "employee data"]):
        impact["regulatory_implications"].append("GDPR notification may be required within 72 hours")
    if any(kw in description_lower for kw in ["payment", "credit card", "cardholder"]):
        impact["regulatory_implications"].append("PCI-DSS breach notification required")
    if any(kw in description_lower for kw in ["health", "medical", "patient", "phi"]):
        impact["regulatory_implications"].append("HIPAA breach notification may be required")
    
    return impact


def _generate_triage_actions(
    incident_type: str,
    severity: str,
    affected_systems: list[str],
    indicators: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Generate recommended response actions."""
    actions = []
    
    # Universal first actions
    actions.append({
        "action": "document_incident",
        "description": "Create incident ticket and document initial findings",
        "priority": 1,
        "automated": False,
    })
    
    # Severity-based actions
    if severity in ["critical", "high"]:
        actions.append({
            "action": "isolate_systems",
            "description": f"Isolate {len(affected_systems)} affected systems from network",
            "priority": 1,
            "automated": True,
            "targets": affected_systems,
        })
        
        actions.append({
            "action": "preserve_evidence",
            "description": "Collect volatile evidence before containment changes system state",
            "priority": 1,
            "automated": True,
        })
    
    # Incident type specific actions
    type_actions = {
        "ransomware": [
            {"action": "disable_network", "description": "Disconnect from network immediately", "priority": 1},
            {"action": "identify_variant", "description": "Identify ransomware variant", "priority": 2},
            {"action": "check_backups", "description": "Verify backup integrity", "priority": 2},
        ],
        "phishing": [
            {"action": "block_sender", "description": "Block sender and similar domains", "priority": 1},
            {"action": "search_mailboxes", "description": "Search and remove from all mailboxes", "priority": 1},
            {"action": "reset_credentials", "description": "Reset credentials for affected users", "priority": 2},
        ],
        "malware": [
            {"action": "quarantine_files", "description": "Quarantine malicious files", "priority": 1},
            {"action": "scan_systems", "description": "Scan all connected systems", "priority": 2},
        ],
        "brute_force": [
            {"action": "block_source", "description": "Block source IPs", "priority": 1},
            {"action": "lock_accounts", "description": "Temporarily lock targeted accounts", "priority": 1},
            {"action": "reset_passwords", "description": "Force password reset for compromised accounts", "priority": 2},
        ],
    }
    
    if incident_type in type_actions:
        for action in type_actions[incident_type]:
            actions.append({**action, "automated": False})
    
    # IOC-based actions
    if indicators:
        actions.append({
            "action": "block_iocs",
            "description": f"Block {len(indicators)} identified IOCs at perimeter",
            "priority": 2,
            "automated": True,
        })
    
    return actions


def _determine_escalation(
    severity: str,
    incident_type: str,
    impact: dict[str, Any],
) -> dict[str, Any]:
    """Determine escalation requirements."""
    escalation = {
        "required": False,
        "level": "none",
        "notify": [],
        "timeline": None,
    }
    
    if severity == "critical":
        escalation.update({
            "required": True,
            "level": "executive",
            "notify": ["CISO", "CTO", "Legal", "PR"],
            "timeline": "Immediate notification required",
        })
    elif severity == "high":
        escalation.update({
            "required": True,
            "level": "management",
            "notify": ["Security Manager", "IT Director"],
            "timeline": "Notify within 1 hour",
        })
    elif severity == "medium":
        escalation.update({
            "required": True,
            "level": "team",
            "notify": ["Security Team Lead"],
            "timeline": "Notify within 4 hours",
        })
    
    # Regulatory escalation
    if impact.get("regulatory_implications"):
        if "executive" not in escalation.get("level", ""):
            escalation["notify"].append("Legal/Compliance")
    
    return escalation
