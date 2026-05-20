"""
Incident Report Generation Tool.

Creates comprehensive incident reports including timeline,
actions taken, evidence collected, and recommendations.
"""

from datetime import datetime
from typing import Any
from uuid import uuid4


async def generate_report(
    incident_id: str,
    incident_summary: str,
    actions_taken: list[dict[str, Any]] | None = None,
    report_type: str = "full",
) -> dict[str, Any]:
    """
    Generate an incident report.
    
    Args:
        incident_id: Unique incident identifier.
        incident_summary: Summary of the incident.
        actions_taken: List of response actions.
        report_type: Type of report ('executive', 'technical', 'compliance', 'full').
        
    Returns:
        dict: Generated report data.
    """
    actions_taken = actions_taken or []
    report_id = f"RPT-{str(uuid4())[:8].upper()}"
    
    # Generate report based on type
    if report_type == "executive":
        report_content = _generate_executive_report(incident_id, incident_summary, actions_taken)
    elif report_type == "technical":
        report_content = _generate_technical_report(incident_id, incident_summary, actions_taken)
    elif report_type == "compliance":
        report_content = _generate_compliance_report(incident_id, incident_summary, actions_taken)
    else:  # full
        report_content = _generate_full_report(incident_id, incident_summary, actions_taken)
    
    return {
        "success": True,
        "report_id": report_id,
        "incident_id": incident_id,
        "report_type": report_type,
        "generated_at": datetime.now().isoformat(),
        "report": report_content,
    }


def _generate_executive_report(
    incident_id: str,
    summary: str,
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate executive-level report."""
    return {
        "title": f"Executive Incident Summary - {incident_id}",
        "classification": "CONFIDENTIAL",
        "sections": {
            "incident_overview": {
                "incident_id": incident_id,
                "summary": summary,
                "date_detected": datetime.now().strftime("%B %d, %Y"),
                "current_status": "Under Investigation" if not actions else "Contained",
            },
            "business_impact": {
                "impact_level": "Medium",
                "affected_operations": "Specific details pending full assessment",
                "financial_impact": "To be determined",
                "customer_impact": "Assessment in progress",
            },
            "response_summary": {
                "actions_taken": len(actions),
                "containment_status": "Active" if actions else "Pending",
                "key_milestones": [
                    "Incident detected and logged",
                    "Initial triage completed",
                    "Containment measures implemented",
                ],
            },
            "recommendations": [
                "Continue monitoring for related activity",
                "Complete full forensic analysis",
                "Review and update security controls",
                "Schedule lessons learned session",
            ],
            "next_briefing": "24 hours or upon significant developments",
        },
    }


def _generate_technical_report(
    incident_id: str,
    summary: str,
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate technical-level report."""
    return {
        "title": f"Technical Incident Report - {incident_id}",
        "classification": "CONFIDENTIAL - TECHNICAL",
        "sections": {
            "incident_details": {
                "incident_id": incident_id,
                "summary": summary,
                "detection_time": datetime.now().isoformat(),
                "detection_source": "Security Monitoring System",
            },
            "technical_analysis": {
                "attack_vector": "Under investigation",
                "techniques_observed": [
                    "T1566 - Phishing (suspected)",
                    "T1059 - Command and Scripting Interpreter",
                    "T1071 - Application Layer Protocol",
                ],
                "affected_systems": ["Systems identified in incident data"],
                "indicators_of_compromise": {
                    "ips": ["Refer to IOC attachment"],
                    "domains": ["Refer to IOC attachment"],
                    "hashes": ["Refer to IOC attachment"],
                },
            },
            "response_actions": {
                "containment": [a for a in actions if a.get("type") == "containment"],
                "eradication": [a for a in actions if a.get("type") == "eradication"],
                "recovery": [a for a in actions if a.get("type") == "recovery"],
            },
            "evidence_collected": {
                "memory_dumps": "Collected and preserved",
                "disk_images": "Collected and preserved",
                "logs": "Collected and preserved",
                "network_captures": "Collected and preserved",
            },
            "timeline": _generate_timeline(actions),
            "technical_recommendations": [
                "Deploy additional monitoring for C2 patterns",
                "Update IDS/IPS signatures",
                "Patch identified vulnerabilities",
                "Implement network segmentation",
                "Review and harden endpoint configurations",
            ],
        },
    }


def _generate_compliance_report(
    incident_id: str,
    summary: str,
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate compliance-focused report."""
    return {
        "title": f"Compliance Incident Report - {incident_id}",
        "classification": "CONFIDENTIAL - COMPLIANCE",
        "sections": {
            "incident_summary": {
                "incident_id": incident_id,
                "description": summary,
                "date_discovered": datetime.now().strftime("%Y-%m-%d"),
                "date_reported": datetime.now().strftime("%Y-%m-%d"),
            },
            "regulatory_impact": {
                "gdpr": {
                    "applicable": True,
                    "personal_data_involved": "Under assessment",
                    "notification_required": "Pending determination",
                    "notification_deadline": "72 hours from confirmation",
                    "dpa_notification": "Will be filed if required",
                },
                "pci_dss": {
                    "applicable": "Under assessment",
                    "cardholder_data_involved": "Under assessment",
                    "notification_required": "Pending determination",
                },
                "hipaa": {
                    "applicable": "Under assessment",
                    "phi_involved": "Under assessment",
                    "notification_required": "Pending determination",
                },
                "other_regulations": [],
            },
            "data_impact_assessment": {
                "data_types_affected": "Under investigation",
                "number_of_records": "Under investigation",
                "data_subjects": "Under investigation",
                "geographic_scope": "Under investigation",
            },
            "response_documentation": {
                "detection_method": "Automated security monitoring",
                "response_initiation": datetime.now().isoformat(),
                "containment_actions": len([a for a in actions if "contain" in str(a).lower()]),
                "evidence_preserved": True,
                "forensic_analysis": "In progress",
            },
            "notification_status": {
                "internal_stakeholders": "Notified",
                "legal_team": "Engaged",
                "regulators": "Pending assessment",
                "affected_individuals": "Pending assessment",
            },
            "remediation_plan": {
                "immediate_actions": "Containment implemented",
                "short_term": "Eradication and recovery",
                "long_term": "Control improvements",
            },
        },
    }


def _generate_full_report(
    incident_id: str,
    summary: str,
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate comprehensive full report."""
    exec_report = _generate_executive_report(incident_id, summary, actions)
    tech_report = _generate_technical_report(incident_id, summary, actions)
    comp_report = _generate_compliance_report(incident_id, summary, actions)
    
    return {
        "title": f"Comprehensive Incident Report - {incident_id}",
        "classification": "CONFIDENTIAL",
        "report_date": datetime.now().strftime("%B %d, %Y"),
        "prepared_by": "Incident Response Team",
        "sections": {
            "executive_summary": exec_report["sections"],
            "technical_details": tech_report["sections"],
            "compliance_assessment": comp_report["sections"],
            "appendices": {
                "a_timeline": _generate_timeline(actions),
                "b_ioc_list": "Attached separately",
                "c_evidence_manifest": "Attached separately",
                "d_communication_log": "Attached separately",
            },
            "lessons_learned": {
                "what_worked": [
                    "Detection capabilities identified the incident",
                    "Response procedures followed",
                    "Evidence preservation successful",
                ],
                "areas_for_improvement": [
                    "To be determined after incident closure",
                ],
                "recommendations": [
                    "Schedule formal lessons learned session",
                    "Update runbooks based on findings",
                    "Review and enhance monitoring",
                ],
            },
        },
    }


def _generate_timeline(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate incident timeline."""
    timeline = [
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": "Incident detected",
            "actor": "Security Monitoring",
        },
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event": "Initial triage completed",
            "actor": "Incident Response Agent",
        },
    ]
    
    for i, action in enumerate(actions):
        timeline.append({
            "time": action.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            "event": action.get("description", f"Action {i+1}"),
            "actor": action.get("actor", "Response Team"),
        })
    
    return timeline
