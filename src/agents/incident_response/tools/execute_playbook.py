"""
Playbook Execution Tool.

Executes predefined incident response playbooks with
step-by-step actions for specific incident types.
"""

from datetime import datetime
from typing import Any
from uuid import uuid4


# Predefined playbooks (in production, these would be loaded from files)
PLAYBOOKS = {
    "ransomware_response": {
        "name": "Ransomware Response Playbook",
        "description": "Standard response procedure for ransomware incidents",
        "version": "2.0",
        "steps": [
            {
                "step": 1,
                "name": "Isolate Affected Systems",
                "action": "network_isolation",
                "description": "Disconnect affected systems from network immediately",
                "automated": True,
                "critical": True,
            },
            {
                "step": 2,
                "name": "Preserve Evidence",
                "action": "collect_volatile_evidence",
                "description": "Capture memory dumps and running processes",
                "automated": True,
                "critical": True,
            },
            {
                "step": 3,
                "name": "Identify Ransomware Variant",
                "action": "malware_analysis",
                "description": "Analyze ransom note and encrypted files to identify variant",
                "automated": False,
                "critical": True,
            },
            {
                "step": 4,
                "name": "Check for Decryption Tools",
                "action": "check_decryptors",
                "description": "Search NoMoreRansom and vendor sites for available decryptors",
                "automated": False,
                "critical": False,
            },
            {
                "step": 5,
                "name": "Assess Backup Status",
                "action": "verify_backups",
                "description": "Verify backup integrity and isolation from infection",
                "automated": False,
                "critical": True,
            },
            {
                "step": 6,
                "name": "Notify Stakeholders",
                "action": "escalation",
                "description": "Notify CISO, Legal, and PR teams",
                "automated": False,
                "critical": True,
            },
            {
                "step": 7,
                "name": "Eradicate Threat",
                "action": "system_rebuild",
                "description": "Clean or rebuild affected systems from known-good images",
                "automated": False,
                "critical": True,
            },
            {
                "step": 8,
                "name": "Restore from Backup",
                "action": "restore_data",
                "description": "Restore data from verified clean backups",
                "automated": False,
                "critical": True,
            },
        ],
    },
    "phishing_response": {
        "name": "Phishing Response Playbook",
        "description": "Response procedure for phishing incidents",
        "version": "1.5",
        "steps": [
            {
                "step": 1,
                "name": "Identify Scope",
                "action": "search_email_logs",
                "description": "Search email logs for all recipients of phishing email",
                "automated": True,
                "critical": True,
            },
            {
                "step": 2,
                "name": "Block Sender",
                "action": "email_block",
                "description": "Block sender address and domain at email gateway",
                "automated": True,
                "critical": True,
            },
            {
                "step": 3,
                "name": "Remove Emails",
                "action": "email_purge",
                "description": "Remove phishing emails from all mailboxes",
                "automated": True,
                "critical": True,
            },
            {
                "step": 4,
                "name": "Block URLs/IPs",
                "action": "block_indicators",
                "description": "Block malicious URLs and IPs at web proxy/firewall",
                "automated": True,
                "critical": True,
            },
            {
                "step": 5,
                "name": "Identify Victims",
                "action": "analyze_clicks",
                "description": "Identify users who clicked links or entered credentials",
                "automated": True,
                "critical": True,
            },
            {
                "step": 6,
                "name": "Reset Credentials",
                "action": "password_reset",
                "description": "Force password reset for affected users",
                "automated": True,
                "critical": True,
            },
            {
                "step": 7,
                "name": "Scan Endpoints",
                "action": "endpoint_scan",
                "description": "Scan victim endpoints for malware",
                "automated": True,
                "critical": False,
            },
            {
                "step": 8,
                "name": "User Notification",
                "action": "notify_users",
                "description": "Send awareness notification to all users",
                "automated": False,
                "critical": False,
            },
        ],
    },
    "malware_response": {
        "name": "Malware Response Playbook",
        "description": "Response procedure for malware infections",
        "version": "1.3",
        "steps": [
            {
                "step": 1,
                "name": "Isolate System",
                "action": "network_isolation",
                "description": "Isolate infected system from network",
                "automated": True,
                "critical": True,
            },
            {
                "step": 2,
                "name": "Collect Evidence",
                "action": "collect_evidence",
                "description": "Capture malware sample and system artifacts",
                "automated": True,
                "critical": True,
            },
            {
                "step": 3,
                "name": "Analyze Malware",
                "action": "malware_analysis",
                "description": "Submit sample for analysis to identify capabilities",
                "automated": True,
                "critical": True,
            },
            {
                "step": 4,
                "name": "Identify Spread",
                "action": "hunt_iocs",
                "description": "Search for IOCs across all systems",
                "automated": True,
                "critical": True,
            },
            {
                "step": 5,
                "name": "Block C2",
                "action": "block_indicators",
                "description": "Block C2 domains and IPs at perimeter",
                "automated": True,
                "critical": True,
            },
            {
                "step": 6,
                "name": "Clean Systems",
                "action": "remediate",
                "description": "Remove malware from all infected systems",
                "automated": False,
                "critical": True,
            },
        ],
    },
    "unauthorized_access": {
        "name": "Unauthorized Access Response Playbook",
        "description": "Response procedure for unauthorized access incidents",
        "version": "1.2",
        "steps": [
            {
                "step": 1,
                "name": "Disable Account",
                "action": "account_disable",
                "description": "Disable compromised account immediately",
                "automated": True,
                "critical": True,
            },
            {
                "step": 2,
                "name": "Review Access Logs",
                "action": "log_analysis",
                "description": "Review all access logs for compromised account",
                "automated": True,
                "critical": True,
            },
            {
                "step": 3,
                "name": "Identify Accessed Data",
                "action": "data_audit",
                "description": "Determine what data was accessed",
                "automated": False,
                "critical": True,
            },
            {
                "step": 4,
                "name": "Check for Persistence",
                "action": "hunt_persistence",
                "description": "Look for backdoors or persistence mechanisms",
                "automated": True,
                "critical": True,
            },
            {
                "step": 5,
                "name": "Reset Credentials",
                "action": "credential_reset",
                "description": "Reset passwords and revoke tokens",
                "automated": True,
                "critical": True,
            },
            {
                "step": 6,
                "name": "Enable MFA",
                "action": "enforce_mfa",
                "description": "Enable or re-enroll MFA for affected accounts",
                "automated": False,
                "critical": False,
            },
        ],
    },
    "data_breach": {
        "name": "Data Breach Response Playbook",
        "description": "Response procedure for data breach incidents",
        "version": "2.1",
        "steps": [
            {
                "step": 1,
                "name": "Contain Breach",
                "action": "containment",
                "description": "Stop ongoing data exfiltration",
                "automated": True,
                "critical": True,
            },
            {
                "step": 2,
                "name": "Assess Scope",
                "action": "scope_assessment",
                "description": "Determine what data was compromised",
                "automated": False,
                "critical": True,
            },
            {
                "step": 3,
                "name": "Preserve Evidence",
                "action": "forensic_collection",
                "description": "Collect forensic evidence for investigation",
                "automated": True,
                "critical": True,
            },
            {
                "step": 4,
                "name": "Legal Notification",
                "action": "legal_review",
                "description": "Engage legal team for breach notification requirements",
                "automated": False,
                "critical": True,
            },
            {
                "step": 5,
                "name": "Regulatory Filing",
                "action": "regulatory_notification",
                "description": "File required regulatory notifications (GDPR: 72 hours)",
                "automated": False,
                "critical": True,
            },
            {
                "step": 6,
                "name": "Customer Notification",
                "action": "customer_notification",
                "description": "Notify affected customers per legal requirements",
                "automated": False,
                "critical": True,
            },
        ],
    },
}


async def execute_playbook(
    playbook_name: str,
    incident_context: dict[str, Any] | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Execute an incident response playbook.
    
    Args:
        playbook_name: Name of the playbook to execute.
        incident_context: Context data for execution.
        dry_run: If True, simulate without making changes.
        
    Returns:
        dict: Execution results with step statuses.
    """
    incident_context = incident_context or {}
    
    # Find playbook
    playbook = PLAYBOOKS.get(playbook_name)
    if not playbook:
        # Try partial match
        for name, pb in PLAYBOOKS.items():
            if playbook_name.lower() in name.lower():
                playbook = pb
                playbook_name = name
                break
    
    if not playbook:
        return {
            "success": False,
            "error": f"Playbook '{playbook_name}' not found",
            "available_playbooks": list(PLAYBOOKS.keys()),
        }
    
    execution_id = f"EXEC-{str(uuid4())[:8].upper()}"
    
    # Execute steps
    step_results = []
    overall_success = True
    
    for step in playbook["steps"]:
        step_result = {
            "step": step["step"],
            "name": step["name"],
            "action": step["action"],
            "status": "pending",
            "automated": step["automated"],
            "critical": step["critical"],
        }
        
        if dry_run:
            step_result["status"] = "simulated"
            step_result["message"] = f"[DRY RUN] Would execute: {step['description']}"
        else:
            # Simulate execution
            if step["automated"]:
                step_result["status"] = "completed"
                step_result["message"] = f"Executed: {step['description']}"
                step_result["execution_time"] = "2.3s"
            else:
                step_result["status"] = "requires_manual"
                step_result["message"] = f"Manual action required: {step['description']}"
        
        step_results.append(step_result)
    
    # Calculate completion metrics
    completed = sum(1 for s in step_results if s["status"] == "completed")
    simulated = sum(1 for s in step_results if s["status"] == "simulated")
    manual = sum(1 for s in step_results if s["status"] == "requires_manual")
    
    return {
        "success": True,
        "execution_id": execution_id,
        "timestamp": datetime.now().isoformat(),
        "playbook": {
            "name": playbook["name"],
            "version": playbook["version"],
            "description": playbook["description"],
        },
        "dry_run": dry_run,
        "context": incident_context,
        "execution_summary": {
            "total_steps": len(playbook["steps"]),
            "completed": completed if not dry_run else 0,
            "simulated": simulated,
            "requires_manual": manual,
        },
        "step_results": step_results,
        "next_actions": _get_next_actions(step_results),
    }


def _get_next_actions(step_results: list[dict[str, Any]]) -> list[str]:
    """Get recommended next actions based on execution results."""
    actions = []
    
    manual_steps = [s for s in step_results if s["status"] == "requires_manual"]
    for step in manual_steps[:3]:  # Top 3 manual actions
        actions.append(f"Complete manual step: {step['name']}")
    
    if manual_steps:
        actions.append("Document completion of manual steps in incident ticket")
    
    actions.append("Review playbook execution results and validate success")
    
    return actions
