"""
Threat Containment Tool.

Executes containment actions to limit the scope and impact
of security incidents.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4


# Containment action definitions
CONTAINMENT_ACTIONS = {
    "network_isolation": {
        "name": "Network Isolation",
        "description": "Isolate system from network while maintaining management access",
        "risk_level": "medium",
        "reversible": True,
        "commands": [
            "Block all inbound/outbound traffic except management",
            "Move to quarantine VLAN",
            "Update firewall rules",
        ],
    },
    "account_disable": {
        "name": "Account Disable",
        "description": "Disable user or service account",
        "risk_level": "low",
        "reversible": True,
        "commands": [
            "Disable account in directory service",
            "Revoke active sessions",
            "Invalidate tokens and API keys",
        ],
    },
    "process_kill": {
        "name": "Process Termination",
        "description": "Terminate malicious processes",
        "risk_level": "low",
        "reversible": False,
        "commands": [
            "Identify process ID",
            "Terminate process and child processes",
            "Block process from restarting",
        ],
    },
    "firewall_block": {
        "name": "Firewall Block",
        "description": "Block IP address or domain at firewall",
        "risk_level": "low",
        "reversible": True,
        "commands": [
            "Add IP/domain to blocklist",
            "Update firewall policy",
            "Verify block is active",
        ],
    },
    "quarantine": {
        "name": "File Quarantine",
        "description": "Quarantine suspicious files",
        "risk_level": "low",
        "reversible": True,
        "commands": [
            "Move file to quarantine location",
            "Hash file for tracking",
            "Log original location",
        ],
    },
}


async def contain_threat(
    containment_type: str,
    target: str,
    reason: str,
    duration: str = "24h",
) -> dict[str, Any]:
    """
    Execute a containment action.
    
    Args:
        containment_type: Type of containment action.
        target: Target of containment (IP, hostname, username, etc.).
        reason: Reason for containment.
        duration: Duration of containment.
        
    Returns:
        dict: Containment action results.
    """
    # Validate containment type
    if containment_type not in CONTAINMENT_ACTIONS:
        return {
            "success": False,
            "error": f"Unknown containment type: {containment_type}",
            "available_types": list(CONTAINMENT_ACTIONS.keys()),
        }
    
    action = CONTAINMENT_ACTIONS[containment_type]
    action_id = f"CONT-{str(uuid4())[:8].upper()}"
    
    # Parse duration
    expiry = _calculate_expiry(duration)
    
    # Simulate containment execution
    execution_log = []
    success = True
    
    for i, command in enumerate(action["commands"], 1):
        execution_log.append({
            "step": i,
            "command": command,
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
        })
    
    # Create containment record
    containment_record = {
        "action_id": action_id,
        "timestamp": datetime.now().isoformat(),
        "containment_type": containment_type,
        "action_name": action["name"],
        "target": target,
        "reason": reason,
        "duration": duration,
        "expiry": expiry.isoformat() if expiry else "permanent",
        "reversible": action["reversible"],
        "risk_level": action["risk_level"],
    }
    
    return {
        "success": success,
        "action_id": action_id,
        "timestamp": datetime.now().isoformat(),
        "containment_details": containment_record,
        "execution_log": execution_log,
        "next_steps": _generate_containment_next_steps(containment_type, target),
        "rollback_available": action["reversible"],
        "rollback_instructions": _get_rollback_instructions(containment_type) if action["reversible"] else None,
    }


def _calculate_expiry(duration: str) -> datetime | None:
    """Calculate expiry time from duration string."""
    if duration.lower() in ["permanent", "indefinite"]:
        return None
    
    try:
        if duration.endswith("m"):
            minutes = int(duration[:-1])
            return datetime.now() + timedelta(minutes=minutes)
        elif duration.endswith("h"):
            hours = int(duration[:-1])
            return datetime.now() + timedelta(hours=hours)
        elif duration.endswith("d"):
            days = int(duration[:-1])
            return datetime.now() + timedelta(days=days)
        else:
            # Default to 24 hours if parsing fails
            return datetime.now() + timedelta(hours=24)
    except ValueError:
        return datetime.now() + timedelta(hours=24)


def _generate_containment_next_steps(containment_type: str, target: str) -> list[str]:
    """Generate next steps after containment."""
    steps = [
        f"Document containment action for {target} in incident ticket",
        "Notify affected stakeholders of containment status",
    ]
    
    type_specific = {
        "network_isolation": [
            "Verify system can still be accessed for investigation",
            "Monitor for attempts to bypass isolation",
            "Schedule system for forensic analysis",
        ],
        "account_disable": [
            "Review account activity prior to disabling",
            "Check for associated service accounts",
            "Prepare credential reset for when account is re-enabled",
        ],
        "process_kill": [
            "Verify process has not restarted",
            "Check for parent process or scheduled tasks",
            "Collect process memory dump if not already done",
        ],
        "firewall_block": [
            "Verify block is effective",
            "Monitor for connections from similar IPs/domains",
            "Add to permanent blocklist if confirmed malicious",
        ],
        "quarantine": [
            "Submit quarantined file for analysis",
            "Check for copies elsewhere on system",
            "Update endpoint protection signatures",
        ],
    }
    
    steps.extend(type_specific.get(containment_type, []))
    return steps


def _get_rollback_instructions(containment_type: str) -> dict[str, Any]:
    """Get rollback instructions for reversible containment."""
    instructions = {
        "network_isolation": {
            "procedure": "Re-enable network access",
            "steps": [
                "Verify threat has been eradicated",
                "Remove firewall rules blocking traffic",
                "Move system back to production VLAN",
                "Verify connectivity and services",
            ],
            "approval_required": True,
        },
        "account_disable": {
            "procedure": "Re-enable account",
            "steps": [
                "Verify account was not compromised",
                "Reset account password",
                "Re-enable account in directory",
                "Verify user can authenticate",
            ],
            "approval_required": True,
        },
        "firewall_block": {
            "procedure": "Remove firewall block",
            "steps": [
                "Verify traffic is legitimate",
                "Remove from blocklist",
                "Update firewall policy",
                "Monitor for any malicious activity",
            ],
            "approval_required": False,
        },
        "quarantine": {
            "procedure": "Restore quarantined file",
            "steps": [
                "Verify file is not malicious",
                "Restore file to original location",
                "Verify file integrity",
                "Document restoration",
            ],
            "approval_required": False,
        },
    }
    
    return instructions.get(containment_type, {
        "procedure": "Contact security team for rollback",
        "steps": ["Manual rollback required"],
        "approval_required": True,
    })
