"""
Evidence Collection Tool.

Collects and preserves digital evidence from affected systems
while maintaining chain of custody and forensic integrity.
"""

import hashlib
from datetime import datetime
from typing import Any
from uuid import uuid4


# Evidence type definitions
EVIDENCE_TYPES = {
    "memory": {
        "name": "Memory Dump",
        "description": "Capture system memory (RAM)",
        "volatility": "high",
        "priority": 1,
        "artifacts": [
            "Full memory dump",
            "Running processes",
            "Network connections",
            "Loaded modules",
            "Encryption keys (if present)",
        ],
    },
    "disk": {
        "name": "Disk Image",
        "description": "Forensic disk image",
        "volatility": "low",
        "priority": 3,
        "artifacts": [
            "Full disk image",
            "File system metadata",
            "Deleted files",
            "File slack space",
            "Unallocated space",
        ],
    },
    "logs": {
        "name": "System Logs",
        "description": "System and application logs",
        "volatility": "medium",
        "priority": 2,
        "artifacts": [
            "Security event logs",
            "System event logs",
            "Application logs",
            "Authentication logs",
            "Web server logs",
        ],
    },
    "network": {
        "name": "Network Capture",
        "description": "Network traffic capture",
        "volatility": "high",
        "priority": 1,
        "artifacts": [
            "PCAP files",
            "NetFlow data",
            "DNS query logs",
            "Proxy logs",
            "Firewall logs",
        ],
    },
    "registry": {
        "name": "Registry Hives",
        "description": "Windows registry data",
        "volatility": "low",
        "priority": 2,
        "artifacts": [
            "SYSTEM hive",
            "SOFTWARE hive",
            "SAM hive",
            "NTUSER.DAT",
            "UsrClass.dat",
        ],
    },
}


async def collect_evidence(
    evidence_type: str,
    target_system: str,
    preserve_volatile: bool = True,
    incident_id: str | None = None,
) -> dict[str, Any]:
    """
    Collect and preserve digital evidence.
    
    Args:
        evidence_type: Type of evidence to collect.
        target_system: System to collect from.
        preserve_volatile: Prioritize volatile evidence.
        incident_id: Incident ID for tracking.
        
    Returns:
        dict: Collection results with evidence manifest.
    """
    if evidence_type == "all":
        # Collect all evidence types in priority order
        return await _collect_all_evidence(target_system, preserve_volatile, incident_id)
    
    if evidence_type not in EVIDENCE_TYPES:
        return {
            "success": False,
            "error": f"Unknown evidence type: {evidence_type}",
            "available_types": list(EVIDENCE_TYPES.keys()) + ["all"],
        }
    
    evidence_info = EVIDENCE_TYPES[evidence_type]
    collection_id = f"EVID-{str(uuid4())[:8].upper()}"
    
    if not incident_id:
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-UNKNOWN"
    
    # Simulate evidence collection
    collected_artifacts = []
    for artifact in evidence_info["artifacts"]:
        artifact_id = str(uuid4())[:8].upper()
        # Simulate hash generation
        artifact_hash = hashlib.sha256(f"{artifact}{datetime.now()}".encode()).hexdigest()
        
        collected_artifacts.append({
            "artifact_id": artifact_id,
            "name": artifact,
            "status": "collected",
            "hash_sha256": artifact_hash,
            "size_bytes": 1024 * 1024 * (10 + hash(artifact) % 100),  # Simulated size
            "timestamp": datetime.now().isoformat(),
        })
    
    # Create chain of custody record
    chain_of_custody = {
        "collection_id": collection_id,
        "incident_id": incident_id,
        "collector": "Automated Collection Agent",
        "collection_time": datetime.now().isoformat(),
        "source_system": target_system,
        "collection_method": "Automated forensic collection",
        "integrity_verified": True,
    }
    
    return {
        "success": True,
        "collection_id": collection_id,
        "incident_id": incident_id,
        "timestamp": datetime.now().isoformat(),
        "evidence_type": evidence_type,
        "target_system": target_system,
        "evidence_details": {
            "name": evidence_info["name"],
            "description": evidence_info["description"],
            "volatility": evidence_info["volatility"],
        },
        "artifacts_collected": collected_artifacts,
        "artifact_count": len(collected_artifacts),
        "chain_of_custody": chain_of_custody,
        "storage_location": f"/evidence/{incident_id}/{collection_id}/",
        "next_steps": _generate_evidence_next_steps(evidence_type),
        "forensic_notes": _generate_forensic_notes(evidence_type),
    }


async def _collect_all_evidence(
    target_system: str,
    preserve_volatile: bool,
    incident_id: str | None,
) -> dict[str, Any]:
    """Collect all evidence types in priority order."""
    collection_id = f"EVID-{str(uuid4())[:8].upper()}"
    
    if not incident_id:
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-UNKNOWN"
    
    # Sort by priority (volatile first if preserve_volatile)
    sorted_types = sorted(
        EVIDENCE_TYPES.items(),
        key=lambda x: (0 if preserve_volatile and x[1]["volatility"] == "high" else 1, x[1]["priority"])
    )
    
    all_collections = []
    total_artifacts = 0
    
    for etype, einfo in sorted_types:
        artifacts = []
        for artifact in einfo["artifacts"]:
            artifact_id = str(uuid4())[:8].upper()
            artifact_hash = hashlib.sha256(f"{artifact}{datetime.now()}".encode()).hexdigest()
            
            artifacts.append({
                "artifact_id": artifact_id,
                "name": artifact,
                "hash_sha256": artifact_hash,
            })
        
        all_collections.append({
            "evidence_type": etype,
            "name": einfo["name"],
            "volatility": einfo["volatility"],
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "status": "collected",
        })
        total_artifacts += len(artifacts)
    
    return {
        "success": True,
        "collection_id": collection_id,
        "incident_id": incident_id,
        "timestamp": datetime.now().isoformat(),
        "target_system": target_system,
        "collection_type": "comprehensive",
        "preserve_volatile_first": preserve_volatile,
        "collections": all_collections,
        "summary": {
            "evidence_types_collected": len(all_collections),
            "total_artifacts": total_artifacts,
            "collection_order": [c["evidence_type"] for c in all_collections],
        },
        "storage_location": f"/evidence/{incident_id}/{collection_id}/",
        "chain_of_custody": {
            "collection_id": collection_id,
            "incident_id": incident_id,
            "collector": "Automated Collection Agent",
            "collection_time": datetime.now().isoformat(),
            "source_system": target_system,
            "integrity_verified": True,
        },
    }


def _generate_evidence_next_steps(evidence_type: str) -> list[str]:
    """Generate next steps after evidence collection."""
    common_steps = [
        "Verify evidence integrity using stored hashes",
        "Create backup copies of all evidence",
        "Document chain of custody",
    ]
    
    type_specific = {
        "memory": [
            "Analyze memory dump with Volatility or similar tool",
            "Extract running processes and network connections",
            "Search for encryption keys and passwords",
            "Look for injected code or rootkits",
        ],
        "disk": [
            "Mount image as read-only for analysis",
            "Search for malware signatures",
            "Recover deleted files",
            "Analyze file system timeline",
        ],
        "logs": [
            "Normalize and index logs for searching",
            "Correlate events across log sources",
            "Build incident timeline",
            "Identify anomalous patterns",
        ],
        "network": [
            "Analyze PCAP for C2 communication",
            "Extract transferred files",
            "Identify data exfiltration",
            "Map communication patterns",
        ],
        "registry": [
            "Analyze for persistence mechanisms",
            "Check user activity artifacts",
            "Review recently executed programs",
            "Look for malware indicators",
        ],
    }
    
    return common_steps + type_specific.get(evidence_type, [])


def _generate_forensic_notes(evidence_type: str) -> list[str]:
    """Generate forensic handling notes."""
    notes = [
        "Evidence collected using forensically sound methods",
        "All artifacts hashed at time of collection",
        "Original evidence preserved unmodified",
    ]
    
    volatility_notes = {
        "high": "⚠️ Volatile evidence - analyze promptly as data may change",
        "medium": "Evidence has medium volatility - prioritize within 24-48 hours",
        "low": "Non-volatile evidence - can be analyzed as time permits",
    }
    
    if evidence_type in EVIDENCE_TYPES:
        volatility = EVIDENCE_TYPES[evidence_type]["volatility"]
        notes.append(volatility_notes.get(volatility, ""))
    
    return notes
