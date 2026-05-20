"""
Network Traffic Analysis Tool.

Analyzes network traffic data for anomalies, suspicious patterns,
and potential security threats.
"""

import re
from datetime import datetime
from typing import Any


# Simulated threat signatures for demo purposes
THREAT_SIGNATURES = {
    "port_scan": {
        "pattern": r"(SYN|scan|probe)",
        "severity": "medium",
        "description": "Potential port scanning activity detected",
    },
    "c2_communication": {
        "pattern": r"(beacon|callback|c2|command.?and.?control)",
        "severity": "critical",
        "description": "Possible Command and Control communication",
    },
    "data_exfiltration": {
        "pattern": r"(exfil|large.?upload|unusual.?outbound)",
        "severity": "high",
        "description": "Potential data exfiltration detected",
    },
    "dns_tunneling": {
        "pattern": r"(dns.?tunnel|long.?subdomain|encoded.?dns)",
        "severity": "high",
        "description": "Possible DNS tunneling activity",
    },
    "brute_force": {
        "pattern": r"(brute|multiple.?failed|repeated.?attempt)",
        "severity": "medium",
        "description": "Brute force attack pattern detected",
    },
}

# Known malicious IP ranges (simulated)
MALICIOUS_IP_RANGES = [
    "192.168.100.",  # Simulated malicious range
    "10.99.99.",     # Simulated malicious range
]

# Suspicious ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 31337, 12345, 54321]


async def analyze_network_traffic(
    traffic_data: str,
    analysis_type: str = "full",
    time_window: str = "1h",
) -> dict[str, Any]:
    """
    Analyze network traffic for security threats.
    
    Args:
        traffic_data: Network traffic data to analyze.
        analysis_type: Type of analysis ('full', 'anomaly', 'signature', 'behavioral').
        time_window: Time window for analysis.
        
    Returns:
        dict: Analysis results including findings and recommendations.
    """
    findings = []
    alerts = []
    statistics = {
        "total_connections": 0,
        "unique_ips": set(),
        "unique_ports": set(),
        "protocols": {},
    }
    
    # Parse traffic data (simplified for demo)
    lines = traffic_data.strip().split("\n")
    statistics["total_connections"] = len(lines)
    
    for line in lines:
        line_lower = line.lower()
        
        # Check for signature matches
        if analysis_type in ["full", "signature"]:
            for sig_name, sig_info in THREAT_SIGNATURES.items():
                if re.search(sig_info["pattern"], line_lower, re.IGNORECASE):
                    finding = {
                        "type": "signature_match",
                        "signature": sig_name,
                        "severity": sig_info["severity"],
                        "description": sig_info["description"],
                        "evidence": line[:200],
                        "mitre_technique": _get_mitre_technique(sig_name),
                    }
                    findings.append(finding)
                    
                    if sig_info["severity"] in ["critical", "high"]:
                        alerts.append({
                            "title": sig_info["description"],
                            "severity": sig_info["severity"],
                            "details": finding,
                        })
        
        # Check for malicious IPs
        for mal_range in MALICIOUS_IP_RANGES:
            if mal_range in line:
                findings.append({
                    "type": "malicious_ip",
                    "severity": "high",
                    "description": f"Connection to known malicious IP range: {mal_range}*",
                    "evidence": line[:200],
                    "mitre_technique": "T1071 - Application Layer Protocol",
                })
        
        # Check for suspicious ports
        for port in SUSPICIOUS_PORTS:
            if str(port) in line:
                findings.append({
                    "type": "suspicious_port",
                    "severity": "medium",
                    "description": f"Traffic on suspicious port: {port}",
                    "evidence": line[:200],
                    "mitre_technique": "T1571 - Non-Standard Port",
                })
        
        # Extract IPs and ports for statistics
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        port_pattern = r":(\d+)"
        
        ips = re.findall(ip_pattern, line)
        ports = re.findall(port_pattern, line)
        
        statistics["unique_ips"].update(ips)
        statistics["unique_ports"].update(ports)
    
    # Anomaly detection for analysis_type 'anomaly' or 'full'
    if analysis_type in ["full", "anomaly"]:
        # Check for unusual patterns
        if len(statistics["unique_ips"]) > 100:
            findings.append({
                "type": "anomaly",
                "severity": "low",
                "description": "High number of unique IPs detected - potential scan or distributed activity",
                "evidence": f"Unique IPs: {len(statistics['unique_ips'])}",
            })
        
        if len(statistics["unique_ports"]) > 50:
            findings.append({
                "type": "anomaly", 
                "severity": "medium",
                "description": "High number of unique ports - potential port scan",
                "evidence": f"Unique ports: {len(statistics['unique_ports'])}",
            })
    
    # Convert sets to lists for JSON serialization
    statistics["unique_ips"] = list(statistics["unique_ips"])[:20]  # Limit output
    statistics["unique_ports"] = list(statistics["unique_ports"])[:20]
    
    # Deduplicate findings
    unique_findings = []
    seen = set()
    for f in findings:
        key = (f["type"], f.get("signature", ""), f.get("severity", ""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    # Generate summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in unique_findings:
        sev = f.get("severity", "low")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    return {
        "analysis_type": analysis_type,
        "time_window": time_window,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_findings": len(unique_findings),
            "severity_breakdown": severity_counts,
            "total_alerts": len(alerts),
        },
        "statistics": statistics,
        "findings": unique_findings[:50],  # Limit to top 50
        "alerts": alerts,
        "recommendations": _generate_recommendations(unique_findings),
    }


def _get_mitre_technique(signature_name: str) -> str:
    """Map signature to MITRE ATT&CK technique."""
    mapping = {
        "port_scan": "T1046 - Network Service Discovery",
        "c2_communication": "T1071 - Application Layer Protocol",
        "data_exfiltration": "T1048 - Exfiltration Over Alternative Protocol",
        "dns_tunneling": "T1071.004 - DNS",
        "brute_force": "T1110 - Brute Force",
    }
    return mapping.get(signature_name, "Unknown")


def _generate_recommendations(findings: list[dict[str, Any]]) -> list[str]:
    """Generate recommendations based on findings."""
    recommendations = []
    
    has_critical = any(f.get("severity") == "critical" for f in findings)
    has_high = any(f.get("severity") == "high" for f in findings)
    
    if has_critical:
        recommendations.extend([
            "IMMEDIATE: Isolate affected systems from the network",
            "Engage incident response team immediately",
            "Preserve all logs and evidence for forensic analysis",
        ])
    
    if has_high:
        recommendations.extend([
            "Block identified malicious IPs at the firewall",
            "Review and validate all outbound connections",
            "Enable enhanced logging on affected systems",
        ])
    
    finding_types = set(f.get("type") for f in findings)
    
    if "malicious_ip" in finding_types:
        recommendations.append("Update threat intelligence feeds and block listed IPs")
    
    if "suspicious_port" in finding_types:
        recommendations.append("Review firewall rules to restrict unnecessary ports")
    
    if "signature_match" in finding_types:
        recommendations.append("Update IDS/IPS signatures and verify detection coverage")
    
    if not recommendations:
        recommendations.append("No immediate action required - continue monitoring")
    
    return recommendations
