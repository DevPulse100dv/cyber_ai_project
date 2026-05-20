"""
Log Analysis Tool.

Parses and analyzes security logs to identify suspicious activities,
authentication issues, and potential security events.
"""

import re
from datetime import datetime
from typing import Any


# Log patterns for different log types
LOG_PATTERNS = {
    "syslog": {
        "timestamp": r"^(\w+\s+\d+\s+\d+:\d+:\d+)",
        "hostname": r"^\w+\s+\d+\s+\d+:\d+:\d+\s+(\S+)",
        "process": r"^\w+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+(\S+?)(?:\[|:)",
    },
    "auth": {
        "failed_login": r"(Failed password|authentication failure|invalid user)",
        "successful_login": r"(Accepted password|Accepted publickey|session opened)",
        "sudo": r"(sudo:|COMMAND=)",
        "user_change": r"(useradd|userdel|usermod|passwd)",
    },
    "web": {
        "status_code": r'\s(\d{3})\s',
        "method": r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)',
        "sql_injection": r"(union\s+select|or\s+1=1|;\s*drop|--\s*$|/\*.*\*/)",
        "path_traversal": r"(\.\./|\.\.\\|%2e%2e)",
        "xss": r"(<script|javascript:|onerror=|onload=)",
    },
    "firewall": {
        "blocked": r"(BLOCK|DROP|DENY|REJECT)",
        "allowed": r"(ALLOW|ACCEPT|PERMIT)",
        "port": r"DPT=(\d+)|dst_port=(\d+)|port\s+(\d+)",
    },
}

# Suspicious patterns across all log types
SUSPICIOUS_PATTERNS = [
    {
        "name": "failed_auth_burst",
        "pattern": r"(Failed password|authentication failure)",
        "severity": "medium",
        "description": "Authentication failure detected",
        "mitre": "T1110 - Brute Force",
    },
    {
        "name": "privilege_escalation",
        "pattern": r"(sudo|su\s+-|privilege|escalat|root)",
        "severity": "high",
        "description": "Potential privilege escalation attempt",
        "mitre": "T1548 - Abuse Elevation Control Mechanism",
    },
    {
        "name": "suspicious_command",
        "pattern": r"(wget|curl|nc\s+-|netcat|bash\s+-i|/dev/tcp|reverse.?shell)",
        "severity": "critical",
        "description": "Suspicious command execution detected",
        "mitre": "T1059 - Command and Scripting Interpreter",
    },
    {
        "name": "data_access",
        "pattern": r"(SELECT.*FROM|INSERT INTO|UPDATE.*SET|DELETE FROM|/etc/passwd|/etc/shadow)",
        "severity": "high",
        "description": "Sensitive data access attempt",
        "mitre": "T1005 - Data from Local System",
    },
    {
        "name": "lateral_movement",
        "pattern": r"(ssh\s+|rdp|psexec|wmiexec|smbclient)",
        "severity": "high",
        "description": "Potential lateral movement activity",
        "mitre": "T1021 - Remote Services",
    },
    {
        "name": "persistence",
        "pattern": r"(crontab|systemctl\s+enable|registry.*run|autostart|scheduled.?task)",
        "severity": "high",
        "description": "Potential persistence mechanism",
        "mitre": "T1053 - Scheduled Task/Job",
    },
    {
        "name": "defense_evasion",
        "pattern": r"(iptables\s+-F|setenforce\s+0|disable.*firewall|clear.*log|rm.*\.log)",
        "severity": "critical",
        "description": "Defense evasion attempt detected",
        "mitre": "T1562 - Impair Defenses",
    },
]


async def analyze_logs(
    log_content: str,
    log_type: str = "generic",
    focus_areas: list[str] | None = None,
) -> dict[str, Any]:
    """
    Analyze security logs for suspicious activities.
    
    Args:
        log_content: Log content to analyze.
        log_type: Type of log ('syslog', 'auth', 'web', 'firewall', 'windows_event', 'generic').
        focus_areas: Specific areas to focus analysis on.
        
    Returns:
        dict: Analysis results with findings and statistics.
    """
    focus_areas = focus_areas or []
    findings = []
    events = []
    statistics = {
        "total_lines": 0,
        "error_count": 0,
        "warning_count": 0,
        "auth_failures": 0,
        "auth_successes": 0,
        "unique_ips": set(),
        "unique_users": set(),
    }
    
    lines = log_content.strip().split("\n")
    statistics["total_lines"] = len(lines)
    
    # Track patterns for burst detection
    auth_failure_times = []
    ip_access_count: dict[str, int] = {}
    user_failure_count: dict[str, int] = {}
    
    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()
        
        # Count errors and warnings
        if re.search(r"\b(error|err)\b", line_lower):
            statistics["error_count"] += 1
        if re.search(r"\b(warn|warning)\b", line_lower):
            statistics["warning_count"] += 1
        
        # Extract IPs
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        statistics["unique_ips"].update(ips)
        for ip in ips:
            ip_access_count[ip] = ip_access_count.get(ip, 0) + 1
        
        # Extract usernames (common patterns)
        user_matches = re.findall(r"user[=:\s]+(\S+)|for\s+(?:user\s+)?(\S+)", line_lower)
        for match in user_matches:
            user = match[0] or match[1]
            if user and len(user) < 32:  # Reasonable username length
                statistics["unique_users"].add(user)
        
        # Auth-specific analysis
        if log_type in ["auth", "generic"]:
            if re.search(r"Failed password|authentication failure", line, re.IGNORECASE):
                statistics["auth_failures"] += 1
                auth_failure_times.append(line_num)
                
                # Extract failed user
                user_match = re.search(r"for (?:invalid user |user )?(\S+)", line)
                if user_match:
                    user = user_match.group(1)
                    user_failure_count[user] = user_failure_count.get(user, 0) + 1
            
            if re.search(r"Accepted password|Accepted publickey|session opened", line, re.IGNORECASE):
                statistics["auth_successes"] += 1
        
        # Check suspicious patterns
        for pattern_info in SUSPICIOUS_PATTERNS:
            # Apply focus area filter if specified
            if focus_areas:
                if not any(area in pattern_info["name"] for area in focus_areas):
                    continue
            
            if re.search(pattern_info["pattern"], line, re.IGNORECASE):
                finding = {
                    "type": pattern_info["name"],
                    "severity": pattern_info["severity"],
                    "description": pattern_info["description"],
                    "line_number": line_num,
                    "evidence": line[:300],
                    "mitre_technique": pattern_info["mitre"],
                }
                findings.append(finding)
                
                events.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": pattern_info["name"],
                    "severity": pattern_info["severity"],
                    "line": line_num,
                })
    
    # Detect patterns: auth failure bursts
    if len(auth_failure_times) >= 5:
        findings.append({
            "type": "brute_force_detected",
            "severity": "high",
            "description": f"Multiple authentication failures detected: {len(auth_failure_times)} failures",
            "evidence": f"Failures at lines: {auth_failure_times[:10]}",
            "mitre_technique": "T1110 - Brute Force",
        })
    
    # Detect targeted user attacks
    for user, count in user_failure_count.items():
        if count >= 5:
            findings.append({
                "type": "targeted_auth_attack",
                "severity": "high",
                "description": f"Targeted authentication attack on user: {user}",
                "evidence": f"{count} failed attempts for user {user}",
                "mitre_technique": "T1110.001 - Password Guessing",
            })
    
    # Detect distributed attacks from IPs
    for ip, count in ip_access_count.items():
        if count >= 20:
            findings.append({
                "type": "high_volume_source",
                "severity": "medium",
                "description": f"High volume of activity from single source",
                "evidence": f"IP {ip}: {count} entries",
                "mitre_technique": "T1046 - Network Service Discovery",
            })
    
    # Convert sets to lists
    statistics["unique_ips"] = list(statistics["unique_ips"])[:20]
    statistics["unique_users"] = list(statistics["unique_users"])[:20]
    
    # Deduplicate findings by type
    unique_findings = []
    seen_types = set()
    for f in findings:
        key = (f["type"], f.get("severity"))
        if key not in seen_types:
            seen_types.add(key)
            unique_findings.append(f)
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique_findings.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))
    
    return {
        "log_type": log_type,
        "focus_areas": focus_areas,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_lines_analyzed": statistics["total_lines"],
            "total_findings": len(unique_findings),
            "critical_findings": sum(1 for f in unique_findings if f.get("severity") == "critical"),
            "high_findings": sum(1 for f in unique_findings if f.get("severity") == "high"),
        },
        "statistics": statistics,
        "findings": unique_findings[:30],
        "events": events[:50],
        "recommendations": _generate_log_recommendations(unique_findings, statistics),
    }


def _generate_log_recommendations(
    findings: list[dict[str, Any]],
    statistics: dict[str, Any],
) -> list[str]:
    """Generate recommendations based on log analysis."""
    recommendations = []
    
    finding_types = set(f.get("type") for f in findings)
    
    if "brute_force_detected" in finding_types or "targeted_auth_attack" in finding_types:
        recommendations.extend([
            "Implement account lockout policies",
            "Enable multi-factor authentication",
            "Consider blocking source IPs at firewall",
            "Review and rotate passwords for targeted accounts",
        ])
    
    if "suspicious_command" in finding_types:
        recommendations.extend([
            "CRITICAL: Investigate affected systems immediately",
            "Check for reverse shell connections or backdoors",
            "Isolate potentially compromised systems",
        ])
    
    if "privilege_escalation" in finding_types:
        recommendations.extend([
            "Audit sudo and privileged access",
            "Review user permissions and group memberships",
            "Enable command logging for privileged accounts",
        ])
    
    if "defense_evasion" in finding_types:
        recommendations.extend([
            "Restore security controls immediately",
            "Verify log integrity and enable tamper protection",
            "Review all recent configuration changes",
        ])
    
    if statistics.get("auth_failures", 0) > 10:
        recommendations.append(
            f"High number of authentication failures ({statistics['auth_failures']}) - "
            "review authentication logs and consider rate limiting"
        )
    
    if not recommendations:
        recommendations.append("No immediate concerns - continue regular monitoring")
    
    return recommendations
