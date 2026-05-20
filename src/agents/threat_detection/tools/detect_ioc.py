"""
Indicators of Compromise (IOC) Detection Tool.

Scans data for known malicious indicators including IPs, domains,
file hashes, URLs, and patterns associated with known threats.
"""

import hashlib
import re
from datetime import datetime
from typing import Any


# Simulated threat intelligence feeds (in production, these would be fetched from real feeds)
KNOWN_MALICIOUS_IPS = {
    "185.220.101.1": {"threat": "Tor Exit Node", "confidence": "high"},
    "45.33.32.156": {"threat": "Known Scanner", "confidence": "medium"},
    "192.168.100.100": {"threat": "Simulated C2 Server", "confidence": "high"},
    "10.99.99.99": {"threat": "Test Malicious IP", "confidence": "high"},
    "203.0.113.100": {"threat": "Phishing Infrastructure", "confidence": "high"},
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware.example.com": {"threat": "Malware Distribution", "category": "malware"},
    "phishing-site.example.net": {"threat": "Phishing", "category": "phishing"},
    "c2-server.bad-domain.com": {"threat": "C2 Server", "category": "c2"},
    "cryptominer.evil.io": {"threat": "Cryptominer", "category": "mining"},
    "ransomware-payment.onion": {"threat": "Ransomware", "category": "ransomware"},
}

KNOWN_MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": {"threat": "Empty File (Suspicious)", "family": "unknown"},
    "5d41402abc4b2a76b9719d911017c592": {"threat": "Test Malware Hash", "family": "test"},
    "098f6bcd4621d373cade4e832627b4f6": {"threat": "Known Malicious Hash", "family": "generic"},
    "e99a18c428cb38d5f260853678922e03": {"threat": "Ransomware Sample", "family": "lockbit"},
}

MALICIOUS_URL_PATTERNS = [
    {"pattern": r"bit\.ly/[a-zA-Z0-9]+", "threat": "Shortened URL (potential phishing)"},
    {"pattern": r"\.exe\?", "threat": "Executable download via URL parameter"},
    {"pattern": r"\.zip\.exe", "threat": "Double extension executable"},
    {"pattern": r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[a-z]+\.exe", "threat": "Direct IP executable download"},
    {"pattern": r"\.tk/|\.ml/|\.ga/|\.cf/", "threat": "Free TLD (often abused)"},
]

SUSPICIOUS_EMAIL_PATTERNS = [
    {"pattern": r"@temp-mail\.", "threat": "Temporary email service"},
    {"pattern": r"@guerrillamail\.", "threat": "Disposable email"},
    {"pattern": r"\+.*@.*\.com", "threat": "Plus addressing (potential enumeration)"},
]


async def detect_ioc(
    data: str,
    ioc_types: list[str] | None = None,
    threat_feeds: list[str] | None = None,
) -> dict[str, Any]:
    """
    Scan data for Indicators of Compromise.
    
    Args:
        data: Data to scan for IOCs.
        ioc_types: Types of IOCs to look for ('ip', 'domain', 'hash', 'url', 'email', 'all').
        threat_feeds: Specific threat feeds to check against.
        
    Returns:
        dict: Detection results with matched IOCs and threat information.
    """
    ioc_types = ioc_types or ["all"]
    if "all" in ioc_types:
        ioc_types = ["ip", "domain", "hash", "url", "email"]
    
    detections = []
    statistics = {
        "data_size": len(data),
        "iocs_checked": 0,
        "matches_found": 0,
    }
    
    # Extract and check IPs
    if "ip" in ioc_types:
        ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ips = set(re.findall(ip_pattern, data))
        statistics["iocs_checked"] += len(ips)
        
        for ip in ips:
            if ip in KNOWN_MALICIOUS_IPS:
                info = KNOWN_MALICIOUS_IPS[ip]
                detections.append({
                    "type": "ip",
                    "ioc": ip,
                    "threat": info["threat"],
                    "confidence": info["confidence"],
                    "severity": "high" if info["confidence"] == "high" else "medium",
                    "recommendation": f"Block IP {ip} at firewall and investigate any connections",
                })
            
            # Check for suspicious IP patterns
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                # Private IP - context dependent
                pass
            elif ip.startswith("0.") or ip.startswith("127."):
                # Localhost/invalid - might be evasion
                detections.append({
                    "type": "ip",
                    "ioc": ip,
                    "threat": "Suspicious localhost/null IP reference",
                    "confidence": "low",
                    "severity": "low",
                    "recommendation": "Review context - may indicate evasion technique",
                })
    
    # Extract and check domains
    if "domain" in ioc_types:
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        domains = set(re.findall(domain_pattern, data.lower()))
        statistics["iocs_checked"] += len(domains)
        
        for domain in domains:
            if domain in KNOWN_MALICIOUS_DOMAINS:
                info = KNOWN_MALICIOUS_DOMAINS[domain]
                detections.append({
                    "type": "domain",
                    "ioc": domain,
                    "threat": info["threat"],
                    "category": info["category"],
                    "severity": "critical" if info["category"] in ["c2", "ransomware"] else "high",
                    "recommendation": f"Block domain {domain} in DNS and proxy",
                })
            
            # Check for suspicious domain patterns
            if ".onion" in domain or ".i2p" in domain:
                detections.append({
                    "type": "domain",
                    "ioc": domain,
                    "threat": "Dark web domain reference",
                    "category": "darkweb",
                    "severity": "high",
                    "recommendation": "Investigate dark web communication attempts",
                })
            
            # DGA-like domains (random looking)
            if _looks_like_dga(domain):
                detections.append({
                    "type": "domain",
                    "ioc": domain,
                    "threat": "Possible DGA (Domain Generation Algorithm) domain",
                    "category": "dga",
                    "severity": "medium",
                    "recommendation": "May indicate malware using DGA for C2",
                })
    
    # Extract and check hashes
    if "hash" in ioc_types:
        # MD5
        md5_pattern = r"\b[a-fA-F0-9]{32}\b"
        md5_hashes = set(re.findall(md5_pattern, data.lower()))
        
        # SHA1
        sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
        sha1_hashes = set(re.findall(sha1_pattern, data.lower()))
        
        # SHA256
        sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
        sha256_hashes = set(re.findall(sha256_pattern, data.lower()))
        
        all_hashes = md5_hashes | sha1_hashes | sha256_hashes
        statistics["iocs_checked"] += len(all_hashes)
        
        for hash_val in all_hashes:
            if hash_val in KNOWN_MALICIOUS_HASHES:
                info = KNOWN_MALICIOUS_HASHES[hash_val]
                detections.append({
                    "type": "hash",
                    "ioc": hash_val,
                    "hash_type": "md5" if len(hash_val) == 32 else "sha1" if len(hash_val) == 40 else "sha256",
                    "threat": info["threat"],
                    "malware_family": info["family"],
                    "severity": "critical",
                    "recommendation": "Isolate affected system and perform forensic analysis",
                })
    
    # Check URLs
    if "url" in ioc_types:
        url_pattern = r"https?://[^\s<>\"'{}|\\^`\[\]]+"
        urls = set(re.findall(url_pattern, data))
        statistics["iocs_checked"] += len(urls)
        
        for url in urls:
            for mal_pattern in MALICIOUS_URL_PATTERNS:
                if re.search(mal_pattern["pattern"], url, re.IGNORECASE):
                    detections.append({
                        "type": "url",
                        "ioc": url[:200],  # Truncate long URLs
                        "threat": mal_pattern["threat"],
                        "severity": "medium",
                        "recommendation": "Block URL and investigate access attempts",
                    })
                    break
    
    # Check emails
    if "email" in ioc_types:
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        emails = set(re.findall(email_pattern, data))
        statistics["iocs_checked"] += len(emails)
        
        for email in emails:
            for sus_pattern in SUSPICIOUS_EMAIL_PATTERNS:
                if re.search(sus_pattern["pattern"], email, re.IGNORECASE):
                    detections.append({
                        "type": "email",
                        "ioc": email,
                        "threat": sus_pattern["threat"],
                        "severity": "low",
                        "recommendation": "Review email origin and associated activity",
                    })
                    break
    
    statistics["matches_found"] = len(detections)
    
    # Deduplicate detections
    unique_detections = []
    seen = set()
    for d in detections:
        key = (d["type"], d["ioc"])
        if key not in seen:
            seen.add(key)
            unique_detections.append(d)
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique_detections.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))
    
    return {
        "timestamp": datetime.now().isoformat(),
        "ioc_types_checked": ioc_types,
        "threat_feeds_used": threat_feeds or ["builtin"],
        "summary": {
            "iocs_analyzed": statistics["iocs_checked"],
            "matches_found": len(unique_detections),
            "critical_matches": sum(1 for d in unique_detections if d.get("severity") == "critical"),
            "high_matches": sum(1 for d in unique_detections if d.get("severity") == "high"),
        },
        "statistics": statistics,
        "detections": unique_detections[:50],
        "recommendations": _generate_ioc_recommendations(unique_detections),
    }


def _looks_like_dga(domain: str) -> bool:
    """
    Check if a domain looks like it was generated by a DGA.
    
    Uses simple heuristics like consonant/vowel ratio and randomness.
    """
    # Get the main part of the domain (before TLD)
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    
    main_part = parts[0]
    
    # Too short or too long
    if len(main_part) < 8 or len(main_part) > 20:
        return False
    
    # Check consonant to vowel ratio
    vowels = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")
    
    vowel_count = sum(1 for c in main_part.lower() if c in vowels)
    consonant_count = sum(1 for c in main_part.lower() if c in consonants)
    
    if consonant_count == 0:
        return False
    
    ratio = vowel_count / (vowel_count + consonant_count) if (vowel_count + consonant_count) > 0 else 0
    
    # Normal English has ~40% vowels, DGA often has very different ratios
    if ratio < 0.1 or ratio > 0.7:
        return True
    
    # Check for digit mixing (common in DGA)
    digit_count = sum(1 for c in main_part if c.isdigit())
    if digit_count > len(main_part) * 0.3:
        return True
    
    return False


def _generate_ioc_recommendations(detections: list[dict[str, Any]]) -> list[str]:
    """Generate recommendations based on IOC detections."""
    recommendations = []
    
    detection_types = set(d.get("type") for d in detections)
    has_critical = any(d.get("severity") == "critical" for d in detections)
    
    if has_critical:
        recommendations.extend([
            "CRITICAL: Immediately isolate affected systems",
            "Engage incident response team",
            "Preserve all logs and evidence",
        ])
    
    if "ip" in detection_types:
        recommendations.append("Update firewall rules to block identified malicious IPs")
    
    if "domain" in detection_types:
        recommendations.append("Update DNS blacklists and proxy rules")
    
    if "hash" in detection_types:
        recommendations.extend([
            "Scan all systems for files matching identified hashes",
            "Update antivirus/EDR signatures",
        ])
    
    if "url" in detection_types:
        recommendations.append("Block identified malicious URLs at web proxy")
    
    if not recommendations:
        recommendations.append("No IOCs detected - data appears clean")
    
    return recommendations
