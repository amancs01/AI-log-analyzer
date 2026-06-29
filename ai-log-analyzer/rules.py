# Detection rules for AI Log Analyzer

suspicious_rules = {
    "failed login": {
        "severity": "MEDIUM",
        "category": "Authentication"
    },
    "failed": {
        "severity": "LOW",
        "category": "General Failure"
    },
    "unauthorized": {
        "severity": "HIGH",
        "category": "Access Control"
    },
    "brute force": {
        "severity": "HIGH",
        "category": "Authentication Attack"
    },
    "port scan": {
        "severity": "HIGH",
        "category": "Network Reconnaissance"
    },
    "malware": {
        "severity": "HIGH",
        "category": "Malware"
    },
    "suspicious": {
        "severity": "MEDIUM",
        "category": "Suspicious Activity"
    },
    "unknown device": {
        "severity": "MEDIUM",
        "category": "Device Security"
    },
    "data exfiltration": {
        "severity": "HIGH",
        "category": "Data Loss"
    },
    "high risk": {
        "severity": "HIGH",
        "category": "High Risk Activity"
    },
    "attack": {
        "severity": "HIGH",
        "category": "Attack Indicator"
    },
    "blocked": {
        "severity": "MEDIUM",
        "category": "Blocked Request"
    },
    "root login": {
        "severity": "HIGH",
        "category": "Privileged Access"
    }
}