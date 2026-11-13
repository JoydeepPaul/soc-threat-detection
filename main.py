import re
import json
import subprocess
import datetime
from collections import defaultdict

INCIDENTS = []

def trigger_alert(severity, category, source_ip, description, evidence, auto_block=False):
    incident = {
        "timestamp": datetime.datetime.now().isoformat(),
        "severity": severity,
        "category": category,
        "source_ip": source_ip,
        "description": description,
        "evidence": evidence,
        "remediation_action": f"Blocked IP {source_ip}" if auto_block else "Flagged for Tier-1 Analyst Triage"
    }
    INCIDENTS.append(incident)
    print(f"[{severity}] {category} | IP: {source_ip} -> {description}")

    if auto_block and source_ip != "N/A":
        try:
            subprocess.run(["bash", "responder.sh", source_ip, category, severity], check=True)
        except Exception as e:
            print(f"[!] Responder script warning: {e}")

# 1. Analyze Linux Auth Logs (IAM & Brute Force)
def analyze_linux_logs(filepath):
    failed_attempts = defaultdict(int)
    with open(filepath, "r") as f:
        for line in f:
            fail_match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
            if fail_match:
                ip = fail_match.group(1)
                failed_attempts[ip] += 1

            success_match = re.search(r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)", line)
            if success_match:
                user, ip = success_match.groups()
                if failed_attempts[ip] >= 4:
                    trigger_alert(
                        "CRITICAL",
                        "IAM / Brute-Force Compromise (Linux)",
                        ip,
                        f"Successful login as '{user}' after {failed_attempts[ip]} failed attempts.",
                        line.strip(),
                        auto_block=True
                    )

            if "sudo:" in line and "COMMAND=/bin/bash" in line:
                trigger_alert(
                    "HIGH",
                    "Privilege Escalation (Linux)",
                    "Localhost",
                    "Interactive root shell spawned via sudo.",
                    line.strip(),
                    auto_block=False
                )

# 2. Analyze Windows Security Logs (EDR / Active Directory IAM)
def analyze_windows_logs(filepath):
    win_failures = defaultdict(int)
    with open(filepath, "r") as f:
        for line in f:
            ip_match = re.search(r"SourceIP:\s*(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else "N/A"

            if "EventID: 4625" in line:
                win_failures[ip] += 1
                if win_failures[ip] == 4:
                    trigger_alert(
                        "HIGH",
                        "Windows Brute-Force Attempt (Event 4625)",
                        ip,
                        "Multiple failed Windows logon attempts detected.",
                        line.strip(),
                        auto_block=True
                    )

            if "EventID: 4720" in line:
                trigger_alert(
                    "CRITICAL",
                    "Unauthorized Account Creation (Event 4720)",
                    ip,
                    "New local/domain user account created.",
                    line.strip(),
                    auto_block=True
                )

# 3. Analyze Web Access Logs (OWASP Top 10)
def analyze_web_logs(filepath):
    owasp_patterns = {
        "SQL Injection (OWASP A03)": r"(\%27|\'|--|\bOR\b\s+\'1\'=\'1)",
        "Directory Traversal (OWASP A01)": r"(\.\./\.\./|/etc/passwd)",
        "Cross-Site Scripting / XSS (OWASP A03)": r"(<script>|%3Cscript%3E)"
    }
    with open(filepath, "r") as f:
        for line in f:
            ip_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else "N/A"
            for attack_name, pattern in owasp_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    trigger_alert(
                        "HIGH",
                        f"Web Attack - {attack_name}",
                        ip,
                        "Malicious HTTP payload signature detected in access logs.",
                        line.strip(),
                        auto_block=True
                    )

# 4. Analyze Network Traffic Logs (Port Scanning & C2 Beaconing)
def analyze_network_logs(filepath):
    dropped_ports = defaultdict(set)
    with open(filepath, "r") as f:
        for line in f:
            src_match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
            port_match = re.search(r"DPORT=(\d+)", line)
            if not (src_match and port_match):
                continue

            src_ip = src_match.group(1)
            dport = int(port_match.group(1))

            if "ACTION=DROP" in line:
                dropped_ports[src_ip].add(dport)
                if len(dropped_ports[src_ip]) == 4:
                    trigger_alert(
                        "MEDIUM",
                        "Network Reconnaissance / Port Scan",
                        src_ip,
                        f"Host probed multiple closed ports: {sorted(list(dropped_ports[src_ip]))}",
                        line.strip(),
                        auto_block=True
                    )

            if "ACTION=ALLOW" in line and dport in {4444, 1337, 6667, 31337}:
                trigger_alert(
                    "CRITICAL",
                    "Suspicious Outbound C2 Traffic",
                    src_ip,
                    f"Allowed outbound connection on known reverse-shell/C2 port {dport}.",
                    line.strip(),
                    auto_block=True
                )

if __name__ == "__main__":
    print("=== Starting Cloud-Integrated SOC Threat Detection Pipeline ===\n")
    analyze_linux_logs("sample_logs/linux_auth.log")
    analyze_windows_logs("sample_logs/windows_security.log")
    analyze_web_logs("sample_logs/web_access.log")
    analyze_network_logs("sample_logs/network_traffic.log")

    report_path = "output/incident_report.json"
    with open(report_path, "w") as out:
        json.dump(INCIDENTS, out, indent=4)

    print(f"\n=== Scan Complete: {len(INCIDENTS)} Incidents Logged to {report_path} ===")