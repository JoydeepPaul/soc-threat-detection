import os
import datetime

os.makedirs("sample_logs", exist_ok=True)
os.makedirs("output", exist_ok=True)

now = datetime.datetime.now()

def ts(offset_sec=0):
    return (now + datetime.timedelta(seconds=offset_sec)).strftime("%Y-%m-%d %H:%M:%S")

# 1. Linux Auth Logs (Brute Force + Privilege Escalation)
linux_logs = [
    f"{ts(1)} ubuntu-srv sshd[1021]: Accepted publickey for admin from 10.0.1.5 port 54322 ssh2",
    f"{ts(5)} ubuntu-srv sshd[1025]: Failed password for invalid user root from 192.168.1.99 port 44120 ssh2",
    f"{ts(7)} ubuntu-srv sshd[1026]: Failed password for invalid user root from 192.168.1.99 port 44121 ssh2",
    f"{ts(9)} ubuntu-srv sshd[1027]: Failed password for invalid user root from 192.168.1.99 port 44122 ssh2",
    f"{ts(11)} ubuntu-srv sshd[1028]: Failed password for invalid user root from 192.168.1.99 port 44123 ssh2",
    f"{ts(13)} ubuntu-srv sshd[1029]: Failed password for invalid user root from 192.168.1.99 port 44124 ssh2",
    f"{ts(15)} ubuntu-srv sshd[1030]: Accepted password for root from 192.168.1.99 port 44125 ssh2",
    f"{ts(20)} ubuntu-srv sudo:     dev_user : TTY=pts/0 ; PWD=/home/dev_user ; USER=root ; COMMAND=/bin/bash",
]

with open("sample_logs/linux_auth.log", "w") as f:
    f.write("\n".join(linux_logs) + "\n")

# 2. Windows Security Logs (Event ID 4625 Failed Logon, 4624 Success, 4720 User Created)
windows_logs = [
    f"{ts(2)} | EventID: 4624 | Account: corp\\jdoe | SourceIP: 10.0.2.14 | Status: Success",
    f"{ts(10)} | EventID: 4625 | Account: corp\\administrator | SourceIP: 203.0.113.45 | Status: Failure",
    f"{ts(12)} | EventID: 4625 | Account: corp\\administrator | SourceIP: 203.0.113.45 | Status: Failure",
    f"{ts(14)} | EventID: 4625 | Account: corp\\administrator | SourceIP: 203.0.113.45 | Status: Failure",
    f"{ts(16)} | EventID: 4625 | Account: corp\\administrator | SourceIP: 203.0.113.45 | Status: Failure",
    f"{ts(30)} | EventID: 4720 | Account: corp\\backdoor_svc | SourceIP: 203.0.113.45 | Status: UserAccountCreated",
]

with open("sample_logs/windows_security.log", "w") as f:
    f.write("\n".join(windows_logs) + "\n")

# 3. Web Access Logs (OWASP Top 10: SQLi, Directory Traversal, XSS)
web_logs = [
    f'10.0.1.12 - - [{ts(3)}] "GET /index.html HTTP/1.1" 200 1024',
    f'185.220.101.4 - - [{ts(18)}] "GET /login.php?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 512',
    f'185.220.101.4 - - [{ts(22)}] "GET /../../../../etc/passwd HTTP/1.1" 403 256',
    f'45.33.32.156 - - [{ts(25)}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 768',
]

with open("sample_logs/web_access.log", "w") as f:
    f.write("\n".join(web_logs) + "\n")

# 4. Network Traffic Logs (Port Scan & Suspicious Outbound C2 Ports)
network_logs = [
    f"{ts(4)} | SRC=10.0.1.15 | DST=8.8.8.8 | PROTO=UDP | DPORT=53 | ACTION=ALLOW",
    f"{ts(19)} | SRC=172.16.0.88 | DST=10.0.1.10 | PROTO=TCP | DPORT=22 | ACTION=DROP",
    f"{ts(20)} | SRC=172.16.0.88 | DST=10.0.1.10 | PROTO=TCP | DPORT=23 | ACTION=DROP",
    f"{ts(21)} | SRC=172.16.0.88 | DST=10.0.1.10 | PROTO=TCP | DPORT=445 | ACTION=DROP",
    f"{ts(22)} | SRC=172.16.0.88 | DST=10.0.1.10 | PROTO=TCP | DPORT=3389 | ACTION=DROP",
    f"{ts(28)} | SRC=10.0.1.22 | DST=198.51.100.77 | PROTO=TCP | DPORT=4444 | ACTION=ALLOW",
]

with open("sample_logs/network_traffic.log", "w") as f:
    f.write("\n".join(network_logs) + "\n")

print("[+] Sample logs generated successfully in ./sample_logs/")