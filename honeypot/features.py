"""Turns the raw event log into one feature vector per session.

Shell sessions are TCP connections. HTTP requests are grouped per source address into
sessions that end after IDLE seconds without a request.
"""
import re
from collections import defaultdict

import pandas as pd

IDLE = 120
DOWNLOAD = re.compile(r"^(wget|curl|tftp|scp)\b")
PRIVILEGE = re.compile(r"\b(sudo|chmod \+x|chmod 777|crontab|useradd|passwd|nohup)\b")
RECON = re.compile(r"^(uname|cat /etc/passwd|id|whoami|w|ps|ifconfig|ip a|nproc|free|"
                   r"cat /proc/cpuinfo|netstat|ss)\b")
EVASION = re.compile(r"\b(history -c|unset HISTFILE|rm -rf /var/log|shred)\b")
ATTACK_PAYLOAD = re.compile(r"(\.\./|%2e%2e|'\s*or\s|union\s+select|<script|;\s*cat\s|"
                            r"/etc/passwd|\$\{jndi:|wp-login|phpmyadmin|\.env\b|\.git/)", re.I)
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|python-requests|"
                        r"curl/)", re.I)

SHELL_FEATURES = ["duration", "login_attempts", "failed_logins", "distinct_users", "logged_in",
                  "commands", "distinct_commands", "downloads", "privilege", "recon", "evasion"]
HTTP_FEATURES = ["requests", "distinct_paths", "login_posts", "not_found", "attack_payloads",
                 "scanner_agent", "requests_per_min"]


def shell_sessions(events: list[dict]) -> pd.DataFrame:
    by = defaultdict(list)
    for e in events:
        if e["service"] == "shell":
            by[e["session"]].append(e)
    rows = []
    for session, evs in by.items():
        logins = [e for e in evs if e["kind"] == "login"]
        commands = [e["command"] for e in evs if e["kind"] == "command"]
        end = next((e["duration"] for e in evs if e["kind"] == "disconnect"),
                   evs[-1]["ts"] - evs[0]["ts"])
        rows.append({
            "session": session, "src_ip": evs[0]["src_ip"], "start": evs[0]["ts"],
            "duration": end, "login_attempts": len(logins),
            "failed_logins": sum(not e["success"] for e in logins),
            "distinct_users": len({e["user"] for e in logins}),
            "logged_in": int(any(e["success"] for e in logins)),
            "commands": len(commands), "distinct_commands": len(set(commands)),
            "downloads": sum(bool(DOWNLOAD.search(c)) for c in commands),
            "privilege": sum(bool(PRIVILEGE.search(c)) for c in commands),
            "recon": sum(bool(RECON.search(c)) for c in commands),
            "evasion": sum(bool(EVASION.search(c)) for c in commands),
            "users": ", ".join(dict.fromkeys(e["user"] for e in logins)),
            "last_commands": " ; ".join(commands[-4:]),
        })
    return pd.DataFrame(rows, columns=["session", "src_ip", "start", *SHELL_FEATURES, "users",
                                       "last_commands"])


def http_sessions(events: list[dict]) -> pd.DataFrame:
    requests = sorted((e for e in events if e["service"] == "http"), key=lambda e: e["ts"])
    open_, done = {}, []
    for e in requests:
        current = open_.get(e["src_ip"])
        if current and e["ts"] - current[-1]["ts"] > IDLE:
            done.append(current)
            current = None
        open_[e["src_ip"]] = (current or []) + [e]
    done += open_.values()
    rows = []
    for evs in done:
        span = max(evs[-1]["ts"] - evs[0]["ts"], 1.0)
        rows.append({
            "session": f"{evs[0]['src_ip']}@{int(evs[0]['ts'])}", "src_ip": evs[0]["src_ip"],
            "start": evs[0]["ts"], "requests": len(evs),
            "distinct_paths": len({e["path"] for e in evs}),
            "login_posts": sum(e["method"] == "POST" and e["path"] == "/login" for e in evs),
            "not_found": sum(e["status"] == 404 for e in evs),
            "attack_payloads": sum(bool(ATTACK_PAYLOAD.search(e["path"] + " " + e["body"]))
                                   for e in evs),
            "scanner_agent": int(any(SCANNER_UA.search(e["user_agent"]) for e in evs)),
            "requests_per_min": round(len(evs) / span * 60, 2),
            "sample": " ".join(e["path"] for e in evs[:4])[:160],
        })
    return pd.DataFrame(rows, columns=["session", "src_ip", "start", *HTTP_FEATURES, "sample"])
