#!/usr/bin/env python3
"""
HoneyShield — Windows Event Log Monitor
Watches real system events: failed logins, new services, privilege escalation, etc.
Runs alongside honeypot.py as a companion process.
"""

import subprocess, json, os, time, datetime, sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE      = r"C:\HoneyShield"
LOG_TXT   = os.path.join(BASE, "logs", "winevent.log")
LOG_JSON  = os.path.join(BASE, "logs", "winevent.jsonl")
SUMMARY   = os.path.join(BASE, "alerts", "winevent_summary.json")

# Event IDs to watch and their meaning
WATCH_IDS = {
    4625: ("FAILED_LOGIN",       "danger",  "Failed logon attempt"),
    4648: ("EXPLICIT_CRED",      "warning", "Explicit credential logon (runas/pass-the-hash)"),
    4672: ("PRIV_ASSIGNED",      "warning", "Special privileges assigned to logon"),
    4688: ("PROCESS_CREATED",    "info",    "New process created"),
    4698: ("TASK_CREATED",       "danger",  "Scheduled task created"),
    4702: ("TASK_MODIFIED",      "danger",  "Scheduled task modified"),
    4720: ("USER_CREATED",       "critical","User account created"),
    4726: ("USER_DELETED",       "danger",  "User account deleted"),
    4732: ("GROUP_MEMBER_ADD",   "danger",  "Member added to privileged group"),
    4756: ("UNIV_GROUP_ADD",     "danger",  "Member added to universal group"),
    7045: ("SERVICE_INSTALLED",  "critical","New service installed"),
    1102: ("AUDIT_LOG_CLEARED",  "critical","Security audit log was cleared — HIGH ALERT"),
    4719: ("AUDIT_POLICY_CHANGE","critical","Audit policy changed"),
}

# Suspicious process names to flag even in 4688 events
SUSPICIOUS_PROCESSES = {
    "mimikatz", "procdump", "pwdump", "gsecdump", "wce", "fgdump",
    "meterpreter", "cobalt", "empire", "metasploit", "nc.exe", "ncat",
    "psexec", "wmiexec", "smbexec", "crackmapexec", "impacket",
    "certutil", "regsvr32", "rundll32", "mshta", "wscript", "cscript",
    "powershell", "cmd.exe",
}

seen_record_ids = set()
last_seen_time  = datetime.datetime.now() - datetime.timedelta(minutes=5)
counts          = {k: 0 for k in WATCH_IDS}


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def query_events(since: datetime.datetime) -> list:
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    id_filter = " or ".join(f"EventID={eid}" for eid in WATCH_IDS)
    ps_cmd = f"""
$since = [datetime]::Parse("{since_str}")
Get-WinEvent -FilterHashtable @{{
    LogName   = 'Security','System','Application'
    StartTime = $since
}} -ErrorAction SilentlyContinue |
Where-Object {{ {id_filter} }} |
Select-Object -First 200 TimeCreated, Id, LevelDisplayName,
    @{{N='Msg';E={{$_.Message -replace '`n',' ' -replace '`r',' '}}}} |
ConvertTo-Json -Compress
""".strip()
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-WindowStyle", "Hidden",
             "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30, encoding="utf-8"
        )
        if not result.stdout.strip():
            return []
        raw = result.stdout.strip()
        data = json.loads(raw)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def process_event(ev: dict):
    global last_seen_time
    eid = ev.get("Id", 0)
    if eid not in WATCH_IDS:
        return

    event_type, severity, description = WATCH_IDS[eid]
    msg      = ev.get("Msg", "")
    time_str = ev.get("TimeCreated", ts())
    if isinstance(time_str, dict):
        time_str = time_str.get("value", ts())

    # Extra checks for process creation — filter noise
    if eid == 4688:
        msg_lower = msg.lower()
        flagged = any(p in msg_lower for p in SUSPICIOUS_PROCESSES)
        if not flagged:
            return  # skip boring process creation events
        severity = "danger"

    counts[eid] = counts.get(eid, 0) + 1

    record = {
        "ts":          ts(),
        "event_id":    eid,
        "event_type":  event_type,
        "severity":    severity,
        "description": description,
        "raw_time":    str(time_str),
        "message":     msg[:500],
    }

    line = f"[{ts()}] [{severity.upper():8}] {eid} {event_type}: {description}"
    if eid == 4625:
        # Extract account name from failed login
        for part in msg.split():
            if "@" in part or (len(part) > 2 and part.isalnum()):
                line += f"  account={part}"
                record["account"] = part
                break
    if eid in (4698, 4702, 7045):
        line += f"  msg_snippet={msg[:120]}"

    print(line, flush=True)

    with open(LOG_TXT,  "a", encoding="utf-8") as f:
        f.write(line + "\n")
    with open(LOG_JSON, "a", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False); f.write("\n")

    # Update summary
    try:
        recent = []
        with open(LOG_JSON, encoding="utf-8") as f:
            lines = f.readlines()
        for ln in reversed(lines[-200:]):
            try:
                recent.append(json.loads(ln))
            except: pass
        by_type = {}
        for r in recent:
            k = r.get("event_type", "?")
            by_type[k] = by_type.get(k, 0) + 1
        with open(SUMMARY, "w", encoding="utf-8") as f:
            json.dump({"last_updated": ts(), "event_counts": by_type,
                       "total_events": len(lines), "last_event": record}, f, indent=2)
    except Exception:
        pass


def main():
    global last_seen_time
    print(f"[WinEvent Monitor] Started {ts()}")
    print(f"  Watching {len(WATCH_IDS)} event types")
    print(f"  Log: {LOG_TXT}\n")

    while True:
        try:
            events = query_events(last_seen_time)
            now = datetime.datetime.now()
            for ev in events:
                process_event(ev)
            last_seen_time = now
        except Exception as e:
            print(f"[WinEvent] Error: {e}", flush=True)
        time.sleep(30)


if __name__ == "__main__":
    main()
