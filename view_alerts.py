#!/usr/bin/env python3
"""
HoneyShield — Live alert viewer.
Usage:
  python view_alerts.py          # show summary + last 30 log lines
  python view_alerts.py --live   # live tail (Ctrl+C to stop)
  python view_alerts.py --json   # dump top attackers from JSON events
"""

import json, os, sys, time, datetime

BASE     = r"C:\HoneyShield"
LOG_TXT  = os.path.join(BASE, "logs", "honeypot.log")
LOG_JSON = os.path.join(BASE, "logs", "events.jsonl")
SUMMARY  = os.path.join(BASE, "alerts", "summary.json")
ALERT    = os.path.join(BASE, "alerts", "latest.txt")

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


def show_summary():
    try:
        with open(SUMMARY) as f:
            s = json.load(f)
        print(f"\n{CYAN}{'═'*54}")
        print(f"  HoneyShield Summary — {datetime.datetime.now().strftime('%H:%M:%S')}")
        print(f"{'═'*54}{RESET}")
        print(f"  {RED}Total hits   : {s['total_hits']}{RESET}")
        print(f"  {YELLOW}Unique IPs   : {s['unique_ips']}{RESET}")
        print(f"  Last hit     : {s.get('last_hit','—')}")
        print(f"  From         : {s.get('last_src','—')}  →  {s.get('last_port','—')}")
        print(f"\n  {CYAN}Port breakdown:{RESET}")
        for port, cnt in sorted(s['port_stats'].items(), key=lambda x: -x[1]):
            bar = "█" * min(cnt, 40)
            print(f"    {port:>5}  {bar}  {cnt}")
        print(f"\n  {RED}Top attackers:{RESET}")
        for ip, cnt in s['top_ips'][:10]:
            print(f"    {ip:<20}  {cnt} hits")
        print(f"\n  Uptime since : {s.get('uptime_since','—')}")
        print(f"{'═'*54}{RESET}\n")
    except FileNotFoundError:
        print("No data yet — honeypot hasn't been hit.")


def tail_log(n: int = 30):
    try:
        with open(LOG_TXT, encoding="utf-8") as f:
            lines = f.readlines()
        for line in lines[-n:]:
            if "HIT" in line or "DATA" in line:
                print(f"{YELLOW}{line}{RESET}", end="")
            else:
                print(line, end="")
    except FileNotFoundError:
        print("No log file yet.")


def live_tail():
    pos = os.path.getsize(LOG_TXT) if os.path.exists(LOG_TXT) else 0
    print(f"{GREEN}[Live mode — Ctrl+C to stop]{RESET}\n")
    while True:
        try:
            sz = os.path.getsize(LOG_TXT) if os.path.exists(LOG_TXT) else 0
            if sz > pos:
                with open(LOG_TXT, encoding="utf-8") as f:
                    f.seek(pos)
                    chunk = f.read()
                for line in chunk.splitlines():
                    if "[HIT]" in line or "DATA" in line:
                        print(f"{RED}{line}{RESET}")
                    else:
                        print(line)
                pos = sz
            time.sleep(0.3)
        except KeyboardInterrupt:
            print("\nStopped.")
            break


def json_analysis():
    from collections import defaultdict, Counter
    ip_data    = defaultdict(list)
    port_seq   = []
    creds_seen = []

    try:
        with open(LOG_JSON, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    ip_data[e["src_ip"]].append(e)
                    port_seq.append(e["dst_port"])
                    # Look for credential patterns in data
                    if e.get("data_ascii"):
                        d = e["data_ascii"]
                        if any(kw in d.lower() for kw in ["pass", "user", "admin", "root", "login"]):
                            creds_seen.append((e["src_ip"], e["dst_port"], e["service"], d[:120]))
                except Exception:
                    continue
    except FileNotFoundError:
        print("No JSON log yet.")
        return

    print(f"\n{CYAN}=== DEEP ANALYSIS ==={RESET}")
    print(f"Total events : {sum(len(v) for v in ip_data.values())}")
    print(f"Unique IPs   : {len(ip_data)}")

    print(f"\n{RED}Credential attempts captured:{RESET}")
    if creds_seen:
        for ip, port, svc, data in creds_seen[:20]:
            print(f"  {ip} → :{port} ({svc}):  {data!r}")
    else:
        print("  None yet.")

    print(f"\n{YELLOW}Most scanned ports:{RESET}")
    for port, cnt in Counter(port_seq).most_common(10):
        print(f"  :{port}  {cnt}×")

    print(f"\n{YELLOW}Persistent attackers (>5 hits):{RESET}")
    for ip, events in sorted(ip_data.items(), key=lambda x: -len(x[1])):
        if len(events) > 5:
            ports = sorted(set(e["dst_port"] for e in events))
            print(f"  {ip}  {len(events)} hits  ports: {ports}")


if __name__ == "__main__":
    if "--live" in sys.argv:
        show_summary()
        live_tail()
    elif "--json" in sys.argv:
        json_analysis()
    else:
        show_summary()
        tail_log(30)
