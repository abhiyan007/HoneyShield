#!/usr/bin/env python3
"""
HoneyShield v2.0 â€” Enhanced multi-port deception honeypot
New: HTTP credential capture, geo-IP, auto-blocking, richer logging.
"""

import socket, threading, json, os, time, datetime, sys, subprocess, urllib.request
from collections import defaultdict
from threading import Lock
from urllib.parse import unquote_plus

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE      = r"C:\HoneyShield"
LOG_TXT   = os.path.join(BASE, "logs", "honeypot.log")
LOG_JSON  = os.path.join(BASE, "logs", "events.jsonl")
CRED_LOG  = os.path.join(BASE, "logs", "credentials.log")
ALERT     = os.path.join(BASE, "alerts", "latest.txt")
SUMMARY   = os.path.join(BASE, "alerts", "summary.json")
BLOCKED   = os.path.join(BASE, "alerts", "blocked_ips.txt")

AUTOBLOCK_THRESHOLD = 15   # hits from one IP within window â†’ block
AUTOBLOCK_WINDOW    = 600  # seconds (10 min)

# â”€â”€ Port definitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
PORTS = {
    21:    ("FTP",           b"220 FileZilla Server 1.8.2\r\n"),
    22:    ("SSH",           b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6\r\n"),
    23:    ("Telnet",        b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"
                              b"\r\nNAS Device v2.1\r\nlogin: "),
    25:    ("SMTP",          b"220 mail.internal.local ESMTP Postfix\r\n"),
    80:    ("HTTP",          None),   # special handler
    110:   ("POP3",          b"+OK Dovecot POP3 server ready\r\n"),
    143:   ("IMAP",          b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n"),
    1433:  ("MSSQL",         b"\x04\x01\x00+\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01"
                              b"\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00"
                              b"\xff\x0a\x00\x15\x88\x00\x00\x02"),
    3306:  ("MySQL",         b"J\x00\x00\x00\n8.0.35\x00\x01\x00\x00\x00HneyPot1"
                              b"\x00\xff\xff\xff\x02\x00\xff\xcf\x15\x00\x00\x00\x00\x00"
                              b"\x00\x00\x00\x00\x00HneyPot2345\x00mysql_native_password\x00"),
    3389:  ("RDP",           b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08"
                              b"\x00\x02\x00\x00\x00"),
    5900:  ("VNC",           b"RFB 003.008\n"),
    6379:  ("Redis",         b"-NOAUTH Authentication required.\r\n"),
    8080:  ("HTTP-Alt",      b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\n"
                              b"Content-Length: 0\r\n\r\n"),
    8443:  ("HTTPS-Alt",     b"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.24.0\r\n"
                              b"Content-Length: 0\r\n\r\n"),
    9200:  ("Elasticsearch", b'{"name":"node-1","cluster_name":"production","version":'
                              b'{"number":"8.11.0"},"tagline":"You Know, for Search"}\n'),
    27017: ("MongoDB",       b"\x3d\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
                              b"\xd4\x07\x00\x00\x00\x00\x00\x00"),
}

# â”€â”€ Fake HTTP admin login page â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_HTML_LOGIN = b"""HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>NAS Admin Login</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:Arial,sans-serif}
.box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:44px 36px;width:340px}
h2{color:#58a6ff;text-align:center;margin-bottom:6px;font-size:20px}
.sub{color:#8b949e;text-align:center;font-size:13px;margin-bottom:28px}
label{color:#8b949e;font-size:12px;display:block;margin-bottom:4px;margin-top:14px}
input{width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:14px}
input:focus{outline:none;border-color:#58a6ff}
button{width:100%;padding:11px;background:#238636;border:none;border-radius:6px;color:#fff;font-size:15px;cursor:pointer;margin-top:22px;font-weight:600}
button:hover{background:#2ea043}
</style></head><body><div class="box">
<h2>\xf0\x9f\x9b\xa1 NAS Admin Panel</h2>
<div class="sub">Administration Panel</div>
<form method="POST" action="/login">
<label>Username</label><input name="username" autocomplete="off" autofocus>
<label>Password</label><input name="password" type="password">
<button type="submit">Sign In</button>
</form></div></body></html>"""

_HTML_FAIL = b"""HTTP/1.1 200 OK\r\nServer: Apache/2.4.58\r\nContent-Type: text/html\r\n\r\n
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>NAS Admin Login</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:Arial,sans-serif}
.box{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:44px 36px;width:340px}
h2{color:#58a6ff;text-align:center;margin-bottom:6px;font-size:20px}
.sub{color:#8b949e;text-align:center;font-size:13px;margin-bottom:16px}
.err{background:rgba(248,81,73,.1);border:1px solid #f85149;color:#f85149;border-radius:6px;padding:10px 12px;font-size:13px;margin-bottom:14px;text-align:center}
label{color:#8b949e;font-size:12px;display:block;margin-bottom:4px;margin-top:14px}
input{width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:14px}
button{width:100%;padding:11px;background:#238636;border:none;border-radius:6px;color:#fff;font-size:15px;cursor:pointer;margin-top:22px;font-weight:600}
</style></head><body><div class="box">
<h2>\xf0\x9f\x9b\xa1 NAS Admin Panel</h2>
<div class="sub">Administration Panel</div>
<div class="err">\xe2\x9c\x96 Invalid username or password.</div>
<form method="POST" action="/login">
<label>Username</label><input name="username" autocomplete="off">
<label>Password</label><input name="password" type="password">
<button type="submit">Sign In</button>
</form></div></body></html>"""

_HTTP_REDIRECT = b"HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n"

# â”€â”€ State â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
lock         = Lock()
ip_hits      = defaultdict(int)
ip_recent    = defaultdict(list)   # ip -> [timestamps] for autoblock
port_hits    = defaultdict(int)
blocked_ips  = set()
geo_cache    = {}
total_hits   = 0
start_time   = datetime.datetime.now()

# â”€â”€ Geo-IP (background, cached) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def geo_lookup_bg(ip: str):
    with lock:
        if ip in geo_cache:
            return
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org,proxy,hosting"
        req = urllib.request.Request(url, headers={"User-Agent": "HoneyShield/2.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read())
        with lock:
            geo_cache[ip] = data
    except Exception:
        with lock:
            geo_cache[ip] = {}

def get_geo(ip: str) -> dict:
    with lock:
        cached = geo_cache.get(ip)
    if cached is None:
        threading.Thread(target=geo_lookup_bg, args=(ip,), daemon=True).start()
        return {}
    return cached

# â”€â”€ Auto-blocking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def check_autoblock(ip: str):
    now = time.time()
    with lock:
        ip_recent[ip] = [t for t in ip_recent[ip] if now - t < AUTOBLOCK_WINDOW]
        ip_recent[ip].append(now)
        count = len(ip_recent[ip])
        already = ip in blocked_ips

    if count >= AUTOBLOCK_THRESHOLD and not already:
        with lock:
            blocked_ips.add(ip)
        threading.Thread(target=_do_block, args=(ip, count), daemon=True).start()

def _do_block(ip: str, hit_count: int):
    try:
        r = subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=HoneyShield_Block_{ip}",
            "dir=in", "action=block", f"remoteip={ip}", "enable=yes"
        ], capture_output=True, timeout=8, text=True)
        status = "BLOCKED" if r.returncode == 0 else "BLOCK_FAILED(need_admin)"
    except Exception as e:
        status = f"BLOCK_ERR:{e}"

    ts = datetime.datetime.now().isoformat(timespec="seconds")
    entry = f"[{ts}] {status}  {ip}  (hits={hit_count})\n"
    with open(BLOCKED, "a", encoding="utf-8") as f:
        f.write(entry)
    print(f"[AUTO-BLOCK] {ip}  {status}", flush=True)

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def hexdump(data: bytes, mx=160) -> str:
    c = data[:mx]
    h = " ".join(f"{b:02x}" for b in c)
    a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
    suf = f" +{len(data)-mx}B" if len(data) > mx else ""
    return f"{h}  |  {a}{suf}"

def win_toast(title: str, msg: str):
    ps = (
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,"
        "ContentType=WindowsRuntime]|Out-Null;"
        "$x=[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom,ContentType=WindowsRuntime]::new();"
        f"$x.LoadXml('<toast><visual><binding template=\"ToastText02\">"
        f"<text id=\"1\">{title}</text><text id=\"2\">{msg}</text>"
        "</binding></visual></toast>');"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('HoneyShield')"
        ".Show([Windows.UI.Notifications.ToastNotification]::new($x))"
    )
    try:
        subprocess.Popen(["powershell","-NonInteractive","-WindowStyle","Hidden","-Command",ps],
                         creationflags=0x08000000)
    except Exception:
        pass

# â”€â”€ Core event logger â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def log_event(port, service, src_ip, src_port, data: bytes, creds=None):
    global total_hits
    timestamp = ts()
    geo = get_geo(src_ip)

    with lock:
        total_hits  += 1
        ip_hits[src_ip] += 1
        port_hits[port]  += 1
        hit_num   = total_hits
        ip_count  = ip_hits[src_ip]
        top_ips   = sorted(ip_hits.items(),   key=lambda x: -x[1])[:10]
        top_ports = sorted(port_hits.items(), key=lambda x: -x[1])

    country   = geo.get("country", "")
    city      = geo.get("city", "")
    isp       = geo.get("isp", "")
    is_proxy  = geo.get("proxy", False) or geo.get("hosting", False)
    geo_str   = f"{country}/{city} [{isp}]{'  VPN/Proxy' if is_proxy else ''}" if country else ""

    event = {
        "ts": timestamp, "hit": hit_num,
        "src_ip": src_ip, "src_port": src_port,
        "dst_port": port, "service": service,
        "ip_total": ip_count,
        "data_len": len(data),
        "data_hex": hexdump(data) if data else "",
        "data_ascii": data[:256].decode("utf-8", errors="replace") if data else "",
        "geo": geo,
        "creds": creds or {},
    }

    # Human log
    loc = f"  [{geo_str}]" if geo_str else ""
    line = (f"[{timestamp}] #{hit_num:05d}  {src_ip}:{src_port} â†’ :{port} ({service})"
            f"  hits={ip_count}{loc}")
    if creds:
        line += f"\n              CREDS: user={creds.get('username','?')}  pass={creds.get('password','?')}"
    if data and not creds:
        line += f"\n              DATA ({len(data)}B): {hexdump(data)}"

    with open(LOG_TXT, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    with open(LOG_JSON, "a", encoding="utf-8") as f:
        json.dump(event, f, ensure_ascii=False); f.write("\n")
    if creds:
        with open(CRED_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {src_ip}:{src_port} â†’ :{port}  "
                    f"user={creds.get('username','?')}  pass={creds.get('password','?')}"
                    f"{loc}\n")

    # Alert file
    with open(ALERT, "w", encoding="utf-8") as f:
        f.write(f"Last hit  : {timestamp}\nFrom      : {src_ip}:{src_port}\n"
                f"Port      : {port} ({service})\nIP hits   : {ip_count}\n"
                f"Total     : {hit_num}\nLocation  : {geo_str or 'â€”'}\n")
        if creds:
            f.write(f"CREDS     : {creds}\n")

    # Summary
    with open(SUMMARY, "w", encoding="utf-8") as f:
        json.dump({"total_hits": hit_num, "unique_ips": len(ip_hits),
                   "port_stats": dict(top_ports), "top_ips": top_ips,
                   "uptime_since": start_time.isoformat(),
                   "last_hit": timestamp, "last_src": f"{src_ip}:{src_port}",
                   "last_port": f"{port} ({service})", "last_geo": geo_str,
                   "blocked_count": len(blocked_ips)}, f, indent=2)

    print(f"[HIT] {timestamp}  {src_ip}:{src_port} â†’ :{port} ({service})"
          + (f"  [{country}]" if country else "")
          + (f"  CREDS:{creds}" if creds else ""), flush=True)

    if ip_count == 1:
        loc_short = f" [{country}]" if country else ""
        win_toast("HoneyShield HIT", f"{src_ip}{loc_short} â†’ port {port} ({service})")

    check_autoblock(src_ip)

# â”€â”€ HTTP handler (port 80) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def handle_http(conn: socket.socket, addr, port: int):
    src_ip, src_port = addr[0], addr[1]
    raw = b""
    try:
        conn.settimeout(10)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                hi = raw.index(b"\r\n\r\n") + 4
                cl = 0
                for ln in raw[:hi].decode("utf-8", errors="replace").split("\r\n"):
                    if ln.lower().startswith("content-length:"):
                        try: cl = int(ln.split(":")[1].strip())
                        except: pass
                if len(raw) - hi >= cl:
                    break
    except Exception:
        pass

    try:
        first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
        parts  = first_line.split(" ")
        method = parts[0] if parts else "GET"
        path   = parts[1] if len(parts) > 1 else "/"
        hi     = raw.index(b"\r\n\r\n") + 4 if b"\r\n\r\n" in raw else len(raw)
        body   = raw[hi:].decode("utf-8", errors="replace")

        creds = {}
        if method == "POST":
            for pair in body.split("&"):
                k, _, v = pair.partition("=")
                k = unquote_plus(k).strip().lower()
                v = unquote_plus(v).strip()
                if k in ("username","user","login","email","name","usr","u","j_username"):
                    creds["username"] = v
                elif k in ("password","pass","pwd","passwd","p","secret","j_password"):
                    creds["password"] = v

        if method == "POST" and path in ("/login", "/"):
            conn.sendall(_HTML_FAIL)
        elif path in ("/", "/login", "/admin", "/wp-admin", "/phpmyadmin",
                      "/manager/html", "/administrator"):
            conn.sendall(_HTML_LOGIN)
        else:
            conn.sendall(_HTTP_REDIRECT)
    except Exception:
        pass
    finally:
        try: conn.close()
        except: pass

    log_event(port, "HTTP", src_ip, src_port, raw[:512], creds if creds else None)

# â”€â”€ Generic handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def handle_conn(conn: socket.socket, addr, port: int, service: str, banner: bytes):
    if port == 80:
        handle_http(conn, addr, port)
        return

    src_ip, src_port = addr[0], addr[1]
    data = b""
    try:
        conn.settimeout(8)
        if banner:
            try: conn.sendall(banner)
            except: pass
        try:
            data = conn.recv(4096)
            if data:
                conn.settimeout(3)
                for _ in range(3):
                    try:
                        more = conn.recv(4096)
                        if not more: break
                        data += more
                    except: break
        except: pass
    except: pass
    finally:
        try: conn.close()
        except: pass

    log_event(port, service, src_ip, src_port, data)

# â”€â”€ Port listener â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def listen(port: int, service: str, banner):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(64)
        print(f"[+] :{port:<6} {service}", flush=True)
    except OSError as e:
        print(f"[!] :{port:<6} {service}  FAILED: {e}", flush=True)
        return
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_conn,
                             args=(conn, addr, port, service, banner),
                             daemon=True).start()
        except: break

# â”€â”€ Status printer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def status_loop():
    while True:
        time.sleep(300)
        with lock:
            n, ui, nb = total_hits, len(ip_hits), len(blocked_ips)
            top = sorted(ip_hits.items(), key=lambda x: -x[1])[:3]
        t = ", ".join(f"{ip}Ã—{c}" for ip, c in top) or "none"
        print(f"[STATUS] {ts()}  hits={n}  ips={ui}  blocked={nb}  top: {t}", flush=True)

# â”€â”€ Main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def main():
    print("â•" * 55)
    print("  HoneyShield v2.0  â€”  Enhanced Deception Honeypot")
    print(f"  Started : {ts()}")
    print(f"  Auto-block threshold : {AUTOBLOCK_THRESHOLD} hits / {AUTOBLOCK_WINDOW}s")
    print("â•" * 55 + "\n")

    for port, (service, banner) in sorted(PORTS.items()):
        threading.Thread(target=listen, args=(port, service, banner),
                         daemon=True, name=f"hp-{port}").start()
        time.sleep(0.03)

    threading.Thread(target=status_loop, daemon=True).start()
    print(f"\n[+] {len(PORTS)} traps armed. Auto-blocking ON. Geo-IP ON.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        with lock:
            n, ui, nb = total_hits, len(ip_hits), len(blocked_ips)
        print(f"\n[HoneyShield] Stopped. hits={n}  ips={ui}  blocked={nb}")

if __name__ == "__main__":
    main()


