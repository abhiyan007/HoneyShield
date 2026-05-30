#!/usr/bin/env python3
"""HoneyShield Dashboard v2 — Enhanced web UI"""

import http.server, json, os, socket, threading, webbrowser, time, datetime
from collections import defaultdict
from urllib.parse import urlparse

DASH_PORT = 7777
BASE = r"C:\HoneyShield"
SUMMARY  = os.path.join(BASE, "alerts",  "summary.json")
EVENTS   = os.path.join(BASE, "logs",    "events.jsonl")
CREDS    = os.path.join(BASE, "logs",    "credentials.log")
BLOCKED  = os.path.join(BASE, "alerts",  "blocked_ips.txt")
WINEVENT = os.path.join(BASE, "logs",    "winevent.jsonl")
WESUM    = os.path.join(BASE, "alerts",  "winevent_summary.json")

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HoneyShield v2</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--dim:#8b949e;
      --green:#3fb950;--red:#f85149;--blue:#58a6ff;--orange:#d29922;--purple:#bc8cff;--yellow:#e3b341}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,"Segoe UI",sans-serif;min-height:100vh}
/* Header */
header{display:flex;align-items:center;justify-content:space-between;padding:16px 28px;
       background:var(--card);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{font-size:26px}
.logo h1{font-size:19px;font-weight:700;background:linear-gradient(90deg,var(--green),var(--blue));
          -webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo small{color:var(--dim);font-size:11px;display:block}
.hdr-right{display:flex;align-items:center;gap:14px}
.badge{display:flex;align-items:center;gap:6px;padding:5px 13px;border-radius:20px;
       font-size:12px;font-weight:600;border:1px solid}
.badge.armed{background:rgba(63,185,80,.12);border-color:var(--green);color:var(--green)}
.badge.offline{background:rgba(248,81,73,.12);border-color:var(--red);color:var(--red)}
.dot{width:7px;height:7px;border-radius:50%}
.armed .dot{background:var(--green);animation:pg 1.5s infinite}
.offline .dot{background:var(--red)}
@keyframes pg{0%,100%{box-shadow:0 0 0 0 rgba(63,185,80,.6)}50%{box-shadow:0 0 0 5px rgba(63,185,80,0)}}
.refresh-info{color:var(--dim);font-size:11px}
/* Layout */
main{padding:22px 28px;max-width:1500px;margin:0 auto}
/* Stat cards */
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-bottom:20px}
@media(max-width:1100px){.stats{grid-template-columns:repeat(3,1fr)}}
@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px 20px;transition:border-color .2s}
.card:hover{border-color:#58a6ff44}
.card-label{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.card-value{font-size:32px;font-weight:700;line-height:1}
.card-sub{font-size:11px;color:var(--dim);margin-top:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card.hits   .card-value{color:var(--red)}
.card.ips    .card-value{color:var(--orange)}
.card.ports  .card-value{color:var(--green)}
.card.uptime .card-value{color:var(--blue);font-size:22px}
.card.blocked .card-value{color:var(--purple)}
.card.creds  .card-value{color:var(--yellow)}
/* Tabs */
.tabs{display:flex;gap:4px;margin-bottom:18px;border-bottom:1px solid var(--border);padding-bottom:0}
.tab{padding:9px 18px;font-size:13px;font-weight:500;cursor:pointer;border-radius:8px 8px 0 0;
     color:var(--dim);border:1px solid transparent;border-bottom:none;margin-bottom:-1px}
.tab:hover{color:var(--text)}
.tab.active{background:var(--card);border-color:var(--border);color:var(--text)}
.tab-panel{display:none}.tab-panel.active{display:block}
/* Grid helpers */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px}
@media(max-width:900px){.grid2,.grid3{grid-template-columns:1fr}}
.card-title{font-size:13px;font-weight:600;margin-bottom:14px;border-bottom:1px solid var(--border);padding-bottom:8px}
/* Chart */
.chart-wrap{position:relative;height:240px}
/* Table */
.htable{width:100%;border-collapse:collapse;font-size:12.5px}
.htable th{color:var(--dim);font-weight:600;text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}
.htable td{padding:8px 10px;border-bottom:1px solid #21262d;font-family:Consolas,monospace}
.htable tr:hover td{background:rgba(88,166,255,.05)}
.htable tr:last-child td{border-bottom:none}
.tc-ip{color:var(--blue)}.tc-red{color:var(--red);font-weight:600}
.tc-dim{color:var(--dim)}.tc-green{color:var(--green)}.tc-orange{color:var(--orange)}
.tc-yellow{color:var(--yellow)}.tc-purple{color:var(--purple)}
.bar{display:inline-block;height:5px;border-radius:3px;background:var(--red);margin-right:6px;vertical-align:middle}
/* Severity badges */
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.sev.critical{background:rgba(248,81,73,.2);color:var(--red)}
.sev.danger  {background:rgba(210,153,34,.2);color:var(--orange)}
.sev.warning {background:rgba(227,179,65,.2);color:var(--yellow)}
.sev.info    {background:rgba(88,166,255,.15);color:var(--blue)}
/* Feed */
.feed{font-family:Consolas,monospace;font-size:12px;height:300px;overflow-y:auto;
      scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.feed::-webkit-scrollbar{width:4px}
.feed::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.frow{display:flex;gap:8px;padding:4px 2px;border-bottom:1px solid #21262d;animation:si .25s ease}
@keyframes si{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.frow:last-child{border-bottom:none}
.f-t{color:var(--dim);min-width:72px}.f-ip{color:var(--blue);min-width:140px}
.f-svc{font-weight:600;min-width:86px}.f-flag{min-width:22px}
.f-data{color:var(--dim);font-size:11px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;max-width:260px}
/* Creds log */
.cred-row{padding:6px 0;border-bottom:1px solid #21262d;font-family:Consolas,monospace;font-size:12px}
.cred-row:last-child{border-bottom:none}
/* Empty */
.empty{color:var(--dim);text-align:center;padding:36px;font-size:13px}
.empty .ico{font-size:28px;display:block;margin-bottom:8px}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div><h1>HoneyShield v2</h1><small>Deception Honeypot — Live Dashboard</small></div>
  </div>
  <div class="hdr-right">
    <div id="status-badge" class="badge offline"><div class="dot"></div><span>Checking...</span></div>
    <div class="refresh-info">Refresh in <span id="cd">3</span>s</div>
  </div>
</header>

<main>
<!-- Stat cards -->
<div class="stats">
  <div class="card hits">  <div class="card-label">Total Hits</div>   <div class="card-value" id="s-hits">—</div>   <div class="card-sub" id="s-lh">—</div></div>
  <div class="card ips">   <div class="card-label">Unique IPs</div>   <div class="card-value" id="s-ips">—</div>    <div class="card-sub" id="s-ls">—</div></div>
  <div class="card creds"> <div class="card-label">Creds Captured</div><div class="card-value" id="s-creds">—</div> <div class="card-sub">Usernames &amp; passwords</div></div>
  <div class="card blocked"><div class="card-label">Auto-Blocked</div> <div class="card-value" id="s-blocked">—</div><div class="card-sub">IPs firewalled</div></div>
  <div class="card ports"> <div class="card-label">Ports Armed</div>  <div class="card-value" id="s-ports">16</div>  <div class="card-sub" id="s-tp">—</div></div>
  <div class="card uptime"><div class="card-label">Uptime</div>       <div class="card-value" id="s-uptime">—</div> <div class="card-sub" id="s-since">—</div></div>
</div>

<!-- Tabs -->
<div class="tabs">
  <div class="tab active" onclick="switchTab('overview')">📊 Overview</div>
  <div class="tab" onclick="switchTab('feed')">⚡ Live Feed</div>
  <div class="tab" onclick="switchTab('attackers')">🔥 Attackers</div>
  <div class="tab" onclick="switchTab('creds')">🔑 Credentials</div>
  <div class="tab" onclick="switchTab('sysevents')">🖥 System Events</div>
  <div class="tab" onclick="switchTab('blocked')">🚫 Blocked IPs</div>
</div>

<!-- Overview tab -->
<div id="tab-overview" class="tab-panel active">
  <div class="grid2">
    <div class="card"><div class="card-title">🎯 Port Hit Breakdown</div><div class="chart-wrap"><canvas id="portChart"></canvas></div></div>
    <div class="card"><div class="card-title">📈 Hits Per Hour (last 24h)</div><div class="chart-wrap"><canvas id="timeChart"></canvas></div></div>
  </div>
  <div class="grid2">
    <div class="card">
      <div class="card-title">🌍 Top Attacker Countries</div>
      <div id="geo-wrap"><div class="empty"><span class="ico">🌐</span>Waiting for geo data...</div></div>
    </div>
    <div class="card">
      <div class="card-title">⚠️ Recent System Alerts</div>
      <div id="sysal-wrap"><div class="empty"><span class="ico">✅</span>No system alerts yet.</div></div>
    </div>
  </div>
</div>

<!-- Live Feed tab -->
<div id="tab-feed" class="tab-panel">
  <div class="card">
    <div class="card-title" style="display:flex;justify-content:space-between">
      <span>⚡ Live Hit Feed</span>
      <span style="color:var(--green);font-size:11px;animation:pg 2s infinite">● LIVE</span>
    </div>
    <div class="feed" id="feed"><div class="empty">No events yet.</div></div>
  </div>
</div>

<!-- Attackers tab -->
<div id="tab-attackers" class="tab-panel">
  <div class="card">
    <div class="card-title">🔥 Top Attacking IPs</div>
    <div id="atk-wrap"><div class="empty"><span class="ico">👀</span>No attackers yet.</div></div>
  </div>
</div>

<!-- Credentials tab -->
<div id="tab-creds" class="tab-panel">
  <div class="card">
    <div class="card-title">🔑 Captured Credentials — Passwords Attackers Tried</div>
    <div id="creds-wrap"><div class="empty"><span class="ico">🔒</span>No credentials captured yet — HTTP trap on port 80 is armed.</div></div>
  </div>
</div>

<!-- System Events tab -->
<div id="tab-sysevents" class="tab-panel">
  <div class="card">
    <div class="card-title">🖥 Windows Event Log — Suspicious System Activity</div>
    <div id="we-wrap"><div class="empty"><span class="ico">✅</span>No suspicious Windows events detected.</div></div>
  </div>
</div>

<!-- Blocked IPs tab -->
<div id="tab-blocked" class="tab-panel">
  <div class="card">
    <div class="card-title">🚫 Auto-Blocked IPs (Firewall rules added)</div>
    <div id="blk-wrap"><div class="empty"><span class="ico">🛡</span>No IPs auto-blocked yet. Threshold: 15 hits in 10 min.</div></div>
  </div>
</div>
</main>

<script>
const SVC = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",80:"HTTP",110:"POP3",143:"IMAP",
             1433:"MSSQL",3306:"MySQL",3389:"RDP",5900:"VNC",6379:"Redis",
             8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elastic",27017:"MongoDB"};
const SC  = {SSH:"#58a6ff",FTP:"#3fb950",RDP:"#f85149",MySQL:"#d29922",MSSQL:"#d29922",
             Telnet:"#bc8cff",VNC:"#ff7b72",SMTP:"#79c0ff",POP3:"#79c0ff",IMAP:"#79c0ff",
             Redis:"#f0883e",MongoDB:"#3fb950",Elasticsearch:"#58a6ff","HTTP-Alt":"#bc8cff",
             "HTTPS-Alt":"#bc8cff",HTTP:"#e3b341",Elastic:"#58a6ff"};

function sc(svc){ return SC[svc]||"#8b949e"; }
function fmt(n){ return n>=1000?n.toLocaleString():String(n); }
function set(id,v){ const e=document.getElementById(id); if(e&&e.textContent!==String(v))e.textContent=v; }

// Active tab
let activeTab = "overview";
function switchTab(name){
  document.querySelectorAll(".tab-panel").forEach(p=>p.classList.remove("active"));
  document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
  document.getElementById("tab-"+name).classList.add("active");
  document.querySelectorAll(".tab")[["overview","feed","attackers","creds","sysevents","blocked"].indexOf(name)].classList.add("active");
  activeTab = name;
}

// Charts
const portChart = new Chart(document.getElementById("portChart").getContext("2d"),{
  type:"bar",
  data:{labels:[],datasets:[{data:[],backgroundColor:[],borderRadius:5,borderSkipped:false}]},
  options:{indexAxis:"y",responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>` ${c.parsed.x} hits`}}},
    scales:{x:{grid:{color:"#21262d"},ticks:{color:"#8b949e"},border:{color:"#30363d"}},
            y:{grid:{display:false},ticks:{color:"#c9d1d9",font:{family:"Consolas"}},border:{color:"#30363d"}}},
    animation:{duration:300}}
});

const timeChart = new Chart(document.getElementById("timeChart").getContext("2d"),{
  type:"line",
  data:{labels:[],datasets:[{data:[],borderColor:"#3fb950",backgroundColor:"rgba(63,185,80,.1)",
        fill:true,tension:.3,pointRadius:3,pointBackgroundColor:"#3fb950"}]},
  options:{responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>` ${c.parsed.y} hits`}}},
    scales:{x:{grid:{color:"#21262d"},ticks:{color:"#8b949e",maxTicksLimit:8},border:{color:"#30363d"}},
            y:{grid:{color:"#21262d"},ticks:{color:"#8b949e",stepSize:1},border:{color:"#30363d"},beginAtZero:true}},
    animation:{duration:300}}
});

function renderStats(s,credCount,blockedCount){
  set("s-hits",    fmt(s.total_hits||0));
  set("s-ips",     fmt(s.unique_ips||0));
  set("s-creds",   fmt(credCount));
  set("s-blocked", fmt(blockedCount));
  set("s-lh",  "Last: "+(s.last_hit||"—"));
  set("s-ls",  (s.last_geo||s.last_src||"—"));
  const tp = Object.entries(s.port_stats||{}).sort((a,b)=>b[1]-a[1])[0];
  set("s-tp",  tp?`Top: :${tp[0]} (${tp[1]})`:"—");
  set("s-uptime", s.uptime||"—");
  set("s-since", "Since: "+(s.uptime_since||"—").slice(0,16).replace("T"," "));
}

function renderPortChart(ps){
  const sorted = Object.entries(ps||{}).sort((a,b)=>b[1]-a[1]).slice(0,14);
  portChart.data.labels = sorted.map(([p])=>`:${p} ${SVC[p]||""}`);
  portChart.data.datasets[0].data = sorted.map(([,c])=>c);
  portChart.data.datasets[0].backgroundColor = sorted.map(([p])=>sc(SVC[p]||""));
  portChart.update("none");
}

function renderTimeChart(events){
  const now = new Date();
  const buckets = {};
  for(let h=23;h>=0;h--){
    const d = new Date(now-h*3600000);
    buckets[d.getHours()] = 0;
  }
  events.forEach(e=>{
    try{
      const h = new Date(e.ts).getHours();
      if(h in buckets) buckets[h]++;
    }catch{}
  });
  const hours = Object.keys(buckets).map(h=>h+":00");
  const vals  = Object.values(buckets);
  timeChart.data.labels = hours;
  timeChart.data.datasets[0].data = vals;
  timeChart.update("none");
}

function renderFeed(events){
  const el = document.getElementById("feed");
  if(!events||!events.length){el.innerHTML='<div class="empty">No events yet.</div>';return;}
  const atBot = el.scrollHeight-el.scrollTop <= el.clientHeight+40;
  el.innerHTML = events.map(e=>{
    const geo  = e.geo||{};
    const flag = geo.countryCode ? String.fromCodePoint(...[...geo.countryCode.toUpperCase()].map(c=>0x1F1E0+c.charCodeAt(0)-65)) : "🌐";
    const svc  = e.service||SVC[e.dst_port]||"?";
    const color = sc(svc);
    const data = e.creds && Object.keys(e.creds).length
      ? `🔑 user=${e.creds.username||"?"} pass=${e.creds.password||"?"}`
      : (e.data_ascii||"").replace(/\n/g," ").slice(0,55);
    return `<div class="frow">
      <span class="f-t">${(e.ts||"").slice(11,19)}</span>
      <span class="f-flag">${flag}</span>
      <span class="f-ip tc-ip">${e.src_ip||"?"}:${e.src_port||"?"}</span>
      <span style="color:var(--dim)">→</span>
      <span class="f-svc" style="color:${color}">:${e.dst_port} ${svc}</span>
      ${data?`<span class="f-data">${data}</span>`:""}
    </div>`;
  }).join("");
  if(atBot) el.scrollTop = el.scrollHeight;
}

function renderAttackers(topIps){
  const w = document.getElementById("atk-wrap");
  if(!topIps||!topIps.length){w.innerHTML='<div class="empty"><span class="ico">👀</span>No attackers yet.</div>';return;}
  const max = topIps[0][1]||1;
  let html='<table class="htable"><thead><tr><th>#</th><th>IP Address</th><th>Country</th><th>Hits</th></tr></thead><tbody>';
  topIps.slice(0,15).forEach(([ip,cnt,geo],i)=>{
    const g = geo||{};
    const flag = g.countryCode ? String.fromCodePoint(...[...g.countryCode.toUpperCase()].map(c=>0x1F1E0+c.charCodeAt(0)-65)) : "";
    const country = g.country||"";
    const bar = Math.max(4,Math.round(cnt/max*100));
    html+=`<tr><td class="tc-dim">${i+1}</td><td class="tc-ip">${ip}</td>
      <td>${flag} ${country}</td>
      <td><span class="bar" style="width:${bar}px"></span><span class="tc-red">${cnt}</span></td></tr>`;
  });
  w.innerHTML=html+"</tbody></table>";
}

function renderGeo(events){
  const w = document.getElementById("geo-wrap");
  const counts = {};
  events.forEach(e=>{
    const g=e.geo||{};
    if(g.country){counts[g.country]=(counts[g.country]||{count:0,code:g.countryCode||""});counts[g.country].count++;}
  });
  const sorted = Object.entries(counts).sort((a,b)=>b[1].count-a[1].count).slice(0,8);
  if(!sorted.length){w.innerHTML='<div class="empty"><span class="ico">🌐</span>Waiting for geo data...</div>';return;}
  const max=sorted[0][1].count;
  let html='<table class="htable"><thead><tr><th>Country</th><th>Hits</th></tr></thead><tbody>';
  sorted.forEach(([country,{count,code}])=>{
    const flag = code ? String.fromCodePoint(...[...code.toUpperCase()].map(c=>0x1F1E0+c.charCodeAt(0)-65)) : "🌐";
    const bar = Math.max(4,Math.round(count/max*120));
    html+=`<tr><td>${flag} ${country}</td><td><span class="bar" style="width:${bar}px"></span><span class="tc-red">${count}</span></td></tr>`;
  });
  w.innerHTML=html+"</tbody></table>";
}

function renderCreds(creds){
  const w=document.getElementById("creds-wrap");
  if(!creds||!creds.length){w.innerHTML='<div class="empty"><span class="ico">🔒</span>No credentials captured yet.<br>Port 80 HTTP trap is armed.</div>';return;}
  let html='<table class="htable"><thead><tr><th>Time</th><th>IP</th><th>Username</th><th>Password</th></tr></thead><tbody>';
  creds.forEach(e=>{
    const c=e.creds||{};
    html+=`<tr><td class="tc-dim">${(e.ts||"").slice(11,19)}</td>
      <td class="tc-ip">${e.src_ip||"?"}</td>
      <td class="tc-yellow">${c.username||"?"}</td>
      <td class="tc-red">${c.password||"?"}</td></tr>`;
  });
  w.innerHTML=html+"</tbody></table>";
}

function renderWinEvents(wevents){
  const w=document.getElementById("we-wrap");
  const sa=document.getElementById("sysal-wrap");
  if(!wevents||!wevents.length){
    w.innerHTML='<div class="empty"><span class="ico">✅</span>No suspicious events detected.</div>';
    sa.innerHTML='<div class="empty"><span class="ico">✅</span>No system alerts.</div>';
    return;
  }
  // Overview widget (last 5)
  const recent5=wevents.slice(0,5);
  sa.innerHTML='<table class="htable"><tbody>'+recent5.map(e=>`
    <tr><td class="tc-dim" style="min-width:70px">${(e.ts||"").slice(11,19)}</td>
    <td><span class="sev ${e.severity||'info'}">${e.severity||""}</span></td>
    <td>${e.description||""}</td></tr>`).join("")+"</tbody></table>";
  // Full tab
  let html='<table class="htable"><thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>Details</th></tr></thead><tbody>';
  wevents.forEach(e=>{
    html+=`<tr><td class="tc-dim">${(e.ts||"").slice(0,19)}</td>
      <td class="tc-blue">${e.event_id} ${e.event_type||""}</td>
      <td><span class="sev ${e.severity||'info'}">${e.severity||""}</span></td>
      <td style="color:var(--dim);font-size:11px;max-width:380px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">${e.description||""}</td></tr>`;
  });
  w.innerHTML=html+"</tbody></table>";
}

function renderBlocked(lines){
  const w=document.getElementById("blk-wrap");
  if(!lines||!lines.length){w.innerHTML='<div class="empty"><span class="ico">🛡</span>No IPs auto-blocked yet.<br>Threshold: 15 hits in 10 min.</div>';return;}
  let html='<table class="htable"><thead><tr><th>Time</th><th>IP Address</th><th>Status</th></tr></thead><tbody>';
  lines.filter(l=>l.trim()).forEach(l=>{
    const m=l.match(/\[(.+?)\] (\S+)\s+(\S+)/);
    if(m)html+=`<tr><td class="tc-dim">${m[1].slice(0,19)}</td><td class="tc-ip">${m[3]}</td><td class="tc-purple">${m[2]}</td></tr>`;
  });
  w.innerHTML=html+"</tbody></table>";
}

// ── Poll loop ──────────────────────────────────────────────────────────────
let cd=3;
async function refresh(){
  try{
    const r=await fetch("/api/data");
    const d=await r.json();
    const s=d.summary||{};
    renderStats(s, d.cred_count||0, d.blocked_count||0);
    renderPortChart(s.port_stats||{});
    renderTimeChart(d.events||[]);
    renderFeed(d.events||[]);
    renderAttackers(d.top_ips_geo||[]);
    renderGeo(d.events||[]);
    renderCreds(d.cred_events||[]);
    renderWinEvents(d.win_events||[]);
    renderBlocked(d.blocked_lines||[]);
    const b=document.getElementById("status-badge");
    b.className="badge "+(d.alive?"armed":"offline");
    b.querySelector("span").textContent=d.alive?"ARMED":"OFFLINE";
  }catch(e){
    const b=document.getElementById("status-badge");
    b.className="badge offline";
    b.querySelector("span").textContent="OFFLINE";
  }
}

function tick(){
  cd--;
  document.getElementById("cd").textContent=cd;
  if(cd<=0){cd=3;refresh();}
}
refresh();
setInterval(tick,1000);
</script>
</body>
</html>"""

# ── Data helpers ─────────────────────────────────────────────────────────────

def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def read_jsonl(path, n=150):
    rows = []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        for ln in reversed(lines[-n:]):
            try:
                rows.append(json.loads(ln))
            except Exception:
                pass
    except Exception:
        pass
    return rows

def read_lines(path, n=200):
    try:
        with open(path, encoding="utf-8") as f:
            return f.readlines()[-n:]
    except Exception:
        return []

def uptime_str(since_iso):
    try:
        start = datetime.datetime.fromisoformat(since_iso)
        delta = datetime.datetime.now() - start
        h, r = divmod(int(delta.total_seconds()), 3600)
        return f"{h}h {r//60}m"
    except Exception:
        return "—"

def honeypot_alive():
    try:
        s = socket.create_connection(("127.0.0.1", 22), timeout=0.5)
        s.close()
        return True
    except Exception:
        return False

def build_top_ips_geo(events, summary):
    """Add geo data to top IPs list."""
    geo_map = {}
    for e in events:
        ip = e.get("src_ip")
        if ip and e.get("geo"):
            geo_map[ip] = e["geo"]
    result = []
    for ip, count in (summary.get("top_ips") or []):
        result.append([ip, count, geo_map.get(ip, {})])
    return result

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            b = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(b))
            self.end_headers()
            self.wfile.write(b)

        elif path == "/api/data":
            summary    = read_json(SUMMARY, {})
            events     = read_jsonl(EVENTS, 150)
            cred_evs   = [e for e in events if e.get("creds")]
            win_events = read_jsonl(WINEVENT, 100)
            blocked    = read_lines(BLOCKED, 100)
            summary["uptime"] = uptime_str(summary.get("uptime_since", ""))

            self.send_json({
                "summary":       summary,
                "events":        events,
                "cred_events":   cred_evs,
                "cred_count":    len(cred_evs),
                "win_events":    win_events,
                "blocked_lines": [l.rstrip() for l in blocked],
                "blocked_count": len([l for l in blocked if "BLOCKED" in l]),
                "top_ips_geo":   build_top_ips_geo(events, summary),
                "alive":         honeypot_alive(),
            })
        else:
            self.send_response(404); self.end_headers()

def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", DASH_PORT), Handler)
    print(f"HoneyShield Dashboard v2 → http://localhost:{DASH_PORT}")
    print("Ctrl+C to stop.\n")
    threading.Timer(1.2, lambda: webbrowser.open(f"http://localhost:{DASH_PORT}")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")

if __name__ == "__main__":
    main()
