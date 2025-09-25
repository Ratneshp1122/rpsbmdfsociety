#!/usr/bin/env bash
#
# fsociety_deploy_and_run_all.sh
# Creates full implementations of 4 features, systemd units, venv, and starts services.
# Designed for Raspberry Pi isolated lab.
#
# Usage:
#   chmod +x fsociety_deploy_and_run_all.sh
#   ./fsociety_deploy_and_run_all.sh
#

set -euo pipefail

# CONFIG
USER_HOME="/home/pi"
BASE="${USER_HOME}/fsociety"
VENV="${BASE}/venv"
PY="${VENV}/bin/python"
PIP="${VENV}/bin/pip"

# Ports (non-privileged to avoid conflicts)
HONEYPOT_PORT_HTTP=8080
HONEYPOT_PORT_SSH=22022
HONEYPOT_PORT_FTP=2121
HONEYPOT_PORT_MYSQL=33060

DASHBOARD_PORT=9000
EDGE_PORT=8001
FORENSICS_PORT=8002

echo "[*] Preparing folders..."
mkdir -p "${BASE}"
mkdir -p "${BASE}/honeypot" "${BASE}/edge_agent" "${BASE}/containment" "${BASE}/forensics" "${BASE}/logs" "${BASE}/db"

# 1) Create venv and install packages
if [ ! -d "${VENV}" ]; then
  echo "[*] Creating Python venv..."
  python3 -m venv "${VENV}"
fi

echo "[*] Activating venv and installing Python packages..."
# shellcheck disable=SC1090
source "${VENV}/bin/activate"
${PIP} install --upgrade pip
${PIP} install flask requests schedule python-nmap flask-socketio eventlet

# 2) Write Honeypot (feature 1) - multi-port, realistic banners, JSON logging
cat > "${BASE}/honeypot_server.py" <<'PYHON'
#!/usr/bin/env python3
"""
Honeypot Server (Feature 1)
- Listens on configurable non-privileged ports to avoid conflicts
- Sends banners, records events into JSON log for dashboard
"""
import socket, threading, json, time, os

BASE = os.path.expanduser(os.path.join("~", "fsociety"))
LOG_PATH = os.path.join(BASE, "honeypot", "logs.json")

SERVICES = [
    {"name": "HTTP", "port": 8080, "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4. FakeHost\r\n\r\n<h1>Fsociety</h1>"},
    {"name": "SSH",  "port": 22022, "banner": "SSH-2.0-OpenSSH_8.9"},
    {"name": "FTP",  "port": 2121, "banner": "220 (vsFTPd 3.0.3)"},
    {"name": "MySQL","port": 33060,"banner": "5.7.37-FakeMySQL"}
]

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
# Initialize log file if missing
if not os.path.exists(LOG_PATH):
    with open(LOG_PATH,"w") as f:
        json.dump([], f)

log_lock = threading.Lock()

def append_event(evt):
    with log_lock:
        arr = []
        try:
            with open(LOG_PATH,"r") as f:
                arr = json.load(f)
        except Exception:
            arr = []
        arr.append(evt)
        # keep last 200 events
        arr = arr[-200:]
        with open(LOG_PATH,"w") as f:
            json.dump(arr, f)

def handle_client(conn, addr, svc):
    with conn:
        try:
            src_ip = addr[0]
            src_port = addr[1]
            now = time.time()
            # send banner (some services expect binary handshake)
            try:
                conn.sendall(svc["banner"].encode(errors="ignore"))
            except Exception:
                pass
            # non-blocking short read for payload
            conn.settimeout(2.0)
            payload = ""
            try:
                payload = conn.recv(2048).decode(errors="ignore")
            except Exception:
                payload = ""
            # simple anomaly scoring heuristics
            severity = 1
            if "password" in payload.lower() or "login" in payload.lower():
                severity += 2
            if len(payload) > 100:
                severity += 1
            evt = {
                "ts": now,
                "service": svc["name"],
                "port": svc["port"],
                "source_ip": src_ip,
                "source_port": src_port,
                "payload": (payload[:400] if payload else ""),
                "severity": severity
            }
            append_event(evt)
            print("[HONEYPOT] Logged", svc["name"], src_ip)
        except Exception as e:
            print("Honeypot client error:", e)

def run_service(svc):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", svc["port"]))
        sock.listen(8)
        print(f"[HONEYPOT] {svc['name']} listening on {svc['port']}")
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, svc))
            t.daemon = True
            t.start()
    except Exception as e:
        print(f"[HONEYPOT] Could not listen on {svc['port']}: {e}")

if __name__ == "__main__":
    threads = []
    for s in SERVICES:
        t = threading.Thread(target=run_service, args=(s,))
        t.daemon = True
        t.start()
        threads.append(t)
    # keep running
    while True:
        time.sleep(1)
PYHON

chmod +x "${BASE}/honeypot_server.py"

# 3) Write Edge Agent (feature 2) - full hashing, baseline, anomaly scoring
cat > "${BASE}/edge_agent.py" <<'PYTH'
#!/usr/bin/env python3
"""
Edge Agent (Feature 2)
- Monitors a set of files/directories
- Stores baseline hashes and detects changes
- Writes JSON events to logs for dashboard
"""
import os, hashlib, sqlite3, time, json, schedule, threading

BASE = os.path.expanduser(os.path.join("~","fsociety"))
DB_DIR = os.path.join(BASE,"db")
LOG_PATH = os.path.join(BASE,"edge_agent","logs.json")
BASELINE_DB = os.path.join(DB_DIR,"edge_baseline.db")

WATCH = [
    "/etc/passwd",
    "/etc/hosts",
    os.path.join(BASE, "")  # monitor project folder recursively (small demo)
]

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

# init logs
if not os.path.exists(LOG_PATH):
    with open(LOG_PATH,"w") as f:
        json.dump([],f)

# sqlite baseline
def init_db():
    conn = sqlite3.connect(BASELINE_DB)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS baseline (path TEXT PRIMARY KEY, hash TEXT, ts INTEGER)")
    conn.commit()
    conn.close()

def sha256_of_file(path):
    try:
        h = hashlib.sha256()
        with open(path,"rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def append_event(evt):
    # keep JSON log for dashboard
    with open(LOG_PATH,"r") as f:
        arr = json.load(f)
    arr.append(evt)
    arr = arr[-200:]
    with open(LOG_PATH,"w") as f:
        json.dump(arr, f)

def scan_paths():
    init_db()
    conn = sqlite3.connect(BASELINE_DB)
    c = conn.cursor()
    timestamp = time.time()
    # check files
    for p in WATCH:
        if os.path.isdir(p):
            # scan small directory recursively (only files <1MB to avoid heavy IO)
            for root, dirs, files in os.walk(p):
                for fname in files:
                    fp = os.path.join(root,fname)
                    try:
                        if os.path.getsize(fp) > 1024*1024:
                            continue
                    except Exception:
                        continue
                    h = sha256_of_file(fp)
                    if h is None:
                        continue
                    c.execute("SELECT hash FROM baseline WHERE path=?", (fp,))
                    row = c.fetchone()
                    if row:
                        if row[0] != h:
                            evt = {"ts": timestamp, "path": fp, "old_hash": row[0], "new_hash": h, "anomaly": 1}
                            append_event(evt)
                            c.execute("UPDATE baseline SET hash=?, ts=? WHERE path=?", (h, int(timestamp), fp))
                    else:
                        c.execute("INSERT INTO baseline(path,hash,ts) VALUES (?,?,?)", (fp,h,int(timestamp)))
        else:
            h = sha256_of_file(p)
            if h is None:
                continue
            c.execute("SELECT hash FROM baseline WHERE path=?", (p,))
            row = c.fetchone()
            if row:
                if row[0] != h:
                    evt = {"ts": timestamp, "path": p, "old_hash": row[0], "new_hash": h, "anomaly": 1}
                    append_event(evt)
                    c.execute("UPDATE baseline SET hash=?, ts=? WHERE path=?", (h, int(timestamp), p))
            else:
                c.execute("INSERT INTO baseline(path,hash,ts) VALUES (?,?,?)", (p,h,int(timestamp)))
    conn.commit()
    conn.close()

def run_scheduler():
    schedule.every(30).seconds.do(scan_paths)
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    import schedule, time
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    init_db()
    # initial scan
    scan_paths()
    # schedule thread
    t = threading.Thread(target=run_scheduler)
    t.daemon = True
    t.start()
    while True:
        time.sleep(1)
PYTH

chmod +x "${BASE}/edge_agent.py"

# 4) Write Containment Orchestrator (feature 3) - reads logs and acts safely
cat > "${BASE}/containment_orchestrator.py" <<'PYCO'
#!/usr/bin/env python3
"""
Containment Orchestrator (Feature 3)
- Polls honeypot and edge_agent JSON logs
- If thresholds hit, perform safe containment actions:
  - Stop listening services (kills processes holding ports)
  - Rollback backed up files (path.bak)
- Writes containment actions to a JSON log for dashboard
"""
import os, time, json, subprocess, requests

BASE = os.path.expanduser(os.path.join("~","fsociety"))
HP_LOG = os.path.join(BASE,"honeypot","logs.json")
EA_LOG = os.path.join(BASE,"edge_agent","logs.json")
CONT_LOG = os.path.join(BASE,"containment","logs.json")

os.makedirs(os.path.dirname(CONT_LOG), exist_ok=True)
if not os.path.exists(CONT_LOG):
    with open(CONT_LOG,"w") as f:
        json.dump([], f)

def append_contain(evt):
    with open(CONT_LOG,"r") as f:
        arr = json.load(f)
    arr.append(evt)
    arr = arr[-200:]
    with open(CONT_LOG,"w") as f:
        json.dump(arr,f)

def read_json(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return []

def stop_port(port):
    # kill process using the port (safe demo)
    try:
        subprocess.run(["sudo","fuser","-k", f"{port}/tcp"], check=False)
        return True
    except Exception:
        return False

def rollback_file(path):
    bak = path + ".bak"
    if os.path.exists(bak):
        try:
            subprocess.run(["cp", bak, path], check=True)
            return True
        except Exception:
            return False
    return False

def evaluate_and_act():
    hp = read_json(HP_LOG)
    ea = read_json(EA_LOG)
    # simple detection: repeated hits from same IP on a service -> stop that service port
    offenders = {}
    for e in hp:
        key = (e.get("source_ip"), e.get("service"))
        offenders[key] = offenders.get(key, 0) + 1
    for (ip, svc), count in offenders.items():
        if count > 6:
            # find port for svc
            svc_map = {"HTTP":8080, "SSH":22022, "FTP":2121, "MySQL":33060}
            port = svc_map.get(svc)
            if port:
                ok = stop_port(port)
                evt = {"ts": time.time(), "action": "stop_port", "port": port, "service": svc, "source_ip": ip, "result": ok}
                append_contain(evt)
    # check file anomalies
    for entry in ea:
        if entry.get("anomaly"):
            path = entry.get("path")
            ok = rollback_file(path)
            evt = {"ts": time.time(), "action":"rollback_file", "path": path, "result": ok}
            append_contain(evt)

if __name__ == "__main__":
    while True:
        try:
            evaluate_and_act()
        except Exception as e:
            print("Containment error:", e)
        time.sleep(5)
PYCO

chmod +x "${BASE}/containment_orchestrator.py"

# 5) Write Forensics exporter (feature 4)
cat > "${BASE}/forensics_export.py" <<'PYF'
#!/usr/bin/env python3
"""
Forensics Export (Feature 4)
- Reads honeypot, edge_agent, containment logs
- Correlates into a single JSON timeline
- Creates zip and SHA256 signature
- Writes metadata into forensics folder
"""
import os, json, time, zipfile, hashlib

BASE = os.path.expanduser(os.path.join("~","fsociety"))
HP_LOG = os.path.join(BASE,"honeypot","logs.json")
EA_LOG = os.path.join(BASE,"edge_agent","logs.json")
CONT_LOG = os.path.join(BASE,"containment","logs.json")
OUT_DIR = os.path.join(BASE,"forensics")
os.makedirs(OUT_DIR, exist_ok=True)

def gather():
    def load(p):
        try:
            with open(p) as f:
                return json.load(f)
        except:
            return []
    hp = load(HP_LOG)
    ea = load(EA_LOG)
    cont = load(CONT_LOG)
    # naive correlation: merge sorted by ts (if missing ts, set 0)
    events = []
    for e in hp: events.append({"type":"honeypot","data":e,"ts":e.get("ts",0)})
    for e in ea: events.append({"type":"edge","data":e,"ts":e.get("ts", e.get("time",0))})
    for e in cont: events.append({"type":"contain","data":e,"ts":e.get("ts",0)})
    events = sorted(events, key=lambda x: x["ts"])
    return {"ts": time.time(), "events": events, "counts": {"hp":len(hp),"ea":len(ea),"cont":len(cont)}}

def export():
    d = gather()
    ts = time.strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(OUT_DIR, f"forensics_{ts}.json")
    zip_path = os.path.join(OUT_DIR, f"forensics_{ts}.zip")
    with open(json_path, "w") as f:
        json.dump(d, f, indent=2)
    with zipfile.ZipFile(zip_path, "w") as z:
        z.write(json_path, os.path.basename(json_path))
    # sha256
    h = hashlib.sha256()
    with open(zip_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    sig = h.hexdigest()
    meta = {"zip": os.path.basename(zip_path), "sha256": sig, "ts": ts}
    with open(os.path.join(OUT_DIR, f"forensics_{ts}.meta.json"), "w") as f:
        json.dump(meta, f)
    print("[FORENSICS] Exported:", zip_path)
    return zip_path, sig

if __name__ == "__main__":
    # run export every 5 minutes
    while True:
        try:
            export()
        except Exception as e:
            print("Forensics error:", e)
        time.sleep(300)
PYF

chmod +x "${BASE}/forensics_export.py"

# 6) Create simple dashboard server that reads these JSON logs (overrides previous dashboards or works standalone)
cat > "${BASE}/dashboard_server.py" <<'PYDB'
#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
import os, json, time, threading

BASE = os.path.expanduser(os.path.join("~","fsociety"))
HP_LOG = os.path.join(BASE,"honeypot","logs.json")
EA_LOG = os.path.join(BASE,"edge_agent","logs.json")
CONT_LOG = os.path.join(BASE,"containment","logs.json")
FOR_DIR = os.path.join(BASE,"forensics")

app = Flask(__name__, template_folder=os.path.join(BASE,"dashboard_templates"))
socketio = SocketIO(app, cors_allowed_origins="*")

def load_json(p):
    try:
        with open(p) as f:
            return json.load(f)
    except:
        return []

def live_loop():
    while True:
        hp = load_json(HP_LOG)
        ea = load_json(EA_LOG)
        cont = load_json(CONT_LOG)
        socketio.emit("update_data", {"honeypot": hp[-200:], "edge_agent": ea[-200:], "containment": cont[-200:]})
        time.sleep(2)

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/forensics")
def list_forensics():
    res = []
    if os.path.exists(FOR_DIR):
        for f in sorted(os.listdir(FOR_DIR), reverse=True):
            if f.endswith(".zip"):
                res.append(f)
    return jsonify(res)

@app.route("/api/forensics/download/<fname>")
def download(fname):
    path = os.path.join(FOR_DIR, fname)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "Not found", 404

if __name__ == "__main__":
    os.makedirs(os.path.join(BASE,"dashboard_templates"), exist_ok=True)
    # ensure template exists (simple frontend)
    if not os.path.exists(os.path.join(BASE,"dashboard_templates","dashboard.html")):
        with open(os.path.join(BASE,"dashboard_templates","dashboard.html"), "w") as fh:
            fh.write("""
<!doctype html>
<html><head>
<title>Fsociety Unified Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.socket.io/4.7.1/socket.io.min.js"></script>
<style>body{font-family:Arial;background:#111;color:#eee} .box{background:#222;padding:10px;margin:10px;border-radius:6px}</style>
</head><body>
<h1>Fsociety Unified Dashboard</h1>
<div id="hp" class="box"><h3>Honeypot</h3><pre id="hp_pre"></pre></div>
<div id="ea" class="box"><h3>Edge Agent</h3><pre id="ea_pre"></pre></div>
<div id="ct" class="box"><h3>Containment</h3><pre id="ct_pre"></pre></div>
<script>
const socket = io();
socket.on("update_data", data => {
  document.getElementById("hp_pre").innerText = JSON.stringify(data.honeypot.slice(-30),null,2);
  document.getElementById("ea_pre").innerText = JSON.stringify(data.edge_agent.slice(-30),null,2);
  document.getElementById("ct_pre").innerText = JSON.stringify(data.containment.slice(-30),null,2);
});
</script>
</body></html>
""")
    t = threading.Thread(target=live_loop, daemon=True)
    t.start()
    socketio.run(app, host="0.0.0.0", port=9000)
PYDB

chmod +x "${BASE}/dashboard_server.py"

# 7) Create systemd service files for each component
echo "[*] Creating systemd units..."

create_unit(){
  name="$1"
  exec="$2"
  cat > "/etc/systemd/system/${name}.service" <<EOF
[Unit]
Description=Fsociety ${name}
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=${BASE}
ExecStart=${exec}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

create_unit "fsoc-honeypot" "${PY} ${BASE}/honeypot_server.py"
create_unit "fsoc-edgeagent" "${PY} ${BASE}/edge_agent.py"
create_unit "fsoc-containment" "${PY} ${BASE}/containment_orchestrator.py"
create_unit "fsoc-forensics" "${PY} ${BASE}/forensics_export.py"
create_unit "fsoc-dashboard" "${PY} ${BASE}/dashboard_server.py"

# 8) Reload systemd, enable & start services
echo "[*] Reloading systemd and starting services..."
sudo systemctl daemon-reload
sudo systemctl enable --now fsoc-honeypot fsoc-edgeagent fsoc-containment fsoc-forensics fsoc-dashboard

# 9) Print status summary
sleep 1
echo
echo "=== Service status summary ==="
sudo systemctl status fsoc-honeypot --no-pager | sed -n '1,6p'
sudo systemctl status fsoc-edgeagent --no-pager | sed -n '1,6p'
sudo systemctl status fsoc-containment --no-pager | sed -n '1,6p'
sudo systemctl status fsoc-forensics --no-pager | sed -n '1,6p'
sudo systemctl status fsoc-dashboard --no-pager | sed -n '1,6p'

echo
echo "[*] All components deployed and started."
echo "Dashboard: http://<pi-ip>:9000"
echo "Honeypot JSON: ${BASE}/honeypot/logs.json"
echo "Edge Agent JSON: ${BASE}/edge_agent/logs.json"
echo "Containment JSON: ${BASE}/containment/logs.json"
echo "Forensics folder: ${BASE}/forensics"
echo
echo "=== Quick tests you can run from your Windows laptop (in the same isolated LAN) ==="
echo "1) Open dashboard: http://<pi-ip>:9000"
echo "2) Trigger honeypot HTTP hit:"
echo "   curl http://<pi-ip>:8080/"
echo "3) Trigger honeypot SSH-like hit:"
echo "   (PowerShell) \$c=New-Object System.Net.Sockets.TcpClient('"<pi-ip>"',22022); \$s=\$c.GetStream(); \$b=[System.Text.Encoding]::ASCII.GetBytes('login test`n'); \$s.Write(\$b,0,\$b.Length); \$s.Close(); \$c.Close()"
echo "4) Check logs on Pi:"
echo "   tail -n 30 ${BASE}/honeypot/logs.json"
echo
echo "[DONE] fsociety deploy+run script finished."
