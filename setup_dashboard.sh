#!/bin/bash

# Fsociety Unified Dashboard Auto-Setup
# Run as root: sudo bash setup_dashboard.sh

echo "[*] Starting Fsociety Dashboard Setup..."

# 1. Update and install dependencies
echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-venv python3-pip git

# 2. Create project structure
BASE_DIR="/home/pi/fsociety_dashboard"
echo "[*] Creating folder structure at $BASE_DIR..."
mkdir -p $BASE_DIR/{dashboard/static/js,dashboard/templates,honeypot,edge_agent,containment,forensics}

# 3. Set up Python virtual environment
echo "[*] Creating Python virtual environment..."
python3 -m venv $BASE_DIR/venv
source $BASE_DIR/venv/bin/activate

# 4. Install Python packages
echo "[*] Installing Python packages..."
pip install --upgrade pip
pip install flask flask-socketio eventlet chart.js

# 5. Create dashboard_server.py
echo "[*] Creating dashboard server..."
cat > $BASE_DIR/dashboard/dashboard_server.py << 'EOF'
from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
import json, os, threading, time

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Paths to logs
HONEYPOT_LOG = "/home/pi/fsociety_dashboard/honeypot/logs.json"
EDGE_LOG = "/home/pi/fsociety_dashboard/edge_agent/logs.json"
CONTAINMENT_LOG = "/home/pi/fsociety_dashboard/containment/logs.json"
FORENSICS_DIR = "/home/pi/fsociety_dashboard/forensics"

def load_json(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []

def live_update():
    while True:
        hp_data = load_json(HONEYPOT_LOG)
        ea_data = load_json(EDGE_LOG)
        cont_data = load_json(CONTAINMENT_LOG)
        socketio.emit('update_data', {
            "honeypot": hp_data[-50:],
            "edge_agent": ea_data[-50:],
            "containment": cont_data[-50:]
        })
        time.sleep(3)

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/forensics")
def forensic_list():
    files = [f for f in os.listdir(FORENSICS_DIR) if f.endswith(".zip")]
    return jsonify(sorted(files, reverse=True))

@app.route("/forensics/download/<filename>")
def download_file(filename):
    path = os.path.join(FORENSICS_DIR, filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "Not found", 404

threading.Thread(target=live_update, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=9000)
EOF

# 6. Create frontend dashboard.html
echo "[*] Creating frontend HTML..."
cat > $BASE_DIR/dashboard/templates/dashboard.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fsociety Unified Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.socket.io/4.7.1/socket.io.min.js"></script>
<style>
body { font-family: Arial; background: #111; color: #eee; }
h1 { text-align: center; }
.dashboard { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; padding: 20px; }
canvas { background: #222; border-radius: 10px; }
.log-box { background: #222; padding: 10px; height: 300px; overflow-y: scroll; border-radius: 10px; }
</style>
</head>
<body>
<h1>Fsociety Unified Dashboard</h1>
<div class="dashboard">
  <div>
    <canvas id="honeypotChart"></canvas>
    <div class="log-box" id="honeypotLog"></div>
  </div>
  <div>
    <canvas id="edgeChart"></canvas>
    <div class="log-box" id="edgeLog"></div>
  </div>
  <div>
    <canvas id="containChart"></canvas>
    <div class="log-box" id="containLog"></div>
  </div>
</div>
<script>
const socket = io();
const hpChart = new Chart(document.getElementById('honeypotChart'), {type:'line', data:{labels:[], datasets:[{label:'Attacks', data:[], borderColor:'red', tension:0.3}]}})
const eaChart = new Chart(document.getElementById('edgeChart'), {type:'line', data:{labels:[], datasets:[{label:'Anomalies', data:[], borderColor:'yellow', tension:0.3}]}})
const contChart = new Chart(document.getElementById('containChart'), {type:'line', data:{labels:[], datasets:[{label:'Containment', data:[], borderColor:'cyan', tension:0.3}]}})
socket.on('update_data', data=>{
    hpChart.data.labels=data.honeypot.map((_,i)=>i); hpChart.data.datasets[0].data=data.honeypot.map(e=>e.severity||1); hpChart.update();
    eaChart.data.labels=data.edge_agent.map((_,i)=>i); eaChart.data.datasets[0].data=data.edge_agent.map(e=>e.anomaly_score||1); eaChart.update();
    contChart.data.labels=data.containment.map((_,i)=>i); contChart.data.datasets[0].data=data.containment.map(e=>e.severity||1); contChart.update();
    document.getElementById('honeypotLog').innerHTML=data.honeypot.map(e=>JSON.stringify(e)).join('<br>');
    document.getElementById('edgeLog').innerHTML=data.edge_agent.map(e=>JSON.stringify(e)).join('<br>');
    document.getElementById('containLog').innerHTML=data.containment.map(e=>JSON.stringify(e)).join('<br>');
});
</script>
</body>
</html>
EOF

# 7. Create systemd service
echo "[*] Creating systemd service..."
cat > /etc/systemd/system/fsoc_dashboard.service << EOF
[Unit]
Description=Fsociety Unified Dashboard
After=network.target

[Service]
User=pi
WorkingDirectory=$BASE_DIR/dashboard
ExecStart=$BASE_DIR/venv/bin/python $BASE_DIR/dashboard/dashboard_server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 8. Reload systemd and start service
echo "[*] Enabling and starting dashboard service..."
systemctl daemon-reload
systemctl enable fsoc_dashboard.service
systemctl start fsoc_dashboard.service

echo "[*] Setup complete! Access the dashboard at http://<pi-ip>:9000"
