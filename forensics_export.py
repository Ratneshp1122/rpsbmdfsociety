#!/usr/bin/env python3
import os
import json
import sqlite3
import time
import threading
import hashlib
import zipfile
from flask import Flask, jsonify, send_file
from flask_socketio import SocketIO
import requests

# ----------------------------
# CONFIG
# ----------------------------
HONEYPOT_URL = "http://localhost:8000/api/logs"
EDGEAGENT_URL = "http://localhost:8001/api/logs"
CONTAINMENT_LOG = "/home/pi/fsociety/logs/containment.log"
EXPORT_DIR = "/home/pi/fsociety/forensics"
EXPORT_INTERVAL = 300  # seconds

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
lock = threading.Lock()
forensic_data = []

# ----------------------------
# HELPER FUNCTIONS
# ----------------------------
def fetch_json(url):
    try:
        resp = requests.get(url, timeout=3)
        return resp.json()
    except:
        return []

def read_containment_logs():
    if not os.path.exists(CONTAINMENT_LOG):
        return []
    with open(CONTAINMENT_LOG, "r") as f:
        lines = f.readlines()
    return [{"line": l.strip()} for l in lines]

def sign_file(filepath):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()

def export_forensics():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    export_file = os.path.join(EXPORT_DIR, f"forensics_{timestamp}.zip")

    # Gather all data
    hp_logs = fetch_json(HONEYPOT_URL)
    ea_logs = fetch_json(EDGEAGENT_URL)
    cont_logs = read_containment_logs()

    data = {
        "honeypot": hp_logs,
        "edge_agent": ea_logs,
        "containment": cont_logs,
        "timestamp": timestamp
    }

    # Save JSON for archive
    json_file = os.path.join(EXPORT_DIR, f"forensics_{timestamp}.json")
    with open(json_file, "w") as f:
        json.dump(data, f, indent=2)

    # Zip all logs
    with zipfile.ZipFile(export_file, "w") as zipf:
        zipf.write(json_file, os.path.basename(json_file))
        if os.path.exists(CONTAINMENT_LOG):
            zipf.write(CONTAINMENT_LOG, os.path.basename(CONTAINMENT_LOG))

    # Generate signature
    signature = sign_file(export_file)
    print(f"[FORENSICS] Exported: {export_file} | SHA256: {signature}")

    # Update global forensic data for dashboard
    with lock:
        forensic_data.append({
            "export_file": export_file,
            "signature": signature,
            "timestamp": timestamp,
            "events_count": len(hp_logs)+len(ea_logs)+len(cont_logs)
        })

# ----------------------------
# DASHBOARD ENDPOINTS
# ----------------------------
@app.route('/api/forensics')
def get_forensics():
    with lock:
        return jsonify(forensic_data[-10:])  # last 10 exports

@app.route('/api/download/<filename>')
def download_forensics(filename):
    filepath = os.path.join(EXPORT_DIR, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return "File not found", 404

# ----------------------------
# SCHEDULER LOOP
# ----------------------------
def scheduler_loop():
    while True:
        export_forensics()
        time.sleep(EXPORT_INTERVAL)

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    os.makedirs(EXPORT_DIR, exist_ok=True)
    t = threading.Thread(target=scheduler_loop)
    t.daemon = True
    t.start()
    socketio.run(app, host="0.0.0.0", port=8002)
