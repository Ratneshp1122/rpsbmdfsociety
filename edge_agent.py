#!/usr/bin/env python3
import os
import hashlib
import sqlite3
import time
import json
import threading
from flask import Flask, jsonify
from flask_socketio import SocketIO
import schedule

# ----------------------------
# CONFIG
# ----------------------------
WATCHED_PATHS = [
    "/etc/passwd",
    "/etc/hosts",
    "/home/pi/fsociety/"
]

DB_FILE = "/home/pi/fsociety/logs/edge_agent.db"
ANOMALY_THRESHOLDS = {
    "hash_change": 1
}

CHECK_INTERVAL = 10  # seconds

# ----------------------------
# GLOBALS
# ----------------------------
telemetry = []
lock = threading.Lock()

# ----------------------------
# DATABASE SETUP
# ----------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS file_hashes (
            path TEXT PRIMARY KEY,
            hash TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            time REAL,
            path TEXT,
            hash TEXT,
            anomaly INTEGER
        )
    """)
    conn.commit()
    conn.close()

# ----------------------------
# HASHING & MONITORING
# ----------------------------
def hash_file(path):
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception as e:
        print(f"[ERROR] Hashing {path}: {e}")
        return None

def check_files():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    for path in WATCHED_PATHS:
        current_hash = hash_file(path)
        if current_hash is None:
            continue

        c.execute("SELECT hash FROM file_hashes WHERE path=?", (path,))
        row = c.fetchone()
        if row:
            if row[0] != current_hash:
                anomaly = 1
                print(f"[ALERT] File tampering detected: {path}")
                c.execute("UPDATE file_hashes SET hash=? WHERE path=?", (current_hash, path))
            else:
                anomaly = 0
        else:
            anomaly = 0
            c.execute("INSERT INTO file_hashes (path, hash) VALUES (?,?)", (path, current_hash))

        # Insert telemetry
        c.execute("INSERT INTO telemetry (time, path, hash, anomaly) VALUES (?,?,?,?)",
                  (time.time(), path, current_hash, anomaly))

        # Update global telemetry
        with lock:
            telemetry_event = {"time": time.time(), "path": path, "hash": current_hash, "anomaly": anomaly}
            telemetry.append(telemetry_event)
            socketio.emit('update', telemetry_event)
    conn.commit()
    conn.close()

# ----------------------------
# DASHBOARD SETUP
# ----------------------------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/api/logs')
def get_logs():
    with lock:
        return jsonify(telemetry[-50:])  # last 50 events

@app.route('/api/stats')
def get_stats():
    with lock:
        stats = {"total_events": len(telemetry), "anomalies": sum(e['anomaly'] for e in telemetry)}
        return jsonify(stats)

# ----------------------------
# SCHEDULER
# ----------------------------
def run_scheduler():
    schedule.every(CHECK_INTERVAL).seconds.do(check_files)
    while True:
        schedule.run_pending()
        time.sleep(1)

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    init_db()

    # Start file monitoring scheduler
    t = threading.Thread(target=run_scheduler)
    t.daemon = True
    t.start()

    # Start Flask dashboard
    socketio.run(app, host="0.0.0.0", port=8001)
