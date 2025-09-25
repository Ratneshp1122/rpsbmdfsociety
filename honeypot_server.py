#!/usr/bin/env python3
import socket
import threading
import time
import json
import os
from flask import Flask, jsonify
from flask_socketio import SocketIO

# ----------------------------
# CONFIG
# ----------------------------
HONEYPOT_SERVICES = [
    {"name": "SSH", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Debian-3"},
    {"name": "HTTP", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52"},
    {"name": "FTP", "port": 21, "banner": "220 (vsFTPd 3.0.3)"},
    {"name": "MySQL", "port": 3306, "banner": "5.7.37-0ubuntu0.18.04.1"}
]

LOG_FILE = "/home/pi/fsociety/logs/honeypot_logs.json"
DECOY_FILES = {
    "/tmp/fake_pass.txt": "root:toor\nadmin:12345",
    "/tmp/fake_config.cfg": "key=ABCD1234\nsecret=XYZ987"
}

ANOMALY_THRESHOLDS = {
    "login_attempts": 5,
    "port_scan": 10
}

# ----------------------------
# GLOBALS
# ----------------------------
telemetry = []
lock = threading.Lock()

# ----------------------------
# FLASK DASHBOARD
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
        stats = {"total_events": len(telemetry)}
        return jsonify(stats)

# ----------------------------
# HONEYPOT HANDLER
# ----------------------------
def handle_connection(conn, addr, service_name, banner):
    with conn:
        try:
            telemetry_event = {
                "time": time.time(),
                "source_ip": addr[0],
                "source_port": addr[1],
                "service": service_name
            }
            print(f"[{service_name}] Connection from {addr}")
            conn.sendall((banner + "\r\n").encode())

            # Simulate decoy file access if attacker sends file request
            data = conn.recv(1024).decode(errors='ignore')
            for f, content in DECOY_FILES.items():
                if f in data:
                    telemetry_event["decoy_accessed"] = f
            # Append to telemetry
            with lock:
                telemetry.append(telemetry_event)
                socketio.emit('update', telemetry_event)

            # Check anomaly thresholds (simplified)
            count = sum(1 for t in telemetry if t['source_ip'] == addr[0])
            if count > ANOMALY_THRESHOLDS["login_attempts"]:
                print(f"[ALERT] {addr[0]} triggered login anomaly")
        except Exception as e:
            print(f"[{service_name}] Error: {e}")

def start_service(service):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", service["port"]))
        sock.listen(5)
        print(f"[{service['name']}] Listening on port {service['port']}")
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(conn, addr, service["name"], service["banner"]))
            t.start()
    except PermissionError:
        print(f"[ERROR] Need root to bind port {service['port']}")
    except Exception as e:
        print(f"[{service['name']}] Socket error: {e}")

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    # Ensure log folder exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    # Start honeypot services in threads
    for service in HONEYPOT_SERVICES:
        t = threading.Thread(target=start_service, args=(service,))
        t.daemon = True
        t.start()

    # Start Flask dashboard
    socketio.run(app, host="0.0.0.0", port=8000)
