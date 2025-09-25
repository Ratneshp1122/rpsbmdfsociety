#!/usr/bin/env python3
import os
import json
import time
import threading
import subprocess
import requests

# ----------------------------
# CONFIG
# ----------------------------
HONEYPOT_URL = "http://localhost:8000/api/logs"       # change to RPI IP if needed
EDGEAGENT_URL = "http://localhost:8001/api/logs"     # change to RPI IP if needed
CHECK_INTERVAL = 5  # seconds
CONTAINMENT_LOG = "/home/pi/fsociety/logs/containment.log"

# Thresholds for automated actions
MAX_LOGIN_ATTEMPTS = 5
FILE_ANOMALY_ALERT = 1

# ----------------------------
# HELPERS
# ----------------------------
def log_event(message):
    os.makedirs(os.path.dirname(CONTAINMENT_LOG), exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(CONTAINMENT_LOG, "a") as f:
        f.write(f"{timestamp} - {message}\n")
    print(f"[CONTAINMENT] {message}")

def fetch_json(url):
    try:
        resp = requests.get(url, timeout=3)
        return resp.json()
    except Exception as e:
        log_event(f"Error fetching {url}: {e}")
        return []

# ----------------------------
# CONTAINMENT ACTIONS
# ----------------------------
def stop_service(port):
    """Simulate stopping service bound to a port (just kills for demo)"""
    try:
        cmd = f"sudo fuser -k {port}/tcp"
        subprocess.run(cmd, shell=True)
        log_event(f"Service on port {port} stopped")
    except Exception as e:
        log_event(f"Failed to stop service on port {port}: {e}")

def rollback_file(path):
    """Simulate rollback of file (backup copy)"""
    try:
        backup = path + ".bak"
        if os.path.exists(backup):
            subprocess.run(f"cp {backup} {path}", shell=True)
            log_event(f"Rolled back file {path}")
        else:
            log_event(f"No backup for {path}, cannot rollback")
    except Exception as e:
        log_event(f"Failed rollback for {path}: {e}")

# ----------------------------
# MONITORING LOOP
# ----------------------------
def monitor_loop():
    known_offenders = {}
    while True:
        # --- Check Honeypot logs ---
        hp_logs = fetch_json(HONEYPOT_URL)
        for event in hp_logs:
            ip = event.get("source_ip")
            service = event.get("service")
            if ip not in known_offenders:
                known_offenders[ip] = {}
            known_offenders[ip][service] = known_offenders[ip].get(service, 0) + 1

            if known_offenders[ip][service] > MAX_LOGIN_ATTEMPTS:
                log_event(f"IP {ip} triggered threshold on {service}, taking action")
                # simulate service stop
                if service == "SSH":
                    stop_service(22)
                elif service == "HTTP":
                    stop_service(80)
                elif service == "FTP":
                    stop_service(21)
                elif service == "MySQL":
                    stop_service(3306)

        # --- Check Edge Agent logs ---
        ea_logs = fetch_json(EDGEAGENT_URL)
        for entry in ea_logs:
            if entry.get("anomaly") >= FILE_ANOMALY_ALERT:
                path = entry.get("path")
                log_event(f"File anomaly detected: {path}")
                rollback_file(path)

        time.sleep(CHECK_INTERVAL)

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    log_event("Containment Orchestrator started")
    t = threading.Thread(target=monitor_loop)
    t.daemon = True
    t.start()
    t.join()
