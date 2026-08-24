"""
simulator/attack_replay.py
--------------------------
Deterministic Multi-Stage Attack Simulator for Chimera SOC Platform.

Replays realistic telemetry payloads targeting:
1. /admin/config.php - Admin endpoint probe / unauthorized access
2. /api/login        - SQL Injection authentication bypass
3. /etc/passwd       - Path traversal / credential harvesting
"""

import sys
import time
import requests

# Ensure UTF-8 output encoding on Windows consoles
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

API_URL = "http://localhost:8000/api/ingest"

# 3 Distinct attack payloads reflecting MITRE ATT&CK techniques
ATTACK_STAGES = [
    {
        "stage": "Stage 1: Admin Interface Probing & Reconnaissance",
        "data": {
            "source_ip": "45.33.32.156",
            "payload": {
                "path": "/admin/config.php",
                "method": "POST",
                "body": "action=dump_config&key=database_password",
            },
            "source": "waf_edge_sensor",
            "event_type": "admin_probe",
            "target_host": "web-prod-01",
            "decoy_used": True,
            "blast_radius_hosts": 2,
            "asset_criticality": 0.85,
        },
    },
    {
        "stage": "Stage 2: SQL Injection (SQLi) Auth Bypass",
        "data": {
            "source_ip": "194.26.29.112",
            "payload": {
                "path": "/api/login",
                "method": "POST",
                "body": "username=admin' OR 1=1 --&password=invalid",
            },
            "source": "api_gateway",
            "event_type": "sql_injection_attempt",
            "target_host": "web-prod-01",
            "decoy_used": True,
            "blast_radius_hosts": 2,
            "asset_criticality": 0.9,
        },
    },
    {
        "stage": "Stage 3: Path Traversal & OS Credential Dumping",
        "data": {
            "source_ip": "185.220.101.5",
            "payload": {
                "path": "/etc/passwd",
                "method": "GET",
            },
            "source": "web_proxy_sensor",
            "event_type": "directory_traversal",
            "target_host": "web-prod-01",
            "decoy_used": False,
            "blast_radius_hosts": 1,
            "asset_criticality": 0.8,
        },
    },
]


def run_attack_simulation():
    """
    Executes the multi-stage attack simulation sequence against the SOC ingestion API.
    """
    print("=" * 70)
    print(" [*] CHIMERA SOC - DETERMINISTIC ATTACK SIMULATION ENGINE")
    print(f" [*] Target Endpoint: {API_URL}")
    print(f" [*] Interval: 4 seconds between attack vectors")
    print("=" * 70)

    total_stages = len(ATTACK_STAGES)

    for idx, attack in enumerate(ATTACK_STAGES, 1):
        stage_name = attack["stage"]
        payload_data = attack["data"]
        source_ip = payload_data["source_ip"]
        target_path = payload_data["payload"]["path"]

        print(f"\n[{idx}/{total_stages}] Transmitting {stage_name}...")
        print(f"    |-- Origin IP   : {source_ip}")
        print(f"    |-- Target Path : {target_path}")

        try:
            start_time = time.time()
            response = requests.post(API_URL, json=payload_data, timeout=10)
            elapsed = time.time() - start_time

            if response.status_code == 200:
                res_json = response.json()
                print(f"    |-- Status      : [200 OK] ({elapsed:.2f}s)")
                print(f"    |-- Event ID    : {res_json.get('event_id')}")
                print(f"    |-- Incident ID : {res_json.get('incident_id')}")
                print(f"    |-- Threat Level: {res_json.get('threat_level', '').upper()}")
                print(f"    |-- MITRE Tactic: {res_json.get('mitre_tactic')} ({res_json.get('mitre_technique')})")
                print(f"    |-- Risk Score  : {res_json.get('risk_score')} (Decision: {res_json.get('risk_status')})")
                print(f"    |-- Action      : {res_json.get('risk_action')}")
                print(f"    [+] Simulation stage succeeded. Broadcast sent to /ws/console.")
            else:
                print(f"    [-] Failed with HTTP {response.status_code}: {response.text}")

        except requests.exceptions.RequestException as err:
            print(f"    [-] Network/Connection Error: {err}")

        # Sleep 4 seconds between stages
        if idx < total_stages:
            print("    ... Waiting 4 seconds before next attack stage ...")
            time.sleep(4)

    print("\n" + "=" * 70)
    print(" [OK] All attack simulation stages completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_attack_simulation()
