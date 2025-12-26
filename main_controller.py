import subprocess
import time
import os
import sys
import json

from scanner.temporal_risk_engine import update_temporal_risk

# ===================== CONFIG =====================

SCAN_INTERVAL_SECONDS = 120
ANALYZE_EVERY_N_SCANS = 3

SCANNER_MODULE = "scanner.scanner"
TEMPORAL_MODULE = "scanner.temporal_analyzer"

SNAPSHOT_DIR = "snapshots"
TEMPORAL_EVENTS_FILE = "temporal_events.json"

FAILURE_BACKOFF_SECONDS = 300  # 5 minutes

# ===================== HELPERS =====================

def snapshot_count():
    if not os.path.exists(SNAPSHOT_DIR):
        return 0
    return sum(1 for f in os.listdir(SNAPSHOT_DIR) if f.endswith(".json"))


def run_module(module_name):
    return subprocess.run(
        [sys.executable, "-m", module_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


def load_temporal_events():
    if not os.path.exists(TEMPORAL_EVENTS_FILE):
        return []
    try:
        with open(TEMPORAL_EVENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def clear_temporal_events():
    """Consume events exactly once."""
    with open(TEMPORAL_EVENTS_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)

# ===================== CONTROLLER =====================

def main():
    print("\n=== Keylogger Detection Controller (Behavioral) ===\n")
    print(f"Scan interval        : {SCAN_INTERVAL_SECONDS}s")
    print(f"Temporal analysis    : every {ANALYZE_EVERY_N_SCANS} scans\n")

    scan_count = 0
    consecutive_failures = 0

    while True:
        print("[*] Running snapshot scanner...")
        scan_result = run_module(SCANNER_MODULE)

        if scan_result.returncode != 0:
            print("[!] Scanner error:")
            print(scan_result.stderr.strip())
            consecutive_failures += 1

            if consecutive_failures >= 3:
                print(f"[!] Too many failures — backing off {FAILURE_BACKOFF_SECONDS}s\n")
                time.sleep(FAILURE_BACKOFF_SECONDS)
                consecutive_failures = 0
            else:
                time.sleep(SCAN_INTERVAL_SECONDS)
            continue

        consecutive_failures = 0
        scan_count += 1
        print(scan_result.stdout.strip())

        # ---------- TEMPORAL ANALYSIS ----------
        if scan_count % ANALYZE_EVERY_N_SCANS == 0 and snapshot_count() >= 2:
            print("\n[*] Running temporal analyzer...")
            t_result = run_module(TEMPORAL_MODULE)

            if t_result.returncode != 0:
                print("[!] Temporal analyzer error:")
                print(t_result.stderr.strip())
            else:
                print(t_result.stdout.strip())

                # ---------- RISK UPDATE (consume events ONCE) ----------
                events = load_temporal_events()
                if events:
                    state = update_temporal_risk(events)
                    clear_temporal_events()

                    # ---------- ALERTING ----------
                    for pid, info in state.items():
                        if info["risk_level"] == "HIGH":
                            print("\n[!!!] HIGH RISK PROCESS DETECTED")
                            print(f" PID        : {pid}")
                            print(f" Risk Score : {info['risk_score']}")
                            print(f" Events     : {dict(info['event_counts'])}")
                            print("------------------------------------------------")

        print(f"\n[*] Sleeping {SCAN_INTERVAL_SECONDS} seconds...\n")
        time.sleep(SCAN_INTERVAL_SECONDS)

# ===================== ENTRY =====================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Controller stopped cleanly.")

