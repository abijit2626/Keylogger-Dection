import subprocess
import time
import json
import os
import sys

from scanner.temporal_risk_engine import update_temporal_risk

SCAN_INTERVAL = 120
ANALYZE_EVERY = 3

SCANNER = "scanner.scanner"
ANALYZER = "scanner.temporal_analyzer"
EVENT_FILE = "temporal_events.json"

print("[DEBUG] CONTROLLER:", __file__)



def run(module):
    return subprocess.run(
        [sys.executable, "-m", module],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


def load_events():
    if not os.path.exists(EVENT_FILE):
        return []
    with open(EVENT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def clear_events():
    with open(EVENT_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)


def main():
    count = 0
    while True:
        run(SCANNER)
        count += 1

        if count % ANALYZE_EVERY == 0:
            run(ANALYZER)
            events = load_events()
            if events:
                state = update_temporal_risk(events)
                clear_events()

                for ident, s in state.items():
                    if s["risk_level"] == "HIGH":
                        print("[!!!] HIGH RISK:", s["exe"])

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
