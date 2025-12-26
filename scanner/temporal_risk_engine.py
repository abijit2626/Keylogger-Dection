import time
import json
import os

STATE_FILE = "temporal_state.json"

EVENT_WEIGHTS = {
    "HOOK_APPEARED": 10,     # weak-to-medium signal
    "NEW_HOOK_MODULE": 35,   # strong signal
    "HOOK_REMOVED": -10     # relief
}

DECAY = 3
MEDIUM = 30
HIGH = 60


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def update_temporal_risk(events):
    state = load_state()
    now = time.time()
    touched = set()

    # --- ingest change events only ---
    for e in events:
        identity = e["identity"]
        etype = e["event"]

        if identity not in state:
            state[identity] = {
                "risk_score": 0,
                "risk_level": "LOW",
                "event_counts": {},
                "first_seen": now,
                "last_seen": now,
                "exe": e["exe"]
            }

        s = state[identity]
        touched.add(identity)

        s["event_counts"][etype] = s["event_counts"].get(etype, 0) + 1
        s["risk_score"] += EVENT_WEIGHTS.get(etype, 0)
        s["last_seen"] = now

    # --- decay & classification ---
    for identity in touched:
        s = state[identity]

        s["risk_score"] = max(0, s["risk_score"] - DECAY)

        if s["risk_score"] >= HIGH:
            s["risk_level"] = "HIGH"
        elif s["risk_score"] >= MEDIUM:
            s["risk_level"] = "MEDIUM"
        else:
            s["risk_level"] = "LOW"

    save_state(state)
    return state
