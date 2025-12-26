import time
import json
import os

STATE_FILE = "temporal_state.json"

# ===================== CONFIG =====================
print("[DEBUG] temporal_risk_engine LOADED FROM:", __file__)
EVENT_WEIGHTS = {
    "HOOK_APPEARED": 8,
    "NEW_HOOK_MODULE": 30,
    "HOOK_REMOVED": -5,
    "HOOK_PERSISTED": 0
}

DECAY_PER_UPDATE = 2
ESCALATE_MEDIUM = 30
ESCALATE_HIGH = 60


def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def update_temporal_risk(events):
    """
    Identity-hardened temporal risk engine.
    Identity = exe + lifetime (create_time)
    """

    state = load_state()
    now = time.time()
    touched = set()

    # ---------- EVENT INGEST ----------
    for event in events:
        identity = event["identity"]
        etype = event["event"]

        if identity not in state:
            state[identity] = {
                "risk_score": 0,
                "risk_level": "LOW",
                "event_counts": {},
                "first_seen": now,
                "last_seen": now,
                "exe": event.get("exe")
            }

        entry = state[identity]
        touched.add(identity)

        entry["event_counts"][etype] = entry["event_counts"].get(etype, 0) + 1
        entry["last_seen"] = now
        entry["risk_score"] += EVENT_WEIGHTS.get(etype, 0)

    # ---------- PER-IDENTITY REASONING ----------
    for identity in touched:
        entry = state[identity]

        has_persistence = entry["event_counts"].get("HOOK_PERSISTED", 0) >= 2
        has_real_signal = (
            entry["event_counts"].get("HOOK_APPEARED", 0) > 0 or
            entry["event_counts"].get("NEW_HOOK_MODULE", 0) > 0
        )

        if has_persistence and has_real_signal:
            entry["risk_score"] += 5

        entry["risk_score"] = max(0, entry["risk_score"] - DECAY_PER_UPDATE)

        if entry["risk_score"] >= ESCALATE_HIGH:
            entry["risk_level"] = "HIGH"
        elif entry["risk_score"] >= ESCALATE_MEDIUM:
            entry["risk_level"] = "MEDIUM"
        else:
            entry["risk_level"] = "LOW"

    save_state(state)
    return state

