import os
import json
from collections import defaultdict

SNAPSHOT_DIR = "snapshots"
OUTPUT_FILE = "temporal_events.json"


def load_snapshots():
    files = sorted(
        f for f in os.listdir(SNAPSHOT_DIR)
        if f.endswith(".json")
    )

    snapshots = []
    for f in files:
        with open(os.path.join(SNAPSHOT_DIR, f), "r", encoding="utf-8") as fp:
            snapshots.append({
                "time": f,
                "data": json.load(fp)
            })
    return snapshots


def index_hooks(snapshot):
    """
    Returns:
      { identity: { dlls, pid, exe } }
    Identity = exe_path + create_time
    """
    hooks = {}

    for entry in snapshot.get("keyboard_hook_suspects", []):
        pid = entry["pid"]
        exe = entry.get("executable", "UNKNOWN_EXE")
        create_time = entry.get("create_time", "UNKNOWN_TIME")

        identity = f"{exe}|{create_time}"

        if "suspicious_modules" in entry:
            dlls = {m["dll"] for m in entry["suspicious_modules"]}
        else:
            dlls = {exe}

        hooks[identity] = {
            "dlls": dlls,
            "pid": pid,
            "exe": exe
        }

    return hooks


def analyze():
    snapshots = load_snapshots()
    if len(snapshots) < 2:
        print("[!] Need at least 2 snapshots for temporal analysis")
        return

    history = defaultdict(list)

    # Build time series by identity
    for snap in snapshots:
        hook_map = index_hooks(snap["data"])
        for identity, info in hook_map.items():
            history[identity].append({
                "time": snap["time"],
                "dlls": info["dlls"],
                "pid": info["pid"],
                "exe": info["exe"]
            })

    events = []

    for identity, records in history.items():
        if len(records) < 2:
            continue

        latest = records[-1]

        # ---- PERSISTENCE (STATE, ONCE PER RUN) ----
        events.append({
            "event": "HOOK_PERSISTED",
            "identity": identity,
            "pid": latest["pid"],
            "exe": latest["exe"],
            "time": latest["time"],
            "dlls": list(latest["dlls"])
        })

        # ---- CHANGE EVENTS ----
        for i in range(1, len(records)):
            prev = records[i - 1]
            curr = records[i]

            if not prev["dlls"] and curr["dlls"]:
                events.append({
                    "event": "HOOK_APPEARED",
                    "identity": identity,
                    "pid": curr["pid"],
                    "exe": curr["exe"],
                    "time": curr["time"],
                    "dlls": list(curr["dlls"])
                })

            new_dlls = curr["dlls"] - prev["dlls"]
            if new_dlls:
                events.append({
                    "event": "NEW_HOOK_MODULE",
                    "identity": identity,
                    "pid": curr["pid"],
                    "exe": curr["exe"],
                    "time": curr["time"],
                    "dlls": list(new_dlls)
                })

            removed = prev["dlls"] - curr["dlls"]
            if removed:
                events.append({
                    "event": "HOOK_REMOVED",
                    "identity": identity,
                    "pid": curr["pid"],
                    "exe": curr["exe"],
                    "time": curr["time"],
                    "dlls": list(removed)
                })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print("\n========== TEMPORAL KEYBOARD HOOK REPORT ==========\n")
    for e in events:
        print(f"[{e['event']}] {e['exe']} @ {e['time']}")
        for d in e["dlls"]:
            print(f"  - {d}")
        print()

    print(f"[+] Temporal events written to {OUTPUT_FILE}")
    print("=============================================\n")


if __name__ == "__main__":
    analyze()
