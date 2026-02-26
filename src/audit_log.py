import json
import time
import os

LOG = "audit.jsonl"

def append(entry: dict):
    entry["ts_ns"] = time.time_ns()
    # Serialize with minimal separators to be byte-dense and JSONL format
    entry_line = json.dumps(entry, separators=(",", ":")) + "\n"
    
    with open(LOG, "a", buffering=1) as f:
        f.write(entry_line)
        f.flush()
        os.fsync(f.fileno())

if __name__ == "__main__":
    # Self-test
    append({"event": "init", "message": "Audit log initialized"})
