import hashlib, json, sys


def verify(path):
    previous = "GENESIS"
    for n, line in enumerate(open(path), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        claimed = row.pop("record_hash")
        stored_prev = row.pop("previous_hash")
        payload = json.dumps(row, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256((previous + payload).encode()).hexdigest()
        if stored_prev != previous or claimed != expected:
            return False, n
        previous = claimed
    return True, None


if __name__ == "__main__":
    ok, line = verify(sys.argv[1])
    print("chain OK" if ok else f"chain BROKEN at line {line}")
    sys.exit(0 if ok else 1)
