"""Every interaction is appended to a JSON-lines event log, one object per line."""
import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()


class EventLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, service: str, session: str, src_ip: str, kind: str, **data) -> None:
        event = {"ts": round(time.time(), 3), "service": service, "session": session,
                 "src_ip": src_ip, "kind": kind, **data}
        with _lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


def read(path: Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
