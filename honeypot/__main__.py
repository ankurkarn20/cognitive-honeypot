"""Command line.

    python -m honeypot serve                 # run the decoys (shell :2323, http :8088)
    python -m honeypot report                # score data/events.jsonl -> data/report.html
    python -m honeypot demo                  # both, with simulated traffic

The detectors are fitted on the baseline (background traffic recorded earlier) together
with the traffic being analysed. Fitted on the baseline alone, an Isolation Forest never
splits on features that are always zero there (downloads, attack payloads), and so cannot
see exactly the behaviour that marks an attack.
"""
import argparse
import asyncio
import json
from pathlib import Path

from honeypot import features, report, simulate
from honeypot.detector import Detector
from honeypot.events import EventLog, read
from honeypot.services import serve

DATA = Path("data")


def write_report(log: Path, baseline: Path, out: Path, truth: Path) -> dict | None:
    events, history = read(log), read(baseline)
    shell = Detector.fit(features.shell_sessions(history + events), features.SHELL_FEATURES
                         ).score(features.shell_sessions(events))
    web = Detector.fit(features.http_sessions(history + events), features.HTTP_FEATURES
                       ).score(features.http_sessions(events))
    known = json.loads(truth.read_text()) if truth.exists() else {}
    out.write_text(report.render(events, shell, web, known), encoding="utf-8")
    import pandas as pd
    result = report.evaluate(pd.concat([shell, web]), known)
    print(f"{len(events)} events, {len(shell)} shell and {len(web)} HTTP sessions; "
          f"{int(shell['anomalous'].sum() + web['anomalous'].sum())} flagged -> {out}")
    if result:
        print(f"precision {result['precision']:.0%}, recall {result['recall']:.0%} "
              f"on {result['n']} simulated sessions")
    return result


async def demo(shell_port: int, http_port: int) -> None:
    DATA.mkdir(exist_ok=True)
    for name in ("baseline.jsonl", "events.jsonl", "truth.json"):
        (DATA / name).unlink(missing_ok=True)
    for log_name, mix, subnet in (("baseline.jsonl", simulate.BASELINE_MIX, 10),
                                  ("events.jsonl", {**simulate.BASELINE_MIX,
                                                    **simulate.ATTACK_MIX}, 20)):
        server = asyncio.create_task(serve(EventLog(DATA / log_name), "127.0.0.1",
                                           shell_port, http_port))
        await asyncio.sleep(0.5)
        truth = DATA / ("truth.json" if log_name == "events.jsonl" else "baseline-truth.json")
        n = await simulate.play(mix, truth, shell=shell_port, http_port=http_port,
                                subnet=subnet, seed=subnet)
        print(f"Simulated {n} clients -> {DATA / log_name}")
        server.cancel()
        await asyncio.sleep(0.2)
    write_report(DATA / "events.jsonl", DATA / "baseline.jsonl", DATA / "report.html",
                 DATA / "truth.json")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="python -m honeypot", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["serve", "report", "demo"])
    p.add_argument("--log", type=Path, default=DATA / "events.jsonl")
    p.add_argument("--baseline", type=Path, default=DATA / "baseline.jsonl")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--shell-port", type=int, default=2323)
    p.add_argument("--http-port", type=int, default=8088)
    a = p.parse_args(argv)
    if a.command == "serve":
        asyncio.run(serve(EventLog(a.log), a.host, a.shell_port, a.http_port))
    elif a.command == "report":
        write_report(a.log, a.baseline, DATA / "report.html", DATA / "truth.json")
    else:
        asyncio.run(demo(a.shell_port, a.http_port))


if __name__ == "__main__":
    main()
