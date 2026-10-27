"""A self-contained HTML dashboard of the scored sessions."""
import base64
import html
import io
from collections import Counter
from datetime import datetime

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

CSS = """
body{margin:0;background:#0b1020;color:#d7def0;font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 24px}
h1{font-size:24px;margin:0}h2{font-size:16px;margin:28px 0 10px;color:#9fb0d6}
.sub{color:#7d8bb0;margin:4px 0 20px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.kpi{background:#121a33;border:1px solid #1f2a4d;border-radius:10px;padding:14px}
.kpi b{display:block;font-size:26px;color:#fff}.kpi span{color:#7d8bb0;font-size:12px}
.red b{color:#ff6b6b}.green b{color:#5ee0a0}
table{width:100%;border-collapse:collapse;background:#121a33;border-radius:10px;overflow:hidden}
th,td{padding:7px 10px;border-bottom:1px solid #1f2a4d;text-align:left;font-size:13px}
th{color:#7d8bb0;font-weight:600;background:#0f1730}
td.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#b8c4e6}
.tag{padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600}
.bad{background:#3a1520;color:#ff8a8a}.ok{background:#11301f;color:#6be3a4}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
img{width:100%;border-radius:10px;border:1px solid #1f2a4d}
"""


def _chart(shell: pd.DataFrame, web: pd.DataFrame) -> str:
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.4), facecolor="#121a33")
    for ax, df, title in ((axes[0], shell, "Shell sessions"), (axes[1], web, "HTTP sessions")):
        ax.set_facecolor("#121a33")
        for side in ax.spines.values():
            side.set_color("#2a375f")
        ax.tick_params(colors="#7d8bb0")
        ax.set_title(title, color="#d7def0", fontsize=11, loc="left")
        if df.empty:
            continue
        t = (df["start"] - df["start"].min()).to_numpy()
        flagged = df["anomalous"].to_numpy(bool)
        ax.scatter(t[~flagged], df["score"][~flagged], s=18, c="#5ee0a0", label="normal")
        ax.scatter(t[flagged], df["score"][flagged], s=30, c="#ff6b6b", label="anomalous")
        ax.axhline(0, color="#7d8bb0", lw=0.8, ls="--")
        ax.set_xlabel("seconds since first session", color="#7d8bb0")
        ax.set_ylabel("anomaly score", color="#7d8bb0")
        ax.legend(facecolor="#121a33", edgecolor="#2a375f", labelcolor="#d7def0", fontsize=9)
    fig.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()


def _table(df: pd.DataFrame, cols: list[tuple[str, str]], truth: dict, limit=12) -> str:
    head = "".join(f"<th>{label}</th>" for _, label in cols)
    rows = []
    for _, r in df.head(limit).iterrows():
        cells = []
        for key, _ in cols:
            if key == "anomalous":
                cells.append(f'<td><span class="tag {"bad" if r[key] else "ok"}">'
                             f'{"anomalous" if r[key] else "normal"}</span></td>')
            elif key == "truth":
                t = truth.get(r["src_ip"], {}).get("behaviour", "–")
                cells.append(f'<td class="mono">{html.escape(t)}</td>')
            else:
                cls = ' class="mono"' if key in ("src_ip", "last_commands", "sample",
                                                 "users") else ""
                cells.append(f"<td{cls}>{html.escape(str(r[key]))}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><tr>{head}</tr>{''.join(rows)}</table>"


def evaluate(scored: pd.DataFrame, truth: dict) -> dict | None:
    known = scored[scored["src_ip"].isin(truth)]
    if known.empty:
        return None
    actual = known["src_ip"].map(lambda ip: truth[ip]["attack"]).to_numpy(bool)
    flagged = known["anomalous"].to_numpy(bool)
    tp = int((actual & flagged).sum())
    fp = int((~actual & flagged).sum())
    fn = int((actual & ~flagged).sum())
    return {"precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0, "tp": tp, "fp": fp, "fn": fn,
            "n": len(known)}


def render(events: list[dict], shell: pd.DataFrame, web: pd.DataFrame, truth: dict) -> str:
    both = pd.concat([shell[["src_ip", "anomalous"]], web[["src_ip", "anomalous"]]])
    flagged = int(both["anomalous"].sum())
    creds = Counter((e["user"], e["password"]) for e in events if e["kind"] == "login")
    commands = Counter(e["command"] for e in events if e["kind"] == "command")
    ev = evaluate(both, truth)
    kpis = [("Events captured", len(events), ""), ("Sessions", len(both), ""),
            ("Flagged anomalous", flagged, "red"),
            ("Unique source IPs", both["src_ip"].nunique(), "")]
    if ev:
        kpis.append(("Precision / recall", f"{ev['precision']:.0%} / {ev['recall']:.0%}",
                     "green"))
    kpi_html = "".join(f'<div class="kpi {c}"><b>{v}</b><span>{k}</span></div>'
                       for k, v, c in kpis)
    cred_rows = "".join(f'<tr><td class="mono">{html.escape(u)}</td><td class="mono">'
                        f'{html.escape(p)}</td><td>{n}</td></tr>'
                        for (u, p), n in creds.most_common(8))
    cmd_rows = "".join(f'<tr><td class="mono">{html.escape(c)}</td><td>{n}</td></tr>'
                       for c, n in commands.most_common(8))
    has_truth = bool(truth)
    shell_cols = [("src_ip", "Source"), ("score", "Score"), ("anomalous", "Verdict"),
                  ("login_attempts", "Logins"), ("commands", "Cmds"),
                  ("downloads", "Downloads"), ("users", "Users tried"),
                  ("last_commands", "Last commands")] + ([("truth", "Simulated as")]
                                                        if has_truth else [])
    web_cols = [("src_ip", "Source"), ("score", "Score"), ("anomalous", "Verdict"),
                ("requests", "Requests"), ("not_found", "404s"),
                ("attack_payloads", "Payloads"), ("sample", "Paths")] + (
        [("truth", "Simulated as")] if has_truth else [])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Cognitive Honeypot - Threat Report</title><style>{CSS}</style></head><body><main>
<h1>Cognitive Honeypot &middot; Threat Report</h1>
<p class="sub">Generated {datetime.now():%d %b %Y, %H:%M} &middot; Isolation Forest anomaly
detection over shell and HTTP decoy sessions</p>
<div class="kpis">{kpi_html}</div>
<h2>Anomaly scores over time</h2><img src="data:image/png;base64,{_chart(shell, web)}">
<h2>Most anomalous shell sessions</h2>{_table(shell, shell_cols, truth)}
<h2>Most anomalous HTTP sessions</h2>{_table(web, web_cols, truth)}
<div class="grid"><div><h2>Top credentials tried</h2><table><tr><th>Username</th>
<th>Password</th><th>Attempts</th></tr>{cred_rows}</table></div>
<div><h2>Top commands run</h2><table><tr><th>Command</th><th>Count</th></tr>{cmd_rows}
</table></div></div></main></body></html>"""
