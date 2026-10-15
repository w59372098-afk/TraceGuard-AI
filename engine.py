"""Simple, transparent log parsing and heuristic detections for a learning PoC."""
from __future__ import annotations
import re
from collections import Counter, defaultdict
from datetime import datetime

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TS_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\b")
LEVEL_RE = re.compile(r"\b(DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|ALERT|FAILED|FAIL|DENIED|BLOCKED)\b", re.I)

def demo_log_text() -> str:
    return """2026-10-15 09:00:02 INFO 10.0.0.8 GET /health 200
2026-10-15 09:01:10 INFO 10.0.0.12 GET / 200
2026-10-15 09:02:04 WARN 198.51.100.24 POST /login 401 authentication failed user=admin
2026-10-15 09:02:09 WARN 198.51.100.24 POST /login 401 authentication failed user=admin
2026-10-15 09:02:12 WARN 198.51.100.24 POST /login 401 authentication failed user=admin
2026-10-15 09:02:16 WARN 198.51.100.24 POST /login 401 authentication failed user=admin
2026-10-15 09:03:01 INFO 10.0.0.8 GET /products 200
2026-10-15 09:04:31 ERROR 203.0.113.77 GET /../../etc/passwd 400 path traversal pattern
2026-10-15 09:04:35 ERROR 203.0.113.77 GET /wp-admin 404
2026-10-15 09:04:38 ERROR 203.0.113.77 GET /.env 404
2026-10-15 09:06:02 INFO 10.0.0.12 GET /checkout 200
2026-10-15 09:08:11 WARN 192.0.2.55 command="powershell -enc ..." action=blocked
"""

def parse_events(text: str) -> list[dict]:
    events = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        ts_match = TS_RE.search(line)
        ip_match = IP_RE.search(line)
        level_match = LEVEL_RE.search(line)
        timestamp = ts_match.group(1).replace("T", " ") if ts_match else None
        if timestamp:
            try:
                datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                timestamp = None
        events.append({
            "line": line_no,
            "timestamp": timestamp,
            "level": level_match.group(1).upper() if level_match else "UNKNOWN",
            "ip": ip_match.group(0) if ip_match else "",
            "message": line,
        })
    return events

def analyze_text(text: str) -> dict:
    events = parse_events(text)
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["ip"]:
            by_ip[e["ip"]].append(e)

    # Repeated login failures, grouped by source IP.
    for ip, rows in by_ip.items():
        failures = [e for e in rows if re.search(r"(login|auth).*(failed|failure|401)|(failed|failure|401).*(login|auth)", e["message"], re.I)]
        if len(failures) >= 3:
            findings.append({
                "title": "Repeated authentication failures",
                "severity": "High" if len(failures) >= 5 else "Medium",
                "count": len(failures),
                "source": ip,
                "explanation": f"{len(failures)} authentication-related failure lines were found for source {ip}. This may indicate mistyped credentials, automation, or a brute-force attempt; validate against expected traffic.",
                "evidence": [e["message"] for e in failures],
                "actions": ["Check whether the source and account are expected.", "Review authentication controls and rate limits.", "Correlate with identity-provider and application logs before taking action."]
            })
        probe_rows = [e for e in rows if re.search(r"(\.\./|/\.env|/wp-admin|/admin\b|/etc/passwd|select.+from)", e["message"], re.I)]
        if len(probe_rows) >= 2:
            findings.append({
                "title": "Multiple web-probing indicators",
                "severity": "High" if len(probe_rows) >= 4 else "Medium",
                "count": len(probe_rows),
                "source": ip,
                "explanation": f"{len(probe_rows)} lines from {ip} match common path-probing or injection-related patterns. These are indicators to investigate, not confirmation of a successful exploit.",
                "evidence": [e["message"] for e in probe_rows],
                "actions": ["Review web-server access logs around these timestamps.", "Confirm sensitive paths are not publicly exposed.", "Check WAF and application responses for successful access."]
            })

    command_rows = [e for e in events if re.search(r"(powershell\s+-enc|base64|curl\s+http|wget\s+http|chmod\s+\+x)", e["message"], re.I)]
    if command_rows:
        findings.append({
            "title": "Suspicious command-like string",
            "severity": "Medium",
            "count": len(command_rows),
            "source": ", ".join(sorted({e["ip"] for e in command_rows if e["ip"]})) or "Unknown",
            "explanation": "A command-like pattern associated with scripting or encoded commands appears in the log. It may be benign or blocked; inspect the originating process and surrounding events.",
            "evidence": [e["message"] for e in command_rows],
            "actions": ["Confirm whether the command was executed or only logged.", "Review endpoint/process telemetry if available.", "Preserve relevant logs and escalate according to your response process."]
        })
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 3), -f["count"], f["title"]))
    return {"events": events, "findings": findings, "line_count": len(text.splitlines())}

def build_report(result: dict) -> str:
    lines = [
        "# TraceGuard AI — Investigation Report", "",
        "> Learning proof of concept. Heuristic matches are not proof of compromise.", "",
        f"- Non-empty events parsed: **{len(result['events'])}**",
        f"- Findings generated: **{len(result['findings'])}**", "",
        "## Findings", ""
    ]
    if not result["findings"]:
        lines.append("No configured rules matched. This does not establish that the logs are safe.")
    for i, f in enumerate(result["findings"], 1):
        lines += [
            f"### {i}. [{f['severity']}] {f['title']}", "",
            f"- Source: {f['source']}",
            f"- Matching events: {f['count']}", "",
            f["explanation"], "", "**Evidence:**"
        ]
        lines.extend(f"- `{e}`" for e in f["evidence"])
        lines += ["", "**Suggested next steps:**"]
        lines.extend(f"- {a}" for a in f["actions"])
        lines.append("")
    lines += ["## Limitations", "", "This tool uses a small set of transparent regular-expression rules. It may miss relevant activity or flag benign events. Validate findings with authorized telemetry and your incident-response process.", ""]
    return "\n".join(lines)
