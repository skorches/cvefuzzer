"""Self-contained HTML; all repository and tool values are rendered as text."""

import html
import json


def render_html(scan):
    payload = scan.to_dict() if hasattr(scan, "to_dict") else scan
    escaped = html.escape(json.dumps(payload, indent=2))
    refresh_note = ""
    if "refresh_id" in payload:
        freshness = payload["advisory_freshness"]
        refresh_note = (f"<p>Advisory data: {html.escape(freshness['status'])}. "
                        f"Original inventory: {html.escape(payload['inventory_status'])}. "
                        "Repository files were not rechecked. Resolved findings describe changed advisory matching; "
                        "dependencies have not been upgraded.</p>")
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>CVEFuzz scan report</title>"
            "<style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:1rem}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f4f6;padding:1rem}</style>"
            "<h1>CVEFuzz scan report</h1>"
            f"<p>Status: {html.escape(payload['status'])}. Findings: {len(payload['findings'])}.</p>"
            f"{refresh_note}"
            "<p>Dependency matches do not establish exploitability. Static analysis and fuzzing have not run. "
            "A successful dependency check is limited to the recorded inputs and provider responses.</p>"
            f"<pre>{escaped}</pre></html>")
