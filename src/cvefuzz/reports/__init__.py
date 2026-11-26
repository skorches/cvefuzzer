"""Self-contained HTML; all repository and tool values are rendered as text."""

import html
import json


def render_html(scan):
    payload = scan.to_dict() if hasattr(scan, "to_dict") else scan
    escaped = html.escape(json.dumps(payload, indent=2))
    findings_count = len(payload["findings"]) if "findings" in payload else payload.get("findings_count", sum(project["findings_count"] for project in payload.get("projects", [])))
    refresh_note = ""
    if "refresh_id" in payload:
        freshness = payload["advisory_freshness"]
        refresh_note = (f"<p>Advisory data: {html.escape(freshness['status'])}. "
                        f"Original inventory: {html.escape(payload['inventory_status'])}. "
                        "Repository files were not rechecked. Resolved findings describe changed advisory matching; "
                        "dependencies have not been upgraded.</p>")
    projects_table = ""
    if "projects" in payload:
        rows = []
        for project in payload["projects"]:
            advisory_status = project.get("advisory_freshness", {}).get("status", project.get("outcome", "unknown"))
            new_count = len(project["new_findings"]) if "new_findings" in project else (project.get("changes") or {}).get("new", "Not checked")
            values = (project["root"], project["inventory_status"], advisory_status,
                      project["findings_count"], new_count)
            rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in values) + "</tr>")
        projects_table = ("<p>Saved dependency inventories only; repository files were not rechecked. "
                          "A project listing is not a safety conclusion. Batch skips follow the configured refresh interval.</p>"
                          "<table><thead><tr><th>Project</th><th>Inventory</th><th>Freshness/outcome</th>"
                          "<th>Findings</th><th>New finding groups</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")
    return ("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>CVEFuzz scan report</title>"
            "<style>body{font:16px system-ui;max-width:1000px;margin:2rem auto;padding:1rem}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f4f6;padding:1rem}"
            "table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;border:1px solid #ddd;padding:.5rem;overflow-wrap:anywhere}</style>"
            "<h1>CVEFuzz scan report</h1>"
            f"<p>Status: {html.escape(payload['status'])}. Findings: {findings_count}.</p>"
            f"{refresh_note}"
            f"{projects_table}"
            "<p>Dependency matches and static warnings do not establish exploitability. "
            "See recorded checks for completed, incomplete, and skipped analysis. "
            "A successful dependency check is limited to the recorded inputs and provider responses.</p>"
            f"<pre>{escaped}</pre></html>")
