"""Validate the deliberately narrow, self-contained requirements input contract."""

import re


PIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\s*==\s*[A-Za-z0-9]+(?:[.!+_-][A-Za-z0-9]+)*", re.ASCII)


def requirements_issues(path):
    """Accept plain exact pins and comments; never follow includes or URLs."""
    issues = []
    count = 0
    for number, original in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = re.split(r"\s+#", original, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if not PIN.fullmatch(line):
            issues.append(f"Unsupported requirements syntax at line {number}; expected a plain name==version pin")
        else:
            count += 1
    if not count and not issues:
        issues.append("No exact dependency pins in requirements input")
    return issues
