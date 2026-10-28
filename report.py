#!/usr/bin/env python3
"""Generate Markdown, JSON and CSV vulnerability-intelligence reports.

Run from the directory containing vuln_monitor.py:
    python report.py --once
"""

import argparse
import csv
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

try:
    import vuln_monitor as monitor
except ImportError as exc:
    raise SystemExit(
        "Could not import vuln_monitor.py. Put report.py in the same directory "
        "as vuln_monitor.py and install its dependencies first."
    ) from exc

BASE = Path(__file__).resolve().parent
REPORTS_DIR = BASE / "reports"


def collect(days: int, min_cvss: float):
    collectors = [
        ("NVD", lambda: monitor.fetch_nvd(days, min_cvss)),
        ("CISA KEV", monitor.fetch_kev),
    ]
    collectors.extend(
        (name, lambda n=name, u=url: monitor.fetch_rss(n, u, days))
        for name, url in monitor.RSS_SOURCES.items()
    )
    all_items = []
    errors = []
    for name, collector in collectors:
        try:
            items = collector()
            all_items.extend(items)
            print(f"[OK] {name}: {len(items)} items")
        except Exception as exc:
            errors.append({"source": name, "error": str(exc)})
            print(f"[WARN] {name}: {exc}", file=sys.stderr)
    # De-duplicate by ID, keeping the first occurrence.
    unique = {}
    for item in all_items:
        unique.setdefault(item.get("id") or item.get("url") or item.get("title"), item)
    items = list(unique.values())
    items.sort(key=lambda x: (
        x.get("source") != "CISA KEV",
        -(float(x.get("cvss") or 0)),
        str(x.get("title", "")).lower(),
    ))
    return items, errors


def write_reports(items, errors, days: int, min_cvss: float):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    generated = datetime.now().astimezone().isoformat(timespec="seconds")
    stem = f"cti_report_{stamp}"
    payload = {
        "generated_at": generated,
        "lookback_days": days,
        "minimum_cvss": min_cvss,
        "total_items": len(items),
        "source_errors": errors,
        "items": items,
    }

    json_path = REPORTS_DIR / f"{stem}.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    csv_path = REPORTS_DIR / f"{stem}.csv"
    fields = ["source", "id", "title", "cvss", "tags", "description", "url", "date_added", "vendor", "product", "due_date"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for item in items:
            row = dict(item)
            row["tags"] = ", ".join(row.get("tags", [])) if isinstance(row.get("tags"), list) else row.get("tags", "")
            writer.writerow(row)

    counts = {}
    for item in items:
        source = item.get("source", "Unknown")
        counts[source] = counts.get(source, 0) + 1

    md_path = REPORTS_DIR / f"{stem}.md"
    lines = [
        "# Cyber Threat & Vulnerability Intelligence Report",
        "",
        f"- **Generated:** {generated}",
