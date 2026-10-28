from pathlib import Path

script = r'''#!/usr/bin/env python3
"""
Vulnerability Intelligence Monitor
----------------------------------
Terminal-first vulnerability and security-news monitor.

Features
- NVD CVE API (recently published CVEs)
- CISA Known Exploited Vulnerabilities (KEV) catalogue
- CISA cybersecurity advisories
- CERT-In advisories (RSS endpoint, if available)
- Security news/research RSS feeds
- CVE extraction, CVSS parsing where available, lightweight tagging
- JSON state-file deduplication and a readable log
- One-shot or recurring polling; no Telegram dependency

Install:
    python -m pip install requests feedparser python-dotenv

Run once:
    python vuln_monitor.py --once

Run continuously (default every 10 minutes):
    python vuln_monitor.py

Optional .env:
    MIN_CVSS=7.0
    LOOKBACK_DAYS=7
    POLL_INTERVAL_MINUTES=10
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import feedparser
import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

APP_NAME = "Vulnerability Intelligence Monitor"
STATE_FILE = os.getenv("STATE_FILE", "vuln_monitor_state.json")
LOG_FILE = os.getenv("LOG_FILE", "vuln_monitor.log")
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_MIN_CVSS = float(os.getenv("MIN_CVSS", "0"))
DEFAULT_LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "7"))
DEFAULT_INTERVAL = int(os.getenv("POLL_INTERVAL_MINUTES", "10"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))
USER_AGENT = "VulnIntelMonitor/2.0 (personal research; contact: maintainer)"

# Broad, non-geographic tags. These are labels for triage, not proof of exploitation.
TAG_RULES = {
    "RCE": re.compile(r"\b(remote code execution|arbitrary code execution|code execution|RCE)\b", re.I),
    "Privilege Escalation": re.compile(r"\b(privilege escalation|elevation of privilege|local privilege)\b", re.I),
    "Authentication Bypass": re.compile(r"\b(authentication bypass|auth bypass|bypass authentication)\b", re.I),
    "SQL Injection": re.compile(r"\b(SQL injection|SQLi)\b", re.I),
    "XSS": re.compile(r"\b(cross.site scripting|XSS)\b", re.I),
    "Denial of Service": re.compile(r"\b(denial.of.service|DoS|DDoS)\b", re.I),
    "Directory Traversal": re.compile(r"\b(directory traversal|path traversal)\b", re.I),
    "Information Disclosure": re.compile(r"\b(information disclosure|sensitive information exposure|data leak)\b", re.I),
    "Deserialization": re.compile(r"\b(deserialization|insecure deserialization)\b", re.I),
    "Zero-day": re.compile(r"\b(zero.day|0.day|actively exploited|exploited in the wild)\b", re.I),
    "Ransomware": re.compile(r"\b(ransomware|ransom)\b", re.I),
    "Phishing": re.compile(r"\b(phishing|credential theft|credential harvesting)\b", re.I),
    "Supply Chain": re.compile(r"\b(supply.chain|dependency confusion|malicious package)\b", re.I),
    "Cloud": re.compile(r"\b(cloud|AWS|Azure|Microsoft 365|Google Cloud|SaaS)\b", re.I),
    "Mobile": re.compile(r"\b(Android|iOS|mobile device|smartphone)\b", re.I),
}

# Feeds are best-effort: a source outage should not stop the whole monitor.
RSS_SOURCES = {
    "CISA Cybersecurity Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "CERT-In Advisories": "https://www.cert-in.org.in/RSSFeed?type=Advisories",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed.xml",
}

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json, application/rss+xml, application/xml, text/xml, */*"})


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("vuln_monitor")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


log = setup_logging()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_state() -> dict[str, Any]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as file:
            state = json.load(file)
            if isinstance(state, dict):
                state.setdefault("seen", {})
                return state
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not read state file (%s); starting with empty state", exc)
    return {"seen": {}}


def save_state(state: dict[str, Any]) -> None:
    temp_path = STATE_FILE + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as file:
        json.dump(state, file, indent=2, ensure_ascii=False)
    os.replace(temp_path, STATE_FILE)


def text_from_html(value: str) -> str:
    # RSS summaries are often HTML; feedparser's built-in sanitizer is not guaranteed.
    from html import unescape
    value = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", unescape(value)).strip()


def extract_cves(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", text or "", flags=re.I)), key=str.lower)


def tag_text(text: str) -> list[str]:
    return [tag for tag, pattern in TAG_RULES.items() if pattern.search(text or "")]


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def parse_nvd_item(vuln: dict[str, Any]) -> dict[str, Any] | None:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None
    descriptions = cve.get("descriptions", [])
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    score = None
    vector = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss = entries[0].get("cvssData", {})
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString")
            if score is not None:
                break
    references = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    published = cve.get("published")
    modified = cve.get("lastModified")
    return {
        "id": cve_id.upper(),
        "title": cve_id.upper() + (": " + description[:240] if description else ""),
        "description": description,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}",
        "source": "NVD",
        "published": published,
        "modified": modified,
        "cvss": float(score) if score is not None else None,
        "cvss_vector": vector,
        "tags": tag_text(description),
        "references": references[:8],
        "kind": "CVE",
    }


def fetch_nvd(days: int, min_cvss: float) -> list[dict[str, Any]]:
    end = utc_now()
    start = end - timedelta(days=max(1, days))
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    results: list[dict[str, Any]] = []
    while True:
        response = SESSION.get(NVD_API, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        for item in payload.get("vulnerabilities", []):
            parsed = parse_nvd_item(item)
            if parsed and (parsed["cvss"] is None or parsed["cvss"] >= min_cvss):
                results.append(parsed)
        total = int(payload.get("totalResults", 0))
        params["startIndex"] += int(payload.get("resultsPerPage", 2000))
        if params["startIndex"] >= total or not payload.get("vulnerabilities"):
            break
        # NVD rate limits unauthenticated clients more aggressively.
        time.sleep(6 if not api_key else 0.7)
    log.info("NVD: collected %d CVEs published in the last %d day(s)", len(results), days)
    return results


def fetch_cisa_kev() -> list[dict[str, Any]]:
    response = SESSION.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json()
    results = []
    for item in payload.get("vulnerabilities", []):
        cve_id = item.get("cveID", "").upper()
        if not cve_id:
            continue
        description = item.get("shortDescription", "")
        text = " ".join(filter(None, [description, item.get("vulnerabilityName", ""), item.get("requiredAction", "")]))
        results.append({
            "id": "KEV:" + cve_id,
            "cve": cve_id,
            "title": f"{cve_id}: {item.get('vulnerabilityName') or description or 'Known exploited vulnerability'}",
            "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "source": "CISA KEV",
            "published": item.get("dateAdded"),
            "modified": None,
            "cvss": None,
            "cvss_vector": None,
            "tags": list(dict.fromkeys(["Known Exploited Vulnerability"] + tag_text(text))),
            "references": [],
            "kind": "KEV",
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "due_date": item.get("dueDate"),
            "required_action": item.get("requiredAction"),
            "known_ransomware": item.get("knownRansomwareCampaignUse"),
        })
    log.info("CISA KEV: collected %d catalogue entries (not all are newly disclosed)", len(results))
    return results


def fetch_rss(name: str, url: str, days: int) -> list[dict[str, Any]]:
    parsed_feed = feedparser.parse(url, request_headers={"User-Agent": USER_AGENT})
    if getattr(parsed_feed, "bozo", False) and not parsed_feed.entries:
        log.warning("RSS source unavailable: %s (%s)", name, getattr(parsed_feed, "bozo_exception", "feed parse error"))
        return []
    cutoff = utc_now() - timedelta(days=max(1, days))
    results = []
    for entry in parsed_feed.entries:
        title = text_from_html(entry.get("title", "")) or "Untitled security update"
        summary = text_from_html(entry.get("summary", entry.get("description", "")))
        link = entry.get("link", "")
        published = entry.get("published", entry.get("updated", ""))
        parsed_time = entry.get("published_parsed") or entry.get("updated_parsed")
        if parsed_time:
            try:
                entry_dt = datetime(*parsed_time[:6], tzinfo=timezone.utc)
                if entry_dt < cutoff:
                    continue
            except (TypeError, ValueError):
                pass
        combined = f"{title}. {summary}"
        cves = extract_cves(combined)
        stable = cves[0] if len(cves) == 1 else (link or title)
        digest = hashlib.sha256(f"{name}|{stable}".encode("utf-8")).hexdigest()[:20]
        results.append({
            "id": f"RSS:{digest}",
            "cves": cves,
            "title": title,
            "description": summary[:1200],
            "url": link,
            "source": name,
            "published": published,
            "modified": entry.get("updated", ""),
            "cvss": None,
            "cvss_vector": None,
            "tags": tag_text(combined),
            "references": [],
            "kind": "RSS",
        })
    log.info("%s: collected %d recent feed item(s)", name, len(results))
    return results


def fetch_all(days: int, min_cvss: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    sources = [
        ("NVD", lambda: fetch_nvd(days, min_cvss)),
        ("CISA KEV", fetch_cisa_kev),
    ]
    for source_name, collector in sources:
        try:
            items.extend(collector())
        except requests.RequestException as exc:
            log.error("%s request failed: %s", source_name, exc)
        except (ValueError, KeyError, TypeError) as exc:
            log.error("%s response could not be parsed: %s", source_name, exc)

    for name, url in RSS_SOURCES.items():
        try:
            items.extend(fetch_rss(name, url, days))
        except (requests.RequestException, ValueError, TypeError) as exc:
            log.error("%s feed failed: %s", name, exc)
    return items


def item_fingerprint(item: dict[str, Any]) -> str:
    if item.get("id"):
        return str(item["id"]).lower()
    basis = "|".join([str(item.get("source", "")), str(item.get("url", "")), str(item.get("title", ""))])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def format_alert(item: dict[str, Any]) -> str:
    score = item.get("cvss")
    score_text = f"{score:.1f} ({severity_from_score(score)})" if score is not None else "Not provided by this source"
    tags = ", ".join(item.get("tags") or []) or "None detected"
    cves = item.get("cves") or ([item["cve"]] if item.get("cve") else extract_cves(item.get("title", "") + " " + item.get("description", "")))
    lines = [
        "=" * 78,
        f"[{item.get('kind', 'INTEL')}] {item.get('title', 'Security intelligence update')}",
        "-" * 78,
        f"Source: {item.get('source', 'Unknown')}",
        f"Published/added: {item.get('published') or 'Not supplied by source'}",
        f"CVSS: {score_text}",
        f"Tags: {tags}",
    ]
    if cves:
        lines.append("CVE(s): " + ", ".join(cves))
    if item.get("vendor") or item.get("product"):
        lines.append(f"Vendor/product: {item.get('vendor', 'Unknown')} / {item.get('product', 'Unknown')}")
    if item.get("known_ransomware"):
        lines.append(f"Known ransomware use: {item['known_ransomware']}")
    if item.get("due_date"):
        lines.append(f"CISA remediation due date: {item['due_date']}")
    if item.get("required_action"):
        lines.append("Required action: " + str(item["required_action"]))
    if item.get("description"):
        lines.extend(["", "Summary:", item["description"][:1200]])
    if item.get("url"):
        lines.extend(["", "URL: " + item["url"]])
    if item.get("references"):
        lines.extend(["", "References:"])
        lines.extend(" - " + ref for ref in item["references"][:5])
    lines.append("=" * 78)
    return "\n".join(lines)


def run_cycle(days: int, min_cvss: float) -> int:
    log.info("=== Starting vulnerability intelligence collection cycle ===")
    items = fetch_all(days, min_cvss)
    state = load_state()
    seen: dict[str, Any] = state.setdefault("seen", {})
    new_count = 0
    now = utc_now().isoformat()

    # Sort so output is stable and reproducible.
    for item in sorted(items, key=lambda x: (str(x.get("published", "")), str(x.get("source", "")), str(x.get("title", ""))), reverse=True):
        fingerprint = item_fingerprint(item)
        if fingerprint in seen:
            continue
        print("\n" + format_alert(item), flush=True)
        seen[fingerprint] = {"first_seen": now, "source": item.get("source"), "title": item.get("title"), "url": item.get("url")}
        new_count += 1

    # Bound state-file growth while retaining the most recently seen records.
    if len(seen) > 12000:
        ordered = sorted(seen.items(), key=lambda pair: pair[1].get("first_seen", ""), reverse=True)
        state["seen"] = dict(ordered[:10000])
    save_state(state)
    log.info("Cycle complete: %d source item(s), %d new alert(s)", len(items), new_count)
    if new_count == 0:
        log.info("No new items. Existing items were suppressed by deduplication.")
    return new_count


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--once", action="store_true", help="Run one collection cycle and exit")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help=f"Polling interval in minutes (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--days", type=int, default=DEFAULT_LOOKBACK_DAYS, help=f"Look back this many days for NVD/RSS items (default: {DEFAULT_LOOKBACK_DAYS})")
    parser.add_argument("--min-cvss", type=float, default=DEFAULT_MIN_CVSS, help=f"Minimum CVSS for NVD results; 0 includes CVEs without a score (default: {DEFAULT_MIN_CVSS})")
    args = parser.parse_args()

    if args.interval < 1:
        parser.error("--interval must be at least 1 minute")
    if args.days < 1:
        parser.error("--days must be at least 1")
    if not 0 <= args.min_cvss <= 10:
        parser.error("--min-cvss must be between 0 and 10")

    log.info("%s starting", APP_NAME)
    log.info("Mode: %s | lookback: %d day(s) | minimum CVSS: %.1f | interval: %d minute(s)",
             "one-shot" if args.once else "continuous", args.days, args.min_cvss, args.interval)
    log.info("Output: terminal | State: %s | Log: %s", STATE_FILE, LOG_FILE)
    log.info("Geographic actor filters are disabled; items are tagged by vulnerability/incident themes only.")

    if args.once:
        run_cycle(args.days, args.min_cvss)
        return

    while True:
        try:
            run_cycle(args.days, args.min_cvss)
        except KeyboardInterrupt:
            log.info("Stopped by user.")
            break
        except Exception:
            log.exception("Unexpected error in collection cycle; the monitor will retry next interval.")
        log.info("Sleeping for %d minute(s). Press Ctrl+C to stop.", args.interval)
        try:
            time.sleep(args.interval * 60)
        except KeyboardInterrupt:
            log.info("Stopped by user.")
            break


if __name__ == "__main__":
    main()
'''
path = Path("/mnt/data/vuln_monitor.py")
path.write_text(script, encoding="utf-8")
print(f"Created {path} ({path.stat().st_size:,} bytes)")
