"""
=============================================================
  REAL-TIME VULNERABILITY INTELLIGENCE MONITOR
  Covers: CVEs, Zero-days, China/Pakistan APT filters,
          Android/iOS bulletin researcher tracking,
          Indian govt sources (CERT-In, NCIIPC)
  Notifications: Telegram (instant push)
  Platform: Windows / Linux / Mac — Python 3.8+
=============================================================

SETUP (one time):
  pip install requests feedparser beautifulsoup4 schedule python-dotenv

CREATE a file called .env in the same folder:
  TELEGRAM_TOKEN=your_bot_token_here
  TELEGRAM_CHAT_ID=your_chat_id_here

HOW TO GET TELEGRAM CREDS:
  1. Message @BotFather on Telegram → /newbot → copy token
  2. Message your bot once, then visit:
     https://api.telegram.org/bot<TOKEN>/getUpdates
     copy the "id" value from "chat" — that is your CHAT_ID

RUN:
  python vuln_monitor.py

WINDOWS TASK SCHEDULER (auto-start):
  Action: Start a program
  Program: python
  Arguments: C:/path/to/vuln_monitor.py
  Trigger: At startup, repeat every 10 minutes
=============================================================
"""

import os
import json
import time
import hashlib
import logging
import requests
import feedparser
import schedule
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
#  CONFIGURATION — edit these to your needs
# ─────────────────────────────────────────────

TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN", "8492871385:AAFKWwoUjUQACmupu5uaSM7WepQXvRjyI6g")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-940105360")

# Minimum CVSS score to alert on (0-10). 7.0 = High+, 9.0 = Critical only
MIN_CVSS = 7.0

# How many hours back to look when polling NVD (keep ≤24 for near-realtime)
NVD_LOOKBACK_HOURS = 2

# State file — tracks which alerts have been sent (avoids duplicates)
STATE_FILE = "vuln_monitor_state.json"

# Log file
LOG_FILE = "vuln_monitor.log"

# ─────────────────────────────────────────────
#  FILTER KEYWORDS
# ─────────────────────────────────────────────

CHINA_KEYWORDS = [
    "apt41", "apt10", "apt40", "apt31", "apt27",
    "volt typhoon", "salt typhoon", "flax typhoon",
    "mustang panda", "bronze silhouette", "hafnium",
    "prc", "china", "chinese", "people's republic",
    "winnti", "double dragon", "wicked panda",
    "dragonbridge", "emperor dragonfly",
]

PAKISTAN_KEYWORDS = [
    "apt36", "transparent tribe", "projectm",
    "mythic leopard", "sidewinder",  # also targets India from Pakistan
    "sidecopy", "c2c pakistan", "pakistan", "pakcert",
    "operation sidecopy", "unc1549",
]

# Combined geo filter — any match triggers the special flag
GEO_FILTER_KEYWORDS = CHINA_KEYWORDS + PAKISTAN_KEYWORDS

# Severity keywords that indicate a zero-day
ZERODAY_KEYWORDS = [
    "zero-day", "0day", "0-day", "in the wild",
    "actively exploited", "no patch", "unpatched",
    "itw", "exploit in the wild",
]

# Android / iOS / mobile filter
MOBILE_KEYWORDS = [
    "android", "ios", "iphone", "ipad", "webkit",
    "kernel android", "pixel", "samsung", "qualcomm snapdragon",
    "mediatek", "arm mali", "bionic libc",
]

# ─────────────────────────────────────────────
#  RSS FEEDS TO MONITOR
# ─────────────────────────────────────────────

RSS_FEEDS = [
    # Pre-CVE / early disclosure
    {
        "name": "Full Disclosure",
        "url": "https://seclists.org/rss/fulldisclosure.rss",
        "category": "pre-cve",
    },
    {
        "name": "Packet Storm Security",
        "url": "https://packetstormsecurity.com/feeds/news/",
        "category": "pre-cve",
    },
    # Vendor advisories
    {
        "name": "Microsoft Security",
        "url": "https://msrc.microsoft.com/blog/feed",
        "category": "vendor",
    },
    {
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "category": "researcher",
    },
    {
        "name": "Talos Intelligence",
        "url": "https://blog.talosintelligence.com/rss/",
        "category": "threat-intel",
    },
    {
        "name": "Recorded Future",
        "url": "https://www.recordedfuture.com/feed",
        "category": "threat-intel",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "news",
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "news",
    },
    {
        "name": "Bleeping Computer Security",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "news",
    },
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "category": "threat-intel",
    },
    # Indian government sources
    {
        "name": "CERT-In Advisories",
        "url": "https://www.cert-in.org.in/RSS/Advisories.rss",
        "category": "india-govt",
    },
    {
        "name": "CERT-In Alerts",
        "url": "https://www.cert-in.org.in/RSS/Alerts.rss",
        "category": "india-govt",
    },
    # GitHub PoC tracker
    {
        "name": "PoC-in-GitHub",
        "url": "https://github.com/nomi-sec/PoC-in-GitHub/commits/master.atom",
        "category": "poc",
    },
    # Exploit DB
    {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "category": "poc",
    },
    # Vulnhub / VulDB
    {
        "name": "VulDB Recent",
        "url": "https://vuldb.com/rss.xml",
        "category": "cve",
    },
]

# Nitter RSS for researcher Twitter monitoring (Nitter mirrors Twitter)
# These are real security researchers who post vulns early
RESEARCHER_NITTER_FEEDS = [
    {"handle": "GossiTheDog",   "name": "Kevin Beaumont"},
    {"handle": "maddiestone",   "name": "Maddie Stone (Android)"},
    {"handle": "hFireF0X",      "name": "Lukas Stefanko (ESET)"},
    {"handle": "vxunderground",  "name": "vx-underground"},
    {"handle": "taviso",        "name": "Tavis Ormandy (Google)"},
    {"handle": "hackerfantastic","name": "Matt Hickey"},
    {"handle": "MsftSecIntel",  "name": "Microsoft Threat Intel"},
    {"handle": "threatintel",   "name": "Threat Intel community"},
]

# Public Nitter instances (fallback list — use first available)
NITTER_INSTANCES = [
    "https://nitter.net",
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
]

# ─────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  STATE MANAGEMENT (deduplication)
# ─────────────────────────────────────────────

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {"sent_hashes": [], "last_cisa_kev": [], "last_nvd_check": ""}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def item_hash(text):
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()

def already_sent(state, h):
    return h in state["sent_hashes"]

def mark_sent(state, h):
    state["sent_hashes"].append(h)
    # Keep last 2000 hashes to avoid unbounded growth
    if len(state["sent_hashes"]) > 2000:
        state["sent_hashes"] = state["sent_hashes"][-2000:]

# ─────────────────────────────────────────────
#  TELEGRAM NOTIFICATIONS
# ─────────────────────────────────────────────

def send_telegram(message, disable_preview=True):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("Telegram not configured — printing to console only")
        print("\n" + "="*60)
        print(message)
        print("="*60 + "\n")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": disable_preview,
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            log.error(f"Telegram error {r.status_code}: {r.text[:200]}")
    except Exception as e:
        log.error(f"Telegram send failed: {e}")

def format_alert(title, source, url, severity="", tags=None, summary="", researcher=""):
    """Build a clean Telegram message."""
    lines = []

   # Extract numerical score if it exists alongside text (e.g., "HIGH 7.3" -> 7.3)
    score = 0.0
    for word in severity.split():
        try:
            score = float(word)
            break
        except ValueError:
            continue

    # Severity emoji mapping
    if "critical" in severity.lower() or score >= 9.0:
        icon = "🔴"
    elif "high" in severity.lower() or score >= 7.0:
        icon = "🟠"
    elif severity:
        icon = "🟡"
    else:
        icon = "⚠️"

    lines.append(f"{icon} <b>{title[:120]}</b>")

    if severity:
        lines.append(f"Severity: <code>{severity}</code>")

    if researcher:
        lines.append(f"Researcher: <b>{researcher}</b>")

    if tags:
        tag_str = "  ".join(f"#{t}" for t in tags)
        lines.append(tag_str)

    if summary:
        lines.append(f"\n{summary[:300]}")

    lines.append(f"\nSource: {source}")
    if url:
        lines.append(f"Link: {url}")

    lines.append(f"\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return "\n".join(lines)

# ─────────────────────────────────────────────
#  KEYWORD ANALYSIS
# ─────────────────────────────────────────────

def classify_text(text):
    """Return list of tags based on keyword matches."""
    t = text.lower()
    tags = []

    # Geo filters
    if any(k in t for k in CHINA_KEYWORDS):
        tags.append("CHINA_APT")
    if any(k in t for k in PAKISTAN_KEYWORDS):
        tags.append("PAKISTAN_APT")

    # Type filters
    if any(k in t for k in ZERODAY_KEYWORDS):
        tags.append("ZERO_DAY")
    if any(k in t for k in MOBILE_KEYWORDS):
        tags.append("MOBILE")

    # RCE
    if "remote code execution" in t or " rce" in t:
        tags.append("RCE")

    # Privilege escalation
    if "privilege escalation" in t or "privesc" in t or "lpe" in t:
        tags.append("PRIVESC")

    # India references
    if any(k in t for k in ["cert-in", "india", "nciipc", "meity", "indian"]):
        tags.append("INDIA")

    return tags

def should_alert(tags, cvss=None):
    """Decide if this item is worth alerting on."""
    # Always alert on geo-targeted items
    if "CHINA_APT" in tags or "PAKISTAN_APT" in tags:
        return True
    # Always alert on zero-days
    if "ZERO_DAY" in tags:
        return True
    # Alert on CVSS threshold
    if cvss and cvss >= MIN_CVSS:
        return True
    # Alert on India govt source items regardless
    if "INDIA" in tags:
        return True
    # Alert on RCE + mobile combo
    if "RCE" in tags or "MOBILE" in tags:
        return True
    return False

# ─────────────────────────────────────────────
#  SOURCE 1: NVD CVE API (near-realtime)
# ─────────────────────────────────────────────

def poll_nvd(state):
    """Poll NVD API for CVEs published/modified in last N hours."""
    log.info("Polling NVD CVE API...")
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=NVD_LOOKBACK_HOURS)
    pub_start = start.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={pub_start}&pubEndDate={pub_end}"
        "&resultsPerPage=50"
    )
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "VulnMonitor/1.0"})
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.error(f"NVD API error: {e}")
        return

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d["lang"] == "en"), "")

        # CVSS score
        cvss = None
        metrics = cve.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "")
                break
        else:
            severity = ""

        combined = f"{cve_id} {desc}"
        tags = classify_text(combined)

        if not should_alert(tags, cvss):
            continue

        h = item_hash(cve_id)
        if already_sent(state, h):
            continue

        sev_str = f"{severity} {cvss}" if cvss else severity
        msg = format_alert(
            title=cve_id,
            source="NVD / NIST",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            severity=sev_str,
            tags=tags,
            summary=desc[:400],
        )
        send_telegram(msg)
        mark_sent(state, h)
        log.info(f"Alerted: {cve_id} | Tags: {tags} | CVSS: {cvss}")

    save_state(state)

# ─────────────────────────────────────────────
#  SOURCE 2: CISA KEV (actively exploited)
# ─────────────────────────────────────────────

def poll_cisa_kev(state):
    """Check CISA KEV for newly added entries (delta compare)."""
    log.info("Polling CISA KEV...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.error(f"CISA KEV error: {e}")
        return

    known = set(state.get("last_cisa_kev", []))
    current_ids = []

    for vuln in data.get("vulnerabilities", []):
        cve_id     = vuln.get("cveID", "")
        vendor     = vuln.get("vendorProject", "")
        product    = vuln.get("product", "")
        vuln_name  = vuln.get("vulnerabilityName", "")
        desc       = vuln.get("shortDescription", "")
        due_date   = vuln.get("dueDate", "")

        current_ids.append(cve_id)

        if cve_id in known:
            continue

        combined = f"{cve_id} {vendor} {product} {vuln_name} {desc}"
        tags = classify_text(combined)
        tags.append("KEV_LISTED")  # Always tag KEV entries
        tags.append("ACTIVELY_EXPLOITED")

        h = item_hash(f"kev_{cve_id}")
        if already_sent(state, h):
            continue

        msg = format_alert(
            title=f"[KEV] {cve_id} — {vuln_name}",
            source="CISA Known Exploited Vulnerabilities",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            severity="ACTIVELY EXPLOITED",
            tags=tags,
            summary=f"{vendor} {product}: {desc}\nPatch due: {due_date}",
        )
        send_telegram(msg)
        mark_sent(state, h)
        log.info(f"CISA KEV new entry: {cve_id}")

    # Update known IDs
    state["last_cisa_kev"] = current_ids[-500:]  # Keep last 500
    save_state(state)

# ─────────────────────────────────────────────
#  SOURCE 3: RSS FEEDS
# ─────────────────────────────────────────────

def poll_rss_feeds(state):
    """Poll all configured RSS feeds for relevant entries."""
    log.info(f"Polling {len(RSS_FEEDS)} RSS feeds...")

    for feed_cfg in RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_cfg["url"])
        except Exception as e:
            log.warning(f"RSS fetch failed [{feed_cfg['name']}]: {e}")
            continue

        for entry in feed.entries[:20]:  # Check latest 20 entries
            title   = getattr(entry, "title", "")
            summary = getattr(entry, "summary", "")
            link    = getattr(entry, "link", "")
            combined = f"{title} {summary}"

            tags = classify_text(combined)
            # Always include category tag
            tags.append(feed_cfg["category"].upper())

            if not should_alert(tags):
                continue

            h = item_hash(f"rss_{link}_{title}")
            if already_sent(state, h):
                continue

            msg = format_alert(
                title=title,
                source=feed_cfg["name"],
                url=link,
                tags=tags,
                summary=summary[:300] if summary else "",
            )
            send_telegram(msg)
            mark_sent(state, h)
            log.info(f"RSS alert [{feed_cfg['name']}]: {title[:80]}")

    save_state(state)

# ─────────────────────────────────────────────
#  SOURCE 4: RESEARCHER TWITTER VIA NITTER RSS
# ─────────────────────────────────────────────

def get_nitter_instance():
    """Find a working Nitter instance."""
    for instance in NITTER_INSTANCES:
        try:
            r = requests.get(instance, timeout=8)
            if r.status_code == 200:
                return instance
        except Exception:
            continue
    return None

def poll_researcher_feeds(state):
    """Monitor security researcher Twitter accounts via Nitter RSS."""
    log.info("Polling researcher Nitter feeds...")

    nitter = get_nitter_instance()
    if not nitter:
        log.warning("No Nitter instance available — skipping researcher feed")
        return

    for researcher in RESEARCHER_NITTER_FEEDS:
        handle = researcher["handle"]
        rss_url = f"{nitter}/{handle}/rss"

        try:
            feed = feedparser.parse(rss_url)
        except Exception as e:
            log.warning(f"Nitter fetch failed [@{handle}]: {e}")
            continue

        for entry in feed.entries[:10]:
            title   = getattr(entry, "title", "")
            summary = getattr(entry, "summary", "")
            link    = getattr(entry, "link", "")
            combined = f"{title} {summary}"

            tags = classify_text(combined)
            tags.append("RESEARCHER_POST")

            # For researcher feeds, alert on any vuln-related post
            vuln_terms = [
                "vuln", "cve", "0day", "zero-day", "exploit", "patch",
                "rce", "lpe", "privesc", "bypass", "overflow", "uaf",
                "working on", "found", "discovered", "disclosure",
            ]
            is_vuln_post = any(t in combined.lower() for t in vuln_terms)

            if not is_vuln_post and not should_alert(tags):
                continue

            h = item_hash(f"nitter_{handle}_{link}")
            if already_sent(state, h):
                continue

            msg = format_alert(
                title=f"@{handle} ({researcher['name']})",
                source=f"Twitter via Nitter",
                url=link.replace(nitter, "https://twitter.com"),
                tags=tags,
                summary=title[:400],
                researcher=researcher["name"],
            )
            send_telegram(msg)
            mark_sent(state, h)
            log.info(f"Researcher alert [@{handle}]: {title[:80]}")

    save_state(state)

# ─────────────────────────────────────────────
#  SOURCE 5: ANDROID SECURITY BULLETIN SCRAPER
# ─────────────────────────────────────────────

ANDROID_BULLETIN_URL = "https://source.android.com/docs/security/bulletin"

def scrape_android_bulletin(state):
    """
    Scrape the Android Security Bulletin for:
    - New CVE entries
    - Researcher names credited
    - Severity levels
    """
    log.info("Checking Android Security Bulletin...")

    try:
        r = requests.get(ANDROID_BULLETIN_URL, timeout=20,
                         headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
    except Exception as e:
        log.error(f"Android bulletin scrape failed: {e}")
        return

    # Find the most recent bulletin link
    bulletin_links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "/docs/security/bulletin/2" in href and href.endswith(".html") or (
            "/docs/security/bulletin/2" in href and href.count("/") >= 5
        ):
            bulletin_links.append(href)

    if not bulletin_links:
        log.warning("No Android bulletin links found")
        return

    # Get the latest (usually first in list)
    latest = bulletin_links[0]
    if not latest.startswith("http"):
        latest = "https://source.android.com" + latest

    h_bulletin = item_hash(f"android_bulletin_{latest}")
    if already_sent(state, h_bulletin):
        log.info(f"Android bulletin already processed: {latest}")
        return

    # Fetch the bulletin page
    try:
        r2 = requests.get(latest, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        r2.raise_for_status()
        soup2 = BeautifulSoup(r2.text, "html.parser")
    except Exception as e:
        log.error(f"Android bulletin detail fetch failed: {e}")
        return

    # Parse CVE table rows for researcher credits
    cves_found = []
    researchers_found = set()

    tables = soup2.find_all("table")
    for table in tables:
        rows = table.find_all("tr")
        for row in rows[1:]:  # Skip header row
            cells = row.find_all("td")
            if len(cells) < 4:
                continue
            cve_id   = cells[0].get_text(strip=True)
            severity = cells[2].get_text(strip=True) if len(cells) > 2 else ""
            reporter = cells[-1].get_text(strip=True)  # Last cell = researcher

            if cve_id.startswith("CVE-"):
                cves_found.append({
                    "cve": cve_id,
                    "severity": severity,
                    "reporter": reporter,
                })
                # Extract researcher names (strip links/emails)
                if reporter and reporter not in ["Google", "Android", "—", "-", ""]:
                    researchers_found.add(reporter)

    if not cves_found:
        log.info("No CVEs parsed from Android bulletin (structure may have changed)")
        return

    # Build summary message
    critical = [c for c in cves_found if "critical" in c["severity"].lower()]
    high     = [c for c in cves_found if "high" in c["severity"].lower()]

    researcher_list = "\n".join(f"  • {r}" for r in sorted(researchers_found)[:20])
    critical_list   = "\n".join(f"  • {c['cve']} ({c['reporter']})" for c in critical[:10])

    msg = (
        f"📱 <b>NEW ANDROID SECURITY BULLETIN</b>\n\n"
        f"Total CVEs: <b>{len(cves_found)}</b>\n"
        f"Critical: <b>{len(critical)}</b>   High: <b>{len(high)}</b>\n\n"
    )
    if critical_list:
        msg += f"<b>Critical CVEs:</b>\n{critical_list}\n\n"
    if researcher_list:
        msg += f"<b>Credited researchers:</b>\n{researcher_list}\n\n"

    msg += f"Full bulletin: {latest}\n"
    msg += f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    send_telegram(msg)
    mark_sent(state, h_bulletin)

    # Also alert individually on critical CVEs
    for cve in critical:
        h = item_hash(f"android_{cve['cve']}")
        if not already_sent(state, h):
            tags = classify_text(f"android {cve['cve']} {cve['reporter']}")
            tags.append("ANDROID")
            tags.append("MOBILE")
            individual_msg = format_alert(
                title=f"[Android Critical] {cve['cve']}",
                source="Android Security Bulletin",
                url=latest,
                severity=cve["severity"],
                tags=tags,
                researcher=cve["reporter"],
                summary="Critical Android vulnerability — patch immediately",
            )
            send_telegram(individual_msg)
            mark_sent(state, h)

    log.info(f"Android bulletin processed: {len(cves_found)} CVEs, {len(researchers_found)} researchers")
    save_state(state)

# ─────────────────────────────────────────────
#  SOURCE 6: CERT-In DIRECT SCRAPE (backup)
# ─────────────────────────────────────────────

def poll_certin(state):
    """Scrape CERT-In advisories directly as backup to RSS."""
    log.info("Checking CERT-In advisories...")
    url = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVISE&type=1"
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
    except Exception as e:
        log.error(f"CERT-In scrape failed: {e}")
        return

    # Parse advisory rows
    rows = soup.find_all("tr")
    for row in rows[:20]:
        cells = row.find_all("td")
        if len(cells) < 3:
            continue
        advisory_id = cells[0].get_text(strip=True)
        title       = cells[1].get_text(strip=True)
        date_str    = cells[2].get_text(strip=True) if len(cells) > 2 else ""

        if not advisory_id.startswith("CIAD") and not advisory_id.startswith("CI"):
            continue

        h = item_hash(f"certin_{advisory_id}")
        if already_sent(state, h):
            continue

        tags = classify_text(f"{advisory_id} {title}")
        tags.append("INDIA")
        tags.append("CERT_IN")

        # Find advisory link
        link_tag = cells[1].find("a")
        link = ""
        if link_tag and link_tag.get("href"):
            link = "https://www.cert-in.org.in" + link_tag["href"]

        msg = format_alert(
            title=f"[CERT-In] {advisory_id}: {title}",
            source="CERT-In (Indian CERT)",
            url=link or "https://www.cert-in.org.in",
            tags=tags,
            summary=f"Published: {date_str}",
        )
        send_telegram(msg)
        mark_sent(state, h)
        log.info(f"CERT-In advisory: {advisory_id} — {title[:60]}")

    save_state(state)

# ─────────────────────────────────────────────
#  STARTUP BANNER
# ─────────────────────────────────────────────

def send_startup_message():
    msg = (
        "✅ <b>Vuln Monitor Started</b>\n\n"
        "Active sources:\n"
        "  • NVD CVE API (every 2h lookback, poll every 10min)\n"
        "  • CISA KEV (daily delta)\n"
        f"  • {len(RSS_FEEDS)} RSS feeds (threat intel, news, PoC)\n"
        f"  • {len(RESEARCHER_NITTER_FEEDS)} researcher Twitter accounts\n"
        "  • Android Security Bulletin (monthly check)\n"
        "  • CERT-In India (advisory scrape)\n\n"
        "Geo filters: #CHINA_APT  #PAKISTAN_APT\n"
        "Type filters: #ZERO_DAY  #RCE  #MOBILE  #KEV\n"
        f"Min CVSS: {MIN_CVSS}\n\n"
        f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    send_telegram(msg)

# ─────────────────────────────────────────────
#  MAIN SCHEDULER
# ─────────────────────────────────────────────

def run_all():
    """Run all polling functions in one cycle."""
    state = load_state()
    log.info("=== Running full intelligence poll cycle ===")

    poll_nvd(state)
    poll_cisa_kev(state)
    poll_rss_feeds(state)
    poll_researcher_feeds(state)
    poll_certin(state)
    # Android bulletin checked less frequently (monthly)
    scrape_android_bulletin(state)

    log.info("=== Cycle complete ===\n")

def main():
    log.info("Vulnerability Intelligence Monitor starting...")

    # Validate config
    if not TELEGRAM_TOKEN:
        log.warning("TELEGRAM_TOKEN not set — alerts will print to console only")
    if not TELEGRAM_CHAT_ID:
        log.warning("TELEGRAM_CHAT_ID not set — alerts will print to console only")

    # Send startup notification
    send_startup_message()

    # Run immediately on start
    run_all()

    # Schedule recurring polls
    schedule.every(10).minutes.do(run_all)   # Main cycle: every 10 minutes
    # (NVD, RSS, researcher feeds, CERT-In run every cycle)
    # (CISA KEV and Android bulletin deduplicate via state so they're safe to poll often)

    log.info("Scheduler running. Press Ctrl+C to stop.")
    while True:
        schedule.run_pending()
        time.sleep(30)

if __name__ == "__main__":
    main()
