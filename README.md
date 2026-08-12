# Vulnerability Intelligence Monitor

Real-time monitor that polls NVD, CISA KEV, security RSS feeds, researcher
sources, Android Security Bulletins, and CERT-In advisories, then pushes
alerts to Telegram. Includes geo/APT keyword tagging, potential zero-day detection/tagging,
and dedupe via local state.

### Why I built this

## Purpose

The goal of this project is to automate the early stages of vulnerability
intelligence collection and reduce the time required to identify potentially
relevant vulnerabilities from multiple intelligence sources.

The workflow follows a CTI-oriented approach:

**Collect → Process → Enrich → Prioritize → Alert**

## Architecture

NVD / CISA KEV / CERT-In / RSS / Researcher Sources
                         │
                         ▼
                    Data Collector
                         │
                         ▼
                       Parser
                         │
                         ▼
             Threat Intelligence Enrichment
              ├── CVE extraction
              ├── APT keyword tagging
              ├── Geographic tagging
              └── Zero-day detection
                         │
                         ▼
                   Deduplication
                         │
                         ▼
                   Alert Engine
                         │
                         ▼
                  Telegram Alerts
## Key Capabilities

- Multi-source vulnerability intelligence collection
- CVE and CISA KEV monitoring
- APT and geographic keyword tagging
- Potential zero-day detection
- Duplicate alert suppression using local state
- Automated Telegram notifications
- RSS and web-based intelligence collection
- Scheduled monitoring and alerting
  
## Sample workflow
CVE discovered → source validated → APT/geo keyword match → deduplicated → priority assigned → Telegram alert

## Setup

```bash
pip install requests feedparser beautifulsoup4 schedule python-dotenv
```

Create a `.env` file (never commit this):

```
TELEGRAM_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```


## Run

```bash
python vuln_monitor.py
```
<img width="655" height="429" alt="image" src="https://github.com/user-attachments/assets/80b7c47f-e746-45c1-a0f3-7853ffff631f" />
<img width="480" height="587" alt="Notification" src="https://github.com/user-attachments/assets/687650e5-2758-43f0-99a1-8c1cd94f259d" />

## Technologies

- Python
- Requests
- Feedparser
- BeautifulSoup
- Schedule
- python-dotenv
- Telegram Bot API
- NVD
- CISA KEV
- CERT-In
- RSS
  
## Sources monitored

See `Feeds_Being_Monitored.txt` for the full feed list.
