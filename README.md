# Vulnerability Intelligence Monitor

Real-time monitor that polls NVD, CISA KEV, security RSS feeds, researcher
sources, Android Security Bulletins, and CERT-In advisories, then pushes
alerts to Telegram. Includes geo/APT keyword tagging, zero-day detection,
and dedupe via local state.

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

## Sources monitored

See `Feeds_Being_Monitored.txt` for the full feed list.
