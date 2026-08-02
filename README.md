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
<img width="655" height="429" alt="image" src="https://github.com/user-attachments/assets/80b7c47f-e746-45c1-a0f3-7853ffff631f" />
<img width="480" height="587" alt="Notification" src="https://github.com/user-attachments/assets/687650e5-2758-43f0-99a1-8c1cd94f259d" />

## Sources monitored

See `Feeds_Being_Monitored.txt` for the full feed list.
