import os
from datetime import timedelta


USER_AGENT = "CVEToTelegramParser/1.0"

RSS_URL = os.getenv("RSS_URL", "https://cvefeed.io/rssfeed/severity/high.xml")
CIRCL_URL_TEMPLATE = "https://cve.circl.lu/api/cve/{cve_id}"

RECENT_WINDOW_HOURS = int(os.getenv("RECENT_WINDOW_HOURS", "24"))
RECENT_WINDOW = timedelta(hours=RECENT_WINDOW_HOURS)

CRITICAL_THRESHOLD = float(os.getenv("CRITICAL_THRESHOLD", "8.5"))
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "9.0"))
SIREN_THRESHOLD = float(os.getenv("SIREN_THRESHOLD", "9.5"))

TELEGRAM_MAX_LEN = 4096
SUBSCRIBERS_FILE = os.getenv("SUBSCRIBERS_FILE", "subscribers.json")
