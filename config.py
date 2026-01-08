import os
from datetime import timedelta


USER_AGENT = "CVEToTelegramParser/1.0"

RSS_URL = os.getenv("RSS_URL", "https://cvefeed.io/rssfeed/severity/high.xml")
CIRCL_URL_TEMPLATE = "https://cve.circl.lu/api/cve/{cve_id}"
NVD_URL_TEMPLATE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
OSV_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{cve_id}"
CVEORG_URL_TEMPLATE = "https://cveawg.mitre.org/api/cve/{cve_id}"
DATABASE_URL = os.getenv("DATABASE_URL")
SUBSCRIBERS_FILE = os.getenv("SUBSCRIBERS_FILE", "subscribers.json")

# Priority order for data sources (higher index = higher priority)
# Data from sources with higher priority will be preferred when merging
SOURCE_PRIORITY = {
    "cveorg": 1,  # Lowest priority
    "osv": 2,
    "nvd": 3,
    "circl": 4,  # Highest priority
}

RECENT_WINDOW_HOURS = int(os.getenv("RECENT_WINDOW_HOURS", "24"))
RECENT_WINDOW = timedelta(hours=RECENT_WINDOW_HOURS)

CRITICAL_THRESHOLD = float(os.getenv("CRITICAL_THRESHOLD", "8.5"))
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "9.0"))
SIREN_THRESHOLD = float(os.getenv("SIREN_THRESHOLD", "9.5"))
MAX_SEND = int(os.getenv("MAX_SEND", "100"))

TELEGRAM_MAX_LEN = 4096
