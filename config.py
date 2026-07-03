from pathlib import Path

# Root directory
BASE_DIR = Path(__file__).resolve().parent

# Reports Folder
REPORT_DIR = BASE_DIR / "reports"

# Request timeout (in seconds)
REQUEST_TIMEOUT = 10

# User-agent
USER_AGENT = "WebSecurityScanner/1.0(Python Requests)"

# VirusTotal API
VIRUSTOTAL_API_KEY = ""

# Google Safe Browsing API
GOOGLE_SAFE_BROWSING_API_KEY = ""
