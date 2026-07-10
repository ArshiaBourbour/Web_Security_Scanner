from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlparse


def safe_report_filename(target: str, extension: str) -> str:
    # turn a target URL + extension into a filesystem-safe report filename
    parsed = urlparse(target)
    host = parsed.netloc or parsed.path or target
    safe_host = re.sub(r"[^a-zA-Z0-9.-]", "_", host)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{safe_host}_{timestamp}.{extension}"
