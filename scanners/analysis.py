from typing import Any

from core.result import CheckResult, CheckStatus


class RiskAnalyzer:
    def __init__(self, results: dict[str, CheckResult]):
        self.results = results
        self.findings: list[dict[str, str]] = []

    def add(self, severity: str, title: str, recommendation: str) -> None:
        self.findings.append(
            {"severity": severity, "title": title, "recommendation": recommendation}
        )

    def _result(self, step: str) -> CheckResult:
        return self.results.get(
            step, CheckResult(name=step, status=CheckStatus.ERROR, data={})
        )

    def analyze_ssl(self):
        ssl_result = self._result("ssl")

        if ssl_result.failed or not ssl_result.data:
            self.add("HIGH", "SSL Missing", "Fix SSL connection")
            return

        if not ssl_result.get("notAfter"):
            self.add("HIGH", "SSL Invalid", "Certificate broken")
            return

    def analyze_dns(self):
        dns_result = self._result("dns")

        if not dns_result.get("A"):
            self.add("HIGH", "No A Record", "Domain not resolving")

        if not dns_result.get("AAAA"):
            self.add("LOW", "No IPv6 Record", "Add AAAA record")

        if not dns_result.get("MX"):
            self.add("MEDIUM", "No Mail Server", "Add MX record")

        if not dns_result.get("TXT"):
            self.add("LOW", "No TXT Records", "Add SPF/DKIM/DMARC")

    def analyze_whois(self):
        whois_result = self._result("whois")

        if whois_result.failed or not whois_result.data:
            return

        if not whois_result.get("expiration_date"):
            self.add("MEDIUM", "Missing Domain Expiry", "Check WHOIS data")

        if not whois_result.get("creation_date"):
            self.add("LOW", "Missing Domain Creation Date", "Check WHOIS data")

    def analyze_html(self):
        html_result = self._result("html")

        if html_result.get("script_count", 0) > 20:
            self.add("LOW", "High JS Usage", "Review scripts")

    def analyze_cookies(self):
        cookies_result = self._result("cookies")

        if cookies_result.failed or not cookies_result.data:
            return

        if cookies_result.get("insecure_count", 0) > 0:
            self.add(
                "MEDIUM",
                "Cookies Missing Secure Flag",
                "Set the Secure attribute so cookies are only sent over HTTPS",
            )

        if cookies_result.get("no_httponly_count", 0) > 0:
            self.add(
                "MEDIUM",
                "Cookies Missing HttpOnly Flag",
                "Set HttpOnly to prevent cookie access via JavaScript",
            )

        if cookies_result.get("no_samesite_count", 0) > 0:
            self.add(
                "LOW",
                "Cookies Missing SameSite Attribute",
                "Set SameSite=Lax or Strict to mitigate CSRF",
            )

    def analyze_http_methods(self):
        methods_result = self._result("http_methods")

        if methods_result.failed or not methods_result.data:
            return

        if methods_result.get("trace_reflects_body"):
            self.add(
                "HIGH",
                "TRACE Method Enabled (XST Risk)",
                "Disable the TRACE method to prevent Cross-Site Tracing attacks",
            )
        elif methods_result.get("trace_enabled"):
            self.add(
                "MEDIUM",
                "TRACE Method Enabled",
                "Disable the TRACE method on the web server",
            )

        risky = set(methods_result.get("risky_methods", [])) - {"TRACE"}

        if "PUT" in risky or "DELETE" in risky:
            self.add(
                "MEDIUM",
                "State-Changing HTTP Methods Allowed",
                "Disable PUT/DELETE unless explicitly required and authenticated",
            )

        if "CONNECT" in risky:
            self.add(
                "MEDIUM",
                "CONNECT Method Allowed",
                "Disable CONNECT unless this server is meant to act as a proxy",
            )

    def analyze_robots(self):
        robots_result = self._result("robots")

        if robots_result.failed or not robots_result.data:
            return

        if not robots_result.get("found"):
            return

        sensitive_paths = robots_result.get("sensitive_paths", [])

        if sensitive_paths:
            self.add(
                "LOW",
                "Sensitive Paths Disclosed in robots.txt",
                "Remove references to sensitive paths from robots.txt; "
                "it is public and does not restrict access",
            )

    def analyze_sitemap(self):
        sitemap_result = self._result("sitemap")

        if sitemap_result.failed or not sitemap_result.data:
            return

        if not sitemap_result.get("found"):
            return

        sensitive_urls = sitemap_result.get("sensitive_urls", [])

        # A small, focused set of matches is a meaningful signal. A very large
        # number usually just means the keywords coincidentally show up in
        # normal user/product-generated content (e.g. package names on a
        # registry site) rather than pointing at real sensitive paths, so we
        # don't want to raise a "finding" for that noise.
        if 0 < len(sensitive_urls) <= 20:
            self.add(
                "LOW",
                "Sensitive URLs Disclosed in sitemap.xml",
                "Remove sensitive/internal URLs from the public sitemap",
            )

    def analyze_csp(self):
        csp_result = self._result("csp")

        if csp_result.failed or not csp_result.data:
            return

        if not csp_result.get("found"):
            self.add("MEDIUM", "No CSP Header", "Add a Content-Security-Policy header")
            return

        for issue in csp_result.get("issues", []):
            self.add(issue["severity"], issue["title"], issue["detail"])

    def analyze_cors(self):
        cors_result = self._result("cors")

        if cors_result.failed or not cors_result.data:
            return

        if not cors_result.get("found"):
            return

        for issue in cors_result.get("issues", []):
            self.add(issue["severity"], issue["title"], issue["detail"])

    def analyze_hsts(self):
        hsts_result = self._result("hsts")

        if hsts_result.failed or not hsts_result.data:
            return

        if not hsts_result.get("found"):
            self.add("MEDIUM", "No HSTS Header", "Add a Strict-Transport-Security header")
            return

        for issue in hsts_result.get("issues", []):
            self.add(issue["severity"], issue["title"], issue["detail"])

    def analyze_clickjacking(self):
        cj_result = self._result("clickjacking")

        if cj_result.failed or not cj_result.data:
            return

        for issue in cj_result.get("issues", []):
            self.add(issue["severity"], issue["title"], issue["detail"])

    def analyze(self) -> dict[str, Any]:
        self.analyze_ssl()
        self.analyze_dns()
        self.analyze_whois()
        self.analyze_html()
        self.analyze_cookies()
        self.analyze_http_methods()
        self.analyze_robots()
        self.analyze_sitemap()
        self.analyze_csp()
        self.analyze_cors()
        self.analyze_hsts()
        self.analyze_clickjacking()

        return {"risk": self.risk_level(), "findings": self.findings}

    def risk_level(self) -> str:
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        med = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        if high >= 2:
            return "HIGH"
        if high == 1 or med >= 2:
            return "MEDIUM"
        return "LOW"