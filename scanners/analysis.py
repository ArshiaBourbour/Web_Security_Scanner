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

    def analyze(self) -> dict[str, Any]:
        self.analyze_ssl()
        self.analyze_dns()
        self.analyze_whois()
        self.analyze_html()

        return {"risk": self.risk_level(), "findings": self.findings}

    def risk_level(self) -> str:
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        med = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        if high >= 2:
            return "HIGH"
        if high == 1 or med >= 2:
            return "MEDIUM"
        return "LOW"
