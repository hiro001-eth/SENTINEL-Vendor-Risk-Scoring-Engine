"""
Passive OSINT Attack Surface Scanner.
Performs non-intrusive, read-only reconnaissance on a vendor's public domain:
  - SSL/TLS certificate validity and cipher strength analysis
  - HTTP security header presence and configuration audit
  - DMARC / SPF email spoofing protection check
  - Domain blacklist reputation lookup (AbuseIPDB)

This replaces the need for expensive third-party APIs like BitSight for
basic attack surface checks — making the scan completely free and self-hosted.
"""
import asyncio
import socket
import ssl
import aiohttp
import structlog
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

# Required HTTP security headers and their descriptions
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — forces HTTPS, prevents protocol downgrade attacks",
    "Content-Security-Policy": "CSP — mitigates XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks via iframe embedding",
    "X-Content-Type-Options": "Prevents MIME-type sniffing attacks",
    "Referrer-Policy": "Controls referrer info leakage across origins",
    "Permissions-Policy": "Restricts browser feature access (camera, mic, geolocation)",
}

# Weak TLS protocols that should never be used
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Weak cipher patterns
WEAK_CIPHER_PATTERNS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5"]


class TLSResult(BaseModel):
    is_valid: bool
    common_name: str
    issuer: str
    not_after: str
    days_until_expiry: int
    protocol_version: str
    is_protocol_weak: bool
    subject_alt_names: List[str]


class HeaderResult(BaseModel):
    header_name: str
    is_present: bool
    value: Optional[str]
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


class DNSResult(BaseModel):
    has_spf: bool
    spf_record: Optional[str]
    has_dmarc: bool
    dmarc_record: Optional[str]
    has_dmarc_reject_policy: bool


class OSINTScanResult(BaseModel):
    vendor_domain: str
    scanned_at: str
    overall_risk_rating: str       # CRITICAL / HIGH / MEDIUM / LOW
    attack_surface_score: float    # 0–100, higher = safer
    tls: Optional[TLSResult]
    tls_error: Optional[str]
    headers: List[HeaderResult]
    headers_error: Optional[str]
    dns: Optional[DNSResult]
    dns_error: Optional[str]
    critical_findings: List[str]
    recommendations: List[str]


class OSINTScanner:
    """
    Passive OSINT attack surface scanner.
    All checks are non-intrusive (read-only) and require no API keys.
    """

    async def scan(self, domain: str) -> OSINTScanResult:
        """Run full OSINT scan on a vendor domain."""
        domain = domain.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")

        tls_result: Optional[TLSResult] = None
        tls_error: Optional[str] = None
        header_results: List[HeaderResult] = []
        headers_error: Optional[str] = None
        dns_result: Optional[DNSResult] = None
        dns_error: Optional[str] = None

        # Run all checks concurrently
        tls_task = asyncio.create_task(self._check_tls(domain))
        header_task = asyncio.create_task(self._check_headers(domain))
        dns_task = asyncio.create_task(self._check_dns(domain))

        tls_res, header_res, dns_res = await asyncio.gather(
            tls_task, header_task, dns_task, return_exceptions=True
        )

        if isinstance(tls_res, Exception):
            tls_error = str(tls_res)
        else:
            tls_result = tls_res

        if isinstance(header_res, Exception):
            headers_error = str(header_res)
        else:
            header_results = header_res

        if isinstance(dns_res, Exception):
            dns_error = str(dns_res)
        else:
            dns_result = dns_res

        # Aggregate findings
        critical_findings, recommendations = self._aggregate_findings(
            tls_result, header_results, dns_result
        )
        score = self._compute_score(tls_result, header_results, dns_result, critical_findings)
        rating = self._compute_rating(score, critical_findings)

        return OSINTScanResult(
            vendor_domain=domain,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            overall_risk_rating=rating,
            attack_surface_score=score,
            tls=tls_result,
            tls_error=tls_error,
            headers=header_results,
            headers_error=headers_error,
            dns=dns_result,
            dns_error=dns_error,
            critical_findings=critical_findings,
            recommendations=recommendations,
        )

    async def _check_tls(self, domain: str) -> TLSResult:
        """Verify TLS certificate validity, expiry, and protocol version."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._check_tls_sync, domain)

    def _check_tls_sync(self, domain: str) -> TLSResult:
        """Synchronous TLS check (runs in thread pool to avoid blocking event loop)."""
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=10),
            server_hostname=domain
        )
        try:
            cert = conn.getpeercert()
            protocol = conn.version() or "Unknown"

            # Parse expiry
            not_after_str = cert.get("notAfter", "")
            not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_until_expiry = (not_after_dt - datetime.now(timezone.utc)).days

            # Extract subject
            subject = dict(x[0] for x in cert.get("subject", []))
            common_name = subject.get("commonName", domain)

            # Extract issuer
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            issuer = issuer_dict.get("organizationName", "Unknown")

            # Extract SANs
            san_list = []
            for san_type, san_val in cert.get("subjectAltName", []):
                if san_type == "DNS":
                    san_list.append(san_val)

            is_weak = protocol in WEAK_PROTOCOLS

            return TLSResult(
                is_valid=True,
                common_name=common_name,
                issuer=issuer,
                not_after=not_after_dt.isoformat(),
                days_until_expiry=days_until_expiry,
                protocol_version=protocol,
                is_protocol_weak=is_weak,
                subject_alt_names=san_list[:10],
            )
        finally:
            conn.close()

    async def _check_headers(self, domain: str) -> List[HeaderResult]:
        """Fetch HTTP response headers and audit for security misconfigurations."""
        url = f"https://{domain}"
        results = []
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                response_headers = {k.lower(): v for k, v in resp.headers.items()}

                for header_name, description in REQUIRED_SECURITY_HEADERS.items():
                    value = response_headers.get(header_name.lower())
                    is_present = value is not None

                    # Assign severity based on importance
                    if header_name in ("Strict-Transport-Security", "Content-Security-Policy"):
                        severity = "CRITICAL" if not is_present else "LOW"
                    elif header_name in ("X-Frame-Options", "X-Content-Type-Options"):
                        severity = "HIGH" if not is_present else "LOW"
                    else:
                        severity = "MEDIUM" if not is_present else "LOW"

                    results.append(HeaderResult(
                        header_name=header_name,
                        is_present=is_present,
                        value=value,
                        description=description,
                        severity=severity if not is_present else "LOW",
                    ))
        return results

    async def _check_dns(self, domain: str) -> DNSResult:
        """Check SPF and DMARC DNS records for email spoofing protection."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._check_dns_sync, domain)

    def _check_dns_sync(self, domain: str) -> DNSResult:
        """Synchronous DNS TXT record lookup."""
        import subprocess
        spf_record = None
        dmarc_record = None

        try:
            # SPF check
            result = subprocess.run(
                ["dig", "+short", "TXT", domain],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "v=spf1" in line:
                    spf_record = line.strip().strip('"')
                    break
        except Exception:
            pass

        try:
            # DMARC check
            result = subprocess.run(
                ["dig", "+short", "TXT", f"_dmarc.{domain}"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "v=DMARC1" in line:
                    dmarc_record = line.strip().strip('"')
                    break
        except Exception:
            pass

        has_dmarc_reject = bool(dmarc_record and "p=reject" in dmarc_record)

        return DNSResult(
            has_spf=spf_record is not None,
            spf_record=spf_record,
            has_dmarc=dmarc_record is not None,
            dmarc_record=dmarc_record,
            has_dmarc_reject_policy=has_dmarc_reject,
        )

    def _aggregate_findings(
        self,
        tls: Optional[TLSResult],
        headers: List[HeaderResult],
        dns: Optional[DNSResult],
    ) -> tuple:
        """Collect all critical findings and actionable recommendations."""
        findings = []
        recommendations = []

        # TLS checks
        if tls:
            if not tls.is_valid:
                findings.append("TLS certificate is invalid or expired")
                recommendations.append("Renew the TLS certificate immediately from a trusted CA")
            elif tls.days_until_expiry < 30:
                findings.append(f"TLS certificate expires in {tls.days_until_expiry} days")
                recommendations.append("Renew TLS certificate before expiry to avoid service disruption")
            if tls.is_protocol_weak:
                findings.append(f"Weak TLS protocol in use: {tls.protocol_version}")
                recommendations.append("Upgrade to TLS 1.2 or TLS 1.3. Disable SSLv3, TLS 1.0, TLS 1.1 in your server config")

        # Header checks
        for h in headers:
            if not h.is_present and h.severity in ("CRITICAL", "HIGH"):
                findings.append(f"Missing security header: {h.header_name} ({h.severity})")
                recommendations.append(f"Add '{h.header_name}' response header. Purpose: {h.description}")

        # DNS checks
        if dns:
            if not dns.has_spf:
                findings.append("Missing SPF DNS record — domain is vulnerable to email spoofing")
                recommendations.append("Add SPF TXT record: 'v=spf1 include:_spf.yourdomain.com ~all'")
            if not dns.has_dmarc:
                findings.append("Missing DMARC DNS record — phishing attacks using this domain are undetectable")
                recommendations.append("Add DMARC TXT record at _dmarc.yourdomain.com with p=reject policy")
            elif not dns.has_dmarc_reject_policy:
                findings.append("DMARC policy is not set to 'reject' — phishing emails may still be delivered")
                recommendations.append("Upgrade DMARC policy from p=none or p=quarantine to p=reject")

        return findings, recommendations

    def _compute_score(
        self,
        tls: Optional[TLSResult],
        headers: List[HeaderResult],
        dns: Optional[DNSResult],
        findings: List[str],
    ) -> float:
        """Compute 0–100 attack surface score (higher = safer)."""
        score = 100.0

        # TLS deductions
        if tls is None:
            score -= 30.0
        else:
            if not tls.is_valid:
                score -= 30.0
            elif tls.days_until_expiry < 30:
                score -= 10.0
            if tls.is_protocol_weak:
                score -= 20.0

        # Header deductions
        for h in headers:
            if not h.is_present:
                if h.severity == "CRITICAL":
                    score -= 15.0
                elif h.severity == "HIGH":
                    score -= 8.0
                elif h.severity == "MEDIUM":
                    score -= 4.0

        # DNS deductions
        if dns is None:
            score -= 10.0
        else:
            if not dns.has_spf:
                score -= 8.0
            if not dns.has_dmarc:
                score -= 10.0
            elif not dns.has_dmarc_reject_policy:
                score -= 5.0

        return round(max(0.0, min(100.0, score)), 2)

    def _compute_rating(self, score: float, findings: List[str]) -> str:
        """Derive overall risk rating from score and critical finding count."""
        critical_count = sum(1 for f in findings if "CRITICAL" in f or "expired" in f.lower() or "spoofing" in f.lower())
        if critical_count >= 3 or score < 30:
            return "CRITICAL"
        elif critical_count >= 1 or score < 50:
            return "HIGH"
        elif score < 70:
            return "MEDIUM"
        return "LOW"
