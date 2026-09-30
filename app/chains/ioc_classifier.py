import ipaddress
import re


_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_URL = re.compile(r"^https?://", re.IGNORECASE)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


def classify_ioc(value: str) -> str:
    v = value.strip()
    if _CVE.match(v):
        return "cve"
    if _URL.match(v):
        return "url"
    if _EMAIL.match(v):
        return "email"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _MD5.match(v) or _SHA1.match(v) or _SHA256.match(v):
        return "hash"
    if _DOMAIN.match(v):
        return "domain"
    return "unknown"


class IocClassifier:
    def classify(self, value: str) -> dict:
        normalized = value.strip().lower()
        ioc_type = classify_ioc(value)
        return {"value": value, "type": ioc_type, "normalized": normalized}
