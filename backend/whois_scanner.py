import whois
import re
from typing import Any

def _extract_domain(url_or_domain: str) -> str:
    domain = re.sub(r'^https?://', '', url_or_domain, flags=re.IGNORECASE)
    domain = domain.split('/')[0]
    domain = domain.split('?')[0]
    domain = domain.split('#')[0]
    domain = domain.split(':')[0]
    domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
    return domain.strip().lower()

def lookup(url_or_domain: str) -> dict:
    domain = _extract_domain(url_or_domain)
    try:
        w = whois.whois(domain)
        if w is None or not any([w.creation_date, w.expiration_date, w.registrar, w.name_servers]):
            return {
                "domain": domain,
                "raw": None,
                "error": (
                    "WHOIS lookup returned no usable data. "
                    "The domain may not exist, use heavy privacy protection, "
                    "or the TLD may not support WHOIS."
                ),
            }
        return {
            "domain": domain,
            "raw": {
                "creation_date":   w.creation_date,
                "expiration_date": w.expiration_date,
                "updated_date":    w.updated_date,
                "registrar":       w.registrar,
                "name_servers":    w.name_servers,
                "status":          w.status,
                "dnssec":          w.dnssec,
                "domain_name":     w.domain_name or domain,
            },
            "error": None,
        }
    except whois.parser.PywhoisError as exc:
        return {
            "domain": domain,
            "raw": None,
            "error": f"WHOIS parse error: {exc}",
        }
    except Exception as exc:  
        return {
            "domain": domain,
            "raw": None,
            "error": f"WHOIS lookup failed: {exc}",
        }
