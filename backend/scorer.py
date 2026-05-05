import datetime
from typing import Any

TRUSTED_REGISTRARS = {
    "markmonitor",
    "csc corporate domains",
    "network solutions",
    "verisign",
    "godaddy",
    "namecheap",
    "tucows",
    "enom",
    "register.com",
    "gandi",
    "ovh",
    "ionos",
    "fastly",
    "cloudflare",
    "amazon registrar",
    "google domains",
    "squarespace domains",
    "porkbun",
    "dynadot",
    "name.com",
    "internet bs",
    "key-systems",
}

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   
    ".xyz", ".top", ".click", ".loan",
    ".online", ".site", ".club", ".icu",
    ".live", ".digital", ".bid",
}

def _strip_tz(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is not None:
        dt = dt.utctimetuple()
        dt = datetime.datetime(*dt[:6])
    return dt

def _normalize_date(value: any) -> datetime.datetime | None:
    if value is None: 
        return None
    if isinstance(value, list):
        dates = []
        for v in value:
            if isinstance(v, datetime.datetime):
                dates.append(_strip_tz(v))
        if dates:
            return min(dates)
        else:
            return None
    if isinstance(value, datetime.datetime):
        return _strip_tz(value)
    return None
  
