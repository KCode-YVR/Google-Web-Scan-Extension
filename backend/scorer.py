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

def _normalize_date(value: Any) -> datetime.datetime | None:
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


def _domain_age_days(creation_date: datetime.datetime | None) -> int | None:
    if creation_date is None:
        return None
    return (datetime.datetime.now() - creation_date).days

def _days_until_expiry(expiration_date: datetime.datetime | None) -> int | None:
    if expiration_date is None:
        return None
    return (expiration_date - datetime.datetime.now()).days

def _registration_length_days(creation_date: datetime.datetime | None, expiration_date: datetime.datetime | None) -> int | None:
    if creation_date is None or expiration_date is None:
        return None
    return (expiration_date - creation_date).days

def score(whois_data: dict) -> dict:
    risk = 0
    reasons: list[str] = []
    creation_date = _normalize_date(whois_data.get("creation_date"))
    expiration_date = _normalize_date(whois_data.get("expiration_date"))
    updated_date = _normalize_date(whois_data.get("updated_date"))
    registrar = whois_data.get("registrar") or ""
    name_servers = whois_data.get("name_servers") or []
    domain_name = whois_data.get("domain_name") or ""
    status = whois_data.get("status") or ""
    dnssec = whois_data.get("dnssec") or ""

    if isinstance(name_servers, str):
        name_servers = [name_servers]
    if isinstance(domain_name, list):
        domain_name = domain_name[0]
    
    age_days = _domain_age_days(creation_date)
    days_to_expiry = _days_until_expiry(expiration_date)
    reg_length_days = _registration_length_days(creation_date, expiration_date)

    if creation_date:
        creation = creation_date.strftime("%Y-%m-%d")
    else:
        creation = "Unknown"

    if expiration_date:
        expiration = expiration_date.strftime("%Y-%m-%d")
    else:
        expiration = "Unknown"

    if updated_date:
        updated = updated_date.strftime("%Y-%m-%d")
    else:
        updated = "Unknown"

    if registrar:
        registrar_value = registrar
    else:
        registrar_value = "Unknown"

    whois_summary = {
        "creation": creation,
        "expiration": expiration,
        "updated": updated,
        "registrar": registrar_value,
    }

    missing = []
    if creation_date is None:
        missing.append("creation date")
        risk += 10
    if expiration_date is None:
        missing.append("expiration date")
        risk += 10
    if not registrar:
        missing.append("registrar")
        risk += 10
     
    if missing:
        reasons.append(
            f"WHOIS is missing critical fields: {', '.join(missing)}. "
            "This may indicate privacy shielding or an incomplete record."
        )
    
    if creation_date is None and expiration_date is None:
        reasons.append(
            "Cannot assess domain age or expiry — WHOIS data is incomplete or "
            "privacy-protected (treated as inconclusive)."
        )

    if age_days is not None:
        if age_days < 30:
            risk += 35
            reasons.append(
                f"Domain is very new — only {age_days} day(s) old. "
                "Freshly registered domains are a strong indicator of phishing or fraud."
            )
        elif age_days < 180:
            risk += 25
            reasons.append(
                f"Domain is less than 6 months old ({age_days} days). "
                "Short-lived domains are frequently used for malicious campaigns."
            )
        elif age_days < 365:
            risk += 15
            reasons.append(
                f"Domain is less than 1 year old ({age_days} days). "
                "Exercise caution with domains under a year old."
            )
        elif age_days < 730:
            risk += 5
            reasons.append(f"Domain is {age_days} days old (1–2 years). Relatively young.")
        else:
            reasons.append(
                f"Domain is over 2 years old ({age_days} days). Age is a positive trust signal."
            )
    
    if days_to_expiry is not None:
        if days_to_expiry < 0:
            risk += 20
            reasons.append(
                f"Domain has already EXPIRED ({abs(days_to_expiry)} days ago). "
                "Expired domains are sometimes hijacked for malicious use."
            )
        elif days_to_expiry < 30:
            risk += 20
            reasons.append(
                f"Domain expires in {days_to_expiry} day(s). "
                "Imminent expiry is a major red flag."
            )
        elif days_to_expiry < 90:
            risk += 10
            reasons.append(
                f"Domain expires in {days_to_expiry} days (under 3 months)."
            )
        else:
            reasons.append(
                f"Domain expiration is {days_to_expiry} days away — not unusually soon."
            )

    if reg_length_days is not None:
        if reg_length_days < 365:
            risk += 15
            reasons.append(
                f"Total registration period is under 1 year ({reg_length_days} days). "
                "Legitimate organisations typically register for multiple years."
            )
        elif reg_length_days < 730:
            risk += 5
            reasons.append(
                f"Registration period is {reg_length_days} days (1–2 years). Slightly short."
            )
        else:
            reasons.append(
                f"Registration period is {reg_length_days} days — multi-year registration "
                "is a positive trust signal."
            )

    if registrar:
        registrar_lower = registrar.lower()
        is_trusted = any(t in registrar_lower for t in TRUSTED_REGISTRARS)
        if not is_trusted:
            risk += 10
            reasons.append(
                f"Registrar '{registrar}' is not on the known-trusted list. "
                "This does not mean it is malicious, but warrants extra caution."
            )
        else:
            reasons.append(f"Registrar '{registrar}' is a recognised, trusted registrar.")
    
    ns_count = len(set(ns.lower() for ns in name_servers if ns))
    if ns_count == 0:
        risk += 5
        reasons.append("No name servers found in WHOIS record.")
    elif ns_count == 1:
        risk += 5
        reasons.append(
            "Only one name server detected. "
            "Established domains typically use two or more for redundancy."
        )

    risk = min(risk, 100)

    if risk <= 15:
        classification = "safe"
    elif risk <= 45:
        classification = "suspicious"
    else:
        classiification = "unsafe"

    return {
        "risk_score": risk,
        "classification": classification,
        "reasons": reasons,
        "whois_summary": whois_summary,
    }