"""Static URL features for phishing and brand-impersonation detection.

All parsing is local. No DNS resolution, HTTP requests, redirect following, or
other network activity occurs in this module.
"""
from ipaddress import ip_address
import math
import re
from urllib.parse import parse_qsl, urlsplit

SUSPICIOUS_TOKENS = ("login", "verify", "update", "secure", "account", "banking",
                     "free", "confirm", "signin", "paypal", "support")
TARGETED_BRANDS = ("paypal", "microsoft", "apple", "google", "amazon", "netflix",
                   "facebook", "instagram", "binance", "chase", "wellsfargo", "dhl", "fedex")
HIGH_RISK_TLDS = {"xyz", "tk", "top", "gq", "ml", "cf", "ga", "work", "click", "zip", "support", "online"}
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "com.au", "net.au", "co.jp", "com.br", "co.in", "co.nz", "com.mx"}
CONFUSABLE_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})
FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "dot_count", "hyphen_count",
    "underscore_count", "slash_count", "question_count", "equals_count", "at_count",
    "digit_count", "subdomain_count", "has_ip", "is_https", "suspicious_token_count",
    "digit_ratio", "hostname_entropy", "path_entropy", "digit_to_letter_ratio",
    "query_parameter_count", "double_slash_redirect", "suspicious_token_density",
    "brand_impersonation_score", "punycode_flag", "non_ascii_hostname_flag", "high_risk_tld_flag",
]

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(char) / len(value)) * math.log2(value.count(char) / len(value))
                for char in set(value))

def _edit_similarity(left: str, right: str) -> float:
    """Normalized Levenshtein similarity using a small rolling-row DP table."""
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[j] + 1,
                               previous[j - 1] + (char_left != char_right)))
        previous = current
    return 1.0 - previous[-1] / max(len(left), len(right))

def _registered_label(host: str) -> str:
    """Approximate the registrable domain label without a PSL/network lookup."""
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) < 2:
        return labels[0] if labels else ""
    suffix2 = ".".join(labels[-2:])
    return labels[-3] if suffix2 in TWO_PART_SUFFIXES and len(labels) >= 3 else labels[-2]

def _decoded_host(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna").lower()
    except (UnicodeError, UnicodeEncodeError):
        return host.lower()

def _brand_score(host: str) -> float:
    label = _registered_label(host)
    decoded = _registered_label(_decoded_host(host))
    candidates = {label, decoded}
    candidates.update(part for candidate in tuple(candidates) for part in candidate.split("-") if part)
    best = 0.0
    for candidate in candidates:
        normalized = candidate.translate(CONFUSABLE_TRANSLATION).replace("-", "")
        # Exact brand registration is not typosquatting; a brand embedded in a
        # longer registrable label is suspicious, as is a close altered spelling.
        for brand in TARGETED_BRANDS:
            if candidate == brand:
                continue
            if brand in normalized:
                best = max(best, 0.98)
            if abs(len(normalized) - len(brand)) <= 2 and normalized[:1] == brand[:1]:
                similarity = _edit_similarity(normalized, brand)
                if similarity >= 0.72:
                    best = max(best, similarity)
    return round(best, 4)

def _parts(url: str):
    raw = "" if url is None else str(url).strip()
    # urlsplit treats a bare host as a path. Adding // lets it parse as a hostname.
    candidate = raw if "://" in raw or raw.startswith("//") else "//" + raw
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        # Some noisy dataset rows contain unmatched IPv6 brackets. Keep all
        # lexical counts from the original string and treat host parsing as unknown.
        parsed = urlsplit("")
    return raw, parsed

def extract_url_features(url: str) -> dict:
    """Return numeric lexical, structural, and brand-similarity URL features."""
    raw, parsed = _parts(url)
    host = (parsed.hostname or "").lower()
    try:
        ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0
    host_labels = [label for label in host.split(".") if label]
    lowered = raw.lower()
    tokens = re.findall(r"[a-z0-9]+", lowered)
    token_count = sum(tokens.count(token) for token in SUSPICIOUS_TOKENS)
    letters = sum(char.isalpha() for char in raw)
    digits = sum(char.isdigit() for char in raw)
    unicode_host = _decoded_host(host)
    tld = host_labels[-1] if host_labels else ""
    after_authority = ""
    if "://" in raw:
        after_authority = raw.split("://", 1)[1].split("/", 1)[1] if "/" in raw.split("://", 1)[1] else ""
    elif raw.startswith("//"):
        after_authority = raw[2:].split("/", 1)[1] if "/" in raw[2:] else ""
    token_density = token_count / max(len(tokens), 1)
    return {
        "url_length": len(raw), "hostname_length": len(host), "path_length": len(parsed.path),
        "dot_count": raw.count("."), "hyphen_count": raw.count("-"),
        "underscore_count": raw.count("_"), "slash_count": raw.count("/"),
        "question_count": raw.count("?"), "equals_count": raw.count("="),
        "at_count": raw.count("@"), "digit_count": sum(ch.isdigit() for ch in raw),
        "subdomain_count": max(0, len(host_labels) - 2), "has_ip": has_ip,
        "is_https": int(parsed.scheme.lower() == "https"),
        "suspicious_token_count": token_count,
        "digit_ratio": digits / max(len(raw), 1),
        "hostname_entropy": _entropy(host), "path_entropy": _entropy(parsed.path),
        "digit_to_letter_ratio": digits / max(letters, 1),
        "query_parameter_count": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "double_slash_redirect": int(parsed.path.startswith("//") or after_authority.startswith("//")),
        "suspicious_token_density": token_density,
        "brand_impersonation_score": _brand_score(host),
        "punycode_flag": int(any(label.startswith("xn--") for label in host_labels)),
        "non_ascii_hostname_flag": int(any(ord(char) > 127 for char in host) or
                                           any(ord(char) > 127 for char in unicode_host)),
        "high_risk_tld_flag": int(tld in HIGH_RISK_TLDS),
    }

def explain_url_features(url: str) -> list[str]:
    """Describe simple URL red flags; these are indicators, not a verdict."""
    features = extract_url_features(url)
    raw, _ = _parts(url)
    explanations = []
    if features["has_ip"]:
        explanations.append("Uses IP address instead of domain")
    if not features["is_https"]:
        explanations.append("Does not use HTTPS")
    lowered = raw.lower()
    for token in SUSPICIOUS_TOKENS:
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lowered):
            explanations.append(f"Contains suspicious keyword: {token}")
    if features["at_count"]:
        explanations.append("Contains @ symbol")
    if features["brand_impersonation_score"] >= 0.72:
        explanations.append("Possible targeted-brand impersonation in registered domain")
    if features["punycode_flag"]:
        explanations.append("Contains punycode hostname label")
    if features["non_ascii_hostname_flag"]:
        explanations.append("Hostname contains non-ASCII characters")
    if features["high_risk_tld_flag"]:
        explanations.append("Uses a high-risk top-level domain")
    if features["double_slash_redirect"]:
        explanations.append("Contains a repeated slash after the hostname")
    if features["subdomain_count"] >= 3:
        explanations.append("Contains many subdomain levels")
    return explanations

def extract_url_feature_rows(urls):
    """Convert an iterable of URLs to a feature table in stable column order."""
    import pandas as pd
    return pd.DataFrame.from_records((extract_url_features(url) for url in urls), columns=FEATURE_NAMES)

def analyze_url(url: str) -> dict:
    """Return URL features and their human-readable static indicators."""
    return {"features": extract_url_features(url), "indicators": explain_url_features(url)}
