"""Static RFC-style email parsing and lightweight header forensics.

This module uses Python's standard email parser and BeautifulSoup's static
HTML parser. It does not follow links, fetch resources, or execute markup.
"""
from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup
from src.webpage_analyzer import extract_link_audits

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", flags=re.IGNORECASE)
AUTH_FAILURE_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*fail\b", flags=re.IGNORECASE)

def _domain(header_value: str | None) -> str:
    address = parseaddr(header_value or "")[1]
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in address else ""

def _part_text(part) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except (LookupError, UnicodeError, TypeError):
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")

def extract_embedded_urls(text: str = "", html: str = "") -> list[str]:
    """Extract literal HTTP(S) links and static anchor hrefs without visiting them."""
    found = []
    for match in URL_PATTERN.findall(text or ""):
        found.append(match.rstrip(".,);]!?}"))
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href", "")).strip()
            if urlsplit(href).scheme.lower() in {"http", "https"}:
                found.append(href)
    return list(dict.fromkeys(url for url in found if url))

def parse_email(raw_email: str | bytes) -> dict:
    """Parse raw email/EML content and return bodies, URLs, and header indicators."""
    raw_bytes = raw_email if isinstance(raw_email, bytes) else str(raw_email).encode("utf-8", errors="replace")
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    plain_parts, html_parts = [], []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type().lower()
        if content_type == "text/plain":
            plain_parts.append(_part_text(part))
        elif content_type == "text/html":
            html_parts.append(_part_text(part))
    plain_body = "\n".join(value for value in plain_parts if value).strip()
    html_body = "\n".join(value for value in html_parts if value).strip()

    from_domain = _domain(message.get("From"))
    reply_domain = _domain(message.get("Reply-To"))
    return_domain = _domain(message.get("Return-Path"))
    indicators = []
    risk = 0.0
    if from_domain and reply_domain and from_domain != reply_domain:
        indicators.append(f"[HEADER] From domain ({from_domain}) differs from Reply-To ({reply_domain})")
        risk += 0.30
    if from_domain and return_domain and from_domain != return_domain:
        indicators.append(f"[HEADER] From domain ({from_domain}) differs from Return-Path ({return_domain})")
        risk += 0.25

    auth_failures = set()
    for header in message.get_all("Authentication-Results", []):
        auth_failures.update(match.lower() for match in AUTH_FAILURE_PATTERN.findall(str(header)))
    for mechanism in sorted(auth_failures):
        indicators.append(f"[HEADER] {mechanism.upper()} authentication failed")
        risk += 0.15

    urls = extract_embedded_urls(plain_body, html_body)
    extracted_links = extract_link_audits(html_body)
    for link in extracted_links:
        if link["is_mismatch"]:
            indicators.append(f"[HTML][LINK] Deceptive link: {link['display_text']} -> {link['actual_href']}")
            risk = min(1.0, risk + 0.25)
    return {
        "subject": str(message.get("Subject", "")),
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_domain,
        "authentication_failures": sorted(auth_failures),
        "header_indicators": indicators,
        "header_risk_score": round(min(risk, 1.0), 4),
        "plain_text": plain_body,
        "html_body": html_body,
        "embedded_urls": urls,
        "extracted_links": extracted_links,
    }

def parse_eml(raw_email: str | bytes) -> dict:
    """Alias emphasizing support for raw `.eml` input."""
    return parse_email(raw_email)
