"""Safe static HTML structure analysis. No scripts run and no resources are fetched."""
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup

TRUSTED_BRANDS = ("paypal", "microsoft", "apple", "google", "amazon", "netflix",
                  "facebook", "instagram", "binance", "chase", "wellsfargo", "dhl", "fedex")

def _hostname(value: str) -> str:
    """Extract a hostname without resolving or fetching it."""
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return (urlsplit(value if "://" in value else "//" + value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""

def extract_link_audits(html: str, page_url: str | None = None) -> list[dict]:
    """Inspect anchor text and href domains using a non-executing HTML parser."""
    soup = BeautifulSoup(html or "", "html.parser")
    audits = []
    page_host = _hostname(page_url) if page_url else ""
    for anchor in soup.find_all("a", href=True):
        display_text = " ".join(anchor.get_text(" ", strip=True).split())
        actual_href = str(anchor.get("href", "")).strip()
        display_host = _hostname(display_text) if display_text.startswith(("http://", "https://")) else ""
        href_host = _hostname(actual_href)
        mismatch = False
        risk_parts = []

        if display_host and href_host and display_host != href_host:
            mismatch = True
            risk_parts.append(f"Anchor text names {display_host}, but href points to {href_host}")
        elif display_host and not href_host:
            mismatch = True
            risk_parts.append("Anchor text contains a URL while href is not an external HTTP(S) link")

        lowered_display = display_text.lower()
        mentioned_brands = [brand for brand in TRUSTED_BRANDS if brand in lowered_display]
        if mentioned_brands:
            brand = mentioned_brands[0]
            if not href_host or brand not in href_host:
                mismatch = True
                risk_parts.append(f"Trusted brand '{brand}' in anchor text differs from href domain")

        if href_host and page_host and href_host != page_host:
            risk_parts.append("Anchor points to an external domain")

        audits.append({
            "display_text": display_text or "[empty link text]",
            "actual_href": actual_href,
            "is_mismatch": mismatch,
            "risk_note": "; ".join(dict.fromkeys(risk_parts)) if risk_parts else "No direct discrepancy detected",
        })
    return audits

DEFAULT_WEIGHTS = {"password_input": 0.25, "hidden_input": 0.05, "form": 0.10,
                   "external_form": 0.30, "iframe": 0.10, "inline_event": 0.10,
                   "external_link_ratio": 0.10}

def _is_external(target: str, page_url: str | None) -> bool:
    """Compare hostnames only; this helper performs no network access."""
    if not target or target.startswith(("#", "mailto:", "tel:", "javascript:")):
        return False
    resolved = urljoin(page_url or "https://local.invalid/", target)
    target_host = (urlsplit(resolved).hostname or "").lower()
    page_host = (urlsplit(page_url).hostname or "").lower() if page_url else ""
    return bool(target_host and page_host and target_host != page_host)

def extract_html_features(html: str, page_url: str | None = None) -> dict:
    """Extract structural HTML counts with BeautifulSoup's non-executing parser."""
    # Python's built-in parser is static and avoids the deprecated lxml builder option.
    soup = BeautifulSoup(html or "", "html.parser")
    links = soup.find_all("a", href=True)
    external_links = sum(_is_external(a.get("href", ""), page_url) for a in links)
    forms = soup.find_all("form")
    external_forms = sum(_is_external(form.get("action", ""), page_url) for form in forms)
    password_inputs = soup.find_all("input", attrs={"type": lambda value: value and value.lower() == "password"})
    hidden_inputs = soup.find_all("input", attrs={"type": lambda value: value and value.lower() == "hidden"})
    event_attributes = sum(1 for tag in soup.find_all(True) for attr in tag.attrs if attr.lower().startswith("on"))
    return {
        "total_links": len(links), "external_links": int(external_links),
        "internal_links": len(links) - int(external_links),
        "external_link_ratio": external_links / max(len(links), 1),
        "form_count": len(forms), "password_input_count": len(password_inputs),
        "hidden_input_count": len(hidden_inputs), "iframe_count": len(soup.find_all("iframe")),
        "script_count": len(soup.find_all("script")), "external_form_count": int(external_forms),
        "inline_event_attribute_count": event_attributes,
    }

def score_html_risk(features: dict, weights: dict | None = None) -> float:
    """Transparent additive score (0–1), capped after applying documented weights."""
    rules = {**DEFAULT_WEIGHTS, **(weights or {})}
    points = (rules["password_input"] * min(features["password_input_count"], 1)
              + rules["hidden_input"] * min(features["hidden_input_count"], 1)
              + rules["form"] * min(features["form_count"], 1)
              + rules["external_form"] * min(features["external_form_count"], 1)
              + rules["iframe"] * min(features["iframe_count"], 1)
              + rules["inline_event"] * min(features["inline_event_attribute_count"] / 2, 1)
              + rules["external_link_ratio"] * features["external_link_ratio"])
    return round(min(max(points, 0.0), 1.0), 4)

def analyze_html(html: str, page_url: str | None = None) -> dict:
    """Return static structural counts, risk score, and readable indicators."""
    features = extract_html_features(html, page_url)
    extracted_links = extract_link_audits(html, page_url)
    indicators = []
    if features["password_input_count"]: indicators.append("Password input field detected")
    if features["hidden_input_count"]: indicators.append("Hidden input field detected")
    if features["external_form_count"]: indicators.append("Form submits to external domain")
    if features["iframe_count"]: indicators.append("Iframe detected")
    if features["inline_event_attribute_count"]: indicators.append("Inline event handler detected")
    if features["external_link_ratio"] > 0: indicators.append("External links detected")
    mismatches = [link for link in extracted_links if link["is_mismatch"]]
    if mismatches:
        indicators.append("[HTML][LINK] Deceptive anchor-text vs href mismatch detected")
        indicators.extend(f"[LINK] {link['display_text']} -> {link['actual_href']}" for link in mismatches)
    return {"features": features, "html_risk_score": score_html_risk(features), "indicators": indicators,
            "extracted_links": extracted_links}
