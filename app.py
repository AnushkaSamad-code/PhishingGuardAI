"""PhishGuard AI V3 Visual Threat Forensics console."""
from __future__ import annotations

from datetime import datetime
from html import escape
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent
SCAN_HISTORY_PATH = ROOT / "data" / "scan_history.json"

st.set_page_config(page_title="PhishGuard AI V3", layout="wide",
                   initial_sidebar_state="collapsed")

SPOOFED_EML = """From: Account Team <alerts@paypa1-security.example>
Reply-To: collect@external-mail.example
Return-Path: <bounce@external-mail.example>
Subject: Action required: verify your account
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="v3-boundary"

--v3-boundary
Content-Type: text/plain; charset="utf-8"

Please verify your account immediately: https://paypa1-security.example/login

--v3-boundary
Content-Type: text/html; charset="utf-8"

<html><body><p>Verify your account now.</p>
<form action="https://external-mail.example/collect"><input type="password"></form>
<a href="https://paypa1-security.example/login">https://paypal.com/verify</a></body></html>
--v3-boundary--
"""

PRESETS = {
    "safe": {"unified": "From: Operations <operations@company.example>\nReply-To: operations@company.example\nSubject: Weekly service notice\nAuthentication-Results: mx.company.example; spf=pass; dkim=pass; dmarc=pass\n\nThe planned maintenance window is Friday at 18:00. Review the schedule at https://intranet.company.example/schedule.", "url": "", "html": ""},
    "typo": {"unified": "Please sign in to review your account: https://paypa1-security.example/login/verify", "url": "", "html": ""},
    "spoofed": {"unified": SPOOFED_EML, "url": "", "html": ""},
    "reset": {"unified": "", "url": "", "html": ""},
}


def _sanitize_text(value: object, limit: int = 200) -> str:
    text = escape(str(value or ""), quote=False)
    text = re.sub(
        r"(?i)\b(password|passwd|passcode|secret|token|api[_-]?key|authorization|bearer)\b\s*[:=]\s*[^\s&,;]+",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)\b(password|passcode|secret)\b\s+is\s+[^\s,;]+", r"\1 is [REDACTED]", text)
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())[:limit]


def _sanitize_url(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host
        if parts.scheme and netloc:
            return escape(urlunsplit((parts.scheme, netloc, parts.path, "", "")).strip(), quote=False)[:500]
        return escape(parts.path or host or raw.split("?", 1)[0].split("#", 1)[0], quote=False)[:500]
    except (TypeError, ValueError):
        return "[invalid URL]"


def _sanitize_preview(value: object, limit: int = 96) -> str:
    text = str(value or "").strip()
    if re.match(r"(?i)^https?://", text):
        text = _sanitize_url(text)
    else:
        text = re.sub(
            r"https?://[^\s]+",
            lambda match: _sanitize_url(match.group(0).rstrip(".,;)")),
            text,
            flags=re.I,
        )
        text = _sanitize_text(text, limit)
    return text[:limit]


def _sanitize_result(result: dict) -> dict:
    final_label = result.get("final_label")
    if final_label not in {"Legitimate", "Suspicious", "Phishing"}:
        final_label = "Suspicious"

    modalities = []
    for modality in result.get("modalities_used", []):
        if modality in {"url", "text", "html", "header"}:
            modalities.append(modality)
    if not modalities:
        modalities = []

    breakdown = {}
    for modality, detail in result.get("modality_breakdown", {}).items():
        if modality not in {"url", "text", "html", "header"} or not isinstance(detail, dict):
            continue
        try:
            score = float(detail.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        breakdown[modality] = {
            "score": max(0.0, min(1.0, score)),
            "indicators": [_sanitize_text(item, 200) for item in detail.get("indicators", [])][:20],
        }

    try:
        risk_percentage = float(result.get("risk_percentage", 0.0))
    except (TypeError, ValueError):
        risk_percentage = 0.0
    risk_percentage = max(0.0, min(100.0, risk_percentage))

    links = []
    for item in result.get("extracted_links", [])[:30]:
        if not isinstance(item, dict):
            continue
        links.append({
            "display_text": _sanitize_text(item.get("display_text", ""), 160),
            "actual_href": _sanitize_url(item.get("actual_href", "")),
            "is_mismatch": bool(item.get("is_mismatch", False)),
            "risk_note": _sanitize_text(item.get("risk_note", ""), 200),
        })

    input_sha256 = str(result.get("input_sha256", ""))
    if not re.fullmatch(r"[0-9a-fA-F]{64}", input_sha256):
        input_sha256 = ""

    return {
        "final_label": final_label,
        "risk_score": risk_percentage / 100.0,
        "risk_percentage": risk_percentage,
        "modalities_used": modalities,
        "modality_breakdown": breakdown,
        "indicators": [_sanitize_text(item, 200) for item in result.get("indicators", [])][:30],
        "extracted_links": links,
        "highlighted_tokens": [],
        "input_sha256": input_sha256,
        "disclaimer": "Static analysis only. No links were visited and submitted scripts were not executed.",
    }


def _load_scan_history() -> tuple[list, dict | None, str | None]:
    if not SCAN_HISTORY_PATH.is_file():
        return [], None, None
    try:
        payload = json.loads(SCAN_HISTORY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return [], None, None

    if isinstance(payload, list):
        history = payload
        latest_result = None
        latest_scan_at = None
    elif isinstance(payload, dict):
        history = payload.get("history", [])
        latest_result = payload.get("latest_result")
        latest_scan_at = payload.get("latest_scan_at")
    else:
        return [], None, None

    if not isinstance(history, list):
        history = []
    safe_history = []
    for item in history[:100]:
        if not isinstance(item, dict):
            continue
        safe_history.append({
            "Timestamp": _sanitize_text(item.get("Timestamp", ""), 80),
            "Target Summary": _sanitize_preview(item.get("Target Summary", ""), 96),
            "Modalities Active": _sanitize_text(item.get("Modalities Active", ""), 80),
            "Risk Score": _sanitize_text(item.get("Risk Score", ""), 20),
            "Verdict": _sanitize_text(item.get("Verdict", ""), 20),
        })

    if not isinstance(latest_result, dict):
        latest_result = None
    elif latest_result:
        latest_result = _sanitize_result(latest_result)
    else:
        latest_result = None

    if not isinstance(latest_scan_at, str):
        latest_scan_at = None
    else:
        latest_scan_at = _sanitize_text(latest_scan_at, 80)
    return safe_history, latest_result, latest_scan_at


def _save_scan_history(history: list, latest_result: dict | None, latest_scan_at: str | None) -> None:
    SCAN_HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "history": history[:100],
        "latest_result": _sanitize_result(latest_result) if latest_result else None,
        "latest_scan_at": latest_scan_at,
    }
    temporary_path = SCAN_HISTORY_PATH.with_suffix(".json.tmp")
    temporary_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary_path.replace(SCAN_HISTORY_PATH)


def _clear_scan_history() -> None:
    st.session_state["scan_history"] = []
    st.session_state["scan_result"] = None
    st.session_state["last_scan_at"] = None
    st.session_state["scan_error"] = None
    _save_scan_history([], None, None)


def _styles(dark: bool) -> None:
    if dark:
        canvas, panel, ink, muted, line, accent = "#0B1120", "#111827", "#F8FAFC", "#94A3B8", "#263244", "#F43F5E"
    else:
        canvas, panel, ink, muted, line, accent = "#F6F8FB", "#FFFFFF", "#111827", "#64748B", "#DCE3EC", "#0F172A"
    st.markdown(f"""
    <style>
      :root {{ --canvas:{canvas}; --panel:{panel}; --ink:{ink}; --muted:{muted}; --line:{line}; --accent:{accent}; }}
      html, body, [class*="css"] {{ font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }}
      .stApp {{ background:{canvas}; color:{ink}; }}
      .block-container {{ max-width:1380px; padding-top:1rem; padding-bottom:1.5rem; }}
      .brand {{ font-size:1.3rem; font-weight:800; letter-spacing:-.035em; color:{ink}; }}
      .subbrand {{ font-size:.78rem; color:{muted}; margin-top:.08rem; }}
      [data-testid="stMetric"] {{ background:{panel}; border:1px solid {line}; border-radius:8px; padding:.65rem .8rem; }}
      [data-testid="stMetricLabel"] {{ color:{muted} !important; }}
      [data-testid="stMetricValue"] {{ color:{ink} !important; font-family:"JetBrains Mono",ui-monospace,monospace !important; }}
      div.stButton > button, div[data-testid="stFormSubmitButton"] button {{ border-radius:6px; border:1px solid {line}; }}
      [data-testid="stVerticalBlockBorderWrapper"] {{ border-color:{line} !important; border-radius:8px !important; }}
      .verdict {{ display:inline-block; border-radius:5px; padding:.38rem .65rem; font-weight:800; font-size:.75rem; letter-spacing:.05em; }}
      .legitimate {{ color:#15803D;background:#DCFCE7;border:1px solid #86EFAC; }}
      .suspicious {{ color:#A16207;background:#FEF3C7;border:1px solid #FDE047; }}
      .phishing {{ color:#BE123C;background:#FFE4E6;border:1px solid #FDA4AF; }}
      .xray {{ background:{panel}; border:1px solid {line}; border-radius:8px; padding:.8rem; line-height:2.1; overflow-wrap:anywhere; }}
      .pill {{ display:inline-block; margin:.12rem; border-radius:999px; padding:.12rem .42rem; font:700 .72rem ui-monospace,monospace; }}
      .pill-high {{ color:#BE123C; background:#FFE4E6; border:1px solid #FDA4AF; }}
      .pill-amber {{ color:#92400E; background:#FEF3C7; border:1px solid #FDE047; }}
      .section-title {{ font-size:.88rem; font-weight:800; color:{ink}; margin:.15rem 0 .45rem; }}
    </style>
    """, unsafe_allow_html=True)


def _set_preset(name: str) -> None:
    preset = PRESETS[name]
    st.session_state["unified_input"] = preset["unified"]
    st.session_state["specific_url"] = preset["url"]
    st.session_state["static_html"] = preset["html"]
    st.session_state["scan_result"] = None


def _header(policy: str) -> str:
    brand, controls = st.columns([3.2, 1.8], vertical_alignment="center")
    with brand:
        st.markdown('<div class="brand">PhishGuard AI <span style="color:#E11D48">V3</span></div>'
                    '<div class="subbrand">Visual Threat Forensics · Batch Scanner · Static Analysis Only</div>', unsafe_allow_html=True)
    with controls:
        policy_value = st.selectbox("Security Policy", ["Balanced", "Strict SOC", "Lenient"],
                                    index=["Balanced", "Strict SOC", "Lenient"].index(policy), key="security_policy")
    return policy_value


def _gauge(result: dict) -> go.Figure:
    figure = go.Figure(go.Indicator(
        mode="gauge+number", value=result["risk_percentage"],
        number={"suffix": "%", "font": {"size": 28}},
        gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#E11D48"},
               "bgcolor": "rgba(0,0,0,0)",
               "steps": [{"range": [0, 35], "color": "#DCFCE7"},
                         {"range": [35, 65], "color": "#FEF3C7"},
                         {"range": [65, 100], "color": "#FFE4E6"}],
               "threshold": {"line": {"color": "#111827", "width": 3}, "thickness": 0.75, "value": result["risk_percentage"]}}))
    figure.update_layout(height=230, margin={"l": 25, "r": 25, "t": 20, "b": 15}, paper_bgcolor="rgba(0,0,0,0)")
    return figure


def _radar(result: dict) -> go.Figure:
    names = {"url": "URL", "text": "NLP Text", "html": "Static HTML", "header": "Email Headers"}
    values = {key: 0.0 for key in names}
    for name, detail in result["modality_breakdown"].items():
        values[name] = float(detail["score"])
    figure = go.Figure(go.Scatterpolar(
        r=[values["url"], values["text"], values["html"], values["header"], values["url"]],
        theta=["URL", "NLP Text", "Static HTML", "Email Headers", "URL"],
        fill="toself", line={"color": "#E11D48", "width": 2},
        marker={"color": "#E11D48"}, hovertemplate="%{theta}: %{r:.3f}<extra></extra>"))
    figure.update_layout(height=230, margin={"l": 35, "r": 35, "t": 15, "b": 15},
                         paper_bgcolor="rgba(0,0,0,0)",
                         polar={"radialaxis": {"visible": True, "range": [0, 1], "gridcolor": "#CBD5E1"},
                                "angularaxis": {"gridcolor": "#CBD5E1"}})
    return figure


def _escaped_preview(result: dict, unified: str, url_value: str) -> str:
    source = unified or url_value or "<static HTML source>"
    escaped = escape(source, quote=False)
    token_lookup = {escape(item["token"], quote=False).lower(): item for item in result["highlighted_tokens"]}
    # Replace only exact escaped tokens; all user markup remains escaped and no unsafe input reaches HTML.
    for token, item in sorted(token_lookup.items(), key=lambda pair: len(pair[0]), reverse=True):
        if not token:
            continue
        klass = "pill-high" if item["severity"] == "high" else "pill-amber"
        escaped = escaped.replace(token, f'<span class="pill {klass}">{token}</span>')
    return escaped


def _incident_json(result: dict, scanned_at: str) -> bytes:
    report = {**result, "product": "PhishGuard AI V3", "scanned_at": scanned_at,
              "raw_input_included": False}
    report.pop("highlighted_tokens", None)
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def _single_inspector(policy: str) -> None:
    for key in ("unified_input", "specific_url", "static_html"):
        st.session_state.setdefault(key, "")

    url_tab, email_tab, html_tab, multimodal_tab = st.tabs([
        "🔗 URL Checker", "✉️ Email & Text Checker",
        "🌐 Static HTML Inspector", "🧩 Full Multimodal Scan",
    ])
    unified_value = ""
    specific = ""
    html_value = ""
    submitted = False

    with url_tab:
        st.caption("Analyze a single URL with the active security policy.")
        url_input = st.text_input("URL", key="specific_url",
                                  placeholder="Enter URL to scan, e.g., https://example.com/login")
        st.button("Use sample typosquatted URL", key="sample_url",
                  on_click=_set_preset, args=("typo",), type="tertiary")
        url_submitted = st.button("Scan URL", key="scan_url", type="primary", use_container_width=True)
        if url_submitted:
            submitted = True
            specific = url_input
    with email_tab:
        st.caption("Paste an email, message, or raw .eml content, or upload a text file.")
        email_text = st.text_area("Email / Message / Raw .eml", key="unified_input", height=190,
                                  placeholder="Paste email headers and body, a message, or text to inspect.")
        email_upload = st.file_uploader("Upload .eml or .txt", type=["eml", "txt"], key="email_upload")
        st.button("Use sample spoofed email", key="sample_email",
                  on_click=_set_preset, args=("spoofed",), type="tertiary")
        email_submitted = st.button("Scan Email / Text", key="scan_email", type="primary",
                                    use_container_width=True)
        if email_submitted:
            submitted = True
            specific = ""
            html_value = ""
            if email_upload is not None:
                uploaded_text = email_upload.getvalue().decode("utf-8", errors="replace")
                unified_value = uploaded_text if not email_text.strip() else uploaded_text + "\n\n" + email_text
            else:
                unified_value = email_text
    with html_tab:
        st.caption("Inspect source statically. The page is never opened and scripts are never executed.")
        html_source = st.text_area("Static HTML Source", key="static_html", height=190,
                                   placeholder="Paste HTML source to inspect.")
        html_upload = st.file_uploader("Upload .html or .htm", type=["html", "htm"], key="html_upload")
        page_url = st.text_input("Optional page URL", key="html_page_url",
                                 placeholder="https://example.com/page")
        html_submitted = st.button("Inspect HTML", key="inspect_html", type="primary",
                                   use_container_width=True)
        if html_submitted:
            submitted = True
            specific = page_url
            unified_value = ""
            html_value = html_source
            if html_upload is not None:
                uploaded_text = html_upload.getvalue().decode("utf-8", errors="replace")
                html_value = uploaded_text if not html_source.strip() else html_source + "\n" + uploaded_text
    with multimodal_tab:
        st.caption("Combine signals to exercise multimodal fusion in one scan.")
        multi_url = st.text_input("URL to inspect", key="multimodal_url",
                                  placeholder="https://example.com/login")
        multi_text = st.text_area("Email / Message / Text", key="multimodal_text", height=130,
                                  placeholder="Paste an email, message, or other text.")
        multi_html = st.text_area("Static HTML Source", key="multimodal_html", height=130,
                                  placeholder="Paste static HTML source.")
        multi_upload = st.file_uploader("Optional .eml, .txt, .html, or .htm", type=["eml", "txt", "html", "htm"], key="multimodal_upload")
        multi_submitted = st.button("Run Full Multimodal Scan", key="scan_multimodal", type="primary",
                                    use_container_width=True)
        if multi_submitted:
            submitted = True
            specific = multi_url
            unified_value = multi_text
            html_value = multi_html
        if multi_submitted and multi_upload is not None:
            uploaded_text = multi_upload.getvalue().decode("utf-8", errors="replace")
            if Path(multi_upload.name).suffix.lower() in {".eml", ".txt"}:
                unified_value = uploaded_text if not unified_value.strip() else uploaded_text + "\n\n" + unified_value
            else:
                html_value = uploaded_text if not html_value.strip() else html_value + "\n" + uploaded_text

    if submitted:
        if not any((unified_value.strip(), specific.strip(), html_value.strip())):
            st.session_state["scan_result"] = None
            st.session_state["scan_error"] = "Enter a URL, message, email, or static HTML source before scanning."
        else:
            try:
                from src.prediction import predict_multimodal
                with st.spinner("Running static multimodal analysis..."):
                    result = predict_multimodal(url=specific, text=unified_value, html=html_value,
                                                policy_mode=policy)
                st.session_state["scan_result"] = result
                st.session_state["scan_error"] = None
                scanned_at = datetime.now().astimezone().isoformat(timespec="seconds")
                st.session_state["last_scan_at"] = scanned_at
                history = st.session_state.setdefault("scan_history", [])
                preview_source = specific or unified_value or "Static HTML"
                preview = _sanitize_preview(preview_source, 96)
                history.insert(0, {"Timestamp": scanned_at, "Target Summary": preview,
                                   "Modalities Active": ", ".join(result["modalities_used"]),
                                   "Risk Score": f"{result['risk_percentage']:.2f}%",
                                   "Verdict": result["final_label"]})
                history = history[:100]
                st.session_state["scan_history"] = history
                _save_scan_history(history, _sanitize_result(result), scanned_at)
            except Exception as exc:
                st.session_state["scan_result"] = None
                st.session_state["scan_error"] = f"Scan could not complete: {exc}"
    if st.session_state.get("scan_error"):
        st.warning(st.session_state["scan_error"])

    result = st.session_state.get("scan_result")
    if not result:
        st.info("Awaiting a submitted threat for visual forensics.")
        return

    st.divider()
    c1, c2, c3, c4 = st.columns(4)
    class_name = {"Legitimate": "legitimate", "Suspicious": "suspicious", "Phishing": "phishing"}[result["final_label"]]
    c1.markdown(f'<span class="verdict {class_name}">{escape(result["final_label"].upper())}</span>',
                unsafe_allow_html=True)
    c2.metric("Aggregated Risk Score", f"{result['risk_percentage']:.2f}%")
    c3.metric("Active Modalities", str(len(result["modalities_used"])))
    c4.caption("Input SHA-256")
    c4.code(result["input_sha256"], language="text")

    chart1, chart2 = st.columns(2)
    chart1.plotly_chart(_gauge(result), use_container_width=True, config={"displayModeBar": False})
    chart2.plotly_chart(_radar(result), use_container_width=True, config={"displayModeBar": False})

    st.markdown('<div class="section-title">THREAT TOKEN X-RAY</div>', unsafe_allow_html=True)
    preview = _escaped_preview(result, unified_value, specific)
    st.markdown(f'<div class="xray">{preview}</div>', unsafe_allow_html=True)

    link_col, ioc_col = st.columns([1.15, .85], gap="large")
    with link_col:
        st.markdown('<div class="section-title">EXTRACTED LINKS AUDIT</div>', unsafe_allow_html=True)
        links = result.get("extracted_links", [])
        if links:
            st.dataframe(pd.DataFrame([{
                "Display Text": item["display_text"], "Actual Href": item["actual_href"],
                "Mismatch": "YES" if item["is_mismatch"] else "No",
                "Risk Note": item["risk_note"],
            } for item in links]), hide_index=True, use_container_width=True)
        else:
            st.caption("No embedded links detected.")
    with ioc_col:
        st.markdown('<div class="section-title">CATEGORIZED IOCs</div>', unsafe_allow_html=True)
        categorized = []
        tags = {"url": "URL", "text": "TEXT", "html": "HTML", "header": "HEADER"}
        for modality, detail in result["modality_breakdown"].items():
            for indicator in detail.get("indicators", []):
                categorized.append(f"[{tags[modality]}] {indicator}")
        for indicator in result["indicators"]:
            if indicator not in ["High-risk combination: phishing-like URL score with an external password form"]:
                categorized.append(indicator if indicator.startswith("[") else "[FUSION] " + indicator)
        categorized = list(dict.fromkeys(categorized))
        st.text("\n".join(categorized) if categorized else "No malicious indicators detected.")

    st.download_button("Export Incident Report (JSON)",
                       _incident_json(result, st.session_state.get("last_scan_at", "")),
                       file_name="phishguard_incident.json",
                       mime="application/json", use_container_width=True)
    st.caption(result["disclaimer"])


def _batch_scanner(policy: str) -> None:
    st.markdown('<div class="section-title">BULK CSV BATCH SCANNER</div>', unsafe_allow_html=True)
    controls = st.columns([1, 3])
    uploaded = controls[0].file_uploader("Upload CSV", type=["csv"])
    if controls[0].button("Load Sample Batch CSV", use_container_width=True):
        uploaded = None
        st.session_state["batch_df"] = pd.DataFrame({
            "url": ["https://example.org/about", "https://paypa1-security.example/login",
                     "http://192.0.2.10/verify/account"],
            "text": ["Routine project update", "Urgent: verify your account now",
                     "Your password expires today"],
        })

    if uploaded is not None:
        st.session_state["batch_df"] = pd.read_csv(uploaded)

    batch_df = st.session_state.get("batch_df")
    if batch_df is None:
        st.info("Upload a CSV or load the sample batch.")
        return
    try:
        from src.batch_scanner import scan_csv_batch
        results = scan_csv_batch(batch_df, policy_mode=policy, max_rows=500)
    except Exception as exc:
        st.error(f"Batch scan could not complete: {exc}")
        return

    counts = results["final_label"].value_counts().to_dict()
    pie = go.Figure(go.Bar(
        x=["Legitimate", "Suspicious", "Phishing"],
        y=[counts.get("Legitimate", 0), counts.get("Suspicious", 0), counts.get("Phishing", 0)],
        marker={"color": ["#22C55E", "#F59E0B", "#E11D48"]},
        texttemplate="%{y}", textposition="outside"))
    pie.update_layout(height=230, margin={"l": 25, "r": 25, "t": 20, "b": 35},
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      showlegend=False, yaxis={"dtick": 1})
    st.plotly_chart(pie, use_container_width=True, config={"displayModeBar": False})
    st.dataframe(results, hide_index=True, use_container_width=True)
    st.download_button("Download phishguard_batch_results.csv",
                       results.to_csv(index=False).encode("utf-8"),
                       file_name="phishguard_batch_results.csv",
                       mime="text/csv", use_container_width=True)


def _history() -> None:
    history = st.session_state.get("scan_history", [])
    if history:
        st.divider()
        title_col, clear_col = st.columns([5, 1], vertical_alignment="center")
        with title_col:
            st.markdown('<div class="section-title">SCAN HISTORY</div>', unsafe_allow_html=True)
        with clear_col:
            st.button("Clear History", on_click=_clear_scan_history,
                      use_container_width=True, type="tertiary")
        st.dataframe(pd.DataFrame(history), hide_index=True, use_container_width=True)


def main() -> None:
    if "scan_history_loaded" not in st.session_state:
        history, latest_result, latest_scan_at = _load_scan_history()
        st.session_state["scan_history"] = history
        st.session_state["scan_result"] = latest_result
        st.session_state["last_scan_at"] = latest_scan_at
        st.session_state["scan_history_loaded"] = True
    st.session_state.setdefault("security_policy", "Balanced")
    dark = st.toggle("Dark Theme", value=False, key="dark_theme")
    _styles(bool(dark))
    policy = _header(st.session_state["security_policy"])
    st.divider()
    inspector, batch = st.tabs(["Single Threat Inspector", "Bulk CSV Batch Scanner"])
    with inspector:
        _single_inspector(st.session_state["security_policy"])
    with batch:
        _batch_scanner(st.session_state["security_policy"])
    _history()
    st.caption("Static analysis only — no links are visited and submitted HTML or scripts are never executed.")


if __name__ == "__main__":
    main()
