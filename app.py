"""PhishGuard AI V3 static threat analysis console."""
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

st.set_page_config(
    page_title="PhishGuard AI V3",
    page_icon="PG",
    layout="wide",
    initial_sidebar_state="collapsed",
)

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
    "safe": {
        "unified": "From: Operations <operations@company.example>\nReply-To: operations@company.example\nSubject: Weekly service notice\nAuthentication-Results: mx.company.example; spf=pass; dkim=pass; dmarc=pass\n\nThe planned maintenance window is Friday at 18:00. Review the schedule at https://intranet.company.example/schedule.",
        "url": "",
        "html": "",
    },
    "typo": {"unified": "Please sign in to review your account: https://paypa1-security.example/login/verify", "url": "https://paypa1-security.example/login/verify", "html": ""},
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
        if parts.scheme and host:
            return escape(urlunsplit((parts.scheme, host, parts.path, "", "")).strip(), quote=False)[:500]
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
    modalities = [m for m in result.get("modalities_used", []) if m in {"url", "text", "html", "header"}]
    breakdown = {}
    for modality, detail in result.get("modality_breakdown", {}).items():
        if modality not in {"url", "text", "html", "header"} or not isinstance(detail, dict):
            continue
        try:
            score = max(0.0, min(1.0, float(detail.get("score", 0.0))))
        except (TypeError, ValueError):
            score = 0.0
        breakdown[modality] = {
            "score": score,
            "indicators": [_sanitize_text(item, 200) for item in detail.get("indicators", [])][:20],
        }
    try:
        risk_percentage = max(0.0, min(100.0, float(result.get("risk_percentage", 0.0))))
    except (TypeError, ValueError):
        risk_percentage = 0.0
    links = []
    for item in result.get("extracted_links", [])[:30]:
        if isinstance(item, dict):
            links.append({
                "display_text": _sanitize_text(item.get("display_text", ""), 160),
                "actual_href": _sanitize_url(item.get("actual_href", "")),
                "is_mismatch": bool(item.get("is_mismatch", False)),
                "risk_note": _sanitize_text(item.get("risk_note", ""), 200),
            })
    fingerprint = str(result.get("input_sha256", ""))
    if not re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint):
        fingerprint = ""
    return {
        "final_label": final_label,
        "risk_score": risk_percentage / 100.0,
        "risk_percentage": risk_percentage,
        "modalities_used": modalities,
        "modality_breakdown": breakdown,
        "indicators": [_sanitize_text(item, 200) for item in result.get("indicators", [])][:30],
        "highlighted_tokens": [],
        "extracted_links": links,
        "input_sha256": fingerprint,
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
        history, latest_result, latest_scan_at = payload, None, None
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
        if isinstance(item, dict):
            safe_history.append({
                "Timestamp": _sanitize_text(item.get("Timestamp", ""), 80),
                "Target Summary": _sanitize_preview(item.get("Target Summary", ""), 96),
                "Modalities Active": _sanitize_text(item.get("Modalities Active", ""), 80),
                "Risk Score": _sanitize_text(item.get("Risk Score", ""), 20),
                "Verdict": _sanitize_text(item.get("Verdict", ""), 20),
            })
    latest_result = _sanitize_result(latest_result) if isinstance(latest_result, dict) else None
    latest_scan_at = _sanitize_text(latest_scan_at, 80) if isinstance(latest_scan_at, str) else None
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


def _styles() -> None:
    st.markdown("""
    <style>
      :root {
        --canvas:#F8FAFC; --surface:#FFFFFF; --ink:#1E293B; --muted:#64748B;
        --line:#E2E8F0; --navy:#243B53;
      }
      html, body, [class*="css"] { font-family:Inter, "Segoe UI", Arial, sans-serif; }
      .stApp { background:var(--canvas); color:var(--ink); }
      .block-container { max-width:1380px; padding:1rem 2rem 2rem 2rem; }
      .brand-row { display:flex; align-items:center; }
      .brand { font-size:1.45rem; line-height:1.15; font-weight:800; letter-spacing:-.025em; color:var(--ink); }
      .subtitle { color:var(--muted); font-size:.82rem; margin-top:.25rem; }
      .version-pill { display:inline-block; margin-top:.42rem; border:1px solid var(--line); border-radius:999px;
                       color:var(--navy); background:#FFFFFF; padding:.18rem .55rem; font-size:.72rem; font-weight:700; }
      [data-testid="stMetric"] { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:.65rem .8rem; }
      [data-testid="stMetricLabel"], [data-testid="stMetricValue"] { color:var(--ink) !important; }
      [data-testid="stVerticalBlockBorderWrapper"] { border:1px solid var(--line) !important; border-radius:8px !important; }
      [data-testid="stForm"] { border:1px solid var(--line); border-radius:8px; background:var(--surface); padding:1rem; }
      div.stButton > button, div[data-testid="stFormSubmitButton"] button {
        border-radius:6px; border:1px solid var(--line); color:var(--ink); background:#FFFFFF; min-height:40px;
      }
      div.stButton > button[kind="primary"], div[data-testid="stFormSubmitButton"] button[kind="primary"] {
        background:var(--navy); border-color:var(--navy); color:#FFFFFF;
      }
      [data-baseweb="tab-list"] { gap:.25rem; border-bottom:1px solid var(--line); }
      [data-baseweb="tab"] { border-radius:6px 6px 0 0; color:var(--muted); padding:.55rem .8rem; }
      [aria-selected="true"][data-baseweb="tab"] { background:var(--navy); color:#FFFFFF; }
      .verdict-card { background:#FFFFFF; border:1px solid var(--line); border-radius:8px; padding:1rem; }
      .verdict { display:inline-block; border-radius:5px; padding:.42rem .68rem; font-weight:800; font-size:.78rem; letter-spacing:.06em; }
      .legitimate { color:#059669; background:#ECFDF5; border:1px solid #A7F3D0; }
      .suspicious { color:#D97706; background:#FFFBEB; border:1px solid #FDE68A; }
      .phishing { color:#DC2626; background:#FEF2F2; border:1px solid #FECACA; }
      .section-title { color:var(--ink); font-size:.86rem; font-weight:800; letter-spacing:.015em; margin:.15rem 0 .55rem; }
      .risk-label { color:var(--muted); font-size:.78rem; margin-bottom:.35rem; }
      .xray { background:#FFFFFF; border:1px solid var(--line); border-radius:8px; padding:.85rem;
              line-height:2.05; overflow-wrap:anywhere; min-height:68px; }
      .pill { display:inline-block; margin:.08rem; border-radius:999px; padding:.1rem .38rem; font:700 .68rem ui-monospace,monospace; }
      .pill-high { color:#DC2626; background:#FEF2F2; border:1px solid #FECACA; }
      .pill-amber { color:#D97706; background:#FFFBEB; border:1px solid #FDE68A; }
      .small-note { color:var(--muted); font-size:.78rem; }
    </style>
    """, unsafe_allow_html=True)


def _set_preset(name: str) -> None:
    preset = PRESETS[name]
    st.session_state["unified_input"] = preset["unified"]
    st.session_state["specific_url"] = preset["url"]
    st.session_state["static_html"] = preset["html"]
    st.session_state["scan_result"] = None
    st.session_state["scan_error"] = None


def _reset_inputs() -> None:
    for name in ("unified_input", "specific_url", "static_html", "multimodal_url", "multimodal_text", "multimodal_html", "html_page_url"):
        st.session_state[name] = ""
    st.session_state["scan_result"] = None
    st.session_state["scan_error"] = None


def _header(policy: str) -> str:
    left, right = st.columns([4.2, 1.25], vertical_alignment="center")
    with left:
        st.markdown(
            '<div class="brand">PhishGuard AI</div>'
            '<div class="subtitle">Multimodal Phishing Detection &amp; Threat Analysis</div>'
            '<div class="version-pill">V3 &bull; Static Analysis</div>',
            unsafe_allow_html=True,
        )
    with right:
        policy_value = st.selectbox(
            "Security Policy",
            ["Balanced", "Strict SOC", "Lenient"],
            index=["Balanced", "Strict SOC", "Lenient"].index(policy),
            key="security_policy",
        )
    return policy_value


def _radar(result: dict) -> go.Figure:
    names = {"url": "URL", "text": "Text", "html": "HTML", "header": "Headers"}
    values = {key: 0.0 for key in names}
    for name, detail in result["modality_breakdown"].items():
        values[name] = float(detail["score"])
    figure = go.Figure(go.Scatterpolar(
        r=[values["url"], values["text"], values["html"], values["header"], values["url"]],
        theta=["URL", "Text", "HTML", "Headers", "URL"],
        fill="toself",
        line={"color": "#243B53", "width": 2},
        marker={"color": "#243B53"},
        hovertemplate="%{theta}: %{r:.3f}<extra></extra>",
    ))
    figure.update_layout(
        height=220,
        margin={"l": 35, "r": 35, "t": 10, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        polar={"radialaxis": {"visible": True, "range": [0, 1], "gridcolor": "#E2E8F0"},
               "angularaxis": {"gridcolor": "#E2E8F0", "tickfont": {"size": 10}}},
    )
    return figure


def _modality_chart(result: dict) -> go.Figure:
    names = {"url": "URL", "text": "Text", "html": "HTML", "header": "Headers"}
    labels = [names[name] for name in names if name in result["modality_breakdown"]]
    values = [float(result["modality_breakdown"][name]["score"]) for name in names if name in result["modality_breakdown"]]
    figure = go.Figure(go.Bar(
        x=labels, y=values,
        marker={"color": "#243B53"},
        text=[f"{value:.2f}" for value in values],
        textposition="outside",
    ))
    figure.update_layout(
        height=220,
        margin={"l": 35, "r": 25, "t": 10, "b": 35},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis={"range": [0, 1], "gridcolor": "#E2E8F0", "tickformat": ".1f"},
        xaxis={"tickfont": {"size": 10}},
        showlegend=False,
    )
    return figure


def _escaped_preview(result: dict, unified: str, url_value: str) -> str:
    source = unified or url_value or "<static HTML source>"
    escaped = escape(source, quote=False)
    token_lookup = {escape(item["token"], quote=False).lower(): item for item in result["highlighted_tokens"]}
    for token, item in sorted(token_lookup.items(), key=lambda pair: len(pair[0]), reverse=True):
        if not token:
            continue
        klass = "pill-high" if item["severity"] == "high" else "pill-amber"
        escaped = escaped.replace(token, f'<span class="pill {klass}">{token}</span>')
    return escaped


def _incident_json(result: dict, scanned_at: str) -> bytes:
    report = {**result, "product": "PhishGuard AI V3", "scanned_at": scanned_at, "raw_input_included": False}
    report.pop("highlighted_tokens", None)
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def _run_scan(policy: str, url_value: str = "", text_value: str = "", html_value: str = "") -> None:
    if not any((url_value.strip(), text_value.strip(), html_value.strip())):
        st.session_state["scan_result"] = None
        st.session_state["scan_error"] = "Enter a URL, message, email, or static HTML"
        return
    try:
        from src.prediction import predict_multimodal
        with st.spinner("Running static multimodal analysis..."):
            result = predict_multimodal(url=url_value, text=text_value, html=html_value, policy_mode=policy)
        st.session_state["scan_result"] = result
        st.session_state["scan_error"] = None
        scanned_at = datetime.now().astimezone().isoformat(timespec="seconds")
        st.session_state["last_scan_at"] = scanned_at
        history = st.session_state.setdefault("scan_history", [])
        preview_source = url_value or text_value or "Static HTML"
        history.insert(0, {
            "Timestamp": scanned_at,
            "Target Summary": _sanitize_preview(preview_source, 96),
            "Modalities Active": ", ".join(result["modalities_used"]),
            "Risk Score": f"{result['risk_percentage']:.2f}%",
            "Verdict": result["final_label"],
        })
        history = history[:100]
        st.session_state["scan_history"] = history
        _save_scan_history(history, result, scanned_at)
    except Exception as exc:
        st.session_state["scan_result"] = None
        st.session_state["scan_error"] = f"Scan could not complete: {exc}"


def _single_inspector(policy: str) -> None:
    for key in ("unified_input", "specific_url", "static_html", "multimodal_url", "multimodal_text", "multimodal_html", "html_page_url"):
        st.session_state.setdefault(key, "")

    url_tab, email_tab, html_tab, multimodal_tab = st.tabs([
        "URL Checker",
        "Email & Text Checker",
        "Static HTML Inspector",
        "Full Multimodal Scan",
    ])

    with url_tab:
        with st.container(border=True):
            st.markdown('<div class="section-title">URL Analysis</div>', unsafe_allow_html=True)
            url_input = st.text_input("URL", key="specific_url", placeholder="https://example.com/login")
            preset_col, reset_col = st.columns(2)
            with preset_col:
                st.button("Typosquatted URL", key="sample_url", on_click=_set_preset, args=("typo",), use_container_width=True)
            with reset_col:
                st.button("Reset", key="reset_url", on_click=_reset_inputs, use_container_width=True)
            if st.button("Scan URL", key="scan_url", type="primary", use_container_width=True):
                _run_scan(policy, url_value=url_input)

    with email_tab:
        with st.container(border=True):
            st.markdown('<div class="section-title">Email / Text Analysis</div>', unsafe_allow_html=True)
            email_text = st.text_area(
                "Email / Message / Raw .eml",
                key="unified_input",
                height=190,
                placeholder="Paste email headers and body, a message, or raw text.",
            )
            email_upload = st.file_uploader("Upload .eml or .txt", type=["eml", "txt"], key="email_upload")
            preset_col, safe_col = st.columns(2)
            with preset_col:
                st.button("Spoofed .eml Phishing Attack", key="sample_email", on_click=_set_preset, args=("spoofed",), use_container_width=True)
            with safe_col:
                st.button("Safe Corporate Email", key="sample_safe", on_click=_set_preset, args=("safe",), use_container_width=True)
            if st.button("Scan Email / Text", key="scan_email", type="primary", use_container_width=True):
                uploaded_text = email_upload.getvalue().decode("utf-8", errors="replace") if email_upload is not None else ""
                combined = uploaded_text if not email_text.strip() else (uploaded_text + "\n\n" + email_text if uploaded_text else email_text)
                _run_scan(policy, text_value=combined)

    with html_tab:
        with st.container(border=True):
            st.markdown('<div class="section-title">Static HTML Analysis</div>', unsafe_allow_html=True)
            html_source = st.text_area("Static HTML Source", key="static_html", height=190, placeholder="Paste HTML source to inspect.")
            html_upload = st.file_uploader("Upload .html or .htm", type=["html", "htm"], key="html_upload")
            page_url = st.text_input("Optional page URL", key="html_page_url", placeholder="https://example.com/page")
            if st.button("Inspect HTML", key="inspect_html", type="primary", use_container_width=True):
                uploaded_text = html_upload.getvalue().decode("utf-8", errors="replace") if html_upload is not None else ""
                combined = uploaded_text if not html_source.strip() else (html_source + "\n" + uploaded_text if uploaded_text else html_source)
                _run_scan(policy, url_value=page_url, html_value=combined)

    with multimodal_tab:
        with st.container(border=True):
            st.markdown('<div class="section-title">Multimodal Analysis</div>', unsafe_allow_html=True)
            multi_url = st.text_input("URL to inspect", key="multimodal_url", placeholder="https://example.com/login")
            multi_text = st.text_area("Email / Message / Text", key="multimodal_text", height=130)
            multi_html = st.text_area("Static HTML Source", key="multimodal_html", height=130)
            multi_upload = st.file_uploader(
                "Optional .eml, .txt, .html, or .htm",
                type=["eml", "txt", "html", "htm"],
                key="multimodal_upload",
            )
            if st.button("Run Multimodal Scan", key="scan_multimodal", type="primary", use_container_width=True):
                text_value, html_value = multi_text, multi_html
                if multi_upload is not None:
                    uploaded_text = multi_upload.getvalue().decode("utf-8", errors="replace")
                    suffix = Path(multi_upload.name).suffix.lower()
                    if suffix in {".eml", ".txt"}:
                        text_value = uploaded_text if not text_value.strip() else uploaded_text + "\n\n" + text_value
                    else:
                        html_value = uploaded_text if not html_value.strip() else html_value + "\n" + uploaded_text
                _run_scan(policy, url_value=multi_url, text_value=text_value, html_value=html_value)

    if st.session_state.get("scan_error"):
        st.warning(st.session_state["scan_error"])

    result = st.session_state.get("scan_result")
    if not result:
        st.caption("Awaiting a submitted threat for forensic analysis.")
        return

    st.markdown("### Analysis Result")
    verdict_card = st.container(border=True)
    with verdict_card:
        top = st.columns([1.15, 2.25, 1])
        class_name = {"Legitimate": "legitimate", "Suspicious": "suspicious", "Phishing": "phishing"}[result["final_label"]]
        with top[0]:
            st.markdown(
                f'<span class="verdict {class_name}">{escape(result["final_label"].upper())}</span>',
                unsafe_allow_html=True,
            )
        with top[1]:
            st.markdown('<div class="risk-label">Risk Score</div>', unsafe_allow_html=True)
            st.progress(min(1.0, max(0.0, result["risk_score"])), text=f"{result['risk_percentage']:.2f}%")
        with top[2]:
            st.metric("Active Modalities", str(len(result["modalities_used"])))

    breakdown_card = st.container(border=True)
    with breakdown_card:
        st.markdown('<div class="section-title">Analysis Breakdown</div>', unsafe_allow_html=True)
        left, right = st.columns(2)
        with left:
            st.plotly_chart(_modality_chart(result), use_container_width=True, config={"displayModeBar": False})
        with right:
            st.plotly_chart(_radar(result), use_container_width=True, config={"displayModeBar": False})

    evidence_card = st.container(border=True)
    with evidence_card:
        st.markdown('<div class="section-title">Forensic Evidence</div>', unsafe_allow_html=True)
        with st.expander("Token X-Ray", expanded=False):
            source = st.session_state.get("specific_url") or st.session_state.get("unified_input") or st.session_state.get("static_html") or "<static HTML source>"
            st.markdown(f'<div class="xray">{_escaped_preview(result, source, source)}</div>', unsafe_allow_html=True)
        with st.expander("Deceptive Link Audit", expanded=bool(result.get("extracted_links"))):
            links = result.get("extracted_links", [])
            if links:
                st.dataframe(pd.DataFrame([{
                    "display_text": item["display_text"],
                    "actual_href": item["actual_href"],
                    "Mismatch": "YES" if item["is_mismatch"] else "No",
                    "risk_note": item["risk_note"],
                } for item in links]), hide_index=True, use_container_width=True)
            else:
                st.caption("No embedded links detected.")
        with st.expander("Modality Indicators", expanded=False):
            categorized = []
            tags = {"url": "URL", "text": "TEXT", "html": "HTML", "header": "HEADER"}
            for modality, detail in result["modality_breakdown"].items():
                categorized.extend(f"[{tags[modality]}] {indicator}" for indicator in detail.get("indicators", []))
            for indicator in result["indicators"]:
                categorized.append(indicator if indicator.startswith("[") else "[FUSION] " + indicator)
            st.text("\n".join(list(dict.fromkeys(categorized))) if categorized else "No malicious indicators detected.")
        with st.expander("Fingerprint & Incident Report", expanded=True):
            st.caption("SHA-256 Input Fingerprint")
            st.code(result["input_sha256"], language="text")
            st.download_button(
                "Export Incident Report (JSON)",
                _incident_json(result, st.session_state.get("last_scan_at", "")),
                file_name="phishguard_incident.json",
                mime="application/json",
                use_container_width=True,
            )
            st.markdown('<div class="small-note">Raw input is excluded from the incident report.</div>', unsafe_allow_html=True)
    st.caption(result["disclaimer"])


def _batch_scanner(policy: str) -> None:
    with st.container(border=True):
        st.markdown('<div class="section-title">CSV Batch Scanner</div>', unsafe_allow_html=True)
        uploaded = st.file_uploader("Upload CSV", type=["csv"], key="batch_csv")
        if uploaded is not None:
            try:
                st.session_state["batch_df"] = pd.read_csv(uploaded)
            except Exception as exc:
                st.error(f"CSV could not be loaded: {exc}")
        if st.button("Load Sample Batch CSV", key="load_sample_batch", use_container_width=True):
            st.session_state["batch_df"] = pd.DataFrame({
                "url": ["https://example.org/about", "https://paypa1-security.example/login", "http://192.0.2.10/verify/account"],
                "text": ["Routine project update", "Urgent: verify your account now", "Your password expires today"],
            })

        batch_df = st.session_state.get("batch_df")
        if batch_df is not None:
            c1, c2, c3 = st.columns(3)
            c1.metric("Rows", f"{len(batch_df):,}")
            c2.metric("Columns", str(len(batch_df.columns)))
            c3.metric("Row Limit", "500")
            st.caption(f"Columns: {', '.join(map(str, batch_df.columns))}")
            if st.button("Run Batch Scan", key="run_batch_scan", type="primary", use_container_width=True):
                try:
                    from src.batch_scanner import scan_csv_batch
                    st.session_state["batch_results"] = scan_csv_batch(batch_df, policy_mode=policy, max_rows=500)
                except Exception as exc:
                    st.session_state["batch_results"] = None
                    st.error(f"Batch scan could not complete: {exc}")
        else:
            st.caption("Upload a CSV or load the sample batch.")

    results = st.session_state.get("batch_results")
    if results is not None:
        counts = results["final_label"].value_counts().to_dict()
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Legitimate", counts.get("Legitimate", 0))
        k2.metric("Suspicious", counts.get("Suspicious", 0))
        k3.metric("Phishing", counts.get("Phishing", 0))
        k4.metric("Scanned Rows", len(results))

        chart_col, table_col = st.columns([1, 2.2])
        with chart_col:
            with st.container(border=True):
                st.markdown('<div class="section-title">Distribution</div>', unsafe_allow_html=True)
                figure = go.Figure(go.Bar(
                    x=["Legitimate", "Suspicious", "Phishing"],
                    y=[counts.get("Legitimate", 0), counts.get("Suspicious", 0), counts.get("Phishing", 0)],
                    marker={"color": ["#059669", "#D97706", "#DC2626"]},
                    texttemplate="%{y}", textposition="outside",
                ))
                figure.update_layout(
                    height=220, margin={"l": 25, "r": 25, "t": 15, "b": 35},
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    showlegend=False, yaxis={"dtick": 1, "gridcolor": "#E2E8F0"},
                )
                st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
        with table_col:
            with st.container(border=True):
                st.markdown('<div class="section-title">Results</div>', unsafe_allow_html=True)
                st.dataframe(results, hide_index=True, use_container_width=True)
        st.download_button(
            "Download CSV Results",
            results.to_csv(index=False).encode("utf-8"),
            file_name="phishguard_batch_results.csv",
            mime="text/csv",
            use_container_width=True,
        )


def _history() -> None:
    history = st.session_state.get("scan_history", [])
    if not history:
        return
    st.markdown("### Scan History")
    with st.expander("View Persistent Scan History", expanded=False):
        c1, c2 = st.columns([5, 1], vertical_alignment="center")
        with c2:
            st.button("Clear History", key="clear_history", on_click=_clear_scan_history, use_container_width=True)
        with c1:
            st.dataframe(pd.DataFrame(history), hide_index=True, use_container_width=True)


def main() -> None:
    if "scan_history_loaded" not in st.session_state:
        history, latest_result, latest_scan_at = _load_scan_history()
        st.session_state["scan_history"] = history
        st.session_state["scan_result"] = latest_result
        st.session_state["last_scan_at"] = latest_scan_at
        st.session_state["scan_history_loaded"] = True
    st.session_state.setdefault("security_policy", "Balanced")
    _styles()
    policy = _header(st.session_state["security_policy"])

    st.markdown("<div style='height:.35rem'></div>", unsafe_allow_html=True)
    inspector, batch = st.tabs(["Single Threat Inspector", "Bulk CSV Batch Scanner"])
    with inspector:
        _single_inspector(policy)
    with batch:
        _batch_scanner(policy)
    _history()
    st.caption("Static analysis only - no links are visited and submitted HTML or scripts are never executed.")


if __name__ == "__main__":
    main()
