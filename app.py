
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit

import streamlit as st
from pathlib import Path


# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="PhishGuard | URL Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Load custom CSS
css_path = Path(__file__).parent / "style.css"

if css_path.exists():
    st.markdown(
        f"<style>{css_path.read_text(encoding='utf-8')}</style>",
        unsafe_allow_html=True,
    )


# ---------------- SESSION HISTORY ----------------

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []


# ---------------- URL ANALYSIS ----------------

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy", "rebrand.ly",
}

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "account",
    "update", "secure", "banking", "password",
    "signin", "confirm", "wallet", "suspended",
    "free-gift", "urgent", "claim",
}


def analyze_url(raw_url):
    """Analyze URL characteristics without opening the website."""

    raw_url = raw_url.strip()

    if not raw_url:
        return None, "Please enter a URL."

    if any(ord(char) < 32 or ord(char) == 127 for char in raw_url):
        return None, "The URL contains invalid control characters."

    if re.search(r"\s", raw_url):
        return None, "The URL must not contain spaces."

    # Require a conventional web URL with an explicit scheme.
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        return None, "Enter a complete URL beginning with http:// or https://."

    try:
        parts = urlsplit(raw_url)
        hostname = parts.hostname

        if (
            parts.scheme.lower() not in {"http", "https"}
            or not hostname
            or "." not in hostname
            or parts.username is not None
            or parts.password is not None
        ):
            return None, "Please enter a valid web URL with a hostname."

        # Validate the port if one is provided.
        _ = parts.port

        if len(hostname) > 253:
            return None, "The hostname is too long to be valid."

        if any(not label for label in hostname.rstrip(".").split(".")):
            return None, "The hostname format is invalid."

    except (ValueError, UnicodeError):
        return None, "The URL format is invalid."

    host = hostname.lower().rstrip(".")
    url_lower = raw_url.lower()
    findings = []
    score = 0

    # 1. IP address used instead of a domain name
    try:
        ipaddress.ip_address(host)
        findings.append(
            "The hostname is an IP address rather than a normal domain."
        )
        score += 2
    except ValueError:
        pass

    # 2. HTTPS is not being used
    if parts.scheme.lower() != "https":
        findings.append(
            "The URL uses HTTP instead of encrypted HTTPS."
        )
        score += 1

    # 3. URL contains an @ sign in its authority section
    if "@" in parts.netloc:
        findings.append(
            "An @ sign appears in the URL authority and may be misleading."
        )
        score += 3

    # 4. Internationalized domain / punycode indicator
    if "xn--" in host:
        findings.append(
            "The hostname contains punycode, which can be used in lookalike domains."
        )
        score += 2

    # 5. Excessive subdomains
    labels = host.split(".")
    if len(labels) >= 5:
        findings.append(
            "The hostname has many domain levels or subdomains."
        )
        score += 1

    # 6. Many hyphens in the hostname
    if host.count("-") >= 3:
        findings.append(
            "The hostname contains several hyphens."
        )
        score += 1

    # 7. Known URL shortening service
    if host in SHORTENERS:
        findings.append(
            "This is a URL-shortening service, so the destination is not visible."
        )
        score += 2

    # 8. Suspicious words in URL
    matched_words = sorted(
        word for word in SUSPICIOUS_WORDS if word in url_lower
    )

    if matched_words:
        findings.append(
            "Potentially misleading or urgency-related words appear in the URL: "
            + ", ".join(matched_words[:6])
            + "."
        )
        score += 1

    # 9. Unusually long URL
    if len(raw_url) > 120:
        findings.append(
            "The URL is unusually long and may be difficult to inspect."
        )
        score += 1

    # 10. Unusual explicit port
    if parts.port is not None and parts.port not in {80, 443}:
        findings.append(
            "The URL uses a non-standard web port."
        )
        score += 1

    # 11. Excessive percent encoding
    if raw_url.count("%") >= 5:
        findings.append(
            "The URL contains many percent-encoded characters."
        )
        score += 1

    # Classify the URL based on accumulated indicators.
    if score >= 5:
        category = "Phishing / High Risk"
        risk = "HIGH"
        color = "#fb7185"
        icon = "🚨"
        message = (
            "Multiple warning signs were detected. "
            "Avoid opening this link or entering personal information."
        )
    elif score >= 2:
        category = "Suspicious"
        risk = "MEDIUM"
        color = "#fbbf24"
        icon = "⚠️"
        message = (
            "Some warning signs were detected. "
            "Verify the destination independently before proceeding."
        )
    else:
        category = "No Obvious Warning Signs"
        risk = "LOW"
        color = "#34d399"
        icon = "🛡️"
        message = (
            "Few URL-pattern warnings were detected. "
            "This does not prove the website is safe."
        )

    if not findings:
        findings.append(
            "No warning signs from the checks in this demonstration were detected."
        )

    result = {
        "url": raw_url,
        "domain": host,
        "category": category,
        "risk": risk,
        "score": score,
        "color": color,
        "icon": icon,
        "message": message,
        "findings": findings,
        "time": datetime.now().strftime("%d %b %Y, %I:%M:%S %p"),
    }

    return result, None


# ---------------- HEADER ----------------

st.markdown(
    """
    <div class="hero">
        <div style="font-size:14px;color:#22d3ee;font-weight:800;
                    letter-spacing:2px;">
            🛡️ PHISHGUARD SECURITY
        </div>
        <h1>Phishing Detection System</h1>
        <p>
            Scan suspicious URLs, identify common warning signs,
            and make safer decisions online.
        </p>
        <div style="margin-top:18px;color:#86efac;font-size:13px;">
            ● URL ANALYZER READY
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------- SCAN FORM ----------------

st.markdown("### 🔎 Scan a Website URL")
st.write(
    "Enter a complete URL to check its structure for common "
    "phishing indicators."
)

with st.form("url_scan_form"):
    entered_url = st.text_input(
        "Website URL",
        placeholder="https://example.com/login",
        help="Enter the full URL, including https:// or http://.",
    )

    submitted = st.form_submit_button(
        "🛡️ Scan URL",
        use_container_width=True,
    )

if submitted:
    result, error = analyze_url(entered_url)

    if error:
        st.error(error)
    else:
        st.session_state.scan_history.insert(0, result)
        st.session_state.last_result = result


# ---------------- LATEST RESULT ----------------

if "last_result" in st.session_state:
    result = st.session_state.last_result

    st.markdown("---")
    st.markdown("### 📊 Scan Result")

    st.markdown(
        f"""
        <div class="section-card"
             style="border-color:{result['color']};">
            <div style="font-size:15px;color:#9caec5;">
                DETECTION STATUS
            </div>
            <div style="font-size:30px;font-weight:800;
                        color:{result['color']};margin:12px 0;">
                {result['icon']} {result['category']}
            </div>
            <div style="color:#e2e8f0;overflow-wrap:anywhere;">
                <b>Scanned URL:</b> {result['url']}
            </div>
            <div style="color:#a7b5ca;margin-top:8px;
                        overflow-wrap:anywhere;">
                <b>Hostname:</b> {result['domain']}
            </div>
            <div style="color:#a7b5ca;margin-top:8px;">
                <b>Risk level:</b> {result['risk']}
                &nbsp; | &nbsp;
                <b>Indicator score:</b> {result['score']}
            </div>
            <p style="color:#e2e8f0;margin-top:18px;">
                {result['message']}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("#### 🔍 Why did the system give this result?")

    for finding in result["findings"]:
        st.markdown(f"- {finding}")

    st.markdown("#### 💡 Recommended actions")

    if result["risk"] == "HIGH":
        st.error(
            "Do not open the link or submit passwords, OTPs, or banking "
            "details. Verify the organization through its official website."
        )
    elif result["risk"] == "MEDIUM":
        st.warning(
            "Do not proceed until you independently verify the full "
            "domain and the reason you received the link."
        )
    else:
        st.info(
            "Check the domain carefully and use an independently verified "
            "website. A low-risk result is not a guarantee of safety."
        )


# ---------------- DASHBOARD STATISTICS ----------------

history = st.session_state.scan_history

total = len(history)
high = sum(item["risk"] == "HIGH" for item in history)
medium = sum(item["risk"] == "MEDIUM" for item in history)
low = sum(item["risk"] == "LOW" for item in history)

st.markdown("---")
st.markdown("### 📈 Session Dashboard")

c1, c2, c3, c4 = st.columns(4)

metrics = [
    (c1, "TOTAL SCANS", total, "#38bdf8"),
    (c2, "HIGH RISK", high, "#fb7185"),
    (c3, "SUSPICIOUS", medium, "#fbbf24"),
    (c4, "LOW RISK", low, "#34d399"),
]

for column, label, value, color in metrics:
    with column:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="color:{color};">
                    {value}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ---------------- SCAN HISTORY ----------------

st.markdown("---")
st.markdown("### 🕘 Recent Scan History")

if history:
    for item in history[:10]:
        with st.expander(
            f"{item['icon']} {item['category']} — {item['domain']}"
        ):
            st.write("**URL:**", item["url"])
            st.write("**Risk:**", item["risk"])
            st.write("**Time:**", item["time"])
            st.write("**Findings:**")
            for finding in item["findings"]:
                st.write("•", finding)

    if st.button("Clear Session History"):
        st.session_state.scan_history = []
        st.session_state.pop("last_result", None)
        st.rerun()
else:
    st.info(
        "No scans yet. Enter a URL above and select Scan URL "
        "to populate the dashboard."
    )


# ---------------- FOOTER ----------------

st.markdown(
    """
    <div style="text-align:center;color:#8190a6;
                padding:30px 0 10px 0;">
        <p>🛡️ PhishGuard | Educational Cybersecurity Project</p>
        <p style="font-size:12px;">
            Results are heuristic estimates, not a verified threat-intelligence
            verdict. No websites are opened by this scanner.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)
