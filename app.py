# app.py
"""
ZeroSight - Flask backend
Improved, human-readable reasons for flagged URLs and env-port support.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from urllib.parse import urlparse
import re
import time
import os

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)

# -----------------------------
# Config / tunable lists
# -----------------------------
SAMPLES = []
MAX_SAMPLES = 1000

SUSPICIOUS_HOSTINGS = [
    "trycloudflare.com", "workers.dev", "pages.dev", "vercel.app",
    "netlify.app", "ngrok.io", "herokuapp.com", "github.io", "pagekite.me"
]

BRAND_TOKENS = [
    "instagram", "paypal", "google", "facebook", "amazon", "microsoft",
    "sbi", "hdfc", "icici", "bank", "upi", "gmail", "otp"
]

SHORTENERS = ["bit.ly", "tinyurl", "t.co", "is.gd", "rb.gy", "ow.ly"]

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# -----------------------------
# Helpers
# -----------------------------
def parse_hostname(url: str) -> str:
    """Return normalized hostname for a URL-like string"""
    u = (url or "").strip()
    if not u:
        return ""
    try:
        # ensure scheme present for urlparse
        parsed = urlparse(u if "://" in u else "https://" + u)
        return (parsed.hostname or "").lower()
    except Exception:
        # fallback: split by slash
        return u.split("/")[0].lower()

def now_ts():
    return int(time.time())

# -----------------------------
# Core classifier
# -----------------------------
def classify_link(url: str):
    """
    Returns a dict with:
      - url, host, score, level, reasons (list), ts
    Scores are heuristic-based. Thresholds:
      score < 35 -> SAFE
      35 <= score < 70 -> MEDIUM
      score >= 70 -> HIGH
    """
    host = parse_hostname(url)
    reasons = []
    score = 0

    # 1) direct IP in host (strong indicator)
    if IP_RE.search(host):
        score += 40
        reasons.append("Direct IP address used in host (not a normal domain)")

    # 2) explicit port
    # note: parse_hostname strips port, so also check original URL
    if re.search(r":\d{2,5}", url):
        score += 12
        reasons.append("Explicit port present in URL (uncommon for legitimate sites)")

    # 3) ephemeral / third-party hosting platforms
    for eh in SUSPICIOUS_HOSTINGS:
        if host == eh or host.endswith("." + eh):
            score += 35
            reasons.append(f"Hosted on ephemeral/third-party platform: {eh}")
            break

    # 4) subdomain analysis (length, hyphens, multi-word)
    labels = host.split(".") if host else []
    if len(labels) >= 3:
        sub = ".".join(labels[:-2])  # full subdomain portion
        # very long subdomain
        if len(sub) > 30:
            score += 15
            reasons.append("Very long subdomain (unusually long host label)")
        # many hyphens
        if sub.count("-") >= 2:
            score += 12
            reasons.append("Multiple hyphens in subdomain (common in phishing hosts)")
        # many tokens (multi-word)
        tokens = [t for t in re.split(r"[-_.]", sub) if t]
        if len(tokens) >= 3:
            score += 18
            reasons.append("Multi-word / token-rich subdomain (likely not a normal brand hostname)")

        # brand impersonation: brand token in subdomain but not in SLD
        sld = labels[-2] if len(labels) >= 2 else ""
        low_sub = sub.lower()
        for b in BRAND_TOKENS:
            if b in low_sub and b != sld:
                # strong indicator if brand token present on a non-brand SLD
                score += 40
                reasons.append(f"Brand impersonation detected: '{b}' appears in subdomain while parent domain is not '{b}'")
                break

    # 5) punycode / IDN tricks
    if "xn--" in host:
        score += 25
        reasons.append("Punycode/IDN detected (possible homoglyph / homograph attack)")

    # 6) known link shorteners
    for s in SHORTENERS:
        if s in url.lower():
            score += 30
            reasons.append(f"Uses known link shortener: {s}")
            break

    # 7) phishing keywords in path or query
    PHISH_KEYWORDS = ["verify", "login", "reset", "auth", "secure", "confirm", "payment", "account", "signin", "password", "otp"]
    for k in PHISH_KEYWORDS:
        if k in url.lower():
            score += 15
            reasons.append(f"Contains phishing-related keyword: '{k}'")
            break

    # clamp score
    score = max(0, min(100, score))

    level = "SAFE"
    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"

    return {
        "url": url,
        "host": host,
        "score": score,
        "level": level,
        "reasons": reasons,
        "ts": now_ts()
    }

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/check_link", methods=["POST"])
def api_check_link():
    payload = request.get_json() or {}
    url = payload.get("url", "").strip()
    if not url:
        return jsonify({"error": "missing url"}), 400

    result = classify_link(url)

    # store sample
    SAMPLES.append(result)
    if len(SAMPLES) > MAX_SAMPLES:
        SAMPLES.pop(0)

    return jsonify(result)

@app.route("/api/latest", methods=["GET"])
def api_latest():
    # return up to last 200 samples
    return jsonify({"samples": list(SAMPLES[-200:])})

# health route for debugging
@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({"ok": True, "ts": now_ts()})

# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":
    # allow overriding port using env PORT
    port = int(os.getenv("PORT", "5001"))
    # ensure host 0.0.0.0 so other laptops can test on LAN
    app.run(host="0.0.0.0", port=port, debug=False)
