from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import ipaddress

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = {
    "verify", "verification", "urgent", "suspended", "account",
    "login", "signin", "password", "reset", "security", "confirm",
    "update", "wallet", "payment", "invoice", "gift", "click"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}

def analyze_url(url):
    original = url.strip()
    value = original if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original) else "http://" + original
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    text = value.lower()

    score = 0
    indicators = []

    if parsed.scheme not in {"http", "https"}:
        score += 25
        indicators.append("Unusual URL scheme.")

    if parsed.scheme == "http":
        score += 10
        indicators.append("URL does not use HTTPS.")

    if host in SHORTENERS:
        score += 20
        indicators.append("URL uses a known shortening service.")

    try:
        ipaddress.ip_address(host)
        score += 25
        indicators.append("URL uses an IP address instead of a domain name.")
    except ValueError:
        pass

    if "@" in value:
        score += 25
        indicators.append("URL contains '@', which can obscure the actual destination.")

    if len(original) > 100:
        score += 10
        indicators.append("Unusually long URL.")

    if host.count(".") >= 3:
        score += 10
        indicators.append("Domain contains many subdomain levels.")

    if host.count("-") >= 2:
        score += 10
        indicators.append("Domain contains multiple hyphens.")

    found = sorted({k for k in SUSPICIOUS_KEYWORDS if k in text})
    if found:
        score += min(30, 5 * len(found))
        indicators.append("Suspicious keyword(s): " + ", ".join(found))

    score = min(score, 100)
    verdict = "Likely Safe" if score < 30 else ("Suspicious" if score < 60 else "Likely Phishing")

    return {
        "type": "URL",
        "input": original,
        "score": score,
        "verdict": verdict,
        "indicators": indicators or ["No major heuristic indicators detected."]
    }

def analyze_email(text):
    value = text.strip()
    low = value.lower()
    score = 0
    indicators = []

    found = sorted({k for k in SUSPICIOUS_KEYWORDS if k in low})
    if found:
        score += min(40, 8 * len(found))
        indicators.append("Suspicious keyword(s): " + ", ".join(found))

    urgency = ["urgent", "immediately", "within 24 hours", "act now", "final notice"]
    urgent_found = [x for x in urgency if x in low]
    if urgent_found:
        score += 20
        indicators.append("Urgency/pressure language detected.")

    if re.search(r"https?://|www\\.", low):
        links = re.findall(r"https?://\\S+|www\\.\\S+", value, flags=re.I)
        score += 10
        indicators.append(f"Contains {len(links)} web link(s); verify destination before opening.")

    if re.search(r"\\b(verify|confirm|reset|login|password)\\b", low):
        score += 10
        indicators.append("Requests or references account credentials/actions.")

    if re.search(r"\\b(prize|winner|gift card|lottery|reward)\\b", low):
        score += 20
        indicators.append("Prize/reward language detected.")

    if re.search(r"\\b\\S+@\\S+\\.\\S+\\b", value):
        indicators.append("Email address detected; sender authenticity still needs independent verification.")

    score = min(score, 100)
    verdict = "Likely Safe" if score < 30 else ("Suspicious" if score < 60 else "Likely Phishing")

    return {
        "type": "Email/Text",
        "input": value[:500],
        "score": score,
        "verdict": verdict,
        "indicators": indicators or ["No major heuristic indicators detected."]
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "url")
    text = data.get("text", "")
    if not text.strip():
        return jsonify({"error": "Please enter a URL or email text."}), 400
    if len(text) > 10000:
        return jsonify({"error": "Input is too long."}), 400

    result = analyze_url(text) if mode == "url" else analyze_email(text)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)