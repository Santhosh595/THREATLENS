from flask import Flask, render_template, request
from urllib.parse import urlparse

app = Flask(__name__)

checked_links = {}
checked_domains = {}


def _first_punycode_label(hostname):
    """First DNS label using punycode (leading "xn--" ACE prefix), or None.

    Accepts raw unicode hosts too: they are normalized through IDNA encoding
    before scanning, so "аpple.com" and its encoded twin both match. A label
    merely *containing* "xn--" mid-string never matches — per IDNA only a
    leading prefix marks an encoded label.

    Returns a (label, decoded_or_None) tuple so callers can show what the
    host actually resolves to.
    """
    if not hostname:
        return None
    hosts = [hostname]
    try:
        hosts.append(hostname.encode("idna").decode("ascii"))
    except (UnicodeError, ValueError):
        pass
    for host in hosts:
        for label in host.split("."):
            if label.startswith("xn--"):
                decoded = None
                try:
                    decoded = label.encode("ascii").decode("idna")
                except (UnicodeError, ValueError):
                    pass
                return label, decoded
    return None


def analyze_url(url):
    indicators = []
    risk = 10
    threat_type = "Safe"
    page_intent = "Normal Browsing"
    explanation = ""
    action = "Link appears safe."

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    lower_url = url.lower()

    if not parsed.scheme.startswith("https"):
        indicators.append("No HTTPS Encryption")
        risk += 20

    if any(s in lower_url for s in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
        indicators.append("Shortened URL")
        risk += 30

    if any(k in lower_url for k in ["login", "verify", "update", "secure"]):
        indicators.append("Login / Verification Keyword")
        risk += 25

    if domain.replace(".", "").isdigit():
        indicators.append("IP-based URL")
        risk += 30

    punycode = _first_punycode_label(parsed.hostname or "")
    if punycode:
        label, decoded = punycode
        if decoded:
            indicators.append(f"Punycode / Homograph Host ({label} resolves to '{decoded}')")
        else:
            indicators.append(f"Punycode / Homograph Host ({label})")
        risk += 30

    if risk >= 70:
        threat_type = "Credential Phishing"
        page_intent = "Login / Account Verification"
        explanation = "This link uses patterns commonly found in phishing attacks."
        action = "Do NOT click the link."
    elif risk >= 40:
        threat_type = "Suspicious Link"
        page_intent = "Redirection / Verification"
        explanation = "This link shows suspicious characteristics."
        action = "Proceed with caution."

    link_seen_before = url in checked_links
    domain_seen_before = domain in checked_domains

    previous_link_result = checked_links.get(url)
    previous_domain_result = checked_domains.get(domain)

    checked_links[url] = threat_type
    checked_domains[domain] = threat_type

    return {
        "risk": min(risk, 100),
        "threat_type": threat_type,
        "page_intent": page_intent,
        "indicators": indicators,
        "explanation": explanation,
        "action": action,
        "link_seen_before": link_seen_before,
        "domain_seen_before": domain_seen_before,
        "previous_link_result": previous_link_result,
        "previous_domain_result": previous_domain_result,
        "domain": domain
    }

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        result = analyze_url(request.form["url"])
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run()
