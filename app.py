from flask import Flask, render_template, request, jsonify, Response
from datetime import datetime
import joblib

from url_analyzer import analyze_urls
from threat_analyzer import analyze_threats


app = Flask(__name__)


# ==========================================
# LOAD ML MODEL
# ==========================================

model = joblib.load("models/phishing_model.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")


# ==========================================
# ANALYZE EMAIL
# ==========================================

def analyze_email(email):

    # Machine Learning Analysis
    email_features = vectorizer.transform([email])
    probability = model.predict_proba(email_features)[0]

    phishing_probability = probability[1] * 100
    safe_probability = probability[0] * 100

    # URL Analysis
    url_result = analyze_urls(email)

    url_risk = 0

    if url_result["total_urls"] > 0:
        url_risk += 10

    if url_result["ip_urls"] > 0:
        url_risk += 25

    if url_result["http_urls"] > 0:
        url_risk += 15

    if url_result["suspicious_keywords"] > 0:
        url_risk += 20

    if url_result["long_urls"] > 0:
        url_risk += 15

    if url_result["shortened_urls"] > 0:
        url_risk += 15

    url_risk = min(url_risk, 100)

    # Threat Analysis
    threat_result = analyze_threats(email)
    threat_score = threat_result["threat_score"]

    # Final Score
    final_score = (
        phishing_probability * 0.50
        + url_risk * 0.25
        + threat_score * 0.25
    )

    final_score = min(final_score, 100)

    # Risk Level
    if final_score >= 80:
        risk_level = "CRITICAL"
    elif final_score >= 60:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Final Classification
    if final_score >= 50:
        result = "PHISHING"
    else:
        result = "SAFE"

    # Scan Statistics
    scan_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    word_count = len(email.split())
    character_count = len(email)

    indicators = list(dict.fromkeys(
        url_result["findings"] +
        threat_result["indicators"]
    ))

    # Return Complete Analysis
    return {
        "result": result,
        "score": round(final_score, 2),
        "risk_level": risk_level,

        "scan": {
            "timestamp": scan_time,
            "word_count": word_count,
            "character_count": character_count,
            "indicator_count": len(indicators)
        },

        "ml": {
            "phishing_probability": round(phishing_probability, 2),
            "safe_probability": round(safe_probability, 2)
        },

        "url": {
            "total_urls": url_result["total_urls"],
            "ip_urls": url_result["ip_urls"],
            "http_urls": url_result["http_urls"],
            "https_urls": url_result["https_urls"],
            "suspicious_keywords": url_result["suspicious_keywords"],
            "long_urls": url_result["long_urls"],
            "shortened_urls": url_result["shortened_urls"],
            "risk": url_risk,
            "urls": url_result["urls"]
        },

        "threat": {
            "urgency": threat_result["urgency_count"],
            "credentials": threat_result["credential_count"],
            "financial": threat_result["financial_count"],
            "threats": threat_result["threat_count"],
            "rewards": threat_result["reward_count"],
            "score": threat_score
        },

        "indicators": indicators
    }


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# ANALYZE API
# ==========================================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data or not data.get("email", "").strip():
        return jsonify({
            "error": "Please enter an email."
        }), 400

    email = data["email"].strip()

    result = analyze_email(email)

    return jsonify(result)


# ==========================================
# DOWNLOAD SECURITY REPORT
# ==========================================

@app.route("/download-report", methods=["POST"])
def download_report():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "No report data received."
        }), 400

    lines = []

    lines.append("=" * 60)
    lines.append("          PHISHING EMAIL SECURITY REPORT")
    lines.append("=" * 60)

    lines.append("")
    lines.append(f"Final Result     : {data.get('result', 'N/A')}")
    lines.append(f"Risk Score       : {data.get('score', 0)}%")
    lines.append(f"Risk Level       : {data.get('risk_level', 'N/A')}")

    # Scan Statistics
    scan = data.get("scan", {})

    lines.append("")
    lines.append("-" * 60)
    lines.append("SCAN STATISTICS")
    lines.append("-" * 60)

    lines.append(
        f"Scan Time        : {scan.get('timestamp', 'N/A')}"
    )

    lines.append(
        f"Word Count       : {scan.get('word_count', 0)}"
    )

    lines.append(
        f"Character Count  : {scan.get('character_count', 0)}"
    )

    lines.append(
        f"Risk Indicators  : {scan.get('indicator_count', 0)}"
    )

    # ML Analysis
    ml = data.get("ml", {})

    lines.append("")
    lines.append("-" * 60)
    lines.append("MACHINE LEARNING")
    lines.append("-" * 60)

    lines.append(
        f"Phishing Probability : "
        f"{ml.get('phishing_probability', 0)}%"
    )

    lines.append(
        f"Safe Probability     : "
        f"{ml.get('safe_probability', 0)}%"
    )

    # URL Analysis
    url = data.get("url", {})

    lines.append("")
    lines.append("-" * 60)
    lines.append("URL SECURITY")
    lines.append("-" * 60)

    lines.append(
        f"URLs Found           : "
        f"{url.get('total_urls', 0)}"
    )

    lines.append(
        f"IP URLs              : "
        f"{url.get('ip_urls', 0)}"
    )

    lines.append(
        f"HTTP URLs            : "
        f"{url.get('http_urls', 0)}"
    )

    lines.append(
        f"HTTPS URLs           : "
        f"{url.get('https_urls', 0)}"
    )

    lines.append(
        f"Suspicious URL Words : "
        f"{url.get('suspicious_keywords', 0)}"
    )

    lines.append(
        f"Long URLs            : "
        f"{url.get('long_urls', 0)}"
    )

    lines.append(
        f"Shortened URLs       : "
        f"{url.get('shortened_urls', 0)}"
    )

    lines.append(
        f"URL Risk             : "
        f"{url.get('risk', 0)}%"
    )

    # Threat Analysis
    threat = data.get("threat", {})

    lines.append("")
    lines.append("-" * 60)
    lines.append("THREAT ANALYSIS")
    lines.append("-" * 60)

    lines.append(
        f"Urgency              : "
        f"{threat.get('urgency', 0)}"
    )

    lines.append(
        f"Credentials          : "
        f"{threat.get('credentials', 0)}"
    )

    lines.append(
        f"Financial            : "
        f"{threat.get('financial', 0)}"
    )

    lines.append(
        f"Threats              : "
        f"{threat.get('threats', 0)}"
    )

    lines.append(
        f"Rewards              : "
        f"{threat.get('rewards', 0)}"
    )

    lines.append(
        f"Threat Score         : "
        f"{threat.get('score', 0)}%"
    )

    # Risk Indicators
    lines.append("")
    lines.append("-" * 60)
    lines.append("RISK INDICATORS")
    lines.append("-" * 60)

    indicators = data.get("indicators", [])

    if indicators:
        for indicator in indicators:
            lines.append(f"[!] {indicator}")
    else:
        lines.append("No major phishing indicators detected.")

    # URLs
    lines.append("")
    lines.append("-" * 60)
    lines.append("DETECTED URLs")
    lines.append("-" * 60)

    detected_urls = url.get("urls", [])

    if detected_urls:
        for detected_url in detected_urls:
            lines.append(detected_url)
    else:
        lines.append("No URLs detected.")

    # Recommendation
    lines.append("")
    lines.append("-" * 60)
    lines.append("RECOMMENDATION")
    lines.append("-" * 60)

    if data.get("result") == "PHISHING":

        lines.append(
            "DO NOT click links or provide sensitive information."
        )

        lines.append(
            "Verify the sender through an independent channel."
        )

        lines.append(
            "Report the message if it was received unexpectedly."
        )

    else:

        lines.append(
            "No strong phishing indicators detected."
        )

        lines.append(
            "Continue normal email security practices."
        )

    lines.append("")
    lines.append("=" * 60)
    lines.append("              END OF REPORT")
    lines.append("=" * 60)

    report = "\n".join(lines)

    return Response(
        report,
        mimetype="text/plain",
        headers={
            "Content-Disposition":
                "attachment; filename=phishing_security_report.txt"
        }
    )


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )