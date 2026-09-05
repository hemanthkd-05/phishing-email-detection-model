import joblib
from url_analyzer import analyze_urls
from threat_analyzer import analyze_threats


# ==========================================
# LOAD MACHINE LEARNING MODEL
# ==========================================

model = joblib.load("models/phishing_model.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")


# ==========================================
# HEADER
# ==========================================

print("\n" + "=" * 60)
print("          PHISHING EMAIL SECURITY ANALYZER")
print("=" * 60)


# ==========================================
# EMAIL INPUT
# ==========================================

email = input("\nPaste email text:\n")


# ==========================================
# 1. MACHINE LEARNING ANALYSIS
# ==========================================

email_features = vectorizer.transform([email])

probability = model.predict_proba(email_features)[0]

phishing_probability = probability[1] * 100
safe_probability = probability[0] * 100


# ==========================================
# 2. URL ANALYSIS
# ==========================================

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


# ==========================================
# 3. THREAT LANGUAGE ANALYSIS
# ==========================================

threat_result = analyze_threats(email)

threat_score = threat_result["threat_score"]


# ==========================================
# 4. COMBINE ALL THREE LAYERS
# ==========================================

final_score = (
    phishing_probability * 0.50
    + url_risk * 0.25
    + threat_score * 0.25
)

final_score = min(final_score, 100)


# ==========================================
# RISK LEVEL
# ==========================================

if final_score >= 80:
    risk_level = "CRITICAL"

elif final_score >= 60:
    risk_level = "HIGH"

elif final_score >= 40:
    risk_level = "MEDIUM"

else:
    risk_level = "LOW"


# ==========================================
# FINAL CLASSIFICATION
# ==========================================

if final_score >= 50:
    final_result = "PHISHING"

else:
    final_result = "SAFE"


# ==========================================
# SECURITY REPORT
# ==========================================

print("\n" + "=" * 60)
print("                    SECURITY REPORT")
print("=" * 60)

print(f"\nFINAL RESULT       : {final_result}")
print(f"FINAL RISK SCORE   : {final_score:.2f}%")
print(f"RISK LEVEL         : {risk_level}")


# ==========================================
# ML REPORT
# ==========================================

print("\n" + "-" * 60)
print("MACHINE LEARNING ANALYSIS")
print("-" * 60)

print(f"Phishing Probability : {phishing_probability:.2f}%")
print(f"Safe Probability     : {safe_probability:.2f}%")


# ==========================================
# URL REPORT
# ==========================================

print("\n" + "-" * 60)
print("URL SECURITY ANALYSIS")
print("-" * 60)

print(f"URLs Found           : {url_result['total_urls']}")
print(f"IP URLs              : {url_result['ip_urls']}")
print(f"HTTP URLs            : {url_result['http_urls']}")
print(f"HTTPS URLs           : {url_result['https_urls']}")
print(f"Suspicious URL Words : {url_result['suspicious_keywords']}")
print(f"Long URLs            : {url_result['long_urls']}")
print(f"Shortened URLs       : {url_result['shortened_urls']}")
print(f"URL Risk Score       : {url_risk}%")


# ==========================================
# THREAT REPORT
# ==========================================

print("\n" + "-" * 60)
print("EMAIL THREAT ANALYSIS")
print("-" * 60)

print(f"Urgency Indicators    : {threat_result['urgency_count']}")
print(f"Credential Indicators : {threat_result['credential_count']}")
print(f"Financial Indicators  : {threat_result['financial_count']}")
print(f"Threat Indicators     : {threat_result['threat_count']}")
print(f"Reward Indicators     : {threat_result['reward_count']}")
print(f"Threat Score          : {threat_score}%")


# ==========================================
# RISK INDICATORS
# ==========================================

print("\n" + "-" * 60)
print("RISK INDICATORS")
print("-" * 60)

all_indicators = []

all_indicators.extend(url_result["findings"])
all_indicators.extend(threat_result["indicators"])

all_indicators = list(dict.fromkeys(all_indicators))

if all_indicators:

    for indicator in all_indicators:
        print(f"⚠ {indicator}")

else:

    print("✓ No major phishing indicators detected")


# ==========================================
# DETECTED URLs
# ==========================================

if url_result["urls"]:

    print("\n" + "-" * 60)
    print("DETECTED URLs")
    print("-" * 60)

    for url in url_result["urls"]:
        print(f"🔗 {url}")


# ==========================================
# RECOMMENDATION
# ==========================================

print("\n" + "-" * 60)
print("SECURITY RECOMMENDATION")
print("-" * 60)

if final_result == "PHISHING":

    print("⚠ DO NOT click links or provide sensitive information.")
    print("⚠ Verify the sender through an independent channel.")
    print("⚠ Report the message if it was received unexpectedly.")

elif risk_level == "MEDIUM":

    print("⚠ Exercise caution with this email.")
    print("⚠ Verify the sender before interacting with links.")

else:

    print("✓ No strong phishing indicators detected.")
    print("✓ Continue normal email security practices.")


# ==========================================
# END
# ==========================================

print("\n" + "=" * 60)
print("              END OF SECURITY REPORT")
print("=" * 60)