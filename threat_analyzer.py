import re


# ==========================================
# THREAT INDICATOR ANALYZER
# ==========================================

def analyze_threats(email_text):

    text = email_text.lower()

    indicators = []

    # --------------------------------------
    # Urgency indicators
    # --------------------------------------

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "as soon as possible",
        "expires today",
        "last chance",
        "right away"
    ]

    urgency_count = 0

    for word in urgency_words:
        if word in text:
            urgency_count += 1
            indicators.append(f"Urgency language detected: '{word}'")


    # --------------------------------------
    # Credential indicators
    # --------------------------------------

    credential_words = [
        "password",
        "login",
        "username",
        "credentials",
        "verify your account",
        "confirm your identity",
        "security code"
    ]

    credential_count = 0

    for word in credential_words:
        if word in text:
            credential_count += 1
            indicators.append(
                f"Credential request detected: '{word}'"
            )


    # --------------------------------------
    # Financial indicators
    # --------------------------------------

    financial_words = [
        "bank",
        "credit card",
        "payment",
        "transaction",
        "account number",
        "billing",
        "refund"
    ]

    financial_count = 0

    for word in financial_words:
        if word in text:
            financial_count += 1
            indicators.append(
                f"Financial keyword detected: '{word}'"
            )


    # --------------------------------------
    # Threat indicators
    # --------------------------------------

    threat_words = [
        "account suspended",
        "account closed",
        "account blocked",
        "permanently deleted",
        "lose access",
        "security alert",
        "unauthorized access"
    ]

    threat_count = 0

    for word in threat_words:
        if word in text:
            threat_count += 1
            indicators.append(
                f"Threat language detected: '{word}'"
            )


    # --------------------------------------
    # Reward / social engineering
    # --------------------------------------

    reward_words = [
        "you have won",
        "free prize",
        "reward",
        "claim now",
        "special offer",
        "congratulations"
    ]

    reward_count = 0

    for word in reward_words:
        if word in text:
            reward_count += 1
            indicators.append(
                f"Reward/social-engineering language detected: '{word}'"
            )


    # --------------------------------------
    # Calculate threat score
    # --------------------------------------

    threat_score = (
        urgency_count * 10
        + credential_count * 10
        + financial_count * 10
        + threat_count * 15
        + reward_count * 10
    )

    threat_score = min(threat_score, 100)


    return {
        "urgency_count": urgency_count,
        "credential_count": credential_count,
        "financial_count": financial_count,
        "threat_count": threat_count,
        "reward_count": reward_count,
        "threat_score": threat_score,
        "indicators": list(dict.fromkeys(indicators))
    }


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    test_email = """
    URGENT! Your bank account has been suspended.
    Verify your password immediately to avoid permanent deletion.
    """

    result = analyze_threats(test_email)

    print("\n" + "=" * 50)
    print("        THREAT INDICATOR ANALYZER")
    print("=" * 50)

    print(f"\nUrgency Indicators     : {result['urgency_count']}")
    print(f"Credential Indicators  : {result['credential_count']}")
    print(f"Financial Indicators   : {result['financial_count']}")
    print(f"Threat Indicators      : {result['threat_count']}")
    print(f"Reward Indicators      : {result['reward_count']}")

    print(f"\nThreat Score           : {result['threat_score']}%")

    print("\nRisk Indicators:")

    if result["indicators"]:

        for indicator in result["indicators"]:
            print(f"⚠ {indicator}")

    else:
        print("✓ No phishing language detected")

    print("=" * 50)