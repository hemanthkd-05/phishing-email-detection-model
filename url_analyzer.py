import re
from urllib.parse import urlparse


def analyze_urls(email_text):

    # Find URLs
    url_pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(url_pattern, email_text)

    total_urls = len(urls)
    ip_urls = 0
    http_urls = 0
    https_urls = 0
    suspicious_keywords = 0
    long_urls = 0
    shortened_urls = 0

    findings = []

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "password",
        "bank",
        "confirm",
        "wallet",
        "payment"
    ]

    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly"
    ]

    for url in urls:

        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        if not hostname:
            continue

        # HTTP / HTTPS
        if parsed_url.scheme == "http":
            http_urls += 1
            findings.append("Unsecured HTTP URL detected")

        elif parsed_url.scheme == "https":
            https_urls += 1

        # IP address
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
            ip_urls += 1
            findings.append("IP address used as URL")

        # Suspicious keywords
        url_lower = url.lower()

        if any(word in url_lower for word in suspicious_words):
            suspicious_keywords += 1
            findings.append("Suspicious keyword found in URL")

        # Long URL
        if len(url) > 100:
            long_urls += 1
            findings.append("Unusually long URL detected")

        # URL shortener
        if hostname.lower() in shortener_domains:
            shortened_urls += 1
            findings.append("URL shortener detected")

    return {
        "urls": urls,
        "total_urls": total_urls,
        "ip_urls": ip_urls,
        "http_urls": http_urls,
        "https_urls": https_urls,
        "suspicious_keywords": suspicious_keywords,
        "long_urls": long_urls,
        "shortened_urls": shortened_urls,
        "findings": list(dict.fromkeys(findings))
    }


if __name__ == "__main__":

    test_email = """
    URGENT! Verify your account immediately.

    http://192.168.1.100/login
    http://bit.ly/secure-login
    """

    result = analyze_urls(test_email)

    print("====================================")
    print("       PROFESSIONAL URL ANALYZER")
    print("====================================")

    print(f"URLs Found          : {result['total_urls']}")
    print(f"IP URLs             : {result['ip_urls']}")
    print(f"HTTP URLs           : {result['http_urls']}")
    print(f"HTTPS URLs          : {result['https_urls']}")
    print(f"Suspicious URLs     : {result['suspicious_keywords']}")
    print(f"Long URLs           : {result['long_urls']}")
    print(f"Shortened URLs      : {result['shortened_urls']}")

    print("\nRisk Indicators:")

    if result["findings"]:
        for finding in result["findings"]:
            print(f"  ⚠ {finding}")
    else:
        print("  ✓ No suspicious URL indicators detected")

    print("====================================")