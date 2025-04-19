import re
from urllib.parse import urlparse

# Urgency words list
URGENCY_WORDS = [
    "urgent", "immediately", "verify now", "action required",
    "account suspended", "click here", "limited time", "respond now"
]

# Trusted brand domains
TRUSTED_BRANDS = {
    "paypal.com": "paypal",
    "linkedin.com": "linkedin",
    "microsoft.com": "microsoft",
    "apple.com": "apple"
}

def detect_phishing_indicators(parsed_email):
    indicators = []

    # 1. Urgency language
    body_lower = parsed_email['body'].lower()
    for word in URGENCY_WORDS:
        if word in body_lower:
            indicators.append(f"⚠️ Urgency Language: '{word}' found in email body.")
            break

    # 2. Suspicious URLs
    for url in parsed_email['urls']:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # IP address instead of domain
        if re.match(r"\d{1,3}(\.\d{1,3}){3}", domain):
            indicators.append(f"⚠️ URL uses IP address: {url}")
            continue

        # Too many subdomains (e.g., login.security.paypal.fake.com)
        if domain.count('.') >= 3:
            indicators.append(f"⚠️ Suspicious subdomain: {domain}")

        # Check if sender domain mismatches link domain
        if parsed_email['from_domain'] and parsed_email['from_domain'] not in domain:
            indicators.append(f"⚠️ Sender domain '{parsed_email['from_domain']}' doesn't match link domain '{domain}'")

    # 3. Brand Spoofing
    for trusted_domain, brand in TRUSTED_BRANDS.items():
        if brand in parsed_email['body'].lower() or brand in parsed_email['subject'].lower():
            if trusted_domain not in parsed_email['from']:
                indicators.append(f"⚠️ Brand spoofing: Mentions '{brand}' but sender is not from '{trusted_domain}'")

    return indicators
