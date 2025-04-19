import re
import os
from email import policy
from email.parser import BytesParser
from textblob import TextBlob
from utils.config_loader import load_ruleset
from utils.template_loader import load_template_patterns

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "aol.com", "outlook.com",
    "icloud.com", "protonmail.com", "live.com", "mail.com", "zoho.com",
    "yandex.com", "gmx.com"
]

def get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                return part.get_payload(decode=True).decode(errors="ignore")
    else:
        return msg.get_payload(decode=True).decode(errors="ignore")
    return ""

def extract_urls(text):
    return re.findall(r"https?://[^\s<>\"']+", text)

def detect_urgency(body):
    keywords = [
        "urgent", "immediately", "verify now", "action required",
        "account suspended", "click now", "limited time"
    ]
    return [kw for kw in keywords if kw.lower() in body.lower()]

def is_ip_address(url):
    return re.match(r"https?://(\d{1,3}\.){3}\d{1,3}", url) is not None

def detect_suspicious_urls(urls, from_domain):
    suspicious = []
    for url in urls:
        domain_match = re.search(r"https?://([^/]+)/?", url)
        if domain_match:
            domain = domain_match.group(1)
            if from_domain and from_domain not in domain:
                suspicious.append(f"Domain mismatch: {domain}")
            if is_ip_address(url):
                suspicious.append(f"IP address used: {url}")
            if domain.count('.') > 3:
                suspicious.append(f"Obfuscated URL: {url}")
    return suspicious

def detect_brand_spoofing(sender, body):
    brands = {
        "PayPal": "paypal.com",
        "Linked": "linkedin.com",
        "Microsoft": "microsoft.com",
        "Amazon": "amazon.com",
        "Google": "google.com",
    }

    alerts = []
    sender = sender.lower()
    body = body.lower()
    for brand, domain in brands.items():
        if brand.lower() in sender or brand.lower() in body:
            if domain not in sender:
                alerts.append(f"Brand spoofing detected: {brand}")
    return alerts

def detect_fraud_scam(body):
    scam_keywords = [
        "my late husband", "inherit", "executor", "financial firm",
        "claim the deposit", "Benin Republic", "I offer you", "trusted person",
        "only daughter", "transfer to your custody", "investment purposes"
    ]
    return [kw for kw in scam_keywords if kw.lower() in body.lower()]

def detect_crypto_bait(subject, body, sender_domain):
    bait_keywords = [
        "digital currency", "crypto", "blockchain", "token",
        "wallet", "airdropped", "airdrop", "transferred to you", "we will send",
        "crypto prize", "bitcoin", "ethereum", "your transaction", "claim your crypto"
    ]
    combined_text = f"{subject.lower()} {body.lower()}"
    matches = [kw for kw in bait_keywords if kw in combined_text]

    trusted_domains = ["linkedin.com", "indeed.com", "glassdoor.com"]
    if matches and not any(td in sender_domain for td in trusted_domains):
        return matches
    return []

def detect_language_score(body):
    keywords = [
        "trust", "confidential", "important", "secure", "privacy",
        "verify", "confirm", "click", "login", "reset", "reply",
        "prize", "winner", "locked", "suspended", "legal action",
        "friend", "partner", "family", "only you", "last chance"
    ]
    return [kw for kw in keywords if kw.lower() in body.lower()]

def detect_sentiment_score(body):
    blob = TextBlob(body)
    polarity = blob.sentiment.polarity
    if polarity > 0.5:
        return [f"Positive tone (+{polarity:.2f})"]
    elif polarity < -0.5:
        return [f"Negative tone ({polarity:.2f})"]
    return []

def detect_sender_name_mismatch(from_field):
    known_brands = {
        "PayPal": "paypal.com",
        "LinkedIn": "linkedin.com",
        "Microsoft": "microsoft.com",
        "Amazon": "amazon.com",
        "Google": "google.com",
        "Netflix": "netflix.com",
        "Facebook": "facebook.com"
    }

    results = []
    match = re.match(r'(.+?)\s*<(.+?)>', from_field)
    if match:
        name = match.group(1).strip().lower()
        email = match.group(2).strip().lower()
        domain = email.split("@")[-1]

        for brand, legit_domain in known_brands.items():
            if brand.lower() in name and legit_domain not in domain:
                results.append(f"Name spoofing: '{name}' via {domain}")
    return results

def detect_free_email_brand_abuse(from_field):
    known_brands = [
        "paypal", "amazon", "microsoft", "linkedin", "google", "facebook", "netflix", "apple"
    ]
    match = re.match(r'.*<(.+?)>', from_field)
    if not match:
        return []

    email = match.group(1).strip().lower()
    domain = email.split("@")[-1]

    triggered = []
    for brand in known_brands:
        if brand in email and domain in FREE_EMAIL_DOMAINS:
            triggered.append(f"Brand '{brand}' spoofed using public domain: {domain}")
    return triggered

def detect_user_defined_rules(body, urls, attachments):
    rules = load_ruleset()
    indicators = []

    for keyword in rules["banned_keywords"]:
        if keyword.lower() in body.lower():
            indicators.append(f"Banned keyword found: '{keyword}'")

    for domain in rules["banned_domains"]:
        for url in urls:
            if domain.lower() in url.lower():
                indicators.append(f"Banned domain in URL: '{domain}'")

    for filename in attachments:
        ext = os.path.splitext(filename)[1].lower()
        if ext in rules["banned_extensions"]:
            indicators.append(f"Banned attachment type: '{ext}' in {filename}")
    return indicators

def detect_phishing_templates(body):
    matches = []
    templates = load_template_patterns()

    for name, patterns in templates.items():
        for pattern in patterns:
            try:
                if re.search(pattern, body, re.IGNORECASE):
                    matches.append(f"Matched template: {name}")
                    break
            except re.error:
                print(f"[⚠️] Invalid regex in {name}: {pattern}")
    return matches

def detect_html_form_usage(msg):
    suspicious_tags = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    html = part.get_payload(decode=True).decode(errors="ignore").lower()
                    if "<form" in html:
                        suspicious_tags.append("<form>")
                    if "<input" in html:
                        suspicious_tags.append("<input>")
                    if "<button" in html:
                        suspicious_tags.append("<button>")
                except Exception:
                    continue
    else:
        if msg.get_content_type() == "text/html":
            try:
                html = msg.get_payload(decode=True).decode(errors="ignore").lower()
                if "<form" in html:
                    suspicious_tags.append("<form>")
                if "<input" in html:
                    suspicious_tags.append("<input>")
                if "<button" in html:
                    suspicious_tags.append("<button>")
            except Exception:
                pass
    return suspicious_tags

def parse_authentication_results(msg):
    """Parses the Authentication-Results header to check SPF and DKIM."""
    results = {
        "spf": "not found",
        "dkim": "not found"
    }

    auth_header = msg.get("Authentication-Results")
    if auth_header:
        if "spf=" in auth_header:
            spf_match = re.search(r"spf=(pass|fail|neutral|none)", auth_header, re.IGNORECASE)
            if spf_match:
                results["spf"] = spf_match.group(1).lower()

        if "dkim=" in auth_header:
            dkim_match = re.search(r"dkim=(pass|fail|neutral|none)", auth_header, re.IGNORECASE)
            if dkim_match:
                results["dkim"] = dkim_match.group(1).lower()

    return results
    

ATTACHMENT_RISK_WEIGHTS = {
    ".exe": 4, ".scr": 4, ".vbs": 4, ".js": 4, ".jar": 4, ".msi": 4,
    ".bat": 4, ".cmd": 4, ".wsf": 4, ".com": 4, ".cpl": 4,
    ".zip": 3, ".7z": 3, ".rar": 3, ".html": 3, ".htm": 3,
    ".docm": 3, ".xlsm": 3, ".pptm": 3, ".rtf": 2, ".pdf": 2,
    ".doc": 1, ".xls": 1, ".ppt": 1, ".txt": 0, ".jpg": 0, ".jpeg": 0, ".png": 0
}

def detect_attachments(msg):
    attachment_list = []
    suspicious = []
    total_score = 0

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            if filename:
                attachment_list.append(filename)
                ext = os.path.splitext(filename)[1].lower()
                weight = ATTACHMENT_RISK_WEIGHTS.get(ext, 0)
                if weight > 0:
                    suspicious.append(f"{filename} (.{ext[1:]}: risk {weight})")
                    total_score += weight
    return attachment_list, suspicious, total_score

def parse_eml_file(filepath):
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    parsed = {}
    parsed["from"] = msg.get("From", "")
    parsed["to"] = msg.get("To", "")
    parsed["subject"] = msg.get("Subject", "")
    parsed["date"] = msg.get("Date", "")
    parsed["body"] = get_body(msg)
    parsed["urls"] = extract_urls(parsed["body"])

    email_from = parsed["from"]
    from_domain = ""
    if "@" in email_from:
        from_domain = email_from.split("@")[-1].strip(">").lower()
    parsed["from_domain"] = from_domain

    attachments, suspicious_attachments, attachment_score = detect_attachments(msg)
    parsed["attachments"] = attachments
    parsed["suspicious_attachments"] = suspicious_attachments
    parsed["attachment_score"] = attachment_score
    parsed["auth_results"] = parse_authentication_results(msg)

    parsed["html_form_usage"] = detect_html_form_usage(msg)

    indicators = {
        "urgency_language": detect_urgency(parsed["body"]),
        "suspicious_url": detect_suspicious_urls(parsed["urls"], from_domain),
        "brand_spoofing": detect_brand_spoofing(email_from, parsed["body"]),
        "advance_fee_scam": detect_fraud_scam(parsed["body"]),
        "crypto_bait": detect_crypto_bait(parsed["subject"], parsed["body"], from_domain),
        "sender_name_mismatch": detect_sender_name_mismatch(email_from),
        "language_scoring": detect_language_score(parsed["body"]),
        "sentiment_score": detect_sentiment_score(parsed["body"]),
        "free_email_brand_abuse": detect_free_email_brand_abuse(email_from),
        "user_defined_rules": detect_user_defined_rules(parsed["body"], parsed["urls"], parsed["attachments"]),
        "phishing_template_match": detect_phishing_templates(parsed["body"]),
        "html_form_detector": parsed["html_form_usage"]
    }

    parsed["indicators"] = indicators
    return parsed
