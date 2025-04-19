import os
from collections import Counter
from utils.email_parser import parse_eml_file

def calculate_risk(indicators, attachment_score, auth_results):
    weights = {
        "urgency_language": 1,
        "suspicious_url": 2,
        "brand_spoofing": 2,
        "advance_fee_scam": 3,
        "crypto_bait": 3,
        "sender_name_mismatch": 2,
        "language_scoring": 2,
        "sentiment_score": 2,
        "free_email_brand_abuse": 2,
        "user_defined_rules": 2,
        "phishing_template_match": 3,
        "html_form_detector": 3
    }

    score = 0
    for key, val in indicators.items():
        if isinstance(val, list) and val:
            score += weights.get(key, 0)

    # Add attachment score
    score += attachment_score

    # Add score for DKIM/SPF failures
    if auth_results.get("spf") == "fail" or auth_results.get("dkim") == "fail":
        score += 2

    if score >= 5:
        severity = "HIGH"
    elif score >= 2:
        severity = "MEDIUM"
    elif score >= 1:
        severity = "LOW"
    else:
        severity = "NONE"

    return score, severity

def main():
    sample_dir = "sample_emails"
    files = [f for f in os.listdir(sample_dir) if f.endswith(".eml")]

    if not files:
        print("No .eml files found in 'sample_emails' folder.")
        return

    all_parsed = []

    for file in files:
        parsed = parse_eml_file(os.path.join(sample_dir, file))
        parsed["filename"] = file
        all_parsed.append(parsed)

    analyze_patterns(all_parsed)
    summarize_suspicious_emails(all_parsed)

def analyze_patterns(emails):
    print("\n=== Batch Pattern Analysis ===")
    subjects = [email['subject'] for email in emails]
    all_urls = [url for email in emails for url in email['urls']]
    senders = [email['from'] for email in emails]

    subject_counts = Counter(subjects)
    url_counts = Counter(all_urls)
    sender_counts = Counter(senders)

    print("\n⚠️ Repeated Subjects:")
    for subj, count in subject_counts.items():
        if count > 1:
            print(f" - '{subj}' appears {count} times")

    print("\n⚠️ Reused URLs:")
    for url, count in url_counts.items():
        if count > 1:
            print(f" - {url} appears {count} times")

    print("\n⚠️ Common Senders:")
    for sender, count in sender_counts.items():
        if count > 1:
            print(f" - {sender} appears {count} times")

def summarize_suspicious_emails(emails):
    print("\n=== Suspicious Emails Summary ===")

    for email in emails:
        indicators = email.get("indicators", {})
        auth = email.get("auth_results", {})
        if any(indicators.values()) or email.get("attachment_score", 0) > 0 or \
           auth.get("spf") == "fail" or auth.get("dkim") == "fail":

            score, severity = calculate_risk(indicators, email.get("attachment_score", 0), auth)
            print(f"\n🚨 Suspicious Email: {email['filename']}")
            print(f"From    : {email['from']}")
            print(f"Subject : {email['subject']}")
            print(f"Risk    : {score} ({severity})")

            print("Indicators Triggered:")
            for k, v in indicators.items():
                if isinstance(v, list) and v:
                    print(f"  - {k}")

            if auth:
                print(f"Authentication:")
                print(f"  SPF : {auth.get('spf')}")
                print(f"  DKIM: {auth.get('dkim')}")

            if email.get("suspicious_attachments"):
                print("\n⚠️ Suspicious Attachments:")
                for att in email["suspicious_attachments"]:
                    print(f"  - {att}")

if __name__ == "__main__":
    main()
