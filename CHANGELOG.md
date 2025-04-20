-------------------CHANGELOG-------------------

All notable changes to this project will be documented here.

v1.0.0 #Initial Release

- Phishing indicator scanner for `.eml` files
- Batch risk scoring with LOW / MEDIUM / HIGH output
- Detects:
  - Urgency language
  - Suspicious URLs and IPs
  - Brand spoofing
  - Advance-fee fraud
  - Crypto bait
  - Risky attachments with score
  - DKIM/SPF auth failures
  - HTML `<form>` phishing
  - Regex-based phishing template matching
  - Custom ruleset support (`ruleset.json`)
  - Sender name mismatch
  - Sentiment + language scoring
