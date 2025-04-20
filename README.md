# 🛡️ PhishyMail

PhishyMail is a command-line tool I built to analyze `.eml` email files and detect signs of phishing using a variety of static techniques. The idea came from wanting to simulate what an email triage tool in a real SOC (Security Operations Center) might look like — something quick, offline, and focused on common phishing indicators.

---

## 🔍 What It Does

PhishyMail checks each email for:

- **Urgency language** – things like "act now", "account suspended", etc.
- **Suspicious URLs** – mismatched domains, IP addresses, or obfuscation
- **Brand spoofing** – pretending to be PayPal, Amazon, etc. from a public domain
- **Advance-fee scams** – common 419-style wording
- **Crypto bait** – scams using airdrop or token giveaways
- **Dangerous attachments** – flags risky file extensions like `.exe`, `.html`
- **DKIM/SPF validation** – detects failed authentication headers
- **HTML form detection** – catches credential harvesters
- **Sentiment & language tone** – NLP used to identify emotional manipulation
- **Custom rules** – load your own keywords/domains via `ruleset.json`
- **Phishing template match** – regex patterns for known scam formats

Each `.eml` file gets scanned and scored, with a summary showing potential risks.

---

## 🚀 Getting Started

Clone the repo:

```bash
git clone https://github.com/YOUR_USERNAME/PhishyMail.git
cd PhishyMail
```

Create a virtual environment and install requirements:

```bash
python3 -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Drop your `.eml` files into the `sample_emails/` folder and run:

```bash
python main.py
```

You’ll get a terminal summary of all suspicious emails and risk levels.

---

## ✏️ How to Customize

You can add your own detection logic in these ways:

- **Edit `ruleset.json`** to add banned domains, keywords, or file types.
- **Add regex templates** in the `phishing_templates/` folder.
- Want to block a new scam you saw in the wild? Just drop in a regex or rule.

---

## 🧪 Sample Output

```
=== Suspicious Emails Summary ===

🚨 Suspicious Email: DHL_TrackYourPackage.eml
From    : DHL Delivery <dhl-tracking@fakesite.com>
Subject : Track Your Package Now
Risk    : 6 (HIGH)

Indicators Triggered:
  - urgency_language
  - brand_spoofing
  - suspicious_url
  - phishing_template_match
  - html_form_detector
```

---

## 🛠 Project Structure

```
PhishyMail/
├── main.py
├── requirements.txt
├── ruleset.json
├── sample_emails/
├── phishing_templates/
└── utils/
    ├── email_parser.py
    ├── config_loader.py
    └── template_loader.py
```

---

## 💬 Why I Made This

This project was a chance to combine my cybersecurity background with Python scripting in a way that feels practical and hands-on. It’s not meant to be a full spam filter, but it’s a solid start to spotting phishing tactics in raw email content. I’ve tested it with real-world `.eml` files and plan to keep improving it as I go.

---

## 📫 Let’s Connect

If you're into email security, Python automation, or just want to talk cyber — feel free to reach out.

Thanks for checking out PhishyMail.

– George Lazai
