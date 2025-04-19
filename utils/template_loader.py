import os
import re

def load_template_patterns(folder="phishing_templates"):
    """Loads phishing regex templates from .txt files in the given folder."""
    templates = {}

    if not os.path.exists(folder):
        print(f"[⚠️] Template folder '{folder}' not found.")
        return templates

    for filename in os.listdir(folder):
        if filename.endswith(".txt"):
            template_name = filename.replace(".txt", "")
            filepath = os.path.join(folder, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                patterns = [line.strip() for line in f if line.strip()]
                templates[template_name] = patterns
    return templates
