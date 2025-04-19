import json
import os

def load_ruleset(path="ruleset.json"):
    """Loads user-defined phishing rules from a JSON file."""
    if not os.path.exists(path):
        print(f"[⚠️] Warning: ruleset file '{path}' not found.")
        return {
            "banned_domains": [],
            "banned_keywords": [],
            "banned_extensions": []
        }

    with open(path, "r") as f:
        try:
            rules = json.load(f)
            return {
                "banned_domains": rules.get("banned_domains", []),
                "banned_keywords": rules.get("banned_keywords", []),
                "banned_extensions": rules.get("banned_extensions", [])
            }
        except json.JSONDecodeError:
            print("[❌] Error: Invalid JSON in ruleset.")
            return {
                "banned_domains": [],
                "banned_keywords": [],
                "banned_extensions": []
            }
