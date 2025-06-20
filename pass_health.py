import json
import hashlib
import requests
import re

def load_bitwarden_export(file_path):
    """Load and parse Bitwarden JSON export."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # Filter only items with a login and password
    return [item for item in data['items'] if 'login' in item and item['login'].get('password')]

def check_hibp(password):
    """Check if password is in HIBP breach database using k-anonymity."""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={'User-Agent': 'Bitwarden-Password-Checker'}
    )
    if response.status_code == 200:
        hashes = [line.split(':')[0] for line in response.text.splitlines()]
        return suffix in hashes
    return False

def is_weak_password(password, min_length=12):
    """Check if password is weak (short or missing required character types)."""
    if len(password) < min_length:
        return f"Shorter than {min_length} characters"
    # Check for at least one uppercase, lowercase, digit, and special character
    if not re.search(r'[A-Z]', password):
        return "No uppercase letter"
    if not re.search(r'[a-z]', password):
        return "No lowercase letter"
    if not re.search(r'\d', password):
        return "No digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "No special character"
    return None

def generate_report(items, hibp_results, weakness_results):
    """Generate Markdown report of leaked and weak passwords."""
    leaked_items = [item for item, leaked in zip(items, hibp_results) if leaked]
    weak_items = [(item, reason) for item, reason in zip(items, weakness_results) if reason]
    
    report = [
        "## Bitwarden Password Security Report",
        f"**Total items checked**: {len(items)}",
        f"**Leaked passwords**: {len(leaked_items)}",
        f"**Weak passwords**: {len(weak_items)}"
    ]
    
    if leaked_items:
        report.append("\n### Leaked Passwords")
        report.extend(f"- {item['name']} (Username: {item['login'].get('username', 'N/A')})" for item in leaked_items)
    
    if weak_items:
        report.append("\n### Weak Passwords")
        report.extend(f"- {item['name']}: {reason}" for item, reason in weak_items)
    
    return "\n".join(report)

def main(export_path, output_path="password_report.md"):
    """Main workflow: load, check, and report."""
    items = load_bitwarden_export(export_path)
    passwords = [item['login']['password'] for item in items]
    
    # Check breaches
    hibp_results = [check_hibp(pwd) for pwd in passwords]
    
    # Check password strength
    weakness_results = [is_weak_password(pwd) for pwd in passwords]
    
    # Generate report
    report = generate_report(items, hibp_results, weakness_results)
    
    with open(output_path, 'w') as f:
        f.write(report)
    print(f"Report saved to {output_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python bitwarden_checker.py <bitwarden_export.json> [output.md]")
        sys.exit(1)
    export_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "password_report.md"
    main(export_path, output_path)
