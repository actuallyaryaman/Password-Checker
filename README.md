# Password-Checker
A Python script that checks passwords from a Bitwarden export for leaks and common weaknesses, then generates a security report.

## Features
- Parses Bitwarden JSON export: Only checks items with login credentials.
- Checks for leaked passwords: Uses the Have I Been Pwned (HIBP) API (k-anonymity).
- Detects weak passwords: Checks for short length and missing character types (uppercase, lowercase, digit, special).
- Generates a Markdown report: Summarizes leaked and weak passwords.

## Requirements
- Python 3.6+
- requests library (pip install requests)

## Usage
Export your Bitwarden vault as unencrypted JSON (via Web Vault → Tools → Export).

Run the script:
```bash
python bitwarden_checker.py bitwarden_export.json
```
Optionally, specify an output file:
```bash
python bitwarden_checker.py bitwarden_export.json my_report.md
```
Review the generated report:
By default, the report is saved as password_report.md.

## Example Report
```text
## Bitwarden Password Security Report
**Total items checked**: 42
**Leaked passwords**: 3
**Weak passwords**: 5

### Leaked Passwords
- Facebook (Username: user@example.com)
- Twitter (Username: handle@domain.com)
- Netflix (Username: streamer@mail.com)

### Weak Passwords
- Bank Account: Shorter than 12 characters
- Work Email: No uppercase letter
- WiFi Password: No special character
```

### Security Note
- Delete the export file after use.
- Never share or leave the export file on untrusted devices.
- For best security, use this tool on a trusted, offline machine.
