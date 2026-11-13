

A command-line phishing email analyzer for SOC analysts. Point it at a suspicious `.eml` file and get a risk score, a list of the red flags it found, and a defanged IOC list ready for threat-intel lookups.

No API keys. No dependencies. Python standard library only, so it runs on locked-down analyst machines and can be audited in minutes.

## What it checks

| Area | Checks |
|------|--------|
| **Headers** | From vs Reply-To vs Return-Path domain mismatches, display-name spoofing, punycode (lookalike) sender domains |
| **Authentication** | SPF, DKIM and DMARC results (fail, softfail, none, or missing entirely) |
| **Routing** | Extracts the originating public IP from the `Received` chain |
| **Links** | Link text vs real destination mismatch, raw-IP URLs, URL shorteners, punycode hosts, `@` obfuscation |
| **Attachments** | Risky file types, double extensions (`invoice.pdf.exe`), SHA-256 hashes |
| **Content** | Urgency and pressure phrases in subject and body |

## Installation

```bash
git clone https://github.com/<your-username>/phish-check.git
cd phish-check
python3 phish_check.py sample_phish.eml
```

Requires Python 3.8+. Nothing to `pip install`.

## Usage

```bash
# Basic analysis
python phish_check.py suspicious.eml

# Save a JSON report and a defanged IOC list
python phish_check.py suspicious.eml --json report.json --iocs iocs.txt
```

| Flag | Description |
|------|-------------|
| `eml` | Path to the `.eml` file |
| `--json PATH` | Write the full report as JSON |
| `--iocs PATH` | Write defanged URLs, domains, IPs and attachment hashes, one per line |

**Exit codes:** `0` for LOW/MEDIUM, `2` for HIGH. Handy for SOAR playbooks and scripts.

### Getting an `.eml` file
- **Outlook:** drag the message to your desktop, or *File → Save As → .eml* (use "Report as attachment" to preserve headers)
- **Gmail:** open the message → ⋮ → *Download message*
- **Thunderbird:** right-click → *Save As*

## Example output

```
Risk score  : 100/100  ->  HIGH

Findings:
  [+30] Attachment Risky attachment type: invoice.pdf.exe
  [+25] Spoofing   Display name contains a different email address (billing@paypal.com)
  [+25] Link       Link text shows 'www.paypal.com' but points to 'paypa1-secure.example'
  [+20] Link       URL uses a raw IP address: http://203.0.113.45/login
  [+20] Auth       SPF result: fail
  ...
```

The included `sample_phish.eml` is a harmless demo built with reserved `.example` domains.

## Scoring

Each finding adds points (capped at 100):

| Score | Verdict |
|-------|---------|
| 0-29 | LOW |
| 30-59 | MEDIUM |
| 60-100 | HIGH |

Point values are set where each check is raised in `phish_check.py`, so you can tune them for your environment.

## Pairs well with IOCcheck

The `--iocs` file is defanged, which the companion VirusTotal tool understands directly:

```bash
python phish_check.py suspicious.eml --iocs iocs.txt
python vt_triage.py -f iocs.txt --csv results.csv
```

## Safety and limitations

- **It never opens links or runs attachments.** Everything is static analysis of the raw message. Still, handle real samples in an isolated environment.
- A LOW score does not mean an email is safe. Well-crafted business email compromise (BEC) messages often have clean headers and no links.
- Authentication results come from the headers your own mail gateway added. Headers in a forwarded or re-saved message may be incomplete.
- The registrable-domain check is simplified and may mis-handle unusual country-code suffixes.
- Never commit real phishing emails to a public repo. They contain recipient data. `.gitignore` excludes `*.eml` except the sample.

