#!/usr/bin/env python3
"""
phish_check.py - Triage a suspicious email (.eml) for phishing indicators.

Parses headers, authentication results, links and attachments, then produces
a risk score, a list of findings and a defanged IOC list. Standard library only.
"""

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at"}
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".vbe", ".jse", ".bat", ".cmd", ".ps1",
                    ".lnk", ".hta", ".iso", ".img", ".jar", ".msi", ".dll", ".wsf",
                    ".docm", ".xlsm", ".pptm", ".html", ".htm", ".svg", ".one"}
DOC_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}
URGENCY_WORDS = ["urgent", "immediately", "action required", "verify your account",
                 "suspended", "password expires", "unusual activity", "confirm your",
                 "within 24 hours", "final notice", "invoice attached", "payment overdue"]
SECOND_LEVEL = {"co", "com", "org", "gov", "ac", "net", "edu"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def reg_domain(domain: str) -> str:
    """Rough registrable domain (handles common co.uk-style suffixes)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def addr_domain(header_value: str) -> str:
    addr = parseaddr(header_value or "")[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""


def defang(text: str) -> str:
    return re.sub(r"^http", "hxxp", text, flags=re.IGNORECASE).replace(".", "[.]")


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
    except ValueError:
        return False


class AnchorParser(HTMLParser):
    """Collect (href, visible text) pairs from HTML bodies."""
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
class Report:
    def __init__(self):
        self.findings = []   # (points, category, description)
        self.iocs = {"urls": set(), "domains": set(), "ips": set(), "hashes": set()}
        self.info = {}

    def flag(self, points, category, description):
        self.findings.append((points, category, description))

    @property
    def score(self):
        return min(100, sum(p for p, _, _ in self.findings))

    @property
    def verdict(self):
        return "HIGH" if self.score >= 60 else "MEDIUM" if self.score >= 30 else "LOW"


def analyse_headers(msg, rpt: Report):
    from_hdr = msg.get("From", "")
    display, from_addr = parseaddr(from_hdr)
    from_dom = addr_domain(from_hdr)
    reply_dom = addr_domain(msg.get("Reply-To", ""))
    return_dom = addr_domain(msg.get("Return-Path", ""))

    rpt.info.update({
        "from": from_hdr, "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""), "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""), "message_id": msg.get("Message-ID", ""),
    })
    if from_dom:
        rpt.iocs["domains"].add(from_dom)

    if reply_dom and from_dom and reg_domain(reply_dom) != reg_domain(from_dom):
        rpt.flag(20, "Header", f"Reply-To domain ({reply_dom}) differs from From domain ({from_dom})")
        rpt.iocs["domains"].add(reply_dom)
    if return_dom and from_dom and reg_domain(return_dom) != reg_domain(from_dom):
        rpt.flag(10, "Header", f"Return-Path domain ({return_dom}) differs from From domain ({from_dom})")
        rpt.iocs["domains"].add(return_dom)

    # Display name pretending to be an email address or a different brand domain
    m = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", display or "")
    if m and m.group(0).lower() != from_addr.lower():
        rpt.flag(25, "Spoofing", f"Display name contains a different email address ({m.group(0)})")
    if from_dom.startswith("xn--") or ".xn--" in from_dom:
        rpt.flag(20, "Spoofing", f"Sender domain uses punycode (possible homoglyph attack): {from_dom}")

    # Authentication results
    auth_text = " ".join(msg.get_all("Authentication-Results", []) + msg.get_all("Received-SPF", []))
    results = {k.lower(): v.lower() for k, v in AUTH_RE.findall(auth_text)}
    rpt.info["auth"] = results
    if not results:
        rpt.flag(10, "Auth", "No SPF/DKIM/DMARC results found in headers")
    for mech in ("spf", "dkim", "dmarc"):
        val = results.get(mech)
        if val in ("fail", "softfail", "permerror", "temperror"):
            rpt.flag(20 if val == "fail" else 10, "Auth", f"{mech.upper()} result: {val}")
        elif val in ("none", "neutral"):
            rpt.flag(5, "Auth", f"{mech.upper()} result: {val}")

    # Originating IP: bottom-most Received header with a public address
    for hop in reversed(msg.get_all("Received", [])):
        ips = [ip for ip in IPV4_RE.findall(hop) if is_public_ip(ip)]
        if ips:
            rpt.info["origin_ip"] = ips[0]
            rpt.iocs["ips"].add(ips[0])
            break

    subject = (msg.get("Subject", "") or "").lower()
    hits = [w for w in URGENCY_WORDS if w in subject]
    if hits:
        rpt.flag(10, "Content", f"Urgency language in subject: {', '.join(hits)}")


def analyse_body(msg, rpt: Report):
    text_parts, html_parts = [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        try:
            if ctype == "text/plain":
                text_parts.append(part.get_content())
            elif ctype == "text/html":
                html_parts.append(part.get_content())
        except (LookupError, UnicodeDecodeError):
            continue

    body = "\n".join(text_parts + html_parts)
    hits = [w for w in URGENCY_WORDS if w in body.lower()]
    if len(hits) >= 2:
        rpt.flag(10, "Content", f"Multiple pressure phrases in body: {', '.join(hits[:4])}")

    urls = set(URL_RE.findall(body))
    for html in html_parts:
        parser = AnchorParser()
        parser.feed(html)
        for href, text in parser.links:
            if not href.lower().startswith("http"):
                continue
            urls.add(href)
            # Visible text looks like a URL/domain that doesn't match the real target
            shown = re.search(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", text)
            real = urlparse(href).hostname or ""
            if shown and real and reg_domain(shown.group(1)) != reg_domain(real):
                rpt.flag(25, "Link", f"Link text shows '{shown.group(1)}' but points to '{real}'")

    for url in urls:
        rpt.iocs["urls"].add(url)
        host = (urlparse(url).hostname or "").lower()
        is_ip_host = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
        if host and not is_ip_host:
            rpt.iocs["domains"].add(host)
        if is_ip_host:
            rpt.flag(20, "Link", f"URL uses a raw IP address: {url[:80]}")
            rpt.iocs["ips"].add(host)
        if host in SHORTENERS:
            rpt.flag(10, "Link", f"URL shortener used: {host}")
        if host.startswith("xn--") or ".xn--" in host:
            rpt.flag(15, "Link", f"Punycode domain in link: {host}")
        if "@" in urlparse(url).netloc:
            rpt.flag(15, "Link", f"URL contains '@' (credential-style obfuscation): {url[:80]}")
    rpt.info["url_count"] = len(urls)


def analyse_attachments(msg, rpt: Report):
    attachments = []
    for part in msg.iter_attachments():
        name = part.get_filename() or "(unnamed)"
        payload = part.get_payload(decode=True)
        if payload is None:   # e.g. nested message/rfc822
            payload = part.as_bytes()
        sha256 = hashlib.sha256(payload).hexdigest()
        attachments.append({"name": name, "size": len(payload), "sha256": sha256,
                            "type": part.get_content_type()})
        rpt.iocs["hashes"].add(sha256)

        parts = name.lower().split(".")
        ext = "." + parts[-1] if len(parts) > 1 else ""
        if ext in RISKY_EXTENSIONS:
            rpt.flag(30, "Attachment", f"Risky attachment type: {name}")
        if len(parts) > 2 and ("." + parts[-2]) in DOC_EXTENSIONS and ext in RISKY_EXTENSIONS:
            rpt.flag(20, "Attachment", f"Double extension disguise: {name}")
    rpt.info["attachments"] = attachments


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_report(path: str, rpt: Report):
    colours = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
    colour = colours[rpt.verdict] if sys.stdout.isatty() else ""
    reset = "\033[0m" if colour else ""
    print(f"\n=== PhishCheck: {path} ===")
    for label, key in (("From", "from"), ("Reply-To", "reply_to"), ("Return-Path", "return_path"),
                       ("Subject", "subject"), ("Date", "date")):
        print(f"{label:<12}: {rpt.info.get(key) or '-'}")
    print(f"{'Auth':<12}: {rpt.info.get('auth') or 'none found'}")
    print(f"{'Origin IP':<12}: {rpt.info.get('origin_ip', 'unknown')}")
    print(f"{'URLs':<12}: {rpt.info.get('url_count', 0)}")
    for a in rpt.info.get("attachments", []):
        print(f"{'Attachment':<12}: {a['name']} ({a['size']} bytes) sha256={a['sha256'][:16]}...")
    print(f"\nRisk score  : {rpt.score}/100  ->  {colour}{rpt.verdict}{reset}\n")
    if rpt.findings:
        print("Findings:")
        for pts, cat, desc in sorted(rpt.findings, reverse=True):
            print(f"  [+{pts:<2}] {cat:<10} {desc}")
    else:
        print("No indicators found.")
    print()


def main():
    p = argparse.ArgumentParser(description="Analyse a suspicious .eml file for phishing indicators.")
    p.add_argument("eml", help="Path to the .eml file")
    p.add_argument("--json", dest="json_out", help="Write the full report as JSON")
    p.add_argument("--iocs", help="Write defanged IOCs (one per line) to a file")
    args = p.parse_args()

    try:
        with open(args.eml, "rb") as fh:
            msg = BytesParser(policy=policy.default).parse(fh)
    except OSError as exc:
        sys.exit(f"[!] Cannot read {args.eml}: {exc}")

    rpt = Report()
    analyse_headers(msg, rpt)
    analyse_body(msg, rpt)
    analyse_attachments(msg, rpt)
    print_report(args.eml, rpt)

    if args.iocs:
        lines = sorted(defang(u) for u in rpt.iocs["urls"]) + \
                sorted(defang(d) for d in rpt.iocs["domains"]) + \
                sorted(defang(i) for i in rpt.iocs["ips"]) + sorted(rpt.iocs["hashes"])
        with open(args.iocs, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"[*] {len(lines)} IOC(s) written to {args.iocs}")

    if args.json_out:
        out = {"file": args.eml, "score": rpt.score, "verdict": rpt.verdict, "info": rpt.info,
               "findings": [{"points": p, "category": c, "description": d} for p, c, d in rpt.findings],
               "iocs": {k: sorted(v) for k, v in rpt.iocs.items()}}
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"[*] JSON report written to {args.json_out}")

    sys.exit(2 if rpt.verdict == "HIGH" else 0)


if __name__ == "__main__":
    main()
