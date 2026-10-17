#!/usr/bin/env python3
"""
WaybackScanner - Passive Web Reconnaissance
Made by Taylor Christian Newsome

Features:
  - Passive subdomain discovery via Certificate Transparency
  - Archived URL discovery via Internet Archive CDX
  - API endpoint classification across archived paths
  - Retries, timeouts, JSON export, and command-line help

Install:
  python3 -m pip install .

Usage:
  waybackscanner -h
  waybackscanner --help
  waybackscanner -d example.com
  waybackscanner -d example.com -l 5000 -o report.json

Only use on domains you own or are authorized to assess.
"""

import argparse
import json
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

VERSION = "1.0.0"
AUTHOR = "Made by Taylor Christian Newsome"
CDX_URL = "https://web.archive.org/cdx/search/cdx"
CRT_URL = "https://crt.sh/"

BANNER = r"""
       █████   ███   █████                      █████                        █████
      ░░███   ░███  ░░███                      ░░███                        ░░███
       ░███   ░███   ░███   ██████   █████ ████ ░███████   ██████    ██████  ░███ █████
       ░███   ░███   ░███  ░░░░░███ ░░███ ░███  ░███░░███ ░░░░░███  ███░░███ ░███░░███
       ░░███  █████  ███    ███████  ░███ ░███  ░███ ░███  ███████ ░███ ░░░  ░██████
        ░░░█████░█████░    ███░░███  ░███ ░███  ░███ ░███ ███░░███ ░███  ███ ░███░░███
          ░░███ ░░███     ░░████████ ░░███████  ████████ ░░████████░░██████  ████ █████
           ░░░   ░░░       ░░░░░░░░   ░░░░░███ ░░░░░░░░   ░░░░░░░░  ░░░░░░  ░░░░ ░░░░
                                      ███ ░███
                                     ░░██████
                                      ░░░░░░
  █████████                                                                             ████        █████
 ███░░░░░███                                                                           ░░███      ███░░░███
░███    ░░░   ██████   ██████   ████████   ████████    ██████  ████████     █████ █████ ░███     ███   ░░███
░░█████████  ███░░███ ░░░░░███ ░░███░░███ ░░███░░███  ███░░███░░███░░███   ░░███ ░░███  ░███    ░███    ░███
 ░░░░░░░░███░███ ░░░   ███████  ░███ ░███  ░███ ░███ ░███████  ░███ ░░░     ░███  ░███  ░███    ░███    ░███
 ███    ░███░███  ███ ███░░███  ░███ ░███  ░███ ░███ ░███░░░   ░███         ░░███ ███   ░███    ░░███   ███
░░█████████ ░░██████ ░░████████ ████ █████ ████ █████░░██████  █████         ░░█████    █████ ██ ░░░█████░
 ░░░░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░ ░░░░ ░░░░ ░░░░░  ░░░░░░  ░░░░░           ░░░░░    ░░    ░░░░░░
"""


def request_text(url, timeout=20, retries=2):
    """Fetch a public HTTP resource with bounded retries."""
    request = Request(
        url,
        headers={
            "User-Agent": "WaybackScanner/1.0 (passive security research)",
            "Accept": "application/json,text/plain,*/*",
        },
    )

    for attempt in range(retries + 1):
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")

        except HTTPError as exc:
            retryable = exc.code in (429, 500, 502, 503, 504)
            if not retryable or attempt >= retries:
                raise

            print(
                f"[!] HTTP {exc.code}; retrying "
                f"({attempt + 1}/{retries})...",
                file=sys.stderr,
            )

        except (URLError, TimeoutError) as exc:
            if attempt >= retries:
                raise

            print(
                f"[!] Network error: {exc}; retrying "
                f"({attempt + 1}/{retries})...",
                file=sys.stderr,
            )

        time.sleep(min(2 ** attempt, 8))

    raise RuntimeError("Request failed after retries")


def validate_domain(value):
    """Validate a base domain supplied by the user."""
    value = value.strip().lower().rstrip(".")

    pattern = (
        r"(?=.{1,253}$)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z]{2,63}"
    )

    if not re.fullmatch(pattern, value):
        raise argparse.ArgumentTypeError(
            "Enter a valid hostname such as example.com, not a full URL"
        )

    return value


def enumerate_subdomains(domain, timeout, retries):
    """Collect subdomains from public Certificate Transparency records."""
    hosts = {domain}

    query = CRT_URL + "?" + urlencode({
        "q": f"%.{domain}",
        "output": "json",
    })

    try:
        rows = json.loads(request_text(query, timeout, retries))

        if not isinstance(rows, list):
            raise ValueError("Unexpected certificate log response")

        for row in rows:
            if not isinstance(row, dict):
                continue

            for raw_name in row.get("name_value", "").splitlines():
                name = raw_name.strip().lower().rstrip(".")

                if name.startswith("*."):
                    name = name[2:]

                if name == domain or name.endswith("." + domain):
                    if re.fullmatch(r"[a-z0-9.-]+", name):
                        hosts.add(name)

    except (
        HTTPError,
        URLError,
        TimeoutError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        print(
            f"[!] Certificate Transparency lookup failed: {exc}",
            file=sys.stderr,
        )

    return sorted(hosts)


def fetch_archived_urls(domain, limit, timeout, retries):
    """Retrieve a bounded sample of archived URLs for a domain."""
    params = {
        "url": domain,
        "matchType": "domain",
        "output": "json",
        "fl": "original,timestamp,statuscode,mimetype",
        "collapse": "urlkey",
        "limit": str(limit),
    }

    url = CDX_URL + "?" + urlencode(params)
    data = json.loads(request_text(url, timeout, retries))

    if not isinstance(data, list) or not data:
        return []

    header = data[0]

    if not isinstance(header, list):
        raise ValueError("Unexpected CDX response header")

    records = []

    for row in data[1:]:
        if not isinstance(row, list):
            continue

        item = dict(zip(header, row))
        original = item.get("original", "")

        if original:
            records.append(item)

    return records


API_PATH = re.compile(
    r"/(?:api(?:/|$)|graphql(?:/|$)|rest(?:/|$)|"
    r"v[0-9]+(?:/|$)|openapi(?:/|$)|swagger(?:/|$))",
    re.IGNORECASE,
)


def is_api_url(url):
    """Return True if a URL contains a recognizable API path."""
    try:
        return bool(API_PATH.search(urlsplit(url).path))
    except ValueError:
        return False


def hostname_in_scope(url, domain):
    """Restrict results to the requested domain and its subdomains."""
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        return host == domain or host.endswith("." + domain)
    except ValueError:
        return False


def run(args):
    domain = args.domain

    print(BANNER)
    print(AUTHOR)
    print(f"WaybackScanner v{VERSION} | Passive reconnaissance")
    print("=" * 72)
    print(f"Target domain : {domain}")
    print(f"CDX limit     : {args.limit}")
    print()

    print("[*] Enumerating public certificate-log subdomains...")

    subdomains = set(
        enumerate_subdomains(domain, args.timeout, args.retries)
    )

    print(f"[+] Certificate-log hosts: {len(subdomains)}")
    print("[*] Querying Internet Archive CDX...")

    try:
        records = fetch_archived_urls(
            domain,
            args.limit,
            args.timeout,
            args.retries,
        )

    except (
        HTTPError,
        URLError,
        TimeoutError,
        json.JSONDecodeError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"[!] Wayback CDX query failed: {exc}", file=sys.stderr)
        print(
            "[!] A 502 may indicate a temporary upstream failure. "
            "Try again later or lower --limit.",
            file=sys.stderr,
        )
        records = []

    # Restrict archive results to the requested domain.
    records = [
        item for item in records
        if hostname_in_scope(item.get("original", ""), domain)
    ]

    # Deduplicate URLs and collect additional archived hostnames.
    unique = {}

    for item in records:
        original = item["original"]
        unique[original] = item

        host = urlsplit(original).hostname

        if host:
            subdomains.add(host.lower().rstrip("."))

    archived_urls = list(unique.values())

    api_urls = [
        item for item in archived_urls
        if is_api_url(item.get("original", ""))
    ]

    result = {
        "tool": "WaybackScanner",
        "version": VERSION,
        "author": AUTHOR,
        "domain": domain,
        "subdomains": sorted(subdomains),
        "archived_url_count": len(archived_urls),
        "api_url_count": len(api_urls),
        "api_urls": api_urls,
        "archived_urls": archived_urls,
    }

    print("\n[*] Discovered subdomains:")

    for host in sorted(subdomains):
        print(f"  {host}")

    print("\n[*] Archived API-like endpoints:")

    for item in api_urls:
        print(f"  {item['original']}")

    print("\n" + "=" * 72)
    print(f"[+] Subdomains    : {len(subdomains)}")
    print(f"[+] Archived URLs : {len(archived_urls)}")
    print(f"[+] API-like URLs : {len(api_urls)}")

    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=False)

        print(f"[+] JSON report   : {args.output}")

    except OSError as exc:
        print(f"[!] Cannot write report: {exc}", file=sys.stderr)
        return 1

    print("[+] Finished. Passive sources only.")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="waybackscanner",
        description=(
            "Passive subdomain discovery and archived API URL enumeration."
        ),
        epilog=(
            "Example: waybackscanner --domain example.com "
            "--limit 500 --output report.json"
        ),
    )

    parser.add_argument(
        "-d",
        "--domain",
        type=validate_domain,
        default="tryhackme.com",
        help="Base domain to investigate (default: tryhackme.com)",
    )

    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=1000,
        help="Maximum CDX records requested (default: 1000)",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=20,
        help="HTTP timeout in seconds (default: 20)",
    )

    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=2,
        help="Retries for transient errors (default: 2)",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="waybackscanner-report.json",
        help="JSON report path",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1")

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    if args.retries < 0:
        parser.error("--retries cannot be negative")

    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

python
# setup.py
from setuptools import setup

setup(
    name="waybackscanner",
    version="1.0.0",
    description="Passive Wayback archive and subdomain reconnaissance",
    py_modules=["waybackscanner"],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "waybackscanner=waybackscanner:main",
        ],
    },
)
