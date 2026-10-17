# WaybackScanner

**Passive Web Reconnaissance Tool**  
Made by Taylor Christian Newsome

WaybackScanner performs passive subdomain discovery and archived URL enumeration using publicly available sources only (Certificate Transparency logs and the Internet Archive CDX API).

## Features

- Passive subdomain enumeration via Certificate Transparency (`crt.sh`)
- Archived URL discovery from the Internet Archive CDX API
- Automatic classification of API-like endpoints (`/api`, `/graphql`, `/rest`, versioned paths, OpenAPI/Swagger, etc.)
- Configurable timeouts, retries, and result limits
- Clean JSON report export
- Proper CLI with help and version support

## Installation

```bash
python3 -m pip install .
```

Or install in editable mode during development:

```bash
python3 -m pip install -e .
```

## Usage

```bash
waybackscanner -h
waybackscanner --help
waybackscanner -d example.com
waybackscanner -d example.com -l 5000 -o report.json
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d`, `--domain` | Target base domain (required) | — |
| `-l`, `--limit` | Maximum CDX records to request | `1000` |
| `-t`, `--timeout` | HTTP timeout in seconds | `20` |
| `-r`, `--retries` | Number of retries on transient errors | `2` |
| `-o`, `--output` | Path for the JSON report | `waybackscanner-report.json` |
| `--version` | Show version and exit | — |

## Example Output

```
[*] Enumerating public certificate-log subdomains...
[+] Certificate-log hosts: 42

[*] Querying Internet Archive CDX...

[*] Discovered subdomains:
  example.com
  api.example.com
  staging.example.com
  ...

[*] Archived API-like endpoints:
  https://api.example.com/v1/users
  https://example.com/graphql
  ...

[+] Subdomains    : 42
[+] Archived URLs : 1873
[+] API-like URLs : 29
[+] JSON report   : report.json
[+] Finished. Passive sources only.
```

## Legal Notice

**Only use this tool on domains you own or have explicit written authorization to assess.**  
This tool is intended for legitimate security research, bug bounty programs, and authorized penetration testing. Unauthorized scanning may violate laws and terms of service.

## Author

Taylor Christian Newsome  
GitHub: [SleepTheGod](https://github.com/SleepTheGod)

## License

MIT
