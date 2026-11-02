# portscout

A small, dependency-free **async TCP port scanner** with **banner grabbing** and JSON/CSV/table output. Built on Python's `asyncio`, so scanning a few thousand ports takes seconds.

> **Use responsibly.** Only scan hosts you own or have explicit written permission to test. Unauthorized scanning may be illegal.

## Features

- Fast full-connect scanning with a configurable concurrency limit
- Banner grabbing (SSH, FTP, SMTP, etc. announce on connect; HTTP ports get a harmless `HEAD /`)
- Open / closed / filtered detection
- Common service-name lookup
- Output as a readable table, JSON, or CSV (to stdout or a file)
- Standard library only, Python 3.9+

## Install

```bash
git clone https://github.com/<your-username>/portscout.git
cd portscout
pip install .
```

Or run without installing:

```bash
python -m portscout 127.0.0.1
```

## Usage

```bash
# Scan the default range (1-1024) on localhost
portscout 127.0.0.1

# Specific ports and ranges
portscout scanme.nmap.org -p 22,80,443,8000-8100

# JSON output saved to a file
portscout 192.168.1.10 -p 1-65535 -c 500 -f json -o results.json

# CSV without banner grabbing, include closed/filtered ports
portscout 10.0.0.5 --no-banner --show-all -f csv
```

Example output:

```
PORT  STATE  SERVICE  BANNER
----  -----  -------  --------------------
22    open   ssh      SSH-2.0-OpenSSH_9.6
80    open   http     HTTP/1.0 200 OK
```

### Options

| Option | Description | Default |
| --- | --- | --- |
| `-p, --ports` | Ports to scan (`22,80`, `1-1024`) | `1-1024` |
| `-t, --timeout` | Connect/banner timeout in seconds | `1.0` |
| `-c, --concurrency` | Max simultaneous connections | `200` |
| `--no-banner` | Skip banner grabbing | off |
| `--show-all` | Include closed and filtered ports | off |
| `-f, --format` | `table`, `json` or `csv` | `table` |
| `-o, --output` | Write to a file instead of stdout | stdout |

Exit codes: `0` success, `2` invalid input (bad ports, unresolvable host), `130` interrupted.

## Use as a library

```python
import asyncio
from portscout import scan, parse_ports

results = asyncio.run(scan("127.0.0.1", parse_ports("20-100")))
for r in results:
    if r.state == "open":
        print(r.port, r.service, r.banner)
```

## Development

```bash
python -m unittest discover -s tests -v
```

Tests spin up local servers on `127.0.0.1`, so they need no network access.

## Ideas for next steps

- UDP scanning
- Service/version fingerprinting beyond raw banners
- CIDR range and multi-target support
- Progress bar and rate limiting

## License

MIT, see [LICENSE](LICENSE).
