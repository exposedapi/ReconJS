# ReconJS

ReconJS is a lightweight Python prototype that automates discovery and scanning of JavaScript files during bug-bounty recon. It crawls target pages, harvests JavaScript links, and scans JS content with regexes to find potential endpoints, API paths, and secrets (API keys, JWTs, bearer tokens, etc.).

> **Important:** Use only on targets you are authorized to test (bug bounty programs, your own assets, or explicit written permission).

## Features

* Recursive crawler with configurable depth and scope filtering (glob patterns)
* JS link harvesting from `<script>` tags, `<link>` preloads and inline text
* Regex-based scanning for AWS keys, JWTs, bearer tokens, API paths and more
* Threaded fetching with progress bars (tqdm)
* CLI interface
* JSON and HTML report output (optional Jinja2 templating)

## Installation

1. Clone or download the repository and change into its directory.

2. Create and activate a virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate   # macOS / Linux
.venv\Scripts\activate     # Windows (PowerShell)
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic example:

```bash
python reconjs_clean.py https://example.com --depth 1 --scope example.com --output-json report.json --output-html report.html
```

Common flags:

* `start` (positional): start URL to crawl (e.g. `https://example.com`)
* `--depth`: crawling depth (default: 1)
* `--scope`: repeatable glob pattern(s) to restrict scope (example: `example.com` or `*.example.com/*`)
* `--passive`: only harvest links and metadata (no active probing)
* `--max-workers`: concurrency for fetching (default: 10)
* `--output-json`: path to write JSON report
* `--output-html`: path to write HTML report
* `--no-verify-ssl`: disable SSL verification (not recommended)

### Example with scope and deeper crawl

```bash
python reconjs_clean.py https://target.example.com --depth 2 --scope target.example.com --output-json findings.json
```

## Output

* JSON (`--output-json`) contains `crawled_pages`, `js_files`, and `findings` with details.
* HTML (`--output-html`) is a simple human-readable report (requires `jinja2` for templating; a fallback exists).

## Notes & Next Steps

* This is a prototype; for large-scale scanning consider switching to an async HTTP client (e.g. `aiohttp`) and adding caching, rate-limiting, robots.txt parsing and error handling.
* Add more detectors (Slack tokens, Google API keys, etc.) and allow custom regex rules via a config file.

## License

MIT

## Acknowledgements

Built for responsible recon and bug bounty work. Use ethically.
