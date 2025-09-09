#!/usr/bin/env python3
"""ReconJS: JavaScript Recon Automation Tool (cleaned)
A compact single-file tool to crawl pages, collect JS files and scan for secrets/endpoints.
"""

from __future__ import annotations
import argparse
import concurrent.futures
import fnmatch
import json
import re
import time
from html import escape
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

try:
    from jinja2 import Template
except Exception:
    Template = None

REGEX_PATTERNS = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_access_key": re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "jwt": re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+/]+=*"),
    "api_path": re.compile(r"(?:/|\")([A-Za-z0-9_\-\./]{2,})(?:\"|\\n|\s)"),
    "url_literal": re.compile(r"https?://[A-Za-z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]+"),
    "token_pair": re.compile(r"(?:token|api_key|apikey|secret|access_token|client_secret)\s*["'`:=\s]{1,4}\s*[\"'`]([A-Za-z0-9\-\._~\+/=]{8,})[\"'`]")
}

API_KEYWORDS = ["/api", "api/", "graphql", "auth", "login", "v1", "/v2/"]

session = requests.Session()
session.headers.update({"User-Agent": "ReconJS/1.0 (+https://github.com/your/reconjs)"})


def is_url_in_scope(url: str, scope_patterns: list[str]) -> bool:
    if not scope_patterns:
        return True
    parsed = urlparse(url)
    host_and_path = parsed.netloc + parsed.path
    for p in scope_patterns:
        if fnmatch.fnmatch(host_and_path, p) or fnmatch.fnmatch(parsed.netloc, p):
            return True
    return False


def normalize_url(base: str, link: str) -> str | None:
    try:
        return urljoin(base, link)
    except Exception:
        return None


def fetch_url(url: str, timeout: int = 10) -> tuple[int, str] | None:
    try:
        r = session.get(url, timeout=timeout)
        return r.status_code, r.text
    except Exception:
        return None


def parse_html_for_js_links(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    js_links = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            full = normalize_url(base_url, src)
            if full:
                js_links.append(full)
    for tag in soup.find_all("link"):
        rel = tag.get("rel")
        if rel and ("preload" in rel or "prefetch" in rel):
            href = tag.get("href")
            if href:
                full = normalize_url(base_url, href)
                if full:
                    js_links.append(full)
    for a in soup.find_all("a", href=True):
        link = normalize_url(base_url, a["href"])
        if link:
            js_links.append(link)
    return list(dict.fromkeys(js_links))


def find_js_links_in_text(base_url: str, text: str) -> list[str]:
    candidates = set()
    for m in re.findall(r"[\'\"]([^\'\"]+\.js(?:\?[^\'\"]*)?)[\'\"]", text):
        full = normalize_url(base_url, m)
        if full:
            candidates.add(full)
    return list(candidates)


def scan_js_for_patterns(js_url: str, js_text: str) -> list[dict]:
    findings = []
    for name, pattern in REGEX_PATTERNS.items():
        for match in pattern.finditer(js_text):
            snippet = js_text[max(0, match.start() - 60): match.end() + 60]
            findings.append({
                "type": name,
                "match": match.group(0),
                "snippet": snippet.replace('\n', '\\n')[:500],
                "url": js_url,
            })
    for m in re.finditer(r"[\'\"](/[^\'\"]{3,200})[\'\"]", js_text):
        candidate = m.group(1)
        if any(k in candidate.lower() for k in API_KEYWORDS):
            findings.append({
                "type": "internal_api_path",
                "match": candidate,
                "snippet": js_text[max(0, m.start() - 60): m.end() + 60].replace('\n', '\\n')[:500],
                "url": js_url,
            })
    return findings


def crawl(start_url: str, depth: int, scope: list[str], max_workers: int = 10, passive: bool = False):
    visited_pages = set()
    discovered_js = set()
    to_crawl = [(start_url, 0)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {}
        pbar = tqdm(total=1, desc="Crawling", unit="page")

        while to_crawl or futures:
            while to_crawl and len(futures) < max_workers:
                url, d = to_crawl.pop(0)
                if url in visited_pages or d > depth:
                    continue
                visited_pages.add(url)
                futures[ex.submit(fetch_url, url)] = (url, d)
            done, _ = concurrent.futures.wait(futures.keys(), timeout=0.1, return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in list(done):
                url, d = futures.pop(fut)
                res = fut.result()
                pbar.update(1)
                if not res:
                    continue
                status, text = res
                try:
                    js_links = parse_html_for_js_links(url, text)
                except Exception:
                    js_links = []
                js_links += find_js_links_in_text(url, text)

                for js in js_links:
                    if is_url_in_scope(js, scope):
                        discovered_js.add(js)
                if d < depth:
                    soup = BeautifulSoup(text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        link = normalize_url(url, a["href"])
                        if not link:
                            continue
                        if is_url_in_scope(link, scope) and link not in visited_pages:
                            to_crawl.append((link, d + 1))
            if not futures and to_crawl:
                continue
            if discovered_js:
                js_list = list(discovered_js)
                discovered_js.clear()
                for js_url in js_list:
                    futures[ex.submit(fetch_url, js_url)] = (js_url, 0)

        pbar.close()

    results = {"crawled_pages": list(visited_pages), "js_files": [], "findings": []}
    js_urls = set()
    for page in tqdm(sorted(visited_pages), desc="Harvesting JS links", unit="page"):
        res = fetch_url(page)
        if not res:
            continue
        _, text = res
        js_urls.update(parse_html_for_js_links(page, text))
        js_urls.update(find_js_links_in_text(page, text))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(fetch_url, u): u for u in js_urls}
        for fut in tqdm(concurrent.futures.as_completed(futs), total=len(futs), desc="Downloading JS"):
            url = futs[fut]
            res = fut.result()
            if not res:
                continue
            _, js_text = res
            results["js_files"].append(url)
            items = scan_js_for_patterns(url, js_text)
            results["findings"].extend(items)

    return results

HTML_TMPL = """
<html>
<head>
  <meta charset="utf-8" />
  <title>ReconJS report</title>
  <style>
    body{font-family: sans-serif;margin:20px}
    .card{border:1px solid #ddd;padding:10px;margin:8px;border-radius:6px}
    pre{white-space:pre-wrap}
  </style>
</head>
<body>
  <h1>ReconJS report</h1>
  <h2>Summary</h2>
  <ul>
    <li>Crawled pages: {{ crawled }}</li>
    <li>JS files discovered: {{ js_count }}</li>
    <li>Findings: {{ findings_count }}</li>
  </ul>
  <h2>Findings</h2>
  {% for f in findings %}
  <div class="card">
    <strong>{{ f.type }}</strong> — <em>{{ f.url }}</em>
    <pre>{{ f.match }}\n\n{{ f.snippet }}</pre>
  </div>
  {% endfor %}
</body>
</html>
"""


def write_reports(results: dict, json_path: str | None, html_path: str | None):
    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    if html_path:
        if Template:
            tpl = Template(HTML_TMPL)
            out = tpl.render(crawled=len(results.get("crawled_pages", [])), js_count=len(results.get("js_files", [])), findings_count=len(results.get("findings", [])), findings=results.get("findings", []))
        else:
            out = HTML_TMPL.replace("{{ crawled }}", str(len(results.get("crawled_pages", [])))).replace("{{ js_count }}", str(len(results.get("js_files", [])))).replace("{{ findings_count }}", str(len(results.get("findings", [])))).replace("{% for f in findings %}", "").replace("{% endfor %}", "")
            items_html = []
            for f in results.get("findings", []):
                items_html.append(f"<div class=\"card\"><strong>{escape(f.get('type',''))}</strong> — <em>{escape(f.get('url',''))}</em><pre>{escape(f.get('match',''))}\n\n{escape(f.get('snippet',''))}</pre></div>")
            out = out + "\n".join(items_html)
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(out)


def build_argparser():
    p = argparse.ArgumentParser(description="ReconJS - JavaScript Recon Automation Tool")
    p.add_argument("start", help="Start URL to crawl (e.g. https://example.com)")
    p.add_argument("--depth", type=int, default=1, help="Crawling depth (default 1)")
    p.add_argument("--scope", action="append", default=[], help="Scope glob pattern (can repeat). Example: example.com or *.example.com/*")
    p.add_argument("--passive", action="store_true", help="Passive mode: only collect JS links and metadata, no aggressive probing")
    p.add_argument("--max-workers", type=int, default=10, help="Concurrency for fetching")
    p.add_argument("--output-json", help="Write JSON report to file")
    p.add_argument("--output-html", help="Write HTML report to file")
    p.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification (not recommended)")
    return p


def main():
    args = build_argparser().parse_args()
    start = args.start
    if args.no_verify_ssl:
        session.verify = False
    if not start.startswith("http"):
        start = "http://" + start
    print(f"Starting ReconJS on {start} (depth={args.depth})")
    start_time = time.time()
    results = crawl(start, depth=args.depth, scope=args.scope, max_workers=args.max_workers, passive=args.passive)
    elapsed = time.time() - start_time
    print(f"Done: found {len(results.get('js_files', []))} JS files and {len(results.get('findings', []))} findings in {elapsed:.1f}s")
    write_reports(results, args.output_json, args.output_html)
    if args.output_json:
        print(f"JSON report written to {args.output_json}")
    if args.output_html:
        print(f"HTML report written to {args.output_html}")


if __name__ == '__main__':
    main()
