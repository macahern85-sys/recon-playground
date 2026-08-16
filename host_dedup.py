#!/usr/bin/env python3
"""Host-level fingerprint deduplication using tldextract.

Groups subdomains by root domain + response fingerprint (status|cl|title).
Within the same root domain, URLs sharing the same fingerprint are treated
as duplicates. One representative is kept; duplicates are logged to stderr.

Works with httpx output: URL [STATUS] [CL] [TITLE]

Usage:
  cat urls.txt | httpx -sc -cl -title -nc | host_dedup > unique.txt 2> groups.txt
"""
import sys
import re
from collections import defaultdict

try:
    import tldextract
except ImportError:
    print("ERROR: tldextract not installed. pip3 install tldextract", file=sys.stderr)
    sys.exit(1)

def get_root(url):
    """Extract registered domain using tldextract (handles .co.uk, .com.br etc.)."""
    host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
    ext = tldextract.extract(host)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or host

# Parse httpx output: URL [STATUS] [CL] [TITLE]
pattern = re.compile(r'^(https?://\S+)\s+\[(\d+)\]\s+\[(\d+)\](?:\s+\[([^\]]*)\])?')

# key: (root_domain, status, cl, title) → [full_lines]
groups = defaultdict(list)
urls_in_group = defaultdict(list)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    m = pattern.match(line)
    if not m:
        # Non-matching lines pass through
        print(line)
        continue
    url = m.group(1)
    status = m.group(2)
    cl = m.group(3)
    title = m.group(4) or ''

    root = get_root(url)
    key = (root, status, cl, title)
    groups[key].append(line)
    urls_in_group[key].append(url)

# Output: one representative per group
for key, lines in groups.items():
    # Print representative (first one)
    print(lines[0])

    # Log duplicates to stderr
    if len(lines) > 1:
        root, status, cl, title = key
        rep_url = urls_in_group[key][0]
        dupes = urls_in_group[key][1:]
        print(f"[DEDUP] {rep_url} represents {len(dupes)} duplicates [{status}][{cl}][{title}]:", file=sys.stderr)
        for d in dupes:
            print(f"  ↳ {d}", file=sys.stderr)
