#!/bin/bash
# HubSpot Bug Bounty — Passive Recon Script
# Run this FIRST before touching the app
# Usage: chmod +x hubspot-recon.sh && ./hubspot-recon.sh

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

WORKDIR="$HOME/hubspot-bounty/recon"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo -e "${GREEN}[*] HubSpot Passive Recon — Starting${NC}"
echo -e "${YELLOW}[!] Optimized for 8GB RAM — tools run sequentially${NC}"
echo "============================================"
echo ""

# ──────────────────────────────────────────────
# STEP 1: Subdomain Enumeration (subfinder only — low RAM)
# ──────────────────────────────────────────────
echo -e "${YELLOW}[1/6] Subdomain enumeration (subfinder)...${NC}"

DOMAINS="hubspot.com hubapi.com hs-sites.com hubspotpagebuilder.com hubspotemail.net chatspot.ai"

for d in $DOMAINS; do
    echo "  [+] subfinder: $d"
    subfinder -d "$d" -silent >> subs-raw.txt 2>/dev/null || echo "  [-] subfinder failed for $d"
    sleep 2  # breathing room between runs
done

# NOTE: amass skipped by default (uses 500MB-1GB RAM)
# Uncomment below if you want to run it AFTER subfinder finishes:
# echo -e "${YELLOW}  [+] Running amass (heavy — close other apps)...${NC}"
# for d in hubspot.com hubapi.com; do
#     timeout 300 amass enum -passive -d "$d" >> subs-raw.txt 2>/dev/null || echo "  [-] amass timeout for $d"
# done

sort -u subs-raw.txt > all-subdomains.txt
TOTAL=$(wc -l < all-subdomains.txt)
echo -e "${GREEN}  [✓] Total unique subdomains: $TOTAL${NC}"
echo ""

# ──────────────────────────────────────────────
# STEP 2: Filter to in-scope
# ──────────────────────────────────────────────
echo -e "${YELLOW}[2/6] Filtering to in-scope targets...${NC}"

grep -E '(\.hs-sites\.com|\.hs-sites-eu1\.com|\.hubspotemail\.net|\.hubspotpagebuilder\.(com|eu)|^api.*\.(hubapi|hubspot)\.com|^app.*\.hubspot\.com|chatspot\.ai)' all-subdomains.txt 2>/dev/null > in-scope-filtered.txt || true

# Remove out-of-scope
grep -v -E '(events\.hubspot\.com|ir\.hubspot\.com|shop\.hubspot\.com|thespot\.hubspot\.com|trust\.hubspot\.com|connect\.com)' in-scope-filtered.txt > in-scope.txt 2>/dev/null || true

# Also keep ALL hubspot.com subdomains for reference (many endpoints are unlisted but still in scope)
grep '\.hubspot\.com' all-subdomains.txt | grep -v -E '(events|ir|shop|thespot|trust)\.' > hubspot-all-subs.txt 2>/dev/null || true

INSCOPE=$(wc -l < in-scope.txt)
echo -e "${GREEN}  [✓] In-scope subdomains: $INSCOPE${NC}"
echo ""

# ──────────────────────────────────────────────
# STEP 3: Probe live hosts
# ──────────────────────────────────────────────
echo -e "${YELLOW}[3/6] Probing live hosts...${NC}"

if command -v httpx &>/dev/null; then
    cat in-scope.txt | httpx -silent -sc -title -tech-detect -follow-redirects -o live-hosts-full.txt 2>/dev/null
    cat live-hosts-full.txt | awk '{print $1}' > live-urls.txt
    LIVE=$(wc -l < live-urls.txt)
    echo -e "${GREEN}  [✓] Live hosts: $LIVE${NC}"
else
    echo -e "${RED}  [-] httpx not installed — skipping. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
fi
echo ""

# ──────────────────────────────────────────────
# STEP 4: Historical URL discovery
# ──────────────────────────────────────────────
echo -e "${YELLOW}[4/6] Gathering historical URLs...${NC}"

for d in hubspot.com hubapi.com chatspot.ai; do
    echo "  [+] waybackurls: $d"
    echo "$d" | waybackurls >> historical-raw.txt 2>/dev/null || echo "  [-] waybackurls failed for $d"
done

if command -v gau &>/dev/null; then
    for d in hubspot.com hubapi.com chatspot.ai; do
        echo "  [+] gau: $d"
        echo "$d" | gau --threads 3 >> historical-raw.txt 2>/dev/null || echo "  [-] gau failed for $d"
    done
fi

sort -u historical-raw.txt > historical-urls.txt 2>/dev/null || true
HIST=$(wc -l < historical-urls.txt 2>/dev/null || echo 0)
echo -e "${GREEN}  [✓] Historical URLs: $HIST${NC}"
echo ""

# ──────────────────────────────────────────────
# STEP 5: Extract interesting patterns
# ──────────────────────────────────────────────
echo -e "${YELLOW}[5/6] Extracting interesting patterns...${NC}"

# Parameters (most common)
grep -oP '[\?&]\K[^=]+' historical-urls.txt 2>/dev/null | sort | uniq -c | sort -rn | head -60 > top-params.txt || true
echo "  [✓] Top parameters → top-params.txt"

# API routes
grep -iE '/api/|/v[0-9]+/|/graphql|/rest/|/rpc/' historical-urls.txt 2>/dev/null | sort -u > api-routes.txt || true
echo "  [✓] API routes → api-routes.txt ($(wc -l < api-routes.txt 2>/dev/null || echo 0))"

# JavaScript files
grep -iE '\.js(\?|$)' historical-urls.txt 2>/dev/null | grep -v '\.json' | sort -u > js-files.txt || true
echo "  [✓] JS files → js-files.txt ($(wc -l < js-files.txt 2>/dev/null || echo 0))"

# Potentially sensitive files
grep -iE '\.(json|xml|yaml|yml|conf|config|env|bak|old|sql|log|csv|xls|pdf|zip|tar|gz)(\?|$)' historical-urls.txt 2>/dev/null | sort -u > sensitive-files.txt || true
echo "  [✓] Sensitive files → sensitive-files.txt ($(wc -l < sensitive-files.txt 2>/dev/null || echo 0))"

# Endpoints with ID-like parameters (IDOR candidates)
grep -iE '(id|Id|ID)=' historical-urls.txt 2>/dev/null | sort -u > id-params.txt || true
echo "  [✓] ID parameters → id-params.txt ($(wc -l < id-params.txt 2>/dev/null || echo 0))"

# URL/redirect parameters (SSRF candidates)
grep -iE '(url|redirect|next|dest|src|source|link|callback|return|goto|target|uri|path|continue|window|data|reference|site|html|val|validate|domain|feed|host|port|to|out|view|dir|show|navigation|open|file|document|folder|pg|php_path|style|img|doc|fetch|proxy)=' historical-urls.txt 2>/dev/null | sort -u > ssrf-candidates.txt || true
echo "  [✓] SSRF candidates → ssrf-candidates.txt ($(wc -l < ssrf-candidates.txt 2>/dev/null || echo 0))"

echo ""

# ──────────────────────────────────────────────
# STEP 6: Response headers on key targets
# ──────────────────────────────────────────────
echo -e "${YELLOW}[6/6] Checking response headers...${NC}"

KEY_TARGETS="https://app.hubspot.com https://api.hubapi.com https://chatspot.ai"

for target in $KEY_TARGETS; do
    echo "  [+] Headers: $target"
    echo "=== $target ===" >> headers.txt
    curl -sI "$target" -m 10 >> headers.txt 2>/dev/null || echo "  [-] timeout"
    echo "" >> headers.txt
done
echo -e "${GREEN}  [✓] Headers → headers.txt${NC}"
echo ""

# ──────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────
echo "============================================"
echo -e "${GREEN}[*] RECON COMPLETE${NC}"
echo "============================================"
echo ""
echo "Results in: $WORKDIR/"
echo ""
echo "Key files:"
echo "  all-subdomains.txt      — $(wc -l < all-subdomains.txt 2>/dev/null || echo 0) total subdomains"
echo "  in-scope.txt            — $(wc -l < in-scope.txt 2>/dev/null || echo 0) in-scope subdomains"
echo "  live-urls.txt           — $(wc -l < live-urls.txt 2>/dev/null || echo 0) live hosts"
echo "  historical-urls.txt     — $(wc -l < historical-urls.txt 2>/dev/null || echo 0) historical URLs"
echo "  api-routes.txt          — $(wc -l < api-routes.txt 2>/dev/null || echo 0) API endpoints"
echo "  top-params.txt          — top 60 parameters by frequency"
echo "  ssrf-candidates.txt     — $(wc -l < ssrf-candidates.txt 2>/dev/null || echo 0) SSRF candidate URLs"
echo "  id-params.txt           — $(wc -l < id-params.txt 2>/dev/null || echo 0) IDOR candidate URLs"
echo "  js-files.txt            — $(wc -l < js-files.txt 2>/dev/null || echo 0) JavaScript files"
echo ""
echo -e "${YELLOW}NEXT STEPS:${NC}"
echo "  1. Review live-hosts-full.txt — look for unusual status codes, tech stacks"
echo "  2. Review top-params.txt — understand what parameters HubSpot uses"
echo "  3. Review api-routes.txt — find undocumented API endpoints"
echo "  4. Review ssrf-candidates.txt — these are your SSRF test targets"
echo "  5. Review id-params.txt — these are your IDOR test targets"
echo "  6. Run Google dorks manually (see recon guide)"
echo "  7. Set up Burp and start Phase 2: Active Mapping"
