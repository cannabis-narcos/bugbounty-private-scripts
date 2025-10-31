#!/bin/bash
# =====================================================================
#  SMART JAVASCRIPT RECON & EXPOSURE/SECRET DETECTION PIPELINE (FINAL FIXED)
# =====================================================================
#  Fixes: LinkFinder auto-open issue | Adds Mantra + TruffleHog
# =====================================================================

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 <file_with_js_urls>"
    echo -e "Example: $0 js_files.txt"
    exit 1
fi

TOOLS_DIR="$HOME/js_analysis_tools"
JS_URLS_FILE=$(realpath "$1")
DOMAIN=$(basename "$JS_URLS_FILE" | cut -d '_' -f 1)
OUTPUT_DIR="js_analysis_results_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"/{temp,beautified,endpoints,secrets,final,nuclei_reports}

echo -e "${CYAN}=================================================================${RESET}"
echo -e "${CYAN}   Smarter JavaScript Recon, Exposure & Secret Scanner${RESET}"
echo -e "${CYAN}=================================================================${RESET}"
echo
echo -e "${GREEN}[+] Saving results to:${RESET} $OUTPUT_DIR"
echo -e "${GREEN}[+] Input file:${RESET} $JS_URLS_FILE"
echo

# ---------------------------------------------------------------------
# Step 1: Check live JS URLs
# ---------------------------------------------------------------------
echo -e "${CYAN}[1/10] Checking live JS files using httpx...${RESET}"
LIVE_JS_FILE="$OUTPUT_DIR/live_js_urls.txt"
cat "$JS_URLS_FILE" | grep -E '^https?://' | \
httpx -silent -mc 200,302 -content-type "javascript" | awk '{print $1}' > "$LIVE_JS_FILE"
LIVE_COUNT=$(wc -l < "$LIVE_JS_FILE")
echo -e "    ${GREEN}Found $LIVE_COUNT live JS URLs${RESET}"
[ "$LIVE_COUNT" -eq 0 ] && { echo -e "${RED}[!] No live JS URLs found.${RESET}"; exit 1; }
echo

# ---------------------------------------------------------------------
# Step 2: Download live JS files
# ---------------------------------------------------------------------
echo -e "${CYAN}[2/10] Downloading JS files...${RESET}"
JS_FILES_LIST="$OUTPUT_DIR/temp/downloaded_files.txt"
: > "$JS_FILES_LIST"

cat "$LIVE_JS_FILE" | parallel -j 10 '
    url={};
    filename=$(echo "$url" | md5sum | cut -d" " -f1).js;
    dest="'"$OUTPUT_DIR"'/temp/$filename";
    curl -s -k -L --max-time 10 "$url" -o "$dest";
    if [ -s "$dest" ]; then
        js-beautify "$dest" > "'"$OUTPUT_DIR"'/beautified/$filename" 2>/dev/null || cp "$dest" "'"$OUTPUT_DIR"'/beautified/$filename";
        echo "'"$OUTPUT_DIR"'/beautified/$filename" >> "'"$JS_FILES_LIST"'";
    fi
'
DOWNLOADED_COUNT=$(wc -l < "$JS_FILES_LIST")
echo -e "    ${GREEN}Downloaded $DOWNLOADED_COUNT JS files${RESET}"
echo

# ---------------------------------------------------------------------
# Step 3: Run custom endpoint finder
# ---------------------------------------------------------------------
echo -e "${CYAN}[3/10] Running custom endpoint finder...${RESET}"
python3 "$TOOLS_DIR/endpoints-finder/endpoints.py" -i "$LIVE_JS_FILE" -o "$OUTPUT_DIR" >/dev/null 2>&1 || true
echo -e "    ${GREEN}Custom endpoint finder complete${RESET}"
echo

# ---------------------------------------------------------------------
# Step 4: LinkFinder (HTML → text fix)
# ---------------------------------------------------------------------
echo -e "${CYAN}[4/10] Running LinkFinder (fixed output)...${RESET}"
while IFS= read -r js_file; do
    basefile=$(basename "$js_file" .js)
    html_output="$OUTPUT_DIR/endpoints/${basefile}_linkfinder.html"
    txt_output="$OUTPUT_DIR/endpoints/${basefile}_linkfinder.txt"

    # Run LinkFinder safely
    python3 "$TOOLS_DIR/LinkFinder/linkfinder.py" -i "$js_file" -o "$html_output" >/dev/null 2>&1

    # Extract URLs from HTML
    grep -oP '(https?://[^"'\''<>\s]+|/[^"'\''<>\s]+)' "$html_output" | sort -u > "$txt_output"

    # Clean up HTML file to prevent it from opening
    rm -f "$html_output"
done < "$JS_FILES_LIST"

cat "$OUTPUT_DIR/endpoints/"*_linkfinder.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/endpoints/linkfinder_endpoints.txt"
echo -e "    ${GREEN}LinkFinder fixed & complete${RESET}"
echo

# ---------------------------------------------------------------------
# Step 5: Relative URL extractor
# ---------------------------------------------------------------------
echo -e "${CYAN}[5/10] Extracting relative URLs...${RESET}"
while IFS= read -r js_file; do
    ruby "$TOOLS_DIR/relative-url-extractor/extract.rb" "$js_file" >> "$OUTPUT_DIR/endpoints/relative_urls.txt" 2>/dev/null || true
done < "$JS_FILES_LIST"
echo -e "    ${GREEN}Relative URL extraction complete${RESET}"
echo

# ---------------------------------------------------------------------
# Step 6: Nuclei exposure scan
# ---------------------------------------------------------------------
echo -e "${CYAN}[6/10] Running Nuclei exposure templates...${RESET}"
cat "$LIVE_JS_FILE" | nuclei -t ~/nuclei-templates/http/exposures/ -o "$OUTPUT_DIR/nuclei_reports/nuclei_exposures.txt" -silent >/dev/null 2>&1 || true
echo -e "    ${GREEN}Nuclei exposure scan complete${RESET}"
echo

# ---------------------------------------------------------------------
# Step 7: Mantra secret scanner
# ---------------------------------------------------------------------
echo -e "${CYAN}[7/10] Running Mantra for API key leaks...${RESET}"
if command -v mantra >/dev/null 2>&1; then
    cat "$LIVE_JS_FILE" | mantra -o "$OUTPUT_DIR/secrets/mantra_results.txt" >/dev/null 2>&1 || true
    echo -e "    ${GREEN}Mantra scan complete${RESET}"
else
    echo -e "${YELLOW}[!] Mantra not found (install with: go install github.com/brosck/mantra@latest)${RESET}"
fi
echo

# ---------------------------------------------------------------------
# Step 8: TruffleHog secret scanner
# ---------------------------------------------------------------------
echo -e "${CYAN}[8/10] Running TruffleHog secret scanner...${RESET}"
truffleHog filesystem --directory="$OUTPUT_DIR/beautified" --json > "$OUTPUT_DIR/secrets/trufflehog_results.json" 2>/dev/null || true
echo -e "    ${GREEN}TruffleHog scan complete${RESET}"
echo

# ---------------------------------------------------------------------
# Step 9: Regex-based endpoint and secret extraction
# ---------------------------------------------------------------------
echo -e "${CYAN}[9/10] Extracting additional patterns...${RESET}"
declare -A REGEX_FILES=(
    ["api"]="(/api/|/v[0-9]+/|/rest/|/graphql)"
    ["auth"]="(/auth/|/login|/logout|/signin|/signup|/register)"
    ["admin"]="(/admin/|/console|/dashboard|/manage|/config)"
    ["internal"]="(/internal/|/private/|/_/|/dev/)"
)
for name in "${!REGEX_FILES[@]}"; do
    grep -r -E "${REGEX_FILES[$name]}" "$OUTPUT_DIR/beautified" 2>/dev/null | \
    grep -o -E "${REGEX_FILES[$name]}[^\"']*" | sort -u > "$OUTPUT_DIR/endpoints/regex_${name}_endpoints.txt"
done
grep -r -E "(secret|key|token|password|auth|apikey|api_key)" "$OUTPUT_DIR/beautified" 2>/dev/null > "$OUTPUT_DIR/secrets/regex_potential_secrets.txt"
grep -r -o -E "[\"'][A-Za-z0-9+/]{40,}={0,2}[\"']" "$OUTPUT_DIR/beautified" 2>/dev/null > "$OUTPUT_DIR/secrets/base64_encoded.txt"
echo -e "    ${GREEN}Regex extraction complete${RESET}"
echo

# ---------------------------------------------------------------------
# Step 10: Summarize
# ---------------------------------------------------------------------
echo -e "${CYAN}[10/10] Creating summary...${RESET}"
cat "$OUTPUT_DIR/endpoints/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/final/all_endpoints.txt"
grep -vE '\.(png|jpg|jpeg|gif|svg|css|woff|ttf|eot|map)$' "$OUTPUT_DIR/final/all_endpoints.txt" > "$OUTPUT_DIR/final/filtered_endpoints.txt"

{
    echo "================================================================="
    echo "# JavaScript Recon & Secret Scan Summary"
    echo "================================================================="
    echo "Target domain: $DOMAIN"
    echo "Date: $(date)"
    echo
    echo "Live JS files: $LIVE_COUNT"
    echo "Downloaded: $DOWNLOADED_COUNT"
    echo "Endpoints found: $(wc -l < "$OUTPUT_DIR/final/filtered_endpoints.txt")"
    echo
    echo "Nuclei exposures: $OUTPUT_DIR/nuclei_reports/nuclei_exposures.txt"
    echo "Mantra report:    $OUTPUT_DIR/secrets/mantra_results.txt"
    echo "TruffleHog report:$OUTPUT_DIR/secrets/trufflehog_results.json"
    echo
    echo "================================================================="
} > "$OUTPUT_DIR/SUMMARY.md"

echo -e "${GREEN}[✓] Recon & Scan Complete${RESET}"
echo -e "${CYAN}Results saved to:${RESET} $OUTPUT_DIR"
