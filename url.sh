#!/bin/bash

# Check if domain parameter is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1

# Create output directory
OUTPUT_DIR="${DOMAIN}_recon"
mkdir -p "$OUTPUT_DIR"

echo "[+] Starting URL discovery for $DOMAIN"

# Step 1: Use waymore exactly as specified to gather URLs
echo "[+] Running waymore..."
waymore -i "$DOMAIN" -mode U -oU "$OUTPUT_DIR/waymore_urls.txt" -p 5 -f -l 5000 -ci none --providers wayback,commoncrawl,otx,urlscan,virustotal,intelx

# Step 2: Use gospider for crawling with correct parameters
echo "[+] Running gospider..."
gospider --site "https://$DOMAIN" -d 5 -c 10 -t 20 -k 1 -K 2 -m 10 -o "$OUTPUT_DIR/gospider"
cat "$OUTPUT_DIR/gospider"/* 2>/dev/null | grep -Eo '(http|https)://[^"]+' > "$OUTPUT_DIR/gospider_urls.txt"

# Step 3: Use katana for more URL discovery with optimized parameters
echo "[+] Running katana..."
katana -u "https://$DOMAIN" -jc -silent -d 10 -c 20 -p 20 -rl 150 -kf all -o "$OUTPUT_DIR/katana_urls.txt"

# Step 4: Combine results and remove duplicates using uro and anew
echo "[+] Combining results and removing duplicates..."
cat "$OUTPUT_DIR/waymore_urls.txt" "$OUTPUT_DIR/gospider_urls.txt" "$OUTPUT_DIR/katana_urls.txt" | sort | uniq > "$OUTPUT_DIR/all_urls.txt"
cat "$OUTPUT_DIR/all_urls.txt" | uro | anew > "$OUTPUT_DIR/unique_urls.txt"

# Step 5: Extract JS files
echo "[+] Extracting JS files..."
cat "$OUTPUT_DIR/unique_urls.txt" | grep -Eo 'https?://[^"'"'"'<> ]+\.js(\?[^\s"'"'"'<>]*)?' > "$OUTPUT_DIR/js_files.txt"

# Step 6: Use gf patterns to separate by vulnerability type
echo "[+] Separating URLs by vulnerability patterns..."
mkdir -p "$OUTPUT_DIR/patterns"
cat "$OUTPUT_DIR/unique_urls.txt" | gf xss > "$OUTPUT_DIR/patterns/xss.txt"
cat "$OUTPUT_DIR/unique_urls.txt" | gf ssrf > "$OUTPUT_DIR/patterns/ssrf.txt"
cat "$OUTPUT_DIR/unique_urls.txt" | gf lfi > "$OUTPUT_DIR/patterns/lfi.txt"
cat "$OUTPUT_DIR/unique_urls.txt" | gf redirect > "$OUTPUT_DIR/patterns/redirect.txt"
# Add more patterns as needed
cat "$OUTPUT_DIR/unique_urls.txt" | gf sqli > "$OUTPUT_DIR/patterns/sqli.txt"
cat "$OUTPUT_DIR/unique_urls.txt" | gf idor > "$OUTPUT_DIR/patterns/idor.txt"
cat "$OUTPUT_DIR/unique_urls.txt" | gf rce > "$OUTPUT_DIR/patterns/rce.txt"

echo "[+] Reconnaissance completed! Results saved in $OUTPUT_DIR directory"
echo "    - All URLs: $(wc -l < "$OUTPUT_DIR/all_urls.txt")"
echo "    - Unique URLs: $(wc -l < "$OUTPUT_DIR/unique_urls.txt")"
echo "    - JS files: $(wc -l < "$OUTPUT_DIR/js_files.txt")"
echo ""
echo "Pattern matches:"
for pattern in "$OUTPUT_DIR/patterns"/*.txt; do
    pattern_name=$(basename "$pattern" .txt)
    count=$(wc -l < "$pattern")
    echo "    - $pattern_name: $count URLs"
done
