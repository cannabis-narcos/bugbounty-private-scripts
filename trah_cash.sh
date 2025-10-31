#!/bin/bash

# TrashCash Pro - Turning Deleted Files Into Bounties
# An enhanced version combining the article's technique with TruffleHog.
# Usage: ./trashcash_pro.sh <local-repo-directory>

set -e

# --- Configuration ---
REPO_DIR="$1"
OUTPUT_FILE="trashcash_pro_findings.txt"
TEMP_DIR="/tmp/trashcash_restore_$$"

# Extensions to focus on, as requested
SENSITIVE_EXTENSIONS_REGEX="(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc|php)"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Banner ---
echo -e "${BLUE}"
cat << "EOF"
╔════════════════════════════════════════════════╗
║                TrashCash Pro                   ║
║      Deleted Files + TruffleHog + Filtering    ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# --- Pre-flight Checks ---
if [[ -z "$REPO_DIR" ]]; then
    echo -e "${RED}Error: Please provide a repository directory.${NC}"
    echo "Usage: $0 <local-repo-directory>"
    exit 1
fi

if [[ ! -d "$REPO_DIR" ]]; then
    echo -e "${RED}Error: Directory '$REPO_DIR' not found.${NC}"
    exit 1
fi

if [[ ! -d "$REPO_DIR/.git" ]]; then
    echo -e "${RED}Error: '$REPO_DIR' is not a git repository.${NC}"
    exit 1
fi

# Check for required tools
for cmd in git jq trufflehog; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}Error: Required command '$cmd' not found. Please install it.${NC}"
        exit 1
    fi
done

# --- Cleanup Function ---
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
# Ensure temp directory is cleaned up on exit
trap cleanup EXIT

# --- Main Logic ---
echo -e "${YELLOW}[!] SECURITY NOTICE: Only use on authorized targets!${NC}"
echo

# Create temp directory for restored files
mkdir -p "$TEMP_DIR"
cd "$REPO_DIR"

# Clear previous findings
echo "TrashCash Pro Report - $(date)" > "../$OUTPUT_FILE"
echo "=================================================" >> "../$OUTPUT_FILE"
echo "" >> "../$OUTPUT_FILE"

echo -e "${GREEN}[+] Starting TrashCash Pro scan on: $(pwd)${NC}"
echo -e "${GREEN}[+] Findings will be saved to: ../$OUTPUT_FILE${NC}"
echo

# --- Step 1: TruffleHog Scan of Main Repository ---
echo -e "${BLUE}[+] Step 1: Running TruffleHog on the current repository...${NC}"
if trufflehog filesystem . --json --no-verification > "$TEMP_DIR/trufflehog_main.json" 2>/dev/null; then
    # --- FIX IS HERE: Use 'jq -s' to correctly count the stream of JSON objects ---
    MAIN_HOG_COUNT=$(jq -s 'length' "$TEMP_DIR/trufflehog_main.json" 2>/dev/null || echo "0")
    if [[ $MAIN_HOG_COUNT -gt 0 ]]; then
        echo -e "${RED}[!] TruffleHog found $MAIN_HOG_COUNT secrets in the main repository!${NC}"
        {
            echo ">>> TRUFFLEHOG FINDINGS (Main Repository) <<<"
            jq -r '.[] | "File: \(.SourceMetadata|split(":")[1]) | Detector: \(.DetectorName) | Secret: \(.Redacted)"' "$TEMP_DIR/trufflehog_main.json"
            echo ""
        } >> "../$OUTPUT_FILE"
    else
        echo -e "${GREEN}[+] TruffleHog found no secrets in the main repository.${NC}"
    fi
else
    echo -e "${YELLOW}[!] TruffleHog scan on main repository failed.${NC}"
fi
echo

# --- Step 2: Find and Analyze Deleted Files ---
echo -e "${BLUE}[+] Step 2: Finding and analyzing deleted files...${NC}"
DELETED_FILES=$(git log --diff-filter=D --summary | grep "delete mode" | awk '{print $NF}' | sort -u)

if [[ -z "$DELETED_FILES" ]]; then
    echo -e "${YELLOW}[!] No deleted files found in this repository.${NC}"
    exit 0
fi

FILE_COUNT=$(echo "$DELETED_FILES" | wc -l)
echo -e "${GREEN}[+] Found $FILE_COUNT deleted files. Filtering and analyzing...${NC}"
echo

MANUAL_SECRETS_FOUND=0
FILES_FOR_TRUFFLEHOG=0

while IFS= read -r file_path; do
    # Check if the file extension is in our list of sensitive extensions
    if [[ ! "$file_path" =~ \.${SENSITIVE_EXTENSIONS_REGEX}$ ]]; then
        continue # Skip files that don't match our extensions
    fi

    echo -e "${YELLOW}---[ Analyzing: $file_path ]---${NC}"

    DELETE_COMMIT=$(git log --diff-filter=D --oneline -- "$file_path" | head -1 | awk '{print $1}')
    if [[ -z "$DELETE_COMMIT" ]]; then
        echo -e "${RED}    Could not find deletion commit. Skipping.${NC}"
        continue
    fi
    
    RESTORE_COMMIT="${DELETE_COMMIT}^"
    echo -e "${CYAN}    Restoring from commit: $RESTORE_COMMIT${NC}"
    
    if git show "$RESTORE_COMMIT:$file_path" > /dev/null 2>&1; then
        RESTORED_CONTENT=$(git show "$RESTORE_COMMIT:$file_path")
        
        # Save the restored file for the bulk TruffleHog scan later
        SAFE_FILENAME=$(echo "$file_path" | sed 's|/|_|g')
        echo "$RESTORED_CONTENT" > "$TEMP_DIR/$SAFE_FILENAME"
        ((FILES_FOR_TRUFFLEHOG++))

        # Manual check for immediate feedback (as per original article)
        if echo "$RESTORED_CONTENT" | grep -nE "AKIA|-----BEGIN PRIVATE KEY-----|password|secret|token" > /dev/null; then
            echo -e "${RED}    [!!!] POTENTIAL SECRET FOUND (Manual Check)!${NC}"
            ((MANUAL_SECRETS_FOUND++))
            {
                echo ">>> MANUAL FINDING (Deleted File) <<<"
                echo "Deleted File: $file_path"
                echo "Deletion Commit: $DELETE_COMMIT"
                echo "GitHub URL: $(git remote get-url origin 2>/dev/null | sed 's/\.git$//' | sed 's/git@/https:\/\//' | sed 's/com:/com\//' 2>/dev/null)/blob/$RESTORE_COMMIT/$file_path"
                echo "---"
                echo "$RESTORED_CONTENT" | grep -nE "AKIA|-----BEGIN PRIVATE KEY-----|password|secret|token"
                echo ""
            } >> "../$OUTPUT_FILE"
        else
            echo -e "${GREEN}[+] No obvious secrets found via manual check.${NC}"
        fi
    else
        echo -e "${RED}    Could not restore file. Skipping.${NC}"
    fi
    echo

done <<< "$DELETED_FILES"


# --- Step 3: TruffleHog Scan of Restored Deleted Files ---
echo -e "${BLUE}[+] Step 3: Running TruffleHog on $FILES_FOR_TRUFFLEHOG restored deleted files...${NC}"
if [[ $FILES_FOR_TRUFFLEHOG -gt 0 ]]; then
    if trufflehog filesystem "$TEMP_DIR" --json --no-verification > "$TEMP_DIR/trufflehog_deleted.json" 2>/dev/null; then
        # --- FIX IS HERE: Use 'jq -s' to correctly count the stream of JSON objects ---
        DELETED_HOG_COUNT=$(jq -s 'length' "$TEMP_DIR/trufflehog_deleted.json" 2>/dev/null || echo "0")
        if [[ $DELETED_HOG_COUNT -gt 0 ]]; then
            echo -e "${RED}[!] TruffleHog found $DELETED_HOG_COUNT secrets in deleted files!${NC}"
            {
                echo ">>> TRUFFLEHOG FINDINGS (Deleted Files) <<<"
                jq -r '.[] | "File: \(.SourceMetadata|split("/")[-1]) | Detector: \(.DetectorName) | Secret: \(.Redacted)"' "$TEMP_DIR/trufflehog_deleted.json"
                echo ""
            } >> "../$OUTPUT_FILE"
        else
            echo -e "${GREEN}[+] TruffleHog found no secrets in the restored deleted files.${NC}"
        fi
    else
        echo -e "${YELLOW}[!] TruffleHog scan on deleted files failed.${NC}"
    fi
else
    echo -e "${YELLOW}[!] No files with matching extensions were restored for TruffleHog scan.${NC}"
fi
echo

# --- Final Report ---
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}                    Scan Complete${NC}"
echo -e "${GREEN}=================================================${NC}"
TOTAL_SECRETS=$((MANUAL_SECRETS_FOUND + MAIN_HOG_COUNT + DELETED_HOG_COUNT))

if [[ $TOTAL_SECRETS -gt 0 ]]; then
    echo -e "${RED}[!] TrashCash Pro found a total of $TOTAL_SECRETS potential secrets!${NC}"
    echo -e "${CYAN}    - Manual Findings (Deleted Files): $MANUAL_SECRETS_FOUND${NC}"
    echo -e "${CYAN}    - TruffleHog (Main Repo): $MAIN_HOG_COUNT${NC}"
    echo -e "${CYAN}    - TruffleHog (Deleted Files): $DELETED_HOG_COUNT${NC}"
    echo -e "${YELLOW}[+] Full report saved to: ../$OUTPUT_FILE${NC}"
else
    echo -e "${GREEN}[+] No secrets were found.${NC}"
fi
