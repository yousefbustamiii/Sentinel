#!/bin/bash
# Sentinel Codebase Intelligence Analyzer
# Ported from analyze.py

# --- Configuration & Stylization ---

PRIMARY='\033[38;5;75m'    # Soft Blue
SECONDARY='\033[38;5;121m'  # Seafoam Green
ACCENT='\033[38;5;214m'    # Gold
DANGER='\033[38;5;196m'    # Vibrant Red
NEUTRAL='\033[38;5;244m'   # Slate Grey
BOLD='\033[1m'
RESET='\033[0m'
DIVIDER=$(printf "${NEUTRAL}%.0s—" {1..60})

print_header() {
    local text=$(echo "$1" | tr '[:lower:]' '[:upper:]')
    echo -e "\n${BOLD}${PRIMARY}${text}${RESET}"
    echo -e "${DIVIDER}${RESET}"
}

print_metric() {
    local label=$1
    local value=$2
    local color=${3:-$SECONDARY}
    local max_width=60
    local label_width=${#label}
    
    printf "${NEUTRAL}%s" "$label"
    
    local dots=$((max_width - label_width))
    if [ "$dots" -lt 1 ]; then dots=3; fi
    
    printf "%s${RESET}" "$(printf '%.0s.' $(seq 1 $dots))"
    printf " ${BOLD}${color}%s${RESET}\n" "$value"
}

# --- Core Analysis ---

root_dir="."
exclude_path="./Tests/senTests"

# temporary data storage
loc_file=$(mktemp)
reg_file=$(mktemp)

# Find Swift files excluding internal and specified test paths
find "$root_dir" -name "*.swift" \
    -not -path "*/.git/*" \
    -not -path "*/.build/*" \
    -not -path "$exclude_path/*" \
    | while read -r filepath; do
    
    # Count non-empty lines
    loc=$(grep -cve '^\s*$' "$filepath")
    echo "$loc" >> "$loc_file"
    echo "$loc $filepath" >> "$reg_file"
done

if [ ! -s "$loc_file" ]; then
    echo -e "${DANGER}Error: No Swift files found.${RESET}"
    exit 1
fi

# Statistics calculations
total_files=$(wc -l < "$loc_file" | xargs)
total_loc=$(awk '{s+=$1} END {print s}' "$loc_file")
avg_loc=$(awk "{s+=\$1} END {printf \"%.1f\", s/$total_files}" "$loc_file")
median_loc=$(sort -n "$loc_file" | awk '{a[NR]=$1} END {if (NR%2==1) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}')

# SRP Rating Heuristic via AWK
final_srp=$(awk '
function srp(loc) {
    if (loc < 60) return 100
    if (loc < 150) return 90
    if (loc < 300) return 70
    if (loc < 550) return 40
    if (loc < 1000) return 15
    return 5
}
{ s += srp($1) }
END { printf "%.1f", s/NR }' "$loc_file")

# --- UI Rendering ---

print_header "Sentinel Codebase Statistics"
print_metric "Production Swift Files" "$total_files"
print_metric "Total Lines of Code" "$(printf "%'d" "$total_loc")"
print_metric "Average Lines per File" "$avg_loc"
print_metric "Median Lines per File" "$median_loc"

print_header "Largest Source Files (Hotspots)"
sort -rn "$reg_file" | head -n 5 | while read -r loc path; do
    color=$SECONDARY
    if [ "$loc" -gt 200 ]; then color=$ACCENT; fi
    print_metric "$path" "$loc" "$color"
done

# Determine color for SRR Rating
srp_color=$SECONDARY
if (( $(echo "$final_srp < 50" | bc -l) )); then srp_color=$DANGER
elif (( $(echo "$final_srp < 75" | bc -l) )); then srp_color=$ACCENT
fi

print_header "Architectural Health"
print_metric "SRP Adherence Rating" "$final_srp / 100" "$srp_color"

# Cleanup
rm "$loc_file" "$reg_file"

# Insight footers
echo -e "\n${NEUTRAL}Analysis context: Excluded test suites and dependency artifacts.${RESET}"
echo -e "${NEUTRAL}SRP rating follows logarithmic decay relative to file length.${RESET}\n"

chmod +x "$0" 2>/dev/null
