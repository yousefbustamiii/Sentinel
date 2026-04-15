#!/bin/bash
# Sentinel Source Code Bundler
# Ported from bundle_code.py

OUTPUT="sentinel_code_bundle.txt"
ROOT="."

# Initialize the bundle file
echo "SENTINEL SOURCE CODE BUNDLE" > "$OUTPUT"
echo "===========================" >> "$OUTPUT"
echo "" >> "$OUTPUT"

# Locate Swift files excluding build, git, and Tests directories
find "$ROOT" -name "*.swift" \
    -not -path "*/.build/*" \
    -not -path "*/.git/*" \
    -not -path "*/Tests/*" \
    | sort | while read -r file; do
    
    # Header for each file
    echo "FILE: $file" >> "$OUTPUT"
    
    # Dynamic divider based on path length
    len=${#file}
    div_size=$((len + 6))
    printf -- '-%.0s' $(seq 1 "$div_size") >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    
    # Append content
    cat "$file" >> "$OUTPUT"
    
    # Page break divider
    echo -e "\n\n==================================================\n" >> "$OUTPUT"
done

echo "Success! Bundle created at: $OUTPUT"
chmod +x "$0" 2>/dev/null
