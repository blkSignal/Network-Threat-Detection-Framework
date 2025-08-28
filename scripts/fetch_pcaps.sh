#!/bin/bash
# Goliath Systems - PCAP Fetch Script
# Downloads sample PCAP files for testing the detection pipeline

set -e

PCAP_DIR="data/pcaps"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Create PCAP directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/$PCAP_DIR"

echo "Fetching sample PCAP files for Goliath Systems..."

# Sample PCAP URLs (replace with actual URLs when available)
# These are examples - you'll need to provide actual PCAP files
PCAP_URLS=(
    "https://example.com/sample1.pcap"
    "https://example.com/sample2.pcap"
    "https://example.com/malware_traffic.pcap"
)

# Function to download PCAP file
download_pcap() {
    local url="$1"
    local filename=$(basename "$url")
    local filepath="$PROJECT_ROOT/$PCAP_DIR/$filename"
    
    echo "Downloading $filename..."
    
    # Use curl with progress bar
    if curl -L -o "$filepath" --progress-bar "$url"; then
        echo "✓ Downloaded $filename"
        
        # Verify file integrity
        if [[ -s "$filepath" ]]; then
            echo "  File size: $(du -h "$filepath" | cut -f1)"
        else
            echo "  Warning: Downloaded file is empty"
            rm -f "$filepath"
        fi
    else
        echo "✗ Failed to download $filename"
        rm -f "$filepath"
    fi
}

# Function to create synthetic PCAP for testing
create_synthetic_pcap() {
    echo "Creating synthetic PCAP for testing..."
    
    # Create a simple text file that can be processed by Zeek/Suricata
    # In a real scenario, you'd use actual PCAP files
    cat > "$PROJECT_ROOT/$PCAP_DIR/synthetic_test.pcap" << 'EOF'
# This is a synthetic test file
# In production, replace with actual PCAP files
# You can download sample PCAPs from:
# - https://www.netresec.com/?page=PcapFiles
# - https://www.malware-traffic-analysis.net/
# - https://github.com/zeek/zeek/tree/master/testing/btest/Traces
EOF
    
    echo "✓ Created synthetic_test.pcap"
}

# Main execution
cd "$PROJECT_ROOT"

echo "Project root: $PROJECT_ROOT"
echo "PCAP directory: $PCAP_DIR"

# Try to download PCAPs if URLs are provided
if [[ ${#PCAP_URLS[@]} -gt 0 ]]; then
    for url in "${PCAP_URLS[@]}"; do
        if [[ "$url" != "https://example.com/"* ]]; then
            download_pcap "$url"
        fi
    done
fi

# Create synthetic PCAP for testing
create_synthetic_pcap

# Create a README for the PCAP directory
cat > "$PCAP_DIR/README.md" << 'EOF'
# PCAP Files Directory

This directory contains network capture files for testing the Goliath Systems detection pipeline.

## File Types
- `.pcap` - Network packet capture files
- `.pcapng` - Next generation packet capture files

## Usage
1. Place your PCAP files in this directory
2. Run the detection pipeline:
   ```bash
   # Parse with Zeek
   zeek -r your_file.pcap
   
   # Parse with Suricata
   suricata -r your_file.pcap -l data/suricata
   ```

## Sample Sources
- [Netresec](https://www.netresec.com/?page=PcapFiles)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [Zeek Testing Traces](https://github.com/zeek/zeek/tree/master/testing/btest/Traces)

## Security Note
- Only use PCAP files from trusted sources
- Be aware that some files may contain malicious traffic
- Run in isolated environments when possible
EOF

echo ""
echo "PCAP setup complete!"
echo ""
echo "Next steps:"
echo "1. Add your PCAP files to $PCAP_DIR/"
echo "2. Run: docker compose up -d"
echo "3. Process PCAPs with Zeek and Suricata"
echo "4. Run detectors: python detectors/python/dga_detector.py --zeek dns.log"
echo "5. View dashboards at http://localhost:3000"
echo ""
echo "Note: Replace the example URLs in this script with actual PCAP sources."
