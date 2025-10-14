#!/bin/bash

# PRC Watermark Detection Script
# Detects PRC watermarks in generated images with corruption testing

set -e  # Exit on error

# Default values
CONFIG_FILE=""
VERBOSE=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Detect PRC watermarks in generated images with corruption testing

OPTIONS:
    -h, --help              Show this help message
    -c, --config FILE       Configuration file (required)
    -v, --verbose           Enable verbose output

CORRUPTIONS TESTED:
    - JPEG compression
    - Gaussian blur
    - Gaussian noise
    - Brightness adjustment
    - Image resizing
    - SDEdit attack (strength 0.5)

EXAMPLES:
    # Detect watermarks with SD2.0 config
    $0 --config configs/prc_sd2_config.yaml

    # Detect watermarks with SDXL config
    $0 --config configs/prc_sdxl_config.yaml

    # Use custom config with verbose output
    $0 --config configs/my_prc_config.yaml --verbose

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate config file is provided
if [[ -z "$CONFIG_FILE" ]]; then
    print_error "Configuration file is required. Use --config option."
    usage
    exit 1
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    print_error "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Extract paths from config
OUTPUT_DIR=$(grep "output_dir:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
WATERMARK_DIR=$(grep "watermark_dir:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
RESULTS_FILE=$(grep "results_file:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')

KEYS_DIR="$WATERMARK_DIR"
if [ ! -f "$KEYS_DIR/encoding_key.npz" ] || [ ! -f "$KEYS_DIR/decoding_key.npz" ]; then
    print_error "PRC keys not found in: $KEYS_DIR (expected encoding_key.npz & decoding_key.npz)"
    print_error "Please run generation first: ./scripts/run_prc_generation.sh"
    exit 1
fi

# Check if generated images exist
if [ ! -d "$OUTPUT_DIR" ]; then
    print_error "Output directory not found: $OUTPUT_DIR"
    print_error "Please run generation first: ./scripts/run_prc_generation.sh"
    exit 1
fi

# Count available images
TOTAL_IMAGES=$(ls -1 "$OUTPUT_DIR"/watermarked_*.png 2>/dev/null | wc -l)
if [ "$TOTAL_IMAGES" -eq 0 ]; then
    print_error "No watermarked images found in $OUTPUT_DIR"
    exit 1
fi

# Print configuration
print_header "PRC Watermark Detection Configuration"
print_info "Config file: $CONFIG_FILE"
print_info "Watermark keys: $KEYS_DIR/encoding_key.npz, $KEYS_DIR/decoding_key.npz"
print_info "Output directory: $OUTPUT_DIR"
print_info "Results file: $RESULTS_FILE"
print_info "Total available images: $TOTAL_IMAGES"

# Get image count from config
CONFIG_COUNT=$(grep "image_generation_count:" "$CONFIG_FILE" | awk '{print $2}' || echo "all")
print_info "Processing: $CONFIG_COUNT images (from config)"

# Extract corruption settings
CORRUPTIONS_ENABLED=$(grep "enable_corruptions:" "$CONFIG_FILE" | awk '{print $2}')
if [ "$CORRUPTIONS_ENABLED" = "true" ]; then
    print_info "Corruptions: ENABLED"
    echo "  - JPEG compression"
    echo "  - Gaussian blur"
    echo "  - Gaussian noise"
    echo "  - Brightness change"
    echo "  - Resize"
    
    # Check SDEdit settings
    SDEDIT_ENABLED=$(grep -A1 "sdedit_corruptions:" "$CONFIG_FILE" | grep "enabled:" | awk '{print $2}')
    if [ "$SDEDIT_ENABLED" = "true" ]; then
        echo "  - SDEdit attack (strength 0.5)"
    fi
else
    print_info "Corruptions: DISABLED"
fi

# Build command
CMD="uv run python src/seed_watermark/prc_watermark/detect_prc.py"
CMD="$CMD $CONFIG_FILE"


# Set logging level
if [ "$VERBOSE" = true ]; then
    export PYTHONUNBUFFERED=1
    export LOG_LEVEL=DEBUG
else
    export LOG_LEVEL=INFO
fi

# Run detection
echo ""
print_header "Starting PRC Watermark Detection"
echo -e "${YELLOW}Command:${NC} $CMD"
echo ""

# Execute the command
if $CMD; then
    echo ""
    print_header "Detection Completed Successfully!"
    
    # Check if results file was created
    if [ -f "$RESULTS_FILE" ]; then
        print_info "Results saved to: $RESULTS_FILE"
        
        # Print summary statistics if available
        echo ""
        print_header "Detection Summary"
        
        # Count results
        NUM_RESULTS=$(wc -l < "$RESULTS_FILE")
        print_info "Total detection results: $((NUM_RESULTS - 1))"  # Subtract header
        
        # Show first few results
        echo ""
        print_info "Sample results (first 5 entries):"
        head -n 6 "$RESULTS_FILE" | column -t -s','
    fi
    
    # Check for corruption images
    CORRUPTION_DIR="${OUTPUT_DIR%/*}/corruptions"
    if [ -d "$CORRUPTION_DIR" ]; then
        NUM_CORRUPTIONS=$(find "$CORRUPTION_DIR" -type f -name "*.png" | wc -l)
        if [ "$NUM_CORRUPTIONS" -gt 0 ]; then
            print_info "Corruption images saved: $NUM_CORRUPTIONS images in $CORRUPTION_DIR"
        fi
    fi
else
    print_error "Detection failed!"
    exit 1
fi

# Print analysis suggestions
echo ""
print_header "Analysis Suggestions"
print_info "1. View detailed results:"
print_info "   cat $RESULTS_FILE | column -t -s','"
print_info ""
print_info "2. Calculate detection rate per corruption:"
print_info "   awk -F',' 'NR>1 {sum[\$2]+=((\$3=="true")||(\$3=="True")); count[\$2]++} END {for(c in sum) printf \"%-30s: %.2f\\n\", c, sum[c]/count[c]}' $RESULTS_FILE"
print_info ""
print_info "3. View corruption images:"
print_info "   ls ${OUTPUT_DIR%/*}/corruptions/*/"
print_info ""
print_info "4. Compare with baseline:"
print_info "   grep baseline $RESULTS_FILE"
