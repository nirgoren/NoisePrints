#!/bin/bash

# PRC Watermark Generation Script
# Generates watermarked images using PRC (Pseudo-Random Correlation) watermarking

set -e  # Exit on error

# Default values
CONFIG_FILE=""
PROMPTS_FILE="prompts/image_prompts.yaml"
COUNT=""
VERBOSE=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate watermarked images using PRC watermarking

OPTIONS:
    -h, --help              Show this help message
    -c, --config FILE       Configuration file (required)
    -p, --prompts FILE      Prompts file (default: prompts/image_prompts.yaml)
    -n, --count NUMBER      Number of images to generate (overrides config)
    -v, --verbose           Enable verbose output

EXAMPLES:
    # Generate with SD2.0 config
    $0 --config configs/prc_sd2_config.yaml

    # Generate with SDXL config
    $0 --config configs/prc_sdxl_config.yaml

    # Generate 10 images using SD2.0 config
    $0 --config configs/prc_sd2_config.yaml --count 10

    # Generate with SDXL config and verbose output
    $0 --config configs/prc_sdxl_config.yaml --count 50 --verbose

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
        -p|--prompts)
            PROMPTS_FILE="$2"
            shift 2
            ;;
        -n|--count)
            COUNT="$2"
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

# Check if prompts file exists
if [ ! -f "$PROMPTS_FILE" ]; then
    print_error "Prompts file not found: $PROMPTS_FILE"
    exit 1
fi

# Print configuration
print_info "PRC Watermark Generation Configuration:"
print_info "  Config file: $CONFIG_FILE"
print_info "  Prompts file: $PROMPTS_FILE"
if [ -n "$COUNT" ]; then
    print_info "  Image count: $COUNT (overriding config)"
else
    # Extract count from config file
    CONFIG_COUNT=$(grep "image_generation_count:" "$CONFIG_FILE" | awk '{print $2}')
    print_info "  Image count: $CONFIG_COUNT (from config)"
fi

# Build command
CMD="uv run python src/seed_watermark/prc_watermark/generate_prc.py"
CMD="$CMD --config $CONFIG_FILE"
CMD="$CMD --prompts $PROMPTS_FILE"

if [ -n "$COUNT" ]; then
    CMD="$CMD --count $COUNT"
fi

# Set logging level
if [ "$VERBOSE" = true ]; then
    export PYTHONUNBUFFERED=1
    export LOG_LEVEL=DEBUG
else
    export LOG_LEVEL=INFO
fi

# Run generation
print_info "Starting PRC watermark generation..."
echo -e "${YELLOW}Command:${NC} $CMD"
echo ""

# Execute the command
if $CMD; then
    print_info "Generation completed successfully!"
    
    # Print output location
    OUTPUT_DIR=$(grep "output_dir:" "$CONFIG_FILE" | awk '{print $2}' | tr -d '"')
    print_info "Generated images saved to: $OUTPUT_DIR"
    
    # Count generated images
    if [ -d "$OUTPUT_DIR" ]; then
        NUM_GENERATED=$(ls -1 "$OUTPUT_DIR"/watermarked_*.png 2>/dev/null | wc -l)
        print_info "Total images generated: $NUM_GENERATED"
    fi
else
    print_error "Generation failed!"
    exit 1
fi

# Print next steps
echo ""
print_info "Next steps:"
print_info "  1. Run detection: ./scripts/run_prc_detection.sh --config $CONFIG_FILE"
print_info "  2. View results in the output directory specified in config"
print_info "  3. Analyze metrics: Review detection accuracy and robustness"