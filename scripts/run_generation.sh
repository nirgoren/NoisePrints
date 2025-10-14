#!/bin/bash

# Unified Image Generation Script
# Uses configuration files directly

set -e  # Exit on any error

# Default parameters
CONFIG_FILE=""
PROMPTS_FILE="prompts/image_prompts.yaml"

# Function to show usage
show_usage() {
    echo "Usage: $0 --config <config_file> [options]"
    echo ""
    echo "Options:"
    echo "  -c, --config FILE    - Configuration file (required)"
    echo "  -p, --prompts FILE   - Prompts file (default: prompts/image_prompts.yaml)"
    echo "  --help               - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --config configs/flux_config.yaml"
    echo "  $0 --config configs/sdxl_config.yaml"
    echo "  $0 --config configs/flux_config.yaml --prompts my_prompts.yaml"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -p|--prompts)
            PROMPTS_FILE="$2"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$1'"
            show_usage
            exit 1
            ;;
    esac
done

# Validate config file
if [[ -z "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file is required. Use --config option."
    show_usage
    exit 1
fi

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Check if prompts file exists
if [[ ! -f "$PROMPTS_FILE" ]]; then
    echo "Error: Prompts file not found: $PROMPTS_FILE"
    exit 1
fi

echo "============================================================"
echo "Unified Image Generation Script"
echo "============================================================"
echo "Config File: $CONFIG_FILE"
echo "Prompts File: $PROMPTS_FILE"
echo "============================================================"

# Run the generation
echo "Starting image generation..."

uv run generate --config "$CONFIG_FILE" --prompts "$PROMPTS_FILE"

if [[ $? -eq 0 ]]; then
    echo ""
    echo "============================================================"
    echo "Image Generation Complete!"
    echo "============================================================"
    echo "Config: $CONFIG_FILE"
    echo "Generated images saved to output directory specified in config"
    echo ""
    echo "Next steps:"
    echo "  - Run analysis: ./scripts/run_analysis.sh --config $CONFIG_FILE"
    echo "  - View results in the output directory"
    echo "============================================================"
else
    echo ""
    echo "Error: Image generation failed!"
    exit 1
fi