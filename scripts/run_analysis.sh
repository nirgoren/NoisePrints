#!/bin/bash

# Unified Image Analysis Script
# Uses configuration files directly with optional DDIM inversion

set -e  # Exit on any error

# Default parameters
CONFIG_FILE=""
INVERT_FLAG=""

# Function to show usage
show_usage() {
    echo "Usage: $0 --config <config_file> [options]"
    echo ""
    echo "Options:"
    echo "  -c, --config FILE    - Configuration file (required)"
    echo "  --invert             - Enable DDIM inversion analysis"
    echo "  --no-invert          - Disable DDIM inversion analysis"
    echo "  --help               - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --config configs/sdxl_config.yaml --invert"
    echo "  $0 --config configs/flux_config.yaml"
    echo "  $0 --config configs/sd2_0_config.yaml --invert"
    echo ""
    echo "Note: SDEdit corruptions are controlled via the config file's 'sdedit_corruptions' section"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --invert)
            INVERT_FLAG="--invert"
            shift
            ;;
        --no-invert)
            INVERT_FLAG="disabled"
            shift
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

# Handle inversion flag
if [[ "$INVERT_FLAG" == "disabled" ]]; then
    INVERT_FLAG=""
    echo "DDIM inversion explicitly disabled"
fi

# Detect model type from config filename for warnings
MODEL_TYPE="unknown"
if [[ "$CONFIG_FILE" == *"flux"* ]]; then
    MODEL_TYPE="flux"
elif [[ "$CONFIG_FILE" == *"sdxl"* ]]; then
    MODEL_TYPE="sdxl"
elif [[ "$CONFIG_FILE" == *"sd2"* ]]; then
    MODEL_TYPE="sd2.0"
elif [[ "$CONFIG_FILE" == *"sd1"* ]]; then
    MODEL_TYPE="sd1.4"
fi

# Warn if inversion is requested for non-SD models
if [[ "$INVERT_FLAG" == "--invert" && "$MODEL_TYPE" == "flux" ]]; then
    echo "Warning: DDIM inversion is only supported for SD models (SDXL, SD2.0, SD1.4)"
    echo "Continuing without inversion..."
    INVERT_FLAG=""
fi

echo "============================================================"
echo "Unified Image Analysis Script"
echo "============================================================"
echo "Config File: $CONFIG_FILE"
if [[ -n "$INVERT_FLAG" ]]; then
    echo "DDIM Inversion: Enabled"
else
    echo "DDIM Inversion: Disabled"
fi
echo "SDEdit Corruptions: Controlled by config file"
echo "============================================================"


# Run the analysis
echo "Starting robustness analysis..."
uv run analyze "$CONFIG_FILE" $INVERT_FLAG

if [[ $? -eq 0 ]]; then
    echo ""
    echo "============================================================"
    echo "Analysis Complete!"
    echo "============================================================"
    echo "Config: $CONFIG_FILE"
    echo "Results saved to CSV file specified in config"
    if [[ -n "$INVERT_FLAG" ]]; then
        echo "DDIM inversion metrics included in results"
    fi
    echo ""
    echo "Check the output directory for:"
    echo "  - Analysis results (CSV file)"
    echo "  - Corruption images (corruptions/ subdirectory)"
    echo "============================================================"
else
    echo ""
    echo "Error: Analysis failed!"
    exit 1
fi