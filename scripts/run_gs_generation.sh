#!/bin/bash

# Gaussian Shading Image Generation Script
# Generates images with Gaussian Shading watermarks using SD2.0 or SDXL

set -e  # Exit on any error

# Default parameters
COUNT=100
ENCRYPTION="simple"
CONFIG_FILE=""

# Function to show usage
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --config FILE    - Configuration file (required)"
    echo "  --count N        - Number of images to generate (default: 100)"
    echo "  --encryption E   - Encryption method: 'simple' (XOR) or 'chacha' (default: simple)"
    echo "  --help           - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --config configs/gaussian_shading_sd2_config.yaml --count 50"
    echo "  $0 --config configs/gaussian_shading_sdxl_config.yaml --encryption chacha"
    echo "  $0 --config configs/gaussian_shading_sd2_config.yaml --count 25 --encryption chacha"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --count)
            COUNT="$2"
            shift 2
            ;;
        --encryption)
            ENCRYPTION="$2"
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

# Validate encryption method
if [[ "$ENCRYPTION" != "simple" && "$ENCRYPTION" != "chacha" ]]; then
    echo "Error: Encryption method must be 'simple' or 'chacha'"
    exit 1
fi

# Extract model info from config filename
if [[ "$CONFIG_FILE" == *"sdxl"* ]]; then
    MODEL_NAME="SDXL"
    MODEL_DIR="SDXL"
else
    MODEL_NAME="SD2.0"
    MODEL_DIR="SD2_0"
fi

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Check if prompts file exists
PROMPTS_FILE="prompts/image_prompts.yaml"
if [[ ! -f "$PROMPTS_FILE" ]]; then
    echo "Error: Prompts file not found: $PROMPTS_FILE"
    exit 1
fi

echo "============================================================"
echo "Gaussian Shading Image Generation Script"
echo "============================================================"
echo "Config File: $CONFIG_FILE"
echo "Model: $MODEL_NAME"
echo "Image Count: $COUNT"
echo "Encryption: $ENCRYPTION"
echo "Prompts File: $PROMPTS_FILE"
echo "============================================================"

# Create temporary config with overrides if needed
TEMP_CONFIG=""
if [[ "$COUNT" != "100" || "$ENCRYPTION" != "simple" ]]; then
    echo "Creating temporary config with overrides..."
    TEMP_CONFIG=$(mktemp --suffix=.yaml)
    
    # Copy original config and override parameters
    cp "$CONFIG_FILE" "$TEMP_CONFIG"
    
    if [[ "$COUNT" != "100" ]]; then
        sed -i "s/image_generation_count: [0-9]*/image_generation_count: $COUNT/" "$TEMP_CONFIG"
    fi
    
    if [[ "$ENCRYPTION" != "simple" ]]; then
        sed -i "s/encryption: \"simple\"/encryption: \"$ENCRYPTION\"/" "$TEMP_CONFIG"
    fi
    
    CONFIG_TO_USE="$TEMP_CONFIG"
else
    CONFIG_TO_USE="$CONFIG_FILE"
fi

# Run the generation
echo "Starting Gaussian Shading watermark generation..."
uv run python src/seed_watermark/gaussian_shading/generate_gs.py --config "$CONFIG_TO_USE" --prompts "$PROMPTS_FILE"

# Clean up temporary config
if [[ -n "$TEMP_CONFIG" ]]; then
    rm "$TEMP_CONFIG"
fi

if [[ $? -eq 0 ]]; then
    echo ""
    echo "============================================================"
    echo "Gaussian Shading Generation Complete!"
    echo "============================================================"
    echo "Config: $CONFIG_FILE"
    echo "Encryption: $ENCRYPTION"
    echo "Generated $COUNT watermarked images"
    echo ""
    echo "Output locations:"
    echo "  - Images: out/gaussian_shading/$MODEL_DIR/generated_images/"
    echo "  - Watermark data: out/gaussian_shading/$MODEL_DIR/watermarks/"
    echo "  - Latents: out/gaussian_shading/$MODEL_DIR/generated_latents/"
    echo ""
    echo "Next steps:"
    echo "  - Run detection: ./scripts/run_gs_detection.sh --config $CONFIG_FILE"
    echo "  - View generated images in the output directory"
    echo "============================================================"
else
    echo ""
    echo "Error: Gaussian Shading generation failed!"
    exit 1
fi