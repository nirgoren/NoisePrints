#!/bin/bash

set -e  # Exit on any error

echo "============================================================"
echo "🚀 SD2.0 Comprehensive Watermarking Pipeline"
echo "============================================================"
echo "🔧 Running on node: $(hostname)"
echo "📅 Started at: $(date)"
echo "============================================================"

# Create output directories
mkdir -p out/robustness_tests/SD2_0
mkdir -p out/watermarks/SD2_0

echo ""
echo "============================================================"
echo "📸 Phase 1: Generate SD2.0 Base Images"
echo "============================================================"
./scripts/run_generation.sh --config configs/sd2_0_config.yaml

echo ""
echo "============================================================"
echo "🔍 Phase 2: Generate Watermarked Images"
echo "============================================================"

echo "🟡 Generating PRC watermarked images..."
./scripts/run_prc_generation.sh --config configs/prc_sd2_config.yaml

echo "🟢 Generating Gaussian Shading watermarked images..."
./scripts/run_gs_generation.sh --config configs/gaussian_shading_sd2_config.yaml

echo ""
echo "============================================================"
echo "🧪 Phase 3: Robustness Analysis (Base Images)"
echo "============================================================"
echo "Running analysis with all corruptions including SDEdit attacks..."
./scripts/run_analysis.sh --config configs/sd2_0_config.yaml --invert

echo ""
echo "============================================================"
echo "🔬 Phase 4: Watermark Detection Analysis"
echo "============================================================"

echo "🟡 Running PRC watermark detection..."
./scripts/run_prc_detection.sh --config configs/prc_sd2_config.yaml

echo "🟢 Running Gaussian Shading watermark detection..."
./scripts/run_gs_detection.sh --config configs/gaussian_shading_sd2_config.yaml

echo ""
echo "============================================================"
echo "📊 Phase 5: Generate Analysis Plots"
echo "============================================================"

echo "📊 Generating attack plots with watermark comparison..."
uv run python utils/generate_attack_plots.py sd2.0 --output-dir figures/attack_analysis_sd2 --image-id latent_0

echo ""
echo "============================================================"
echo "✅ Pipeline Complete!"
echo "============================================================"
echo "📅 Finished at: $(date)"
echo ""
echo "📁 Output locations:"
echo "  Base images:     out/robustness_tests/SD2_0/"
echo "  Watermarks:      out/watermarks/SD2_0/"
echo "  Plots:           figures/"
echo "============================================================"
