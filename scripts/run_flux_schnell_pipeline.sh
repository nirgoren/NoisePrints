#!/bin/bash

set -e  # Exit on any error

echo "============================================================"
echo "🚀 FLUX Schnell Comprehensive Watermarking Pipeline"
echo "============================================================"
echo "🔧 Running on node: $(hostname)"
echo "📅 Started at: $(date)"
echo "============================================================"

# Create output directories
mkdir -p out/robustness_tests/FLUX_schnell

echo ""
echo "============================================================"
echo "📸 Phase 1: Generate FLUX Schnell Base Images"
echo "============================================================"
./scripts/run_generation.sh --config configs/flux_schnell_config.yaml

echo ""
echo "============================================================"
echo "🧪 Phase 2: Robustness Analysis (Base Images)"
echo "============================================================"
echo "Running analysis with all corruptions..."
./scripts/run_analysis.sh --config configs/flux_schnell_config.yaml

echo ""
echo "============================================================"
echo "📊 Phase 3: Generate Analysis Plots"
echo "============================================================"

echo "📊 Generating attack plots..."
uv run python utils/generate_attack_plots.py flux-schnell

echo ""
echo "============================================================"
echo "✅ Pipeline Complete!"
echo "============================================================"
echo "📅 Finished at: $(date)"
echo ""
echo "📁 Output locations:"
echo "  Base images:     out/robustness_tests/FLUX_Schnell/"
echo "  Watermarks:      out/watermarks/FLUX_Schnell/"
echo "  Plots:           figures/"
echo "============================================================"
