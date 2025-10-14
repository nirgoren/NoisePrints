#!/bin/bash

set -e  # Exit on any error

echo "============================================================"
echo "🚀 SDXL Complete Pipeline - All Tasks"
echo "============================================================"
echo "🔧 Running on node: $(hostname)"
echo "📅 Started at: $(date)"
echo "============================================================"

# Create output directories
mkdir -p out/robustness_tests/SDXL
mkdir -p out/watermarks/SDXL
mkdir -p figures

echo ""
echo "============================================================"
echo "📸 Phase 1: Generate SDXL Base Images"
echo "============================================================"
./scripts/run_generation.sh --config configs/sdxl_config.yaml

echo ""
echo "============================================================"
echo "🧪 Phase 2: Robustness Analysis (Base Images)"
echo "============================================================"

echo "Running analysis with all corruptions including SDEdit attacks..."
./scripts/run_analysis.sh --config configs/sdxl_config.yaml --invert
echo "✅ Robustness Analysis Complete!"

echo ""
echo "============================================================"
echo "🟡 Phase 3: PRC Watermark Detection"
echo "============================================================"

echo "🟡 Generating PRC watermarked images..."
./scripts/run_prc_generation.sh --config configs/prc_sdxl_config.yaml

echo "🟡 Running PRC detection..."
./scripts/run_prc_detection.sh --config configs/prc_sdxl_config.yaml
echo "✅ PRC Watermark Detection Complete!"

echo ""
echo "============================================================"
echo "🟢 Phase 4: Gaussian Shading Watermark Detection"
echo "============================================================"

echo "🟢 Generating Gaussian Shading watermarked images..."
./scripts/run_gs_generation.sh --config configs/gaussian_shading_sdxl_config.yaml

echo "🟢 Running Gaussian Shading detection..."
./scripts/run_gs_detection.sh --config configs/gaussian_shading_sdxl_config.yaml
echo "✅ Gaussian Shading Detection Complete!"

echo ""
echo "============================================================"
echo "📊 Phase 5: Generate Analysis Plots"
echo "============================================================"

echo "📊 Generating attack plots with watermark comparison..."
uv run python utils/generate_attack_plots.py sdxl --output-dir figures/attack_analysis_sdxl --image-id latent_0

echo ""
echo "============================================================"
echo "🎉 All SDXL Pipeline Tasks Complete!"
echo "============================================================"
echo "📅 Finished at: $(date)"
echo ""
echo "📁 Output locations:"
echo "  Base images:     out/robustness_tests/SDXL/"
echo "  Watermarks:      out/watermarks/SDXL/"
echo "  Plots:           figures/"
echo "============================================================"
