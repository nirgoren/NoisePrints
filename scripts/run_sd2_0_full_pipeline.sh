#!/bin/bash
set -e  # Exit on any error

echo "============================================================"
echo "🚀 SD2.0 Complete Watermarking Pipeline (100 images)"
echo "============================================================"
echo "🔧 Running on: $(hostname)"
echo "📅 Started at: $(date)"
echo "============================================================"

# Configuration
SD2_CONFIG="configs/sd2_0_config.yaml"
PRC_CONFIG="configs/prc_sd2_config.yaml"
GS_CONFIG="configs/gaussian_shading_sd2_config.yaml"
PROMPTS="prompts/image_prompts.yaml"
FPR_POWER=128

# Create output directories
mkdir -p out/robustness_tests/SD2_0
mkdir -p out/prc_watermark/SD2_0
mkdir -p out/gaussian_shading/SD2_0
mkdir -p figures/attack_analysis_sd2_0

echo ""
echo "============================================================"
echo "📸 Phase 1: Generate Base Images (Seed Watermark)"
echo "============================================================"
uv run python src/seed_watermark/robustness_tests/generate.py \
    --config ${SD2_CONFIG} \
    --prompts ${PROMPTS}

echo ""
echo "============================================================"
echo "🔍 Phase 2: Generate Watermarked Images"
echo "============================================================"

echo "🟡 Generating PRC watermarked images..."
uv run python src/seed_watermark/prc_watermark/generate_prc.py \
    --config ${PRC_CONFIG} \
    --prompts ${PROMPTS}

echo ""
echo "🟢 Generating Gaussian Shading watermarked images..."
uv run python src/seed_watermark/gaussian_shading/generate_gs.py \
    --config ${GS_CONFIG} \
    --prompts ${PROMPTS}

echo ""
echo "============================================================"
echo "🧪 Phase 3: Robustness Analysis with Corruptions"
echo "============================================================"
echo "Running analysis with DDIM inversion + all corruptions (SDEdit, traditional)..."
uv run python src/seed_watermark/robustness_tests/analyze.py \
    ${SD2_CONFIG} \
    --invert

echo ""
echo "============================================================"
echo "🔬 Phase 4: Watermark Detection Analysis"
echo "============================================================"

echo "🟡 Running PRC watermark detection..."
uv run python src/seed_watermark/prc_watermark/detect_prc.py \
    ${PRC_CONFIG}

echo ""
echo "🟢 Running Gaussian Shading watermark detection..."
uv run python src/seed_watermark/gaussian_shading/detect_gs.py \
    --config ${GS_CONFIG}

echo ""
echo "============================================================"
echo "📊 Phase 5: Generate Comprehensive Attack Plots"
echo "============================================================"
echo "Generating PDFs with all 4 methods (Ours, WIND, PRC, GS)..."
uv run python utils/generate_attack_plots.py \
    --csv out/robustness_tests/SD2_0/results.csv \
    --config ${SD2_CONFIG} \
    --output-dir figures/attack_analysis_sd2_0 \
    --fpr-power ${FPR_POWER} \
    --image-id latent_0

echo ""
echo "============================================================"
echo "✅ Pipeline Complete!"
echo "============================================================"
echo "📅 Finished at: $(date)"
echo ""
echo "📁 Output locations:"
echo "  Base images & analysis:  out/robustness_tests/SD2_0/"
echo "  PRC watermark:           out/prc_watermark/SD2_0/"
echo "  Gaussian Shading:        out/gaussian_shading/SD2_0/"
echo "  Attack plots (PDFs):     figures/attack_analysis_sd2_0/"
echo ""
echo "📊 Generated files:"
echo "  - ROC curves comparing all 4 methods"
echo "  - TPR vs Quality plots at FPR=2^-${FPR_POWER}"
echo "  - Visual corruption comparisons"
echo "============================================================"
