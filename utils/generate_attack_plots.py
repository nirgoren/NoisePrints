#!/usr/bin/env python3
"""
Generate comprehensive attack analysis PDFs.

Creates one PDF per attack type containing:
- ROC curves for each attack level
- TPR vs quality metrics at fixed FPR
- Qualitative image comparisons
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, MaxNLocator, FuncFormatter
import argparse
import math
import sys
from pathlib import Path
from typing import Dict, List, Optional
import yaml
from PIL import Image
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure
import scipy.special as sp

# Import required modules
sys.path.append(str(Path(__file__).parent))
try:
    from high_precision_cosine_solver import log_tightest_cosine_bound, find_cosine_threshold_log
except ImportError:
    print("Error: Could not import high_precision_cosine_solver.py")
    sys.exit(1)

# Import image metrics
try:
    sys.path.append(str(Path(__file__).parent.parent / "src"))
    from seed_watermark.utils.image_metrics import compute_ssim_psnr_lpips
    # For consistent, pretty corruption names
    from seed_watermark.utils.generate_corruption_comparison import (
        clean_corruption_name as _clean_corr_name,
    )
except ImportError:
    print("Warning: Could not import image_metrics. Image comparison will be disabled.")
    compute_ssim_psnr_lpips = None
    _clean_corr_name = None

# Set style
plt.style.use('seaborn-v0_8-whitegrid')


def calculate_analytical_fp(threshold: float, dimensions: int) -> float:
    """Calculate analytical false positive rate for given threshold and dimensions."""
    try:
        log_prob = log_tightest_cosine_bound(dimensions, threshold)
        return math.exp(log_prob)
    except:
        # Fallback to normal approximation
        z = threshold * math.sqrt(dimensions)
        return 0.5 * math.erfc(z / math.sqrt(2))


def calculate_empirical_tp(df: pd.DataFrame, threshold: float, corruption: str, noise_column: str) -> float:
    """Calculate empirical true positive rate for a specific corruption and column."""
    corruption_data = df[df['corruption'] == corruption]

    if len(corruption_data) == 0:
        return 0.0

    # TP: fraction of samples above threshold (detected as watermarked)
    detections = (corruption_data[noise_column] >= threshold).sum()
    total = len(corruption_data)

    return detections / total if total > 0 else 0.0


def generate_threshold_range(df: pd.DataFrame, columns: List[str]) -> np.ndarray:
    """Generate a range of thresholds based on the data distribution across columns."""
    all_values = []
    for col in columns:
        if col in df.columns:
            all_values.extend(df[col].dropna().values)
    
    if not all_values:
        return np.linspace(0, 1, 200)
    
    min_val = min(all_values)
    max_val = max(all_values)
    
    # Create threshold range from slightly below min to slightly above max
    margin = (max_val - min_val) * 0.1
    return np.linspace(max(0, min_val - margin), min(1, max_val + margin), 200)


def _extract_parenthetical(text: str) -> str:
    """Return the substring inside the last pair of parentheses, or the original if none."""
    import re
    if not text:
        return text
    matches = list(re.finditer(r"\(([^()]*)\)", text))
    if matches:
        return matches[-1].group(1).strip()
    return text


def _gs_threshold_bits_for_fpr(total_bits: int, target_fpr: float) -> int:
    """Find the smallest bit threshold k such that P[X>=k] <= target_fpr for X~Binom(n=total_bits,p=0.5)."""
    if target_fpr <= 0:
        return total_bits
    if target_fpr >= 1:
        return 0
    lo, hi = 0, total_bits
    # monotone decreasing in k
    while lo <= hi:
        mid = (lo + hi) // 2
        fp = float(sp.betainc(mid + 1, total_bits - mid, 0.5))
        if fp > target_fpr:
            lo = mid + 1
        else:
            hi = mid - 1
    return max(0, min(total_bits, lo))


def infer_dimensions_from_config(config_path: str) -> int:
    """Infer the latent space dimensions from model configuration."""
    import yaml
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        model_type = config.get('model_type', '').lower()
        width = config.get('image_width', 512)
        height = config.get('image_height', 512)
        
        if model_type == 'flux':
            return 4096 * 64  # 262,144 dimensions
        elif model_type in ['sdxl', 'sd1_4', 'sd2_0']:
            # Standard SD models: 4 channels, height//8, width//8
            return 4 * (height // 8) * (width // 8)
        else:
            # Default fallback
            return 4 * (height // 8) * (width // 8)
            
    except Exception as e:
        print(f"Warning: Could not read config {config_path}: {e}")
        # Default to SD dimensions for 512x512
        return 4 * 64 * 64  # 16,384


def format_corruption_name(corruption: str) -> str:
    import re
    """Format corruption names for display, including inversion/SDEdit model where available."""
    name_mapping = {
        'jpeg_corruption': 'JPEG Compression',
        'gaussian_blur': 'Gaussian Blur',
        'gaussian_noise': 'Gaussian Noise',
        'brightness_change': 'Brightness Change',
        'contrast_change': 'Contrast Change',
        'resize': 'Resize',
    }
    
    # Handle SDEdit variations with model and noise strength
    if 'sdedit' in corruption.lower():
        # Prefer explicit ns pattern: sdedit_<model>_ns<eps>
        m = re.match(r'^sdedit_([^_]+(?:_[^_]+)*)_ns([\d.]+)$', corruption, flags=re.IGNORECASE)
        if m:
            model_tok, eps = m.group(1), m.group(2)
            pretty_model = format_model_name(model_tok.lower())
            return f'SDEdit ({pretty_model}, ε={eps})'
        # Cross shorthand: sdedit_cross_<eps>
        m = re.match(r'^sdedit_cross_([\d.]+)$', corruption, flags=re.IGNORECASE)
        if m:
            eps = m.group(1)
            return f'SDEdit (Cross, ε={eps})'
        # Model without epsilon: sdedit_<model>
        m = re.match(r'^sdedit_([^_]+(?:_[^_]+)*)$', corruption, flags=re.IGNORECASE)
        if m:
            model_tok = m.group(1)
            pretty_model = format_model_name(model_tok.lower())
            return f'SDEdit ({pretty_model})'
        return 'SDEdit'
    
    # Handle inversion attack variations
    if corruption.lower().startswith('inversion'):
        # Examples: inversion_sdxl_sw0.3, inversion_sd2_0_sw0.5, inversion_sd1_4
        import re
        m = re.search(r'^inversion_(.+?)(?:_sw([\d.]+))?$', corruption, flags=re.IGNORECASE)
        model_tok = m.group(1) if m else None
        sw = m.group(2) if m else None
        pretty_model = format_model_name((model_tok or '').lower()) if model_tok else None
        if pretty_model and sw:
            return f'Inversion Attack ({pretty_model}, w={sw})'
        if pretty_model:
            return f'Inversion Attack ({pretty_model})'
        if sw:
            return f'Inversion Attack (w={sw})'
        return 'Inversion Attack'

    return name_mapping.get(corruption, corruption.replace('_', ' ').title())


def corruption_family(name: str) -> str:
    """Infer family/type from corruption name for grouping parameter variants."""
    lname = name.lower()
    if lname == 'baseline':
        return 'baseline'
    for fam in ['jpeg_corruption', 'gaussian_blur', 'gaussian_noise', 'brightness_change', 'resize']:
        if lname.startswith(fam):
            return fam
    if lname.startswith('sdedit'):
        # Split SDEdit by model so each model gets its own subplot
        import re
        # Match sdedit_<model>_ns<eps> or sdedit_<model>
        m = re.match(r'^sdedit_([^_]+(?:_[^_]+)*?)(?:_ns[\d.]+)?$', name, flags=re.IGNORECASE)
        if m:
            model_tok = m.group(1)
            return f'sdedit_{model_tok}'
        return 'sdedit'
    if lname.startswith('inversion'):
        # Split inversion by model so each model gets its own subplot
        import re
        m = re.search(r'^inversion_(.+?)(?:_sw[\d.]+)?$', name, flags=re.IGNORECASE)
        if m:
            model_tok = m.group(1)
            return f'inversion_{model_tok}'
        return 'inversion'
    # Fallback to prefix before first underscore
    return lname.split('_')[0]


def extract_level(name: str) -> float:
    """Extract numeric severity/level from corruption name for sorting within family."""
    import re
    patterns = ['ns', 'std', 'sw', 'q', 'r', 'f', 's']
    for p in patterns:
        m = re.search(rf'{p}([-+]?[0-9]*\.?[0-9]+)', name)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                pass
    # Fallback: last numeric value
    nums = re.findall(r'([-+]?[0-9]*\.?[0-9]+)', name)
    if nums:
        try:
            return float(nums[-1])
        except Exception:
            return 0.0
    return 0.0




def group_corruptions_by_family(df: pd.DataFrame) -> Dict[str, List[str]]:
    """Group corruptions by family for PDF generation."""
    families = {}

    for corruption in df['corruption'].unique():
        if corruption == 'baseline':
            continue
        family = corruption_family(corruption)
        if family not in families:
            families[family] = []
        families[family].append(corruption)

    # Sort corruptions within each family by level. For families where higher
    # numeric value means less corruption (e.g., JPEG quality, Resize scale),
    # reverse the order so the figure shows more severe to the right consistently.
    for family in families:
        families[family].sort(key=extract_level)
        if family in ['resize', 'jpeg_corruption']:
            families[family].reverse()

    return families




def create_family_analysis_figure(
    df: pd.DataFrame,
    family_data: List[str],
    dimensions: int,
    threshold: float,
    vae_column: str,
    inv_column: str,
    prc_data=None,
    gs_data=None,
    config_path=None,
    image_id: str = "latent_0",
    image_id2: Optional[str] = None,
    fpr_power: int = 128
) -> Figure:
    """Create a 2-row family analysis figure with square subplots.

    Layout (GridSpec):
    - Row 1: 3 ROC plots + 3 quality plots (6 axes total)
      • ROC spans 2 cols each: [0:2], [2:4], [4:6]
      • Quality spans 2 cols each: [6:8], [8:10], [10:12]
    - Row 2: Single row with 8 tiles: Original (A) + 3 corruptions, then Original (B) + 3 corruptions

    Using height ratios [4, 2.4] keeps each axis approximately square.
    """
    family_name = corruption_family(family_data[0]) if family_data else "Unknown"

    # We design the grid explicitly so that squares fit:
    # - 12 columns total; top row has 6 plots (2 cols each), bottom row has 4 images (3 cols each)
    COLS = 12
    # Derive a figure size proportional to the grid to keep squares neat in PDF
    base_unit = 1.2  # inches per grid unit (tuned for readability)
    fig_w = COLS * base_unit
    # Tie height to width so square axes consume most vertical space
    fig_h = fig_w * 0.4
    fig = plt.figure(figsize=(fig_w, fig_h))
    gs = fig.add_gridspec(
        2,
        COLS,
        height_ratios=[4, 2.4],
        hspace=0.01,
        wspace=0.80,
    )
    try:
        # Build a nicely formatted family title, with pretty model names
        fam = family_name.lower()
        title_core = None
        if fam == 'jpeg_corruption':
            title_core = 'JPEG Compression'
        elif fam == 'gaussian_blur':
            title_core = 'Gaussian Blur'
        elif fam == 'gaussian_noise':
            title_core = 'Gaussian Noise'
        elif fam == 'brightness_change':
            title_core = 'Brightness Change'
        elif fam == 'resize':
            title_core = 'Resize'
        elif fam.startswith('sdedit_'):
            model_tok = fam.split('_', 1)[1]
            title_core = f"SDEdit ({format_model_name(model_tok)})"
        elif fam == 'sdedit':
            title_core = 'SDEdit'
        elif fam.startswith('inversion_'):
            model_tok = fam.split('_', 1)[1]
            title_core = f"Inversion Attack ({format_model_name(model_tok)})"
        elif fam == 'inversion':
            title_core = 'Inversion Attack'
        else:
            title_core = family_name.replace('_', ' ').title()

        # Make the main title closer to the plots by nudging its y and
        # pulling the subplots up toward the title.
        fig.suptitle(
            f"{title_core} Attacks",
            fontsize=16,
            fontweight='bold',
            y=0.985,
        )
        fig.subplots_adjust(top=0.965)
    except Exception:
        pass

    # ===== ROW 1: Combined ROC + Quality Metrics =====
    print(f"    Creating combined ROC + quality row...")
    # For ROC, drive the x-axis by target FPRs and map to cosine thresholds analytically.
    # This ensures curves are visible even when data-driven thresholds map to vanishing FPRs.
    thresholds = generate_threshold_range(df, [vae_column, inv_column])  # kept for potential future use
    roc_exponents = np.linspace(0, 128, 33)  # 33 points from 2^0 to 2^-128
    roc_fprs = 2.0 ** (-roc_exponents)
    roc_thresholds = [find_cosine_threshold_log(dimensions, -k * math.log(2.0)) for k in roc_exponents]

    # Show up to 3 ROC plots (left half of the row)
    max_rocs = min(3, len(family_data))
    legend_handles, legend_labels = None, None
    shared_y_ax = None
    for i, corruption in enumerate(family_data[:max_rocs]):
        # Span 2 columns per ROC axis: [0:2], [2:4], [4:6]
        if shared_y_ax is None:
            ax = fig.add_subplot(gs[0, 2 * i : 2 * (i + 1)])
            shared_y_ax = ax
        else:
            ax = fig.add_subplot(gs[0, 2 * i : 2 * (i + 1)], sharey=shared_y_ax)
        try:
            ax.set_box_aspect(1)
        except Exception:
            pass
        has_data = False

        # Plot VAE method
        if vae_column in df.columns:
            tp_rates = [
                calculate_empirical_tp(df, thr, corruption, vae_column)
                for thr in roc_thresholds
            ]
            if tp_rates:
                ax.plot(roc_fprs, tp_rates, color='blue', label='Ours',
                       marker='o', linestyle='-', markersize=2, linewidth=1.5, alpha=0.8, zorder=10)
                has_data = True

        # Plot inversion method
        if inv_column in df.columns:
            tp_rates = [
                calculate_empirical_tp(df, thr, corruption, inv_column)
                for thr in roc_thresholds
            ]
            if tp_rates:
                ax.plot(roc_fprs, tp_rates, color='red', label='WIND',
                       marker='s', linestyle='-', markersize=2, linewidth=1.5, alpha=0.8, zorder=7)
                has_data = True

        # Plot PRC method with proper FPR mapping via analytic threshold
        if prc_data is not None:
            prc_sub = prc_data[prc_data['corruption'] == corruption]
            if not prc_sub.empty and {'sum_log_plus','sum_log_prod','const'}.issubset(prc_sub.columns):
                # Choose a range of target FPRs (powers of 2) and compute per-image thresholds
                exponents = np.linspace(0, 128, 33)  # 33 points from 2^0 to 2^-128
                fprs = 2.0 ** (-exponents)
                tp_rates = []
                ln2 = math.log(2.0)
                for k in exponents:
                    # threshold(fpr=2^-k) = sqrt(2*const*k*ln2) + 0.5*sum_log_prod
                    thr = np.sqrt(2.0 * prc_sub['const'].values * (k * ln2)) + 0.5 * prc_sub['sum_log_prod'].values
                    detections = (prc_sub['sum_log_plus'].values >= thr)
                    total = detections.size
                    tp_rates.append(float(detections.sum() / total) if total > 0 else 0.0)

                ax.plot(fprs, tp_rates, color='green', label='PRC',
                        marker='D', linestyle='-', markersize=2, linewidth=1.2, alpha=0.8, zorder=6)
                has_data = True

        # Plot GS method using target FPRs and per-FPR bit thresholds
        if gs_data is not None:
            gs_sub = gs_data[gs_data['corruption'] == corruption]
            if not gs_sub.empty and 'correct_bits' in gs_sub.columns:
                if 'latent_length' in gs_sub.columns and not gs_sub['latent_length'].isna().all():
                    total_bits = int(gs_sub['latent_length'].iloc[0])
                else:
                    total_bits = 256

                # Choose target FPRs as powers of two down to 2^-128
                exponents = np.linspace(0, 128, 33)
                fprs = 2.0 ** (-exponents)
                tp_rates = []
                bits = gs_sub['correct_bits'].astype(int).to_numpy()
                for k in exponents:
                    thr_bits = _gs_threshold_bits_for_fpr(total_bits, 2.0 ** (-k))
                    tp = float(np.mean(bits >= thr_bits)) if bits.size > 0 else 0.0
                    tp_rates.append(tp)

                ax.plot(fprs, tp_rates, color='purple', label='GS',
                        marker='^', linestyle='-', markersize=2, linewidth=1.2, alpha=0.8, zorder=5)
                has_data = True

        if has_data:
            attack_name = (
                _clean_corr_name(corruption) if _clean_corr_name else format_corruption_name(corruption)
            )
            # Only show the specification (content in parentheses)
            spec = _extract_parenthetical(attack_name)
            ax.set_title(f"{spec}", fontsize=14, pad=4, fontweight='bold')
            ax.set_xlabel('FPR', fontsize=12)
            # Give each ROC subplot its own y-axis label
            ax.set_ylabel('TPR', fontsize=12, labelpad=2)
            ax.set_xscale('log', base=2)
            ax.set_xlim(1e-40, 1)
            ax.set_ylim(-0.05, 1.05)
            ax.grid(True, alpha=0.3)
            ax.tick_params(labelsize=8)
            # Improve x-axis tick resolution and readability on log2 FPR
            try:
                ax.xaxis.set_major_locator(LogLocator(base=2.0, numticks=7))
            except Exception:
                pass

            
            # Collect legend entries once
            if legend_handles is None:
                legend_handles, legend_labels = ax.get_legend_handles_labels()

    # Prepare data for quality metrics (right half of the row)
    print(f"    Adding quality metrics to top row...")

    # Prepare data for quality metrics plotting
    data = []
    for corr in family_data:
        sub = df[df['corruption'] == corr]
        if sub.empty:
            continue

        psnr_mean = sub['psnr'].dropna().mean() if 'psnr' in sub.columns else np.nan
        ssim_mean = sub['ssim'].dropna().mean() if 'ssim' in sub.columns else np.nan
        lpips_mean = sub['lpips'].dropna().mean() if 'lpips' in sub.columns else np.nan

        tpr_vae = calculate_empirical_tp(df, threshold, corr, vae_column) if vae_column in df.columns else None
        tpr_inv = calculate_empirical_tp(df, threshold, corr, inv_column) if inv_column in df.columns else None

        # Calculate PRC TPR
        tpr_prc = None
        if prc_data is not None:
            prc_sub = prc_data[prc_data['corruption'] == corr]
            if not prc_sub.empty:
                tpr_prc = float(prc_sub['prc_detect'].mean())

        # Calculate GS TPR at fixed FPR using bit-tail threshold
        tpr_gs = None
        if gs_data is not None:
            gs_sub = gs_data[gs_data['corruption'] == corr]
            if not gs_sub.empty and {'correct_bits','latent_length'}.issubset(gs_sub.columns):
                total_bits = int(gs_sub['latent_length'].iloc[0]) if not gs_sub['latent_length'].isna().all() else 256
                target_fpr = 2.0 ** (-fpr_power)
                thr_bits = _gs_threshold_bits_for_fpr(total_bits, target_fpr)
                bits = gs_sub['correct_bits'].astype(int).to_numpy()
                tpr_gs = float(np.mean(bits >= thr_bits)) if bits.size > 0 else 0.0

        data.append({
            'corruption': corr,
            'level': extract_level(corr),
            'psnr': psnr_mean,
            'ssim': ssim_mean,
            'lpips': lpips_mean,
            'tpr_vae': tpr_vae,
            'tpr_inv': tpr_inv,
            'tpr_prc': tpr_prc,
            'tpr_gs': tpr_gs
        })

    data.sort(key=lambda x: x['level'])

    metrics = ['ssim', 'psnr', 'lpips']
    labels = ['SSIM', 'PSNR (dB)', 'LPIPS']

    for i, (metric, label) in enumerate(zip(metrics, labels)):
        # Span 2 columns per quality axis on the right: [6:8], [8:10], [10:12]
        ax = fig.add_subplot(gs[0, 6 + 2 * i : 6 + 2 * (i + 1)], sharey=shared_y_ax)
        try:
            ax.set_box_aspect(1)
        except Exception:
            pass

        # Plot all methods
        methods = [
            ('tpr_vae', 'o', 'blue', 'Ours'),
            ('tpr_inv', 's', 'red', 'WIND'),
            ('tpr_prc', 'D', 'green', 'PRC'),
            ('tpr_gs', '^', 'purple', 'GS')
        ]

        for tpr_key, marker, color, label_name in methods:
            x_vals = [d[metric] for d in data if not np.isnan(d[metric]) and d[tpr_key] is not None]
            y_vals = [d[tpr_key] for d in data if not np.isnan(d[metric]) and d[tpr_key] is not None]
            if x_vals:
                z = 10 if label_name == 'Ours' else 5
                ax.plot(x_vals, y_vals, color=color, label=label_name,
                        marker=marker, linestyle='-', markersize=4, linewidth=1.5, alpha=0.8, zorder=z)

        ax.set_title(f'TPR@FPR=$2^{{-{fpr_power}}}$ vs {label}', fontsize=9, pad=3, fontweight='bold')
        ax.set_xlabel(label, fontsize=12)
        # Each quality metric subplot gets its own y-axis label
        ax.set_ylabel(f'TPR@FPR=$2^{{-{fpr_power}}}$', fontsize=10, labelpad=2)
        ax.set_ylim(-0.05, 1.05)
        ax.grid(True, alpha=0.3)
        ax.tick_params(labelsize=6)
        # Slightly denser x-axis tick marks for readability on linear scales
        try:
            ax.xaxis.set_major_locator(MaxNLocator(nbins=5, min_n_ticks=5))
        except Exception:
            pass

        # Flip LPIPS x-axis so lower (better) is to the right
        if metric == 'lpips':
            try:
                ax.invert_xaxis()
            except Exception:
                pass

        # Collect legend entries if not already
        if legend_handles is None:
            legend_handles, legend_labels = ax.get_legend_handles_labels()

    # Add a single shared legend outside the plots (top center)
    if legend_handles:
        try:
            fig.legend(
                legend_handles,
                legend_labels,
                loc='upper center',
                bbox_to_anchor=(0.5, 0.95),
                ncol=min(4, len(legend_labels)),
                fontsize=10,
                frameon=False,
            )
        except Exception:
            pass

    # ===== ROW 2: Image Comparisons (both images in one row) =====
    print(f"    Creating single-row image comparison...")

    if config_path:
        # Load image data
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Resolve directories robustly from config paths when available
        original_dir_cfg = config.get('output_dir')  # typically .../generated_images
        results_file_cfg = config.get('results_file')
        if original_dir_cfg:
            original_dir = Path(original_dir_cfg)
        elif results_file_cfg:
            original_dir = Path(results_file_cfg).parent / "generated_images"
        else:
            # Fallback by model_type mapping
            model_type = config.get('model_type', '').lower()
            model_map = {
                'flux': 'FLUX',
                'flux_schnell': 'FLUX_schnell',
                'flux-schnell': 'FLUX_schnell',
                'sdxl': 'SDXL',
                'sd2_0': 'SD2_0',
                'sd1_4': 'SD1_4',
            }
            model_name = model_map.get(model_type, format_model_name(model_type))
            original_dir = Path(f"out/robustness_tests/{model_name}/generated_images")

        corruption_dir = Path(original_dir) / "corruptions"

        def _resolve_original(path_dir: Path, preferred: Optional[str]) -> Optional[Path]:
            """Return a valid original image path given preferred id or fallback."""
            if preferred:
                p = path_dir / f"{preferred}.png"
                if p.exists():
                    return p
            files = sorted(path_dir.glob("latent_*.png"))
            return files[0] if files else None

        def _collect_corruptions_for(stem: str) -> List[tuple[str, Path]]:
            """Collect all corruption images for a given image stem in this family."""
            collected: List[tuple[str, Path]] = []
            for corr in family_data:
                corr_dir_name = corr
                if corr.startswith('sdedit_'):
                    import re as _re
                    m = _re.search(r'_ns([\d.]+)$', corr)
                    if m:
                        corr_dir_name = f"sdedit_ns{m.group(1)}"
                elif corr.startswith('inversion_'):
                    import re as _re
                    m = _re.search(r'_sw([\d.]+)$', corr)
                    if m:
                        corr_dir_name = f"inversion_attack_sw{m.group(1)}"
                corr_type_dir = corruption_dir / corr_dir_name
                if corr_type_dir.exists():
                    files = sorted(corr_type_dir.glob(f"{stem}_*.png"))
                    if files:
                        collected.append((corr, files[0]))
            return collected

        # Resolve originals
        original_path_1 = _resolve_original(original_dir, image_id)
        if original_path_1 is None:
            return fig
        if image_id2:
            original_path_2 = _resolve_original(original_dir, image_id2)
        else:
            original_path_2 = None
            all_latents = sorted(original_dir.glob("latent_*.png"))
            for p in all_latents:
                if p != original_path_1:
                    original_path_2 = p
                    break

        # Compose up to 8 tiles: [Orig A] + 3 corr A + [Orig B] + 3 corr B
        tiles: List[tuple[str, Optional[Path], Optional[Path]]] = []
        # Tuple: (kind, path_original, path_corruption)
        tiles.append(("origA", original_path_1, None))
        corr_A = _collect_corruptions_for(original_path_1.stem)
        if len(corr_A) > 3:
            print(f"    Note: Showing first 3 of {len(corr_A)} corruptions for {original_path_1.name}")
        for corr, p in corr_A[:3]:
            tiles.append((corr, None, p))

        if original_path_2 is not None:
            tiles.append(("origB", original_path_2, None))
            corr_B = _collect_corruptions_for(original_path_2.stem)
            if len(corr_B) > 3:
                print(f"    Note: Showing first 3 of {len(corr_B)} corruptions for {original_path_2.name}")
            for corr, p in corr_B[:3]:
                tiles.append((corr, None, p))

        # Limit to 8 tiles
        tiles = tiles[:8]

        # Create a subgrid for the 8 tiles in the bottom row
        sub = gs[1, :].subgridspec(1, 8, wspace=0.05)
        # Load original images once if needed for metric computation
        origA_img = Image.open(original_path_1)
        origB_img = Image.open(original_path_2) if original_path_2 is not None else None

        for i, entry in enumerate(tiles):
            kind, p_orig, p_corr = entry
            ax_img = fig.add_subplot(sub[0, i])
            if kind == "origA" and p_orig is not None:
                ax_img.imshow(origA_img)
                ax_img.set_title('Original (A)', fontweight='bold', fontsize=10)
            elif kind == "origB" and p_orig is not None and origB_img is not None:
                ax_img.imshow(origB_img)
                ax_img.set_title('Original (B)', fontweight='bold', fontsize=10)
            elif p_corr is not None:
                corr_img = Image.open(p_corr)
                # Determine which original to compare with
                ref_img = origA_img
                if origB_img is not None and (len(tiles) >= 5 and i >= 4):
                    ref_img = origB_img
                if compute_ssim_psnr_lpips:
                    ssim_v, psnr_v, lpips_v = compute_ssim_psnr_lpips(ref_img, corr_img)
                else:
                    ssim_v, psnr_v, lpips_v = float('nan'), float('nan'), float('nan')
                pretty = (_clean_corr_name(kind) if _clean_corr_name else format_corruption_name(kind))
                def _fmt(v, fmt):
                    try:
                        return fmt.format(v)
                    except Exception:
                        return 'n/a'
                ssim_s = _fmt(ssim_v, "{:.3f}") if np.isfinite(ssim_v) else 'n/a'
                psnr_s = _fmt(psnr_v, "{:.1f}") if np.isfinite(psnr_v) else 'n/a'
                lpips_s = _fmt(lpips_v, "{:.3f}") if np.isfinite(lpips_v) else 'n/a'
                mline = f"SSIM: {ssim_s}\nPSNR: {psnr_s} dB\nLPIPS: {lpips_s}"
                ax_img.imshow(corr_img)
                name = _extract_parenthetical(pretty)
                ax_img.set_title(f"{name}\n{mline}", fontsize=9, fontweight='bold')
            ax_img.axis('off')
            try:
                ax_img.set_box_aspect(1)
            except Exception:
                pass

    return fig




def load_additional_watermarking_data(config_path: str, fpr_power: int):
    """Load PRC and GS watermarking data if available."""
    # Infer PRC and GS paths from config
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    model_type = config.get('model_type', '').lower()
    # Map model type to output directories where applicable
    model_map = {
        'flux': 'FLUX',
        'flux_schnell': 'FLUX_schnell',
        'flux-schnell': 'FLUX_schnell',
        'sdxl': 'SDXL',
        'sd2_0': 'SD2_0',
        'sd1_4': 'SD1_4'
    }

    model_name = model_map.get(model_type)
    if not model_name:
        return None, None

    prc_path = f'out/prc_watermark/{model_name}/results.csv'
    gs_path = f'out/gaussian_shading/{model_name}/results.csv'

    # Load PRC data
    prc_data = None
    if Path(prc_path).exists():
        try:
            prc_df = pd.read_csv(prc_path)
            if {'sum_log_plus','sum_log_prod','const'}.issubset(prc_df.columns):
                # Compute PRC threshold and detection
                prc_df = prc_df.copy()
                prc_df['prc_threshold'] = np.sqrt(2*prc_df['const'] * (fpr_power * math.log(2))) + 0.5*prc_df['sum_log_prod']
                prc_df['prc_detect'] = prc_df['sum_log_plus'] >= prc_df['prc_threshold']
                prc_data = prc_df
                print(f"  Loaded PRC data from {prc_path}")
        except Exception as e:
            print(f"  Warning: Failed to read PRC CSV {prc_path}: {e}")

    # Load GS data
    gs_data = None
    if Path(gs_path).exists():
        try:
            gs_df = pd.read_csv(gs_path)
            if {'correct_bits','latent_length'}.issubset(gs_df.columns):
                gs_data = gs_df
                print(f"  Loaded GS data from {gs_path}")
        except Exception as e:
            print(f"  Warning: Failed to read GS CSV {gs_path}: {e}")

    return prc_data, gs_data


def generate_attack_pdfs(
    csv_path: str,
    config_path: str,
    output_dir: str,
    fpr_power: int = 128,
    image_id: str = "latent_0",
    image_id2: Optional[str] = None,
):
    """Generate comprehensive attack analysis PDFs - one per attack family."""
    print("Generating comprehensive attack PDFs...")

    # Load data
    df = pd.read_csv(csv_path)
    dimensions = infer_dimensions_from_config(config_path)

    # Calculate threshold for target FPR
    log_target = -fpr_power * math.log(2)
    threshold = find_cosine_threshold_log(dimensions, log_target)
    print(f"Using threshold {threshold:.6f} for FPR=2^-{fpr_power} (d={dimensions})")

    # Available columns
    vae_column = 'cosine_similarity_with_original_noise'
    inv_column = 'inversion_recovered_vs_original_noise'

    if vae_column not in df.columns:
        print(f"Error: Required column '{vae_column}' not found")
        return

    print(f"Available methods: VAE={vae_column in df.columns}, Inversion={inv_column in df.columns}")

    # Load additional watermarking methods
    prc_data, gs_data = load_additional_watermarking_data(config_path, fpr_power)
    if prc_data is not None:
        print(f"  Also found PRC watermarking data")
    if gs_data is not None:
        print(f"  Also found GS watermarking data")

    # Group corruptions by family
    families = group_corruptions_by_family(df)

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Generate PDF for each family
    for family, corruptions in families.items():
        print(f"\nGenerating PDF for {family} family ({len(corruptions)} levels)...")

        pdf_path = Path(output_dir) / f"{family}.pdf"

        with PdfPages(pdf_path) as pdf:
            # Single page: 2-row layout (top: plots, bottom: 8 image tiles)
            print(f"  Creating 2-row analysis layout")
            fig = create_family_analysis_figure(
                df,
                corruptions,
                dimensions,
                threshold,
                vae_column,
                inv_column,
                prc_data,
                gs_data,
                config_path,
                image_id=image_id,
                image_id2=image_id2,
                fpr_power=fpr_power
            )
            pdf.savefig(fig, bbox_inches='tight', dpi=300)
            plt.close(fig)

        print(f"  Saved: {pdf_path}")

    print(f"\n✅ Generated {len(families)} attack PDFs in: {output_dir}")


# Model configurations for shortcuts
MODELS = {
    'flux': {
        'config': 'configs/flux_config.yaml',
        'results': 'out/robustness_tests/FLUX/results.csv',
        'name': 'FLUX'
    },
    'flux-schnell': {
        'config': 'configs/flux_schnell_config.yaml',
        'results': 'out/robustness_tests/FLUX_schnell/results.csv',
        'name': 'FLUX_schnell'
    },
    'sdxl': {
        'config': 'configs/sdxl_config.yaml',
        'results': 'out/robustness_tests/SDXL/results.csv',
        'name': 'SDXL'
    },
    'sdxl-turbo': {
        'config': 'configs/sdxl_turbo.yaml',
        'results': 'out/robustness_tests/SDXL_turbo/results.csv',
        'name': 'SDXL_turbo'
    },
    'sdxl-pixelart': {
        'config': 'configs/sdxl_pixel_art_config.yaml',
        'results': 'out/robustness_tests/SDXL_PixelArt/results.csv',
        'name': 'SDXL_PixelArt'
    },
    'sd1.4': {
        'config': 'configs/sd1_4_config.yaml',
        'results': 'out/robustness_tests/SD1_4/results.csv',
        'name': 'SD1_4'
    },
    'sd2.0': {
        'config': 'configs/sd2_0_config.yaml',
        'results': 'out/robustness_tests/SD2_0/results.csv',
        'name': 'SD2_0'
    }
}

def format_model_name(model_key: str) -> str:
    """Return a nicely formatted model name for display (e.g., sd2_0 -> SD2.0)."""
    if not model_key:
        return ''
    key = model_key.lower()
    name_mapping = {
        'flux': 'FLUX',
        'flux_schnell': 'FLUX Schnell',
        'flux-schnell': 'FLUX Schnell',
        'sdxl': 'SDXL',
        'sdxl_turbo': 'SDXL Turbo',
        'sdxl-turbo': 'SDXL Turbo',
        'sdxl-pixelart': 'SDXL PixelArt',
        'sd1_4': 'SD1.4',
        'sd1-4': 'SD1.4',
        'sd2_0': 'SD2.0',
        'sd2-0': 'SD2.0',
    }
    if key in name_mapping:
        return name_mapping[key]
    if key.startswith('sd'):
        return key.replace('_', '.').replace('-', '.').upper()
    return model_key.replace('_', ' ').title()

# Model configurations for shortcuts
MODELS = {
    'flux': {
        'config': 'configs/flux_config.yaml',
        'results': 'out/robustness_tests/FLUX/results.csv',
        'name': 'FLUX'
    },
    'flux-schnell': {
        'config': 'configs/flux_schnell_config.yaml',
        'results': 'out/robustness_tests/FLUX_schnell/results.csv',
        'name': 'FLUX_schnell'
    },
    'sdxl': {
        'config': 'configs/sdxl_config.yaml', 
        'results': 'out/robustness_tests/SDXL/results.csv',
        'name': 'SDXL'
    },
    'sdxl-turbo': {
        'config': 'configs/sdxl_turbo.yaml',
        'results': 'out/robustness_tests/SDXL_turbo/results.csv',
        'name': 'SDXL_turbo'
    },
    'sdxl-pixelart': {
        'config': 'configs/sdxl_pixel_art_config.yaml',
        'results': 'out/robustness_tests/SDXL_PixelArt/results.csv', 
        'name': 'SDXL_PixelArt'
    },
    'sd1.4': {
        'config': 'configs/sd1_4_config.yaml',
        'results': 'out/robustness_tests/SD1_4/results.csv',
        'name': 'SD1_4'
    },
    'sd2.0': {
        'config': 'configs/sd2_0_config.yaml',
        'results': 'out/robustness_tests/SD2_0/results.csv',
        'name': 'SD2_0'
    }
}


def main():
    parser = argparse.ArgumentParser(description="Generate comprehensive attack analysis PDFs")

    # Allow either model shortcut or explicit paths
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("model", nargs='?', choices=MODELS.keys(),
                      help="Model shortcut (flux, sdxl, sd2.0, etc.)")
    group.add_argument("--csv", help="Path to results CSV file")

    parser.add_argument("--config", help="Path to model config YAML file")
    parser.add_argument("--output-dir", help="Output directory for plots")
    parser.add_argument("--fpr-power", type=int, default=128,
                       help="FPR power for fixed-FPR analysis (default: 128 for 2^-128)")
    parser.add_argument("--image-id", type=str, default="latent_0",
                       help="Image ID to use for qualitative comparisons (default: latent_0)")
    parser.add_argument("--image-id2", type=str, default=None,
                       help="Optional second image ID for a side-by-side comparison row")

    args = parser.parse_args()

    # Handle model shortcuts vs explicit paths
    if args.model:
        # Using model shortcut
        model_config = MODELS[args.model]
        csv_path = model_config['results']
        config_path = model_config['config']
        model_name = model_config['name']

        # Set default output directory if not provided
        if not args.output_dir:
            args.output_dir = f"figures/attack_analysis_{model_name.lower()}"

        print(f"Using model shortcut: {args.model}")
    else:
        # Using explicit paths
        if not args.config:
            print("Error: --config is required when using --csv")
            sys.exit(1)
        if not args.output_dir:
            print("Error: --output-dir is required when using --csv")
            sys.exit(1)

        csv_path = args.csv
        config_path = args.config

    # Validate input files
    if not Path(csv_path).exists():
        print(f"Error: CSV file not found: {csv_path}")
        if args.model:
            print(f"       Run: ./scripts/run_generation.sh {args.model}")
            print(f"       Then: ./scripts/run_analysis.sh {args.model} [--invert]")
        sys.exit(1)

    if not Path(config_path).exists():
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)

    # Generate comprehensive attack PDFs
    print("📊 Generating comprehensive attack analysis...")
    print(f"📁 Results: {csv_path}")
    print(f"⚙️  Config: {config_path}")
    print(f"📂 Output: {args.output_dir}")
    print(f"🎯 FPR: 2^-{args.fpr_power}")

    generate_attack_pdfs(
        csv_path=csv_path,
        config_path=config_path,
        output_dir=args.output_dir,
        fpr_power=args.fpr_power,
        image_id=args.image_id,
        image_id2=args.image_id2,
    )


if __name__ == "__main__":
    main()
