#!/usr/bin/env python3
"""
Generate ROC plots comparing multiple watermarking methods.

This script creates plots showing:
- Seed watermarking (cosine similarity based)
- DDIM inversion (WIND method)
- PRC watermarking (bit detection based)
- Gaussian Shading watermarking (bit detection based)

Each plot shows TP vs FP for a specific attack using all available methods.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import argparse
import math
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import scipy.special as sp
import yaml
from matplotlib.ticker import FuncFormatter

# Set style
plt.style.use('seaborn-v0_8-whitegrid')

# Import the high precision solver functions
sys.path.append(str(Path(__file__).parent))
try:
    from high_precision_cosine_solver import log_tightest_cosine_bound
except ImportError:
    print("Warning: Could not import high_precision_cosine_solver.py")


def calculate_analytical_fp_cosine(threshold: float, dimensions: int) -> float:
    """Calculate analytical false positive rate for cosine similarity threshold."""
    try:
        log_prob = log_tightest_cosine_bound(dimensions, threshold)
        return math.exp(log_prob)
    except:
        # Fallback to asymptotic approximation
        z = threshold * math.sqrt(dimensions)
        log_prob = sp.log_ndtr(-z)
        return math.exp(log_prob)


def calculate_analytical_fp_bits(k: int, n: int) -> float:
    """
    Calculate analytical false positive rate for bit detection.
    
    Args:
        k: Number of correct bits (threshold)
        n: Total number of bits
        
    Returns:
        False positive probability using betainc
    """
    if k >= n:
        return 0.0
    if k < 0:
        return 1.0
    
    # Using regularized incomplete beta function
    # P(X >= k) where X ~ Binomial(n, 0.5)
    return sp.betainc(k + 1, n - k, 0.5)


def calculate_empirical_tp_prc(df: pd.DataFrame, target_fpr: float, corruption: str) -> float:
    """
    Calculate empirical true positive rate for PRC detection at a target FPR.

    Uses stored sums: sum_log_plus, sum_log_prod, const to recompute the
    threshold for the given FPR, and counts detections where
    sum_log_plus >= threshold.
    """
    required = {"sum_log_plus", "sum_log_prod", "const"}
    if not required.issubset(df.columns):
        return 0.0
    data = df[df['corruption'] == corruption]
    if len(data) == 0:
        return 0.0
    const = data['const'].astype(float).to_numpy()
    sum_log_prod = data['sum_log_prod'].astype(float).to_numpy()
    sum_log_plus = data['sum_log_plus'].astype(float).to_numpy()
    const = np.maximum(const, 0.0)
    thr = np.sqrt(2.0 * const * np.log(1.0 / target_fpr)) + 0.5 * sum_log_prod
    det = (sum_log_plus >= thr).astype(np.float32)
    return float(det.mean()) if det.size > 0 else 0.0


def calculate_empirical_tp_cosine(df: pd.DataFrame, threshold: float, 
                                 corruption: str, noise_column: str) -> float:
    """Calculate empirical true positive rate for cosine similarity detection."""
    corruption_data = df[df['corruption'] == corruption]
    
    if len(corruption_data) == 0:
        return 0.0
    
    # TP: fraction of samples above threshold
    detections = (corruption_data[noise_column] >= threshold).sum()
    total = len(corruption_data)
    
    return detections / total if total > 0 else 0.0


def calculate_empirical_tp_bits(df: pd.DataFrame, threshold_bits: int, 
                               corruption: str, total_bits: int) -> float:
    """
    Calculate empirical true positive rate for bit detection.
    
    Args:
        df: DataFrame with results
        threshold_bits: Minimum number of correct bits for detection
        corruption: Corruption type to filter
        total_bits: Total number of bits in watermark
        
    Returns:
        True positive rate
    """
    corruption_data = df[df['corruption'] == corruption]
    
    if len(corruption_data) == 0:
        return 0.0
    
    # TP: fraction of samples with correct_bits >= threshold
    detections = (corruption_data['correct_bits'] >= threshold_bits).sum()
    total = len(corruption_data)
    
    return detections / total if total > 0 else 0.0


def load_watermarking_results(base_dir: Path, model_name: str) -> Dict:
    """
    Load all available watermarking results for a given model.
    
    Returns dict with keys:
        'seed': DataFrame from robustness_tests
        'prc': DataFrame from prc_watermark
        'gaussian': DataFrame from gaussian_shading
    """
    results = {}
    
    # Try to load seed watermarking results
    seed_path = base_dir / f"robustness_tests/{model_name}/results.csv"
    if seed_path.exists():
        results['seed'] = pd.read_csv(seed_path)
        print(f"  Loaded seed watermarking: {seed_path}")
    
    # Try to load PRC watermarking results
    prc_path = base_dir / f"prc_watermark/{model_name}/results.csv"
    if prc_path.exists():
        results['prc'] = pd.read_csv(prc_path)
        print(f"  Loaded PRC watermarking: {prc_path}")
    
    # Try to load Gaussian Shading results
    gs_path = base_dir / f"gaussian_shading/{model_name}/results.csv"
    if gs_path.exists():
        results['gaussian'] = pd.read_csv(gs_path)
        print(f"  Loaded Gaussian Shading: {gs_path}")
    
    return results


def get_model_dimensions(config_path: str) -> Dict[str, int]:
    """
    Get dimensions for different watermarking methods based on model config.
    
    Returns dict with:
        'cosine_dims': Dimensions for cosine similarity (seed watermarking)
        'prc_bits': Total bits for PRC watermarking
        'gs_bits': Total bits for Gaussian Shading
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        model_type = config.get('model_type', '').lower()
        width = config.get('image_width', 512)
        height = config.get('image_height', 512)
        
        # Cosine similarity dimensions
        if model_type == 'flux':
            cosine_dims = 4096 * 64  # 262,144 dimensions
        else:  # SD models
            cosine_dims = 4 * (height // 8) * (width // 8)
        
        # PRC bits (same as cosine dims for SD models)
        prc_bits = 4 * (height // 8) * (width // 8)
        
        # Gaussian Shading bits (depends on ch_factor and hw_factor)
        # Default: ch_factor=1, hw_factor=8
        latent_length = 4 * (height // 8) * (width // 8)
        gs_bits = latent_length // (1 * 8 * 8)  # Default: 256 for 512x512
        
        return {
            'cosine_dims': cosine_dims,
            'prc_bits': prc_bits,
            'gs_bits': gs_bits
        }
        
    except Exception as e:
        print(f"Warning: Could not read config {config_path}: {e}")
        # Default to SD2.0 512x512
        return {
            'cosine_dims': 16384,
            'prc_bits': 16384,
            'gs_bits': 256
        }


def _pretty_model_name(model_key: str) -> str:
    """Return a nicely formatted model name for display (e.g., sd2_0 -> SD2.0)."""
    key = (model_key or '').lower()
    mapping = {
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
    if key in mapping:
        return mapping[key]
    # Fallbacks
    if key.startswith('sd'):
        return key.replace('_', '.').replace('-', '.').upper()
    return model_key.replace('_', ' ').title()


def format_corruption_name(corruption: str) -> str:
    """Format corruption names for display, including inversion model where available."""
    import re
    
    # Handle base corruptions with parameters
    if corruption.startswith('jpeg_corruption_q'):
        quality = corruption.replace('jpeg_corruption_q', '')
        return f'JPEG Compression (Q={quality})'
    
    elif corruption.startswith('gaussian_blur_r'):
        radius = corruption.replace('gaussian_blur_r', '')
        return f'Gaussian Blur (r={radius})'
    
    elif corruption.startswith('gaussian_noise_std'):
        std = corruption.replace('gaussian_noise_std', '')
        return f'Gaussian Noise (σ={std})'
    
    elif corruption.startswith('brightness_change_f'):
        factor = corruption.replace('brightness_change_f', '')
        return f'Brightness Change (×{factor})'

    elif corruption.startswith('contrast_change_f'):
        factor = corruption.replace('contrast_change_f', '')
        return f'Contrast Change (×{factor})'
    
    elif corruption.startswith('resize_s'):
        scale = corruption.replace('resize_s', '')
        return f'Resize (×{scale})'
    
    # Handle SDEdit variations with noise strength
    elif 'sdedit' in corruption.lower():
        # Pattern examples:
        #  - sdedit_sd1_4_ns0.3 => model=sd1_4, eps=0.3
        #  - sdedit_sd2_0_ns0.5 => model=sd2_0, eps=0.5
        #  - sdedit_cross_0.5   => model=cross, eps=0.5
        m = re.match(r'^sdedit_([^_]+(?:_[^_]+)*)_ns([\d.]+)$', corruption, flags=re.IGNORECASE)
        if m:
            model_tok, eps = m.group(1), m.group(2)
            pretty_model = _pretty_model_name(model_tok)
            return f'SDEdit ({pretty_model}, ε={eps})'
        m = re.match(r'^sdedit_cross_([\d.]+)$', corruption, flags=re.IGNORECASE)
        if m:
            eps = m.group(1)
            return f'SDEdit (Cross, ε={eps})'
        m = re.match(r'^sdedit_([^_]+(?:_[^_]+)*)$', corruption, flags=re.IGNORECASE)
        if m:
            model_tok = m.group(1)
            pretty_model = _pretty_model_name(model_tok)
            return f'SDEdit ({pretty_model})'
        return 'SDEdit'
    
    # Handle inversion attack variations
    elif corruption.lower().startswith('inversion'):
        # Examples: inversion_sdxl_sw0.3, inversion_sd2_0_sw0.5, inversion_sd1_4
        m = re.search(r'^inversion_(.+?)(?:_sw([\d.]+))?$', corruption, flags=re.IGNORECASE)
        model_tok = m.group(1) if m else None
        sw = m.group(2) if m else None
        pretty_model = _pretty_model_name(model_tok) if model_tok else None
        if pretty_model and sw:
            return f'Inversion Attack ({pretty_model}, w={sw})'
        if pretty_model:
            return f'Inversion Attack ({pretty_model})'
        if sw:
            return f'Inversion Attack (w={sw})'
        return 'Inversion Attack'
    
    # Fallback: just clean up underscores and capitalize
    return corruption.replace('_', ' ').title()


def create_comparison_plots(results: Dict, config_path: str, output_dir: str,
                          figsize: Tuple[float, float] = (10, 6)):
    """Generate ROC plots comparing all available watermarking methods."""
    
    # Get dimensions for each method
    dims = get_model_dimensions(config_path)
    print(f"Model dimensions: {dims}")
    
    # Get all corruption types (exclude baseline)
    all_corruptions = set()
    for method_df in results.values():
        if 'corruption' in method_df.columns:
            all_corruptions.update(method_df['corruption'].unique())
    
    corruptions = sorted([c for c in all_corruptions if c != 'baseline'])
    print(f"Found {len(corruptions)} attack types: {corruptions}")
    
    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Generate one plot per corruption
    for corruption in corruptions:
        print(f"\nGenerating comparison plot for: {corruption}")
        
        # Create the plot
        fig, ax = plt.subplots(1, 1, figsize=figsize)
        has_data = False
        
        # Plot seed watermarking (cosine similarity based)
        if 'seed' in results:
            df = results['seed']
            vae_column = 'cosine_similarity_with_original_noise'
            if vae_column in df.columns:
                # Generate thresholds for cosine similarity
                thresholds_cosine = np.linspace(0, 1, 100)
                fp_rates = []
                tp_rates = []
                
                for threshold in thresholds_cosine:
                    fp_rate = calculate_analytical_fp_cosine(threshold, dims['cosine_dims'])
                    tp_rate = calculate_empirical_tp_cosine(df, threshold, corruption, vae_column)
                    fp_rates.append(fp_rate)
                    tp_rates.append(tp_rate)
                
                if fp_rates:
                    ax.plot(fp_rates, tp_rates, 'o-',
                           color='blue', label='Seed Watermarking',
                           markersize=3, linewidth=2, alpha=0.8)
                    has_data = True
            
            # Also check for DDIM inversion (WIND)
            inv_column = 'inversion_recovered_vs_original_noise'
            if inv_column in df.columns:
                corruption_data = df[df['corruption'] == corruption]
                if not corruption_data[inv_column].isna().all():
                    fp_rates_inv = []
                    tp_rates_inv = []
                    
                    for threshold in thresholds_cosine:
                        fp_rate = calculate_analytical_fp_cosine(threshold, dims['cosine_dims'])
                        tp_rate = calculate_empirical_tp_cosine(df, threshold, corruption, inv_column)
                        fp_rates_inv.append(fp_rate)
                        tp_rates_inv.append(tp_rate)
                    
                    if fp_rates_inv:
                        ax.plot(fp_rates_inv, tp_rates_inv, 's-',
                                color='red', label='WIND (DDIM)',
                                markersize=3, linewidth=2, alpha=0.8)
                        has_data = True
        
        # Plot PRC watermarking (true PRC)
        if 'prc' in results:
            df = results['prc']
            if {'sum_log_plus', 'sum_log_prod', 'const'}.issubset(df.columns):
                # Sweep a set of target FPRs directly on x-axis (down to 1e-40)
                fp_rates_prc = np.logspace(-40, -2, 60)
                tp_rates_prc = [calculate_empirical_tp_prc(df, fpr, corruption) for fpr in fp_rates_prc]
                # Add ROC anchor at (FPR=1, TPR=1) and sort in descending FPR so the curve starts at (1,1)
                x = np.r_[1.0, fp_rates_prc]
                y = np.r_[1.0, tp_rates_prc]
                order = np.argsort(-x)
                x, y = x[order], y[order]
                if len(y) > 0:
                    ax.plot(x, y, '^-',
                            color='green', label='PRC Watermarking',
                            markersize=3, linewidth=2, alpha=0.8)
                    has_data = True
            elif 'correct_bits' in df.columns:
                # Legacy PRC (bit counting) fallback
                total_bits = dims['prc_bits']
                min_bits = int(total_bits * 0.5)
                max_bits = total_bits
                threshold_bits_list = np.unique(np.logspace(
                    np.log10(min_bits), np.log10(max_bits), 50, dtype=int
                ))
                fp_rates_prc = []
                tp_rates_prc = []
                for threshold_bits in threshold_bits_list:
                    fp_rate = calculate_analytical_fp_bits(threshold_bits, total_bits)
                    tp_rate = calculate_empirical_tp_bits(df, threshold_bits, corruption, total_bits)
                    fp_rates_prc.append(fp_rate)
                    tp_rates_prc.append(tp_rate)
                if fp_rates_prc:
                    ax.plot(fp_rates_prc, tp_rates_prc, '^-',
                           color='green', label='PRC (legacy)',
                           markersize=3, linewidth=2, alpha=0.8)
                    has_data = True
        
        # Plot Gaussian Shading (bit detection based)
        if 'gaussian' in results:
            df = results['gaussian']
            if 'correct_bits' in df.columns:
                # For Gaussian Shading, total bits is in the latent_length column
                if 'latent_length' in df.columns:
                    total_bits = df['latent_length'].iloc[0]
                else:
                    total_bits = dims['gs_bits']
                
                # Generate thresholds for bit detection
                min_bits = int(total_bits * 0.5)  # Start from 50%
                max_bits = total_bits
                threshold_bits_list = np.unique(np.linspace(
                    min_bits, max_bits, 50, dtype=int
                ))
                
                fp_rates_gs = []
                tp_rates_gs = []
                
                for threshold_bits in threshold_bits_list:
                    fp_rate = calculate_analytical_fp_bits(threshold_bits, total_bits)
                    tp_rate = calculate_empirical_tp_bits(df, threshold_bits, corruption, total_bits)
                    fp_rates_gs.append(fp_rate)
                    tp_rates_gs.append(tp_rate)
                
                if fp_rates_gs:
                    ax.plot(fp_rates_gs, tp_rates_gs, 'D-',
                           color='orange', label='Gaussian Shading',
                           markersize=3, linewidth=2, alpha=0.8)
                    has_data = True
        
        # Only save plot if we have data
        if has_data:
            # Add title
            model_name = Path(config_path).stem.replace('_config', '')
            attack_name = format_corruption_name(corruption)
            ax.set_title(f"{_pretty_model_name(model_name)} - {attack_name}", fontsize=16, pad=20)
            
            # Format plot with base 2 log scale
            ax.set_xlabel('False Positive Rate', fontsize=14)
            ax.set_ylabel('True Positive Rate', fontsize=14)
            
            # Use base 2 logarithmic scale
            ax.set_xscale('log', base=2)
            ax.set_xlim(1e-40, 1)
            ax.set_ylim(-0.05, 1.05)
            ax.grid(True, alpha=0.3)
            ax.legend(fontsize=12, framealpha=0.9, loc='lower right')
            
            # Clean styling
            ax.tick_params(labelsize=12)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
            plt.tight_layout()
            
            # Create safe filename
            safe_corruption = corruption.replace('/', '_').replace(' ', '_').lower()
            
            # Save the plot
            pdf_path = Path(output_dir) / f"{safe_corruption}_comparison.pdf"
            png_path = Path(output_dir) / f"{safe_corruption}_comparison.png"
            
            plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.savefig(png_path, dpi=150, bbox_inches='tight', facecolor='white')
            
            print(f"  Saved: {pdf_path}")
            print(f"  Saved: {png_path}")
            
            plt.close()
        else:
            print(f"  Skipping {corruption} - no valid data")
            plt.close()
    
    # Create grid figure with all attacks
    print(f"\nGenerating grid figure with all attacks...")
    create_grid_figure(results, config_path, output_dir, corruptions, dims)


def create_grid_figure(results: Dict, config_path: str, output_dir: str,
                      corruptions: List[str], dims: Dict):
    """Create a grid figure showing all attacks in subplots."""
    
    # Calculate grid dimensions - 4 per row
    n_attacks = len(corruptions)
    cols = min(4, n_attacks)  # Maximum 4 columns
    rows = math.ceil(n_attacks / 4)  # Calculate rows needed for 4 per row
    
    # Set figure size
    figsize = (cols * 5, rows * 4)
    
    # Create the grid figure
    fig, axes = plt.subplots(rows, cols, figsize=figsize)
    
    # Handle single subplot case
    if n_attacks == 1:
        axes = [axes]
    elif rows == 1 or cols == 1:
        axes = axes.flatten() if hasattr(axes, 'flatten') else [axes]
    else:
        axes = axes.flatten()
    
    # Plot each attack in a subplot
    for i, corruption in enumerate(corruptions[:len(axes)]):
        ax = axes[i]
        has_data = False
        
        # Plot each watermarking method (simplified for grid)
        # Similar logic to individual plots but with smaller markers/lines
        
        # Seed watermarking
        if 'seed' in results:
            df = results['seed']
            vae_column = 'cosine_similarity_with_original_noise'
            if vae_column in df.columns:
                thresholds_cosine = np.linspace(0, 1, 50)  # Fewer points for grid
                fp_rates = []
                tp_rates = []
                
                for threshold in thresholds_cosine:
                    fp_rate = calculate_analytical_fp_cosine(threshold, dims['cosine_dims'])
                    tp_rate = calculate_empirical_tp_cosine(df, threshold, corruption, vae_column)
                    fp_rates.append(fp_rate)
                    tp_rates.append(tp_rate)
                
                if fp_rates:
                    ax.plot(fp_rates, tp_rates, 'o-',
                           color='blue', label='Ours' if i == 0 else "",
                           markersize=2, linewidth=1.5, alpha=0.8)
                    has_data = True
            
            # Also check for DDIM inversion (WIND) in grid
            inv_column = 'inversion_recovered_vs_original_noise'
            if inv_column in df.columns:
                corruption_data = df[df['corruption'] == corruption]
                if not corruption_data[inv_column].isna().all():
                    fp_rates_inv = []
                    tp_rates_inv = []
                    
                    for threshold in thresholds_cosine:
                        fp_rate = calculate_analytical_fp_cosine(threshold, dims['cosine_dims'])
                        tp_rate = calculate_empirical_tp_cosine(df, threshold, corruption, inv_column)
                        fp_rates_inv.append(fp_rate)
                        tp_rates_inv.append(tp_rate)
                    
                    if fp_rates_inv:
                        ax.plot(fp_rates_inv, tp_rates_inv, 's-',
                                color='red', label='WIND' if i == 0 else "",
                                markersize=2, linewidth=1.5, alpha=0.8)
                        has_data = True
        
        # PRC watermarking (grid)
        if 'prc' in results:
            df = results['prc']
            if {'sum_log_plus', 'sum_log_prod', 'const'}.issubset(df.columns):
                fp_rates_prc = np.logspace(-40, -2, 40)
                tp_rates_prc = [calculate_empirical_tp_prc(df, fpr, corruption) for fpr in fp_rates_prc]
                x = np.r_[1.0, fp_rates_prc]
                y = np.r_[1.0, tp_rates_prc]
                order = np.argsort(-x)
                x, y = x[order], y[order]
                if len(y) > 0:
                    ax.plot(x, y, '^-',
                            color='green', label='PRC' if i == 0 else "",
                            markersize=2, linewidth=1.5, alpha=0.8)
                    has_data = True
            elif 'correct_bits' in df.columns:
                total_bits = dims['prc_bits']
                min_bits = int(total_bits * 0.5)
                max_bits = total_bits
                threshold_bits_list = np.unique(np.logspace(
                    np.log10(min_bits), np.log10(max_bits), 30, dtype=int
                ))
                fp_rates_prc = []
                tp_rates_prc = []
                for threshold_bits in threshold_bits_list:
                    fp_rate = calculate_analytical_fp_bits(threshold_bits, total_bits)
                    tp_rate = calculate_empirical_tp_bits(df, threshold_bits, corruption, total_bits)
                    fp_rates_prc.append(fp_rate)
                    tp_rates_prc.append(tp_rate)
                if fp_rates_prc:
                    ax.plot(fp_rates_prc, tp_rates_prc, '^-',
                           color='green', label='PRC' if i == 0 else "",
                           markersize=2, linewidth=1.5, alpha=0.8)
                    has_data = True
        
        # Gaussian Shading
        if 'gaussian' in results:
            df = results['gaussian']
            if 'correct_bits' in df.columns:
                if 'latent_length' in df.columns:
                    total_bits = df['latent_length'].iloc[0]
                else:
                    total_bits = dims['gs_bits']
                
                min_bits = int(total_bits * 0.5)
                max_bits = total_bits
                threshold_bits_list = np.unique(np.linspace(
                    min_bits, max_bits, 30, dtype=int
                ))
                
                fp_rates_gs = []
                tp_rates_gs = []
                
                for threshold_bits in threshold_bits_list:
                    fp_rate = calculate_analytical_fp_bits(threshold_bits, total_bits)
                    tp_rate = calculate_empirical_tp_bits(df, threshold_bits, corruption, total_bits)
                    fp_rates_gs.append(fp_rate)
                    tp_rates_gs.append(tp_rate)
                
                if fp_rates_gs:
                    ax.plot(fp_rates_gs, tp_rates_gs, 'D-',
                           color='orange', label='GS' if i == 0 else "",
                           markersize=2, linewidth=1.5, alpha=0.8)
                    has_data = True
        
        # Format subplot
        if has_data:
            ax.set_title(format_corruption_name(corruption), fontsize=16, pad=12)
            
            # Use base 2 logarithmic scale
            ax.set_xscale('log', base=2)
            ax.set_xlim(1e-40, 1)
            ax.set_ylim(-0.05, 1.05)
            ax.grid(True, alpha=0.3)
            ax.tick_params(labelsize=12)
            
            # Only add legend to first subplot
            if i == 0:
                ax.legend(fontsize=12, framealpha=0.9)
            
            # Add axis labels only to bottom and left edges
            if i >= (rows - 1) * cols:  # Bottom row
                ax.set_xlabel('False Positive Rate', fontsize=14)
            if i % cols == 0:  # Left column
                ax.set_ylabel('True Positive Rate', fontsize=14)
        else:
            ax.set_visible(False)
    
    # Hide any remaining empty subplots
    for i in range(len(corruptions), len(axes)):
        axes[i].set_visible(False)
    
    plt.tight_layout()
    
    # Save the grid plot
    grid_path = Path(output_dir) / "comparison_grid.pdf"
    plt.savefig(grid_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"  Grid plot saved: {grid_path}")
    
    grid_png_path = Path(output_dir) / "comparison_grid.png"
    plt.savefig(grid_png_path, dpi=150, bbox_inches='tight', facecolor='white')
    print(f"  Grid PNG saved: {grid_png_path}")
    
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Generate ROC plots comparing watermarking methods")
    parser.add_argument("--model", default="SD2_0", help="Model name (e.g., SD2_0, SDXL)")
    parser.add_argument("--config", default="configs/sd2_0_config.yaml", 
                       help="Path to model config YAML file")
    parser.add_argument("--output-dir", default="figures/watermark_comparison",
                       help="Output directory for plots")
    parser.add_argument("--base-dir", default="out",
                       help="Base directory containing results")
    parser.add_argument("--figsize", nargs=2, type=float, default=[10, 6],
                       help="Figure size (width height)")
    
    args = parser.parse_args()
    
    # Validate config file
    if not Path(args.config).exists():
        print(f"Error: Config file not found: {args.config}")
        sys.exit(1)
    
    # Load all available watermarking results
    print(f"Loading watermarking results for {args.model}...")
    results = load_watermarking_results(Path(args.base_dir), args.model)
    
    if not results:
        print(f"Error: No watermarking results found for {args.model}")
        sys.exit(1)
    
    print(f"\nFound {len(results)} watermarking methods:")
    for method in results:
        print(f"  - {method}")
    
    # Generate the comparison plots
    print(f"\nGenerating comparison plots...")
    print(f"Config: {args.config}")
    print(f"Output: {args.output_dir}")
    
    create_comparison_plots(
        results=results,
        config_path=args.config,
        output_dir=args.output_dir,
        figsize=tuple(args.figsize)
    )
    
    print(f"\n✅ Comparison plots generated in: {args.output_dir}")


if __name__ == "__main__":
    main()
