#!/usr/bin/env python3
"""
Generate a comparison figure showing an original image and all its corruptions.

Usage:
    python utils/generate_corruption_comparison.py --image path/to/original/image.png
"""

import argparse
from pathlib import Path
import matplotlib.pyplot as plt
from PIL import Image

# Handle both module import and direct script execution
from seed_watermark.utils.image_metrics import compute_ssim_psnr_lpips


def find_corruption_images(original_image_path):
    """Find all corruption images corresponding to the original image.

    Also splits model-specific attacks into separate entries, e.g.:
    - SDEdit: sdedit_nsX -> sdedit_{model}_nsX (parsed from filename)
    - Inversion: inversion_attack_swY -> inversion_{model}_swY (parsed from filename)
    """
    original_path = Path(original_image_path)
    original_name = original_path.stem  # e.g., "latent_0"
    
    # Find the corruptions directory
    corruptions_dir = original_path.parent / "corruptions"
    
    if not corruptions_dir.exists():
        raise FileNotFoundError(f"Corruptions directory not found: {corruptions_dir}")
    
    corruption_images = {}
    
    # Look through each corruption type directory
    for corruption_type_dir in corruptions_dir.iterdir():
        if corruption_type_dir.is_dir():
            corruption_type = corruption_type_dir.name
            
            # Look for the corresponding corrupted image
            candidates = []
            for corruption_file in corruption_type_dir.iterdir():
                # Use more precise matching: must start with original_name followed by underscore or end
                if (corruption_file.stem.startswith(original_name + "_") or 
                    corruption_file.stem == original_name):
                    candidates.append(corruption_file)
            
            if not candidates:
                continue
            # Sort candidates to ensure consistent selection
            candidates.sort()

            # Special handling to split by model for SDEdit and inversion
            if corruption_type.startswith('sdedit_ns'):
                # Files are named like: <orig>_sdedit_<model>_ns<eps>_seed<...>.png
                import re
                for cf in candidates:
                    m = re.search(r'_sdedit_(.+?)_ns([\d.]+)', cf.stem)
                    if not m:
                        continue
                    model_tok, eps = m.group(1), m.group(2)
                    # Normalize model token by stripping trailing _config if present
                    model_tok = re.sub(r'_config$', '', model_tok, flags=re.IGNORECASE)
                    key = f"sdedit_{model_tok}_ns{eps}"
                    # First occurrence wins to keep deterministic
                    corruption_images.setdefault(key, cf)
                    print(f"  {key}: selected {cf.name}")
            elif corruption_type.startswith('inversion_attack_sw'):
                # Files are named like: <orig>_inversion_<model>_sw<weight>.png
                import re
                for cf in candidates:
                    m = re.search(r'_inversion_(.+?)_sw([\d.]+)', cf.stem)
                    if not m:
                        continue
                    model_tok, sw = m.group(1), m.group(2)
                    # Normalize model token by stripping trailing _config if present
                    model_tok = re.sub(r'_config$', '', model_tok, flags=re.IGNORECASE)
                    key = f"inversion_{model_tok}_sw{sw}"
                    corruption_images.setdefault(key, cf)
                    print(f"  {key}: selected {cf.name}")
            else:
                # Default: keep directory name as corruption key
                selected_file = candidates[0]
                corruption_images[corruption_type] = selected_file
                print(f"  {corruption_type}: found {len(candidates)} candidates, selected {selected_file.name}")
    
    return corruption_images


def calculate_image_metrics(original_img, corrupted_img):
    """Calculate SSIM, PSNR, and LPIPS between original and corrupted images."""
    return compute_ssim_psnr_lpips(original_img, corrupted_img)


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
    if key.startswith('sd'):
        return key.replace('_', '.').replace('-', '.').upper()
    return model_key.replace('_', ' ').title()


def clean_corruption_name(corruption_type):
    """Clean up corruption type names for display with smart parameter parsing."""
    import re
    
    # Handle base corruptions with parameters
    if corruption_type.startswith('jpeg_corruption_q'):
        quality = corruption_type.replace('jpeg_corruption_q', '')
        return f'JPEG Compression (Q={quality})'
    
    elif corruption_type.startswith('gaussian_blur_r'):
        radius = corruption_type.replace('gaussian_blur_r', '')
        return f'Gaussian Blur (r={radius})'
    
    elif corruption_type.startswith('gaussian_noise_std'):
        std = corruption_type.replace('gaussian_noise_std', '')
        return f'Gaussian Noise (σ={std})'
    
    elif corruption_type.startswith('brightness_change_f'):
        factor = corruption_type.replace('brightness_change_f', '')
        return f'Brightness Change (×{factor})'
    
    elif corruption_type.startswith('contrast_change_f'):
        factor = corruption_type.replace('contrast_change_f', '')
        return f'Contrast Change (×{factor})'
    
    elif corruption_type.startswith('resize_s'):
        scale = corruption_type.replace('resize_s', '')
        return f'Resize (×{scale})'
    
    # Handle SDEdit variations with noise strength
    elif 'sdedit' in corruption_type.lower():
        # Examples: sdedit_sd1_4_ns0.3, sdedit_sd2_0_ns0.5, sdedit_cross_0.5
        m = re.match(r'^sdedit_([^_]+(?:_[^_]+)*)_ns([\d.]+)$', corruption_type, flags=re.IGNORECASE)
        if m:
            model_tok, eps = m.group(1), m.group(2)
            model_tok = re.sub(r'_config$', '', model_tok, flags=re.IGNORECASE)
            pretty_model = _pretty_model_name(model_tok)
            return f'SDEdit ({pretty_model}, ε={eps})'
        m = re.match(r'^sdedit_cross_([\d.]+)$', corruption_type, flags=re.IGNORECASE)
        if m:
            eps = m.group(1)
            return f'SDEdit (Cross, ε={eps})'
        m = re.match(r'^sdedit_([^_]+(?:_[^_]+)*)$', corruption_type, flags=re.IGNORECASE)
        if m:
            model_tok = m.group(1)
            model_tok = re.sub(r'_config$', '', model_tok, flags=re.IGNORECASE)
            pretty_model = _pretty_model_name(model_tok)
            return f'SDEdit ({pretty_model})'
        return 'SDEdit'
    
    # Handle inversion attack variations
    elif corruption_type.lower().startswith('inversion'):
        # Examples: inversion_sdxl_sw0.3, inversion_sd2_0_sw0.5, inversion_sd1_4
        m = re.search(r'^inversion_(.+?)(?:_sw([\d.]+))?$', corruption_type, flags=re.IGNORECASE)
        model_tok = m.group(1) if m else None
        sw = m.group(2) if m else None
        if model_tok:
            model_tok = re.sub(r'_config$', '', model_tok, flags=re.IGNORECASE)
        pretty_model = _pretty_model_name(model_tok) if model_tok else None
        if pretty_model and sw:
            return f'Inversion Attack ({pretty_model}, w={sw})'
        if pretty_model:
            return f'Inversion Attack ({pretty_model})'
        if sw:
            return f'Inversion Attack (w={sw})'
        return 'Inversion Attack'
    
    # Fallback: just clean up underscores and capitalize
    return corruption_type.replace('_', ' ').title()


def generate_comparison_figure(original_image_path, output_path=None):
    """Generate a comparison figure with original and all corruptions."""
    original_path = Path(original_image_path)
    
    if not original_path.exists():
        raise FileNotFoundError(f"Original image not found: {original_path}")
    
    # Find corruption images
    corruption_images = find_corruption_images(original_image_path)
    
    if not corruption_images:
        print("No corruption images found")
        return
    
    print(f"Found {len(corruption_images)} corruption types:")
    for corruption_type in sorted(corruption_images.keys()):
        print(f"  - {corruption_type}")
    
    # Calculate grid dimensions dynamically
    total_images = 1 + len(corruption_images)  # original + corruptions
    cols = min(4, total_images)  # Maximum 4 columns, but can be fewer
    rows = (total_images + cols - 1) // cols  # Ceiling division
    
    # Create figure
    fig, axes = plt.subplots(rows, cols, figsize=(4*cols, 4*rows))
    
    # Handle single subplot case and flatten axes for easier indexing
    if total_images == 1:
        axes_flat = [axes]
    elif rows == 1 and cols == 1:
        axes_flat = [axes]
    elif rows == 1 or cols == 1:
        axes_flat = axes if hasattr(axes, '__len__') else [axes]
    else:
        axes_flat = axes.flatten()
    
    # Load and display original image
    original_img = Image.open(original_path)
    axes_flat[0].imshow(original_img)
    axes_flat[0].set_title('Original', fontweight='bold', fontsize=12)
    axes_flat[0].axis('off')
    
    # Load and display corruption images
    corruption_types = sorted(corruption_images.keys())
    for i, corruption_type in enumerate(corruption_types, 1):
        corruption_path = corruption_images[corruption_type]
        corruption_img = Image.open(corruption_path)
        
        # Calculate SSIM, PSNR, LPIPS for this corruption
        ssim_val, psnr_val, lpips_val = calculate_image_metrics(original_img, corruption_img)
        
        axes_flat[i].imshow(corruption_img)
        corruption_name = clean_corruption_name(corruption_type)
        lpips_str = f"{lpips_val:.3f}" if (lpips_val == lpips_val) else "n/a"  # handle NaN
        title = f"{corruption_name}\nSSIM: {ssim_val:.3f} | PSNR: {psnr_val:.1f}dB | LPIPS: {lpips_str}"
        axes_flat[i].set_title(title, fontsize=9)
        axes_flat[i].axis('off')
    
    # Hide unused subplots
    total_slots = rows * cols
    for i in range(total_images, total_slots):
        axes_flat[i].axis('off')
    
    # Adjust layout
    plt.tight_layout()
    
    # Determine output path
    if output_path is None:
        figures_dir = Path("figures")
        figures_dir.mkdir(exist_ok=True)
        output_path = figures_dir / f"{original_path.stem}_corruption_comparison.png"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save figure
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Comparison figure saved to: {output_path}")
    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Generate corruption comparison figure for an image",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--image", 
        required=True,
        help="Path to the original image"
    )
    parser.add_argument(
        "--output",
        help="Output path for the figure (default: figures/{image_stem}_corruption_comparison.png)"
    )
    
    args = parser.parse_args()
    
    try:
        output_path = generate_comparison_figure(args.image, args.output)
        print(f"Successfully generated comparison figure: {output_path}")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
