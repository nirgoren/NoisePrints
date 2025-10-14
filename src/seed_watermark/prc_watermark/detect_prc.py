#!/usr/bin/env python3
"""
PRC Watermark Detection Script

Detects PRC watermarks in generated images using DDIM inversion and corruption testing.
Reports raw detection metrics for user analysis.
"""

import os
import sys
import argparse
import json
import torch
import numpy as np
from pathlib import Path
from PIL import Image
import yaml
from tqdm import tqdm
import csv
import logging
from typing import Dict, Any, Optional

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from src.seed_watermark.prc_watermark.prc_watermark import PRCWatermark
from src.seed_watermark.adversary_attacks.inversion_attack import DDIMInversion
from src.seed_watermark.robustness_tests.config import get_base_corruptions
from src.seed_watermark.robustness_tests.sdedit_corruption import get_sdedit_corruptions
from src.seed_watermark.robustness_tests.inversion_corruption import get_inversion_corruptions
from diffusers import StableDiffusionPipeline, StableDiffusionXLPipeline, DDIMScheduler
from src.seed_watermark.utils.image_metrics import compute_ssim_psnr_lpips

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)




def apply_corruptions_batch(image: Image.Image, corruptions: list, base_filename: str, output_dir: Path) -> dict:
    """Apply all corruptions to an image and return results."""
    corrupted_images = {}
    
    for corruption in corruptions:
        try:
            # Prepare context for corruption function
            corruption_context = {
                'output_dir': str(output_dir.parent),
                'base_filename': base_filename
            }
            
            # Apply corruption with context
            corruption_details = corruption["function"](image, **corruption_context)
            corrupted_image = corruption_details["image"]
            
            # Save corruption image if not already saved by the corruption function
            if not corruption_details.get("output_path"):
                # Create corruption-specific directory
                corruption_dir = output_dir.parent / "corruptions" / corruption['name']
                corruption_dir.mkdir(parents=True, exist_ok=True)
                
                # Save the corrupted image
                output_filename = f"{base_filename}_{corruption['name']}.png"
                output_path = corruption_dir / output_filename
                corrupted_image.save(output_path)
                logger.info(f"  Corruption image saved: {output_path}")
            
            # Store corrupted image and metadata
            corrupted_images[corruption['name']] = {
                "image": corrupted_image,
                "metadata": corruption_details.get("metadata", {}),
                "cleanup": corruption_details.get("cleanup")
            }
            
        except Exception as e:
            logger.error(f"Failed to apply {corruption['name']}: {e}")
            # Store original image as fallback
            corrupted_images[corruption['name']] = {
                "image": image,
                "metadata": {"error": str(e)},
                "cleanup": None
            }
    
    return corrupted_images


def detect_watermark_in_image(
    image_path: str,
    watermark_system: PRCWatermark,
    inverter: DDIMInversion,
    config: Dict[str, Any],
    corruptions: list = None
) -> Dict[str, Any]:
    """
    Detect watermark in a single image with optional corruptions.
    
    Args:
        image_path: Path to the image
        watermark_system: PRC watermark system
        inverter: DDIM inverter instance
        config: Configuration dictionary
        corruptions: List of corruption functions to apply
        
    Returns:
        Dictionary with detection results
    """
    results = {}
    image_name = Path(image_path).stem
    output_dir = Path(config['output_dir'])
    
    # Load original image
    original_image = Image.open(image_path).convert("RGB")
    
    # First, apply all corruptions and store corrupted images
    corrupted_images = {"baseline": {"image": original_image, "metadata": {}}}
    
    if corruptions:
        logger.debug(f"Applying corruptions to {image_name}")
        batch_results = apply_corruptions_batch(original_image, corruptions, image_name, output_dir)
        corrupted_images.update(batch_results)
    
    # Now test watermark detection on all images (baseline + corruptions)
    logger.debug(f"Testing watermark detection for {image_name}")
    
    for corruption_name, corruption_data in corrupted_images.items():
        logger.debug(f"  Testing {corruption_name}...")
        
        try:
            corrupted_image = corruption_data["image"]
            # Compute image quality metrics relative to original
            ssim, psnr, lpips = compute_ssim_psnr_lpips(original_image, corrupted_image)
            
            # Perform DDIM inversion
            inverted_latents = inverter.invert_image(
                image=corrupted_image,
                prompt="",  # Empty prompt as in PRC paper
                guidance_scale=config['inversion']['guidance_scale'],
                num_inference_steps=config['inversion']['num_inference_steps']
            )
            
            # Detect watermark (true PRC)
            detected, metrics = watermark_system.detect(
                inverted_latents, false_positive_rate=config['prc_watermark']['fpr']
            )

            results[corruption_name] = {
                'detected': bool(detected),
                'sum_log_plus': float(metrics['sum_log_plus']),
                'sum_log_prod': float(metrics['sum_log_prod']),
                'const': float(metrics['const']),
                'threshold': float(metrics['threshold']),
                'margin': float(metrics['margin']),
                'ssim': float(ssim),
                'psnr': float(psnr),
                'lpips': float(lpips),
            }

            status = "PASS" if detected else "FAIL"
            logger.info(
                f"{image_name} - {corruption_name}: {status} | sum_log_plus={metrics['sum_log_plus']:.4f} "
                f"threshold={metrics['threshold']:.4f} margin={metrics['margin']:.4f}"
            )
            
        except Exception as e:
            logger.error(f"Error detecting watermark in {corruption_name}: {e}")
            # Attempt SSIM/PSNR/LPIPS even if detection fails
            try:
                ssim, psnr, lpips = compute_ssim_psnr_lpips(original_image, corruption_data.get("image", original_image))
            except Exception:
                ssim, psnr, lpips = float('nan'), float('nan'), float('nan')
            results[corruption_name] = {
                'detected': False,
                'sum_log_plus': 0.0,
                'sum_log_prod': 0.0,
                'const': 0.0,
                'threshold': 0.0,
                'margin': 0.0,
                'ssim': float(ssim),
                'psnr': float(psnr),
                'lpips': float(lpips),
                'error': str(e),
            }
        
        # Perform cleanup if needed
        if corruption_data.get("cleanup"):
            corruption_data["cleanup"]()
    
    return results


def detect_watermarks(
    config_path: str,
    num_images: Optional[int] = None,
    merge_results: bool = False,
    corruptions_filter: Optional[str] = None,
):
    """
    Detect PRC watermarks in generated images with corruption testing.
    
    Args:
        config_path: Path to configuration file
        num_images: Number of images to process (None for all)
    """
    # Load configuration
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Setup paths
    output_dir = Path(config['output_dir'])
    watermark_dir = Path(config['watermark_dir'])
    results_file = Path(config['results_file'])
    
    # Ensure results directory exists
    results_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize PRC watermark system
    prc_config = config['prc_watermark']
    watermark_system = PRCWatermark(
        latent_h=prc_config['latent_h'],
        latent_w=prc_config['latent_w'],
        channels=prc_config['channels'],
        fpr=prc_config['fpr'],
        device="cuda" if torch.cuda.is_available() else "cpu",
        posterior_scale=prc_config.get('posterior_scale', 1.0),
        clamp_eps=prc_config.get('clamp_eps', 1e-3),
        posterior_mapping=prc_config.get('posterior_mapping', 'erf'),
        posterior_variance=prc_config.get('posterior_variance', 1.5),
    )
    
    # Load PRC keys
    if not (watermark_dir / "encoding_key.npz").exists():
        raise FileNotFoundError(f"PRC keys not found in {watermark_dir}. Run generation first.")
    watermark_system.load_keys(str(watermark_dir))
    logger.info(f"Loaded PRC keys from {watermark_dir}")
    
    # Initialize DDIM inverter for inversion
    logger.info(f"Initializing DDIM inverter with model: {config['model_id']}")
    inverter = DDIMInversion(config_path)
    
    # Get corruptions to test
    corruptions = []
    
    # Add base corruptions if enabled
    if config.get('enable_corruptions', False):
        # Get base corruptions (parameterized)
        base_corruptions = get_base_corruptions(config)
        if config.get('corruptions'):
            requested = set(config['corruptions'])
            # Keep entries whose full name matches or whose type matches a requested base name
            base_corruptions = [c for c in base_corruptions if (c.get('type') in requested) or (c['name'] in requested)]
        corruptions.extend(base_corruptions)
    
    # Add SDEdit corruptions if enabled
    sdedit_config = config.get('sdedit_corruptions', {'enabled': False})
    if sdedit_config.get('enabled', False):
        # Create a minimal config object for SDEdit
        class SDEditConfig:
            def __init__(self, base_config):
                self.MODEL_TYPE = base_config['model_type']
                self.MODEL_ID = base_config['model_id']
                self.IMAGE_WIDTH = base_config.get('image_width', 512)
                self.IMAGE_HEIGHT = base_config.get('image_height', 512)
                self.SDEDIT_CONFIG = sdedit_config
        
        sdedit_config_obj = SDEditConfig(config)
        sdedit_corruptions = get_sdedit_corruptions(sdedit_config_obj, sdedit_config)
        corruptions.extend(sdedit_corruptions)

    # Add Inversion-Attack corruptions if enabled
    inversion_config = config.get('inversion_corruptions', {'enabled': False})
    if inversion_config.get('enabled', False):
        class InvConfig:
            def __init__(self, base_config):
                self.MODEL_TYPE = base_config['model_type']
                self.MODEL_ID = base_config['model_id']
                self.IMAGE_WIDTH = base_config.get('image_width', 512)
                self.IMAGE_HEIGHT = base_config.get('image_height', 512)

        inv_cfg_obj = InvConfig(config)
        inversion_corruptions = get_inversion_corruptions(inv_cfg_obj, inversion_config)
        corruptions.extend(inversion_corruptions)
    
    # Apply optional CLI-based corruption-name filter
    if corruptions_filter:
        requested = [name.strip() for name in corruptions_filter.split(",")]
        print(f"Available corruptions: {[c['name'] for c in corruptions]}")
        corruptions = [c for c in corruptions if c["name"] in requested]
        logger.info(f"Running only selected corruptions: {[c['name'] for c in corruptions]}")

    logger.info(f"Testing {len(corruptions)} corruption types: {[c['name'] for c in corruptions]}")
    
    # Get list of images to process
    image_files = sorted(list(output_dir.glob("watermarked_*.png")))
    if num_images is not None:
        image_files = image_files[:num_images]
    
    logger.info(f"Processing {len(image_files)} images...")
    
    # Prepare CSV output
    csv_rows = []
    csv_headers = ['image', 'corruption', 'detected', 'sum_log_plus', 'sum_log_prod', 'const', 'threshold', 'margin', 'ssim', 'psnr', 'lpips']
    
    # Process each image
    all_results = {}
    for image_path in tqdm(image_files, desc="Detecting watermarks"):
        image_name = image_path.stem
        
        # Detect watermark with corruptions
        image_results = detect_watermark_in_image(
            str(image_path),
            watermark_system,
            inverter,
            config,
            corruptions=corruptions
        )
        
        all_results[image_name] = image_results
        
        # Add to CSV rows
        for corruption_type, metrics in image_results.items():
            row = {
                'image': image_name,
                'corruption': corruption_type,
                'detected': bool(metrics.get('detected', False)),
                'sum_log_plus': float(metrics.get('sum_log_plus', 0.0)),
                'sum_log_prod': float(metrics.get('sum_log_prod', 0.0)),
                'const': float(metrics.get('const', 0.0)),
                'threshold': float(metrics.get('threshold', 0.0)),
                'margin': float(metrics.get('margin', 0.0)),
                'ssim': float(metrics.get('ssim', float('nan'))),
                'psnr': float(metrics.get('psnr', float('nan'))),
                'lpips': float(metrics.get('lpips', float('nan'))),
            }
            csv_rows.append(row)
    
    # Write or merge CSV results
    if merge_results and results_file.exists():
        try:
            import pandas as pd
            existing_df = pd.read_csv(results_file)
            new_df = pd.DataFrame(csv_rows)
            corruption_types = new_df['corruption'].unique()
            # Drop existing rows for the same corruption types
            if 'corruption' in existing_df.columns:
                existing_df = existing_df[~existing_df['corruption'].isin(corruption_types)]
            merged_df = pd.concat([existing_df, new_df], ignore_index=True)
            merged_df.to_csv(results_file, index=False)
            logger.info(f"Results merged with existing CSV. Updated corruption types: {list(corruption_types)}")
        except ImportError:
            logger.warning("pandas not available for merging. Writing new CSV instead.")
            with open(results_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=csv_headers)
                writer.writeheader()
                writer.writerows(csv_rows)
            logger.info(f"Results saved to {results_file}")
    else:
        with open(results_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_headers)
            writer.writeheader()
            writer.writerows(csv_rows)
        logger.info(f"Results saved to {results_file}")
    
    # Print summary statistics
    print("\n" + "="*80)
    print("PRC WATERMARK DETECTION RESULTS")
    print("="*80)
    
    # Calculate detection rate per corruption type
    corruption_stats = {}
    for row in csv_rows:
        corruption = row['corruption']
        if corruption not in corruption_stats:
            corruption_stats[corruption] = []
        corruption_stats[corruption].append(1 if row['detected'] else 0)

    print(f"\nDetection Rate by Corruption Type:")
    print(f"{'Corruption Type':<30} {'Detection Rate':<20}")
    print("-" * 50)
    
    for corruption in sorted(corruption_stats.keys()):
        dr = np.mean(corruption_stats[corruption])
        print(f"{corruption:<30} {dr:.2%}")
    
    print("\n" + "="*80)
    
    # Save detailed results as JSON (convert numpy types)
    json_results_path = results_file.parent / "detection_results.json"
    
    # Convert numpy types to native Python types for JSON serialization
    def convert_numpy_types(obj):
        if isinstance(obj, dict):
            return {k: convert_numpy_types(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [convert_numpy_types(v) for v in obj]
        elif isinstance(obj, (np.integer, np.int64)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return obj
    
    json_ready_results = convert_numpy_types(all_results)
    with open(json_results_path, 'w') as f:
        json.dump(json_ready_results, f, indent=2)
    
    logger.info(f"Detailed results saved to {json_results_path}")


def main():
    parser = argparse.ArgumentParser(description="Detect PRC watermarks in images")
    parser.add_argument("config", type=str,
                        help="Path to configuration file")
    parser.add_argument("--num-images", type=int, default=None,
                        help="Number of images to process (default: all)")
    parser.add_argument("--merge", action="store_true", help="Merge with existing results CSV")
    parser.add_argument("--corruptions", help="Comma-separated list of corruptions to run (default: all)")
    
    args = parser.parse_args()
    
    detect_watermarks(
        args.config,
        args.num_images,
        merge_results=args.merge,
        corruptions_filter=args.corruptions,
    )


if __name__ == "__main__":
    main()
