"""
Gaussian Shading Watermark Detection Script

This script detects Gaussian Shading watermarks from images and tests robustness against corruptions.
It uses DDIM inversion to recover the initial noise and then applies the Gaussian Shading detection method.
"""

import os
import sys
import csv
import argparse
import pickle
import torch
import yaml
import numpy as np
from PIL import Image
from pathlib import Path
import logging
from typing import Optional

# Add the gaussian_shading module to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from gaussian_shading import Gaussian_Shading, Gaussian_Shading_chacha

# Import existing inversion and corruption functionality
from seed_watermark.adversary_attacks.inversion_attack import DDIMInversion
from seed_watermark.robustness_tests.config import get_base_corruptions
from seed_watermark.robustness_tests.sdedit_corruption import get_sdedit_corruptions
from seed_watermark.robustness_tests.inversion_corruption import get_inversion_corruptions
from seed_watermark.utils.image_metrics import compute_ssim_psnr_lpips

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_gs_config(config_path: str):
    """Load configuration from YAML file for Gaussian Shading detection."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    class GSConfig:
        def __init__(self, config_dict):
            # General Configuration  
            self.DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
            self.MODEL_TYPE = config_dict["model_type"]
            self.MODEL_ID = config_dict["model_id"]
            self.OUTPUT_DIR = config_dict["output_dir"]
            self.LATENT_DIR = config_dict["latent_dir"]
            self.WATERMARK_DIR = config_dict["watermark_dir"]
            self.RESULTS_FILE = config_dict["results_file"]
            
            # Image parameters
            self.IMAGE_WIDTH = config_dict["image_width"]
            self.IMAGE_HEIGHT = config_dict["image_height"]
            self.NUM_INFERENCE_STEPS = config_dict["num_inference_steps"]
            self.GUIDANCE_SCALE = config_dict["guidance_scale"]
            
            # Gaussian Shading parameters
            gs_config = config_dict["gaussian_shading"]
            self.GS_CH_FACTOR = gs_config["ch_factor"]
            self.GS_HW_FACTOR = gs_config["hw_factor"]
            self.GS_FPR = gs_config["fpr"]
            self.GS_USER_NUMBER = gs_config["user_number"]
            self.GS_ENCRYPTION = gs_config["encryption"]
            
            # Corruption and inversion settings
            self.ENABLE_CORRUPTIONS = config_dict.get("enable_corruptions", True)
            self.CORRUPTIONS = config_dict.get("corruptions", [])
            
            inversion_config = config_dict.get("inversion", {})
            self.INVERSION_STEPS = inversion_config.get("num_inference_steps", 50)
            self.INVERSION_GUIDANCE = inversion_config.get("guidance_scale", 1.0)
            self.INVERSION_PROMPT = inversion_config.get("empty_prompt", "")
            
            # Model-specific parameters
            if self.MODEL_TYPE == "sd2_0":
                self.VAE_SCALE_FACTOR = 8
            elif self.MODEL_TYPE == "sdxl":
                self.VAE_SCALE_FACTOR = 8
            else:
                raise ValueError(f"Gaussian Shading supports SD2.0 and SDXL, got: {self.MODEL_TYPE}")
    
    return GSConfig(config)


def load_watermark_system(watermark_path, config):
    """Load watermark system from saved state."""
    with open(watermark_path, 'rb') as f:
        watermark_data = pickle.load(f)
    
    # Recreate watermark system with same parameters
    if watermark_data['encryption'] == "chacha":
        watermark_system = Gaussian_Shading_chacha(
            ch_factor=watermark_data['ch_factor'],
            hw_factor=watermark_data['hw_factor'],
            fpr=watermark_data['fpr'], 
            user_number=watermark_data['user_number'],
            image_size=watermark_data['image_size']
        )
        # Restore ChaCha20 encryption state
        watermark_system.key = watermark_data['encryption_key']
        watermark_system.nonce = watermark_data['nonce']
    else:
        watermark_system = Gaussian_Shading(
            ch_factor=watermark_data['ch_factor'],
            hw_factor=watermark_data['hw_factor'],
            fpr=watermark_data['fpr'],
            user_number=watermark_data['user_number'], 
            image_size=watermark_data['image_size']
        )
        # Restore XOR key
        if watermark_data['key'] is not None:
            watermark_system.key = watermark_data['key'].cuda()
    
    # Restore watermark and thresholds
    if watermark_data['watermark'] is not None:
        watermark_system.watermark = watermark_data['watermark'].cuda()
    watermark_system.tau_onebit = watermark_data['tau_onebit']
    watermark_system.tau_bits = watermark_data['tau_bits']
    
    return watermark_system


def get_correct_bits(watermark_system, inverted_noise):
    """
    Get the raw number of correctly detected bits.
    
    Args:
        watermark_system: The Gaussian Shading watermark system
        inverted_noise: The recovered noise from DDIM inversion
        
    Returns:
        int: Number of correctly detected bits
    """
    # Perform the watermark evaluation steps without calculating accuracy
    reversed_m = (inverted_noise > 0).int()
    
    if hasattr(watermark_system, 'nonce'):  # ChaCha20 variant
        reversed_sd = watermark_system.stream_key_decrypt(reversed_m.flatten().cpu().numpy())
    else:  # Simple XOR variant
        reversed_sd = (reversed_m + watermark_system.key) % 2
    
    reversed_watermark = watermark_system.diffusion_inverse(reversed_sd)
    
    # Count correct bits
    correct_bits = (reversed_watermark == watermark_system.watermark).sum().item()
    
    return correct_bits


def save_corruption_image(corrupted_image, corruption_name, base_filename, output_dir):
    """Save a corrupted image to the corruptions subdirectory."""
    from pathlib import Path
    
    # Create corruption-specific directory
    corruption_dir = Path(output_dir) / "corruptions" / corruption_name
    corruption_dir.mkdir(parents=True, exist_ok=True)
    
    # Save the corrupted image
    output_filename = f"{base_filename}_{corruption_name}.png"
    output_path = corruption_dir / output_filename
    
    corrupted_image.save(output_path)
    logger.info(f"  Corruption image saved: {output_path}")


def detect_watermarks(
    config,
    config_path: Optional[str] = None,
    merge_results: bool = False,
    corruptions_filter: Optional[str] = None,
):
    """Detect watermarks in generated images and test robustness against corruptions."""
    
    # Create temporary DDIM inversion config for SD2.0
    import tempfile
    import yaml
    temp_config_dict = {
        'model_id': config.MODEL_ID,
        'model_type': config.MODEL_TYPE,
        'image_width': config.IMAGE_WIDTH,
        'image_height': config.IMAGE_HEIGHT,
        'image_generation_count': 100,  # Required by config loader
        'output_dir': config.OUTPUT_DIR,
        'latent_dir': config.LATENT_DIR,
        'results_file': config.RESULTS_FILE,
        'num_inference_steps': config.NUM_INFERENCE_STEPS,
        'guidance_scale': config.GUIDANCE_SCALE
    }
    
    # Create temporary config file for DDIMInversion
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml.dump(temp_config_dict, f)
        temp_config_path = f.name
    
    try:
        # Initialize DDIM inversion system for SD2.0
        logger.info("Initializing DDIM inversion system...")
        ddim_inverter = DDIMInversion(temp_config_path)
        logger.info("DDIM inversion system initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize DDIM inversion: {e}")
        return
    finally:
        # Clean up temporary config
        os.unlink(temp_config_path)
    
    # Find all generated images
    image_files = []
    for file_path in Path(config.OUTPUT_DIR).glob("watermarked_*.png"):
        image_files.append(file_path.name)
    
    image_files.sort()  # Sort for consistent processing order
    logger.info(f"Found {len(image_files)} watermarked images to analyze")
    
    if not image_files:
        logger.error(f"No watermarked images found in {config.OUTPUT_DIR}")
        return
    
    # Get corruptions to test
    corruptions = []
    if config.ENABLE_CORRUPTIONS:
        # Get base corruptions (parameterized)
        # For GS, the config object doesn't carry base_corruptions; we load YAML dict below if available
        base_corruptions = get_base_corruptions()
        if config.CORRUPTIONS:
            requested = set(config.CORRUPTIONS)
            base_corruptions = [c for c in base_corruptions if (c.get('type') in requested) or (c['name'] in requested)]
        corruptions.extend(base_corruptions)
        
    # Add SDEdit corruptions if enabled
    if config_path:
        with open(config_path, 'r') as f:
            config_dict = yaml.safe_load(f)
            sdedit_config = config_dict.get('sdedit_corruptions', {'enabled': False})
        
        if sdedit_config.get('enabled', False):
            # Add SDEDIT_CONFIG to config object
            config.SDEDIT_CONFIG = sdedit_config
            sdedit_corruptions = get_sdedit_corruptions(config, sdedit_config)
            corruptions.extend(sdedit_corruptions)

        # Add Inversion-Attack corruptions if enabled
        inversion_config = config_dict.get('inversion_corruptions', {'enabled': False})
        if inversion_config.get('enabled', False):
            inversion_corruptions = get_inversion_corruptions(config, inversion_config)
            corruptions.extend(inversion_corruptions)

        # Override base corruptions from config file if provided
        base_cfg = config_dict.get('base_corruptions')
        if base_cfg:
            param_corruptions = get_base_corruptions(config_dict)
            if config.CORRUPTIONS:
                requested = set(config.CORRUPTIONS)
                param_corruptions = [c for c in param_corruptions if (c.get('type') in requested) or (c['name'] in requested)]
            # Replace any default base corruptions with parameterized set
            # Remove existing base types
            corrupt_types = {c['type'] for c in param_corruptions}
            corruptions = [c for c in corruptions if c.get('type') not in corrupt_types]
            corruptions.extend(param_corruptions)
    
    # Apply optional CLI-based corruption-name filter
    if corruptions_filter:
        requested = [name.strip() for name in corruptions_filter.split(",")]
        print(f"Available corruptions: {[c['name'] for c in corruptions]}")
        corruptions = [c for c in corruptions if c["name"] in requested]
        logger.info(f"Running only selected corruptions: {[c['name'] for c in corruptions]}")

    logger.info(f"Testing {len(corruptions)} corruption types: {[c['name'] for c in corruptions]}")
    
    # Results storage
    results = []
    
    # Process each image
    for i, image_file in enumerate(image_files):
        logger.info(f"Processing image {i+1}/{len(image_files)}: {image_file}")
        
        # Load image
        image_path = os.path.join(config.OUTPUT_DIR, image_file)
        image = Image.open(image_path).convert("RGB")
        
        # Load corresponding watermark system
        image_idx = int(image_file.replace('watermarked_', '').replace('.png', ''))
        watermark_path = os.path.join(config.WATERMARK_DIR, f"watermark_{image_idx}.pkl")
        
        if not os.path.exists(watermark_path):
            logger.warning(f"Watermark file not found: {watermark_path}, skipping...")
            continue
        
        watermark_system = load_watermark_system(watermark_path, config)
        base_filename = f"watermarked_{image_idx}"
        
        # First, apply all corruptions and store corrupted images
        logger.info(f"  Applying corruptions for {image_file}...")
        corrupted_images = {}
        
        # Store baseline image
        corrupted_images["baseline"] = {"image": image, "metadata": {}}
        
        # Apply each corruption
        for corruption in corruptions:
            logger.info(f"    Applying {corruption['name']}...")
            
            try:
                # Prepare context for corruption function
                corruption_context = {
                    'output_dir': config.OUTPUT_DIR,
                    'base_filename': base_filename
                }
                
                # Apply corruption with context
                corruption_details = corruption["function"](image, **corruption_context)
                corrupted_image = corruption_details["image"]
                
                # Save corruption image if not already saved
                if not corruption_details.get("output_path"):
                    save_corruption_image(
                        corrupted_image, 
                        corruption['name'], 
                        base_filename, 
                        config.OUTPUT_DIR
                    )
                
                # Store corrupted image and metadata
                corrupted_images[corruption['name']] = {
                    "image": corrupted_image,
                    "metadata": corruption_details.get("metadata", {}),
                    "cleanup": corruption_details.get("cleanup")
                }
                
            except Exception as e:
                logger.error(f"    Failed to apply {corruption['name']}: {e}")
                # Store original image as fallback
                corrupted_images[corruption['name']] = {
                    "image": image,
                    "metadata": {"error": str(e)},
                    "cleanup": None
                }
        
        # Now test watermark detection on all corrupted images (baseline + corruptions)
        logger.info(f"  Testing watermark detection for {image_file}...")
        for corruption_name, corruption_data in corrupted_images.items():
            logger.info(f"    Testing {corruption_name}...")
            
            try:
                corrupted_image = corruption_data["image"]
                # Compute image similarity metrics vs original
                ssim, psnr, lpips = compute_ssim_psnr_lpips(image, corrupted_image)
                
                # Perform DDIM inversion to recover noise
                inverted_noise = ddim_inverter.invert_image(
                    image=corrupted_image,
                    prompt=config.INVERSION_PROMPT,
                    num_inference_steps=config.INVERSION_STEPS,
                    guidance_scale=config.INVERSION_GUIDANCE
                )
                
                # Get raw detection metrics
                correct_bits = get_correct_bits(watermark_system, inverted_noise)
                latent_length = watermark_system.marklength
                
                results.append({
                    "image": image_file,
                    "corruption": corruption_name,
                    "correct_bits": correct_bits,
                    "latent_length": latent_length,
                    "ssim": ssim,
                    "psnr": psnr,
                    "lpips": lpips,
                })
                
                logger.info(f"      Correct bits: {correct_bits}/{latent_length}")
                logger.info(f"      Detection rate: {correct_bits/latent_length:.6f}")
                
            except Exception as e:
                logger.error(f"    Failed {corruption_name} detection: {e}")
                # Attempt to compute metrics even on failure
                try:
                    ssim, psnr, lpips = compute_ssim_psnr_lpips(image, corruption_data.get("image", image))
                except Exception:
                    ssim, psnr, lpips = float("nan"), float("nan"), float("nan")
                results.append({
                    "image": image_file,
                    "corruption": corruption_name,
                    "correct_bits": 0,
                    "latent_length": watermark_system.marklength if 'watermark_system' in locals() else 0,
                    "ssim": ssim,
                    "psnr": psnr,
                    "lpips": lpips,
                    "error": str(e)
                })
            
            # Perform cleanup if needed
            if corruption_data.get("cleanup"):
                corruption_data["cleanup"]()
    
    # Save results to CSV
    if results:
        # Ensure results directory exists
        os.makedirs(os.path.dirname(config.RESULTS_FILE), exist_ok=True)

        if merge_results and os.path.exists(config.RESULTS_FILE):
            try:
                import pandas as pd
                existing_df = pd.read_csv(config.RESULTS_FILE)
                new_df = pd.DataFrame(results)
                corruption_types = new_df['corruption'].unique()
                if 'corruption' in existing_df.columns:
                    existing_df = existing_df[~existing_df['corruption'].isin(corruption_types)]
                merged_df = pd.concat([existing_df, new_df], ignore_index=True)
                merged_df.to_csv(config.RESULTS_FILE, index=False)
                logger.info(f"Results merged with existing CSV. Updated corruption types: {list(corruption_types)}")
            except ImportError:
                logger.warning("pandas not available for merging. Writing new CSV instead.")
                # Build unified fieldnames across all rows
                all_keys = set()
                for r in results:
                    all_keys.update(r.keys())
                other_keys = sorted(k for k in all_keys if k not in ("image", "corruption"))
                fieldnames = ["image", "corruption"] + other_keys
                with open(config.RESULTS_FILE, "w", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    for row in results:
                        writer.writerow({k: row.get(k) for k in fieldnames})
                logger.info(f"Results saved to {config.RESULTS_FILE}")
        else:
            # Write CSV
            with open(config.RESULTS_FILE, "w", newline="") as f:
                fieldnames = ["image", "corruption", "correct_bits", "latent_length", "ssim", "psnr", "lpips"]
                # Add error field if any results have errors
                if any("error" in r for r in results):
                    fieldnames.append("error")
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            logger.info(f"Results saved to {config.RESULTS_FILE}")
        
        # Print aggregated results
        print_aggregated_results(results)
    
    else:
        logger.warning("No results to save")


def print_aggregated_results(results):
    """Print aggregated detection results by corruption type."""
    logger.info("\n--- Aggregated Detection Results ---")
    
    # Group by corruption type
    corruption_groups = {}
    for result in results:
        corruption = result["corruption"]
        if corruption not in corruption_groups:
            corruption_groups[corruption] = []
        corruption_groups[corruption].append(result)
    
    # Print results for each corruption
    for corruption, group_results in corruption_groups.items():
        valid_results = [r for r in group_results if "error" not in r]
        
        if valid_results:
            total_correct = sum(r["correct_bits"] for r in valid_results)
            total_bits = sum(r["latent_length"] for r in valid_results)
            avg_correct = sum(r["correct_bits"] for r in valid_results) / len(valid_results)
            avg_rate = sum(r["correct_bits"] / r["latent_length"] for r in valid_results) / len(valid_results)
            total_images = len(valid_results)
            
            logger.info(f"\nCorruption: {corruption}")
            logger.info(f"  Total correct bits: {total_correct}/{total_bits}")
            logger.info(f"  Average correct bits per image: {avg_correct:.1f}/{valid_results[0]['latent_length']}")
            logger.info(f"  Average detection rate: {avg_rate:.6f}")
            logger.info(f"  Images processed: {total_images}")
        else:
            logger.info(f"\nCorruption: {corruption}")
            logger.info(f"  No valid results (all failed)")


def main():
    """Main function for Gaussian Shading detection."""
    parser = argparse.ArgumentParser(description="Detect Gaussian Shading watermarks and test robustness")
    parser.add_argument("--config", help="Path to YAML configuration file",
                       default="configs/gaussian_shading_sd2_config.yaml")
    parser.add_argument("--merge", action="store_true", help="Merge with existing results CSV")
    parser.add_argument("--corruptions", help="Comma-separated list of corruptions to run (default: all)")
    args = parser.parse_args()
    
    # Load configuration
    config = load_gs_config(args.config)
    logger.info(f"Loaded configuration from {args.config}")
    
    # Detect watermarks
    detect_watermarks(
        config,
        config_path=args.config,
        merge_results=args.merge,
        corruptions_filter=args.corruptions,
    )


if __name__ == "__main__":
    main()
