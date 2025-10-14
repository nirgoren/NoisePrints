import os
import csv
import argparse
import torch
from PIL import Image
from diffusers import AutoencoderKL, FluxPipeline, StableDiffusionXLPipeline, StableDiffusionPipeline
from diffusers.image_processor import VaeImageProcessor
import scipy.special as sp
from seed_watermark.robustness_tests.config import load_config
from seed_watermark.adversary_attacks.inversion_attack import DDIMInversion
from seed_watermark.utils.image_metrics import compute_ssim_psnr_lpips

def tightest_cosine_bound(d, a):
    if not (-1 <= a <= 1):
        raise ValueError("a must be in [-1, 1]")
    if d < 2:
        raise ValueError("dimension d must be at least 2")
    x = 1 - a**2
    alpha = (d - 1) / 2
    beta = 0.5
    prob = 0.5 * sp.betainc(alpha, beta, x)
    return prob

def encode_and_check(image, original_latents, original_noise, vae, image_processor, config):
    with torch.no_grad():
        tmp_img = image_processor.preprocess(image)
        latents = tmp_img.to(torch.bfloat16).to(config.DEVICE)
        latents = vae.encode(latents, return_dict=False)[0].sample()
        
        if config.MODEL_TYPE == "flux":
            latents = (latents - vae.config.shift_factor) * vae.config.scaling_factor
            reencoded_latents = FluxPipeline._pack_latents(latents, 1, 16, config.IMAGE_HEIGHT // 8, config.IMAGE_WIDTH // 8)
        else:  # sdxl, sd1_4, or sd2_0
            latents = latents * vae.config.scaling_factor
            reencoded_latents = latents

    dim = reencoded_latents.flatten().shape[0]
    original_cosine_similarity = torch.cosine_similarity(original_latents.flatten(), reencoded_latents.flatten(), dim=0).item()
    original_noise_similarity = torch.cosine_similarity(reencoded_latents.flatten(), original_noise.flatten(), dim=0).item()
    
    max_corr = 0
    for _ in range(1000):
        rand_noise = torch.randn_like(original_noise, device=config.DEVICE)
        max_corr = max(max_corr, torch.cosine_similarity(reencoded_latents.flatten(), rand_noise.flatten(), dim=0).item())

    prob = tightest_cosine_bound(dim, original_noise_similarity)

    return {
        "cosine_similarity_with_original_latents": original_cosine_similarity,
        "cosine_similarity_with_original_noise": original_noise_similarity,
        "max_cosine_similarity_with_random_noise": max_corr,
        "probability_higher_cosine_similarity": prob,
    }

def invert_and_check(image, original_noise, ddim_inverter, config):
    """
    Perform DDIM inversion to recover noise and compute cosine similarity with original noise.
    Supports SDXL, SD2.0, and SD1.4 models.
    
    Args:
        image: PIL Image to invert
        original_noise: Original noise tensor used to generate the image
        ddim_inverter: DDIMInversion instance for performing inversion
        config: Configuration object
    
    Returns:
        Dict containing inversion metrics, or None if not supported for this model
    """
    if config.MODEL_TYPE not in ["sdxl", "sd2_0", "sd1_4"]:
        # FLUX inversion not yet supported
        return None
    
    try:
        with torch.no_grad():
            # Perform DDIM inversion to recover noise
            inverted_noise = ddim_inverter.invert_image(
                image=image,
                prompt="",  # Empty prompt for inversion
                num_inference_steps=50,
                guidance_scale=1.0
            )
            
            # Compute cosine similarity between recovered noise and original noise
            recovered_vs_original_noise = torch.cosine_similarity(
                inverted_noise.flatten(), 
                original_noise.flatten(), 
                dim=0
            ).item()
            
            # Compute max correlation with random noise for comparison
            max_random_corr = 0
            for _ in range(100):  # Use fewer samples than main analysis for efficiency
                rand_noise = torch.randn_like(original_noise, device=config.DEVICE)
                max_random_corr = max(max_random_corr, 
                    torch.cosine_similarity(inverted_noise.flatten(), rand_noise.flatten(), dim=0).item())
            
            # Calculate statistical probability
            dim = inverted_noise.flatten().shape[0]
            prob = tightest_cosine_bound(dim, recovered_vs_original_noise)
            
            return {
                "inversion_recovered_vs_original_noise": recovered_vs_original_noise,
                "inversion_max_random_correlation": max_random_corr,
                "inversion_probability_higher_cosine_similarity": prob,
            }
            
    except Exception as e:
        print(f"Warning: DDIM inversion failed: {str(e)}")
        return None


def save_corruption_image(corrupted_image, corruption_name, base_filename, output_dir):
    """
    Save a corrupted image to the corruptions subdirectory.
    
    Args:
        corrupted_image: PIL Image to save
        corruption_name: Name of the corruption type
        base_filename: Base filename (without extension)
        output_dir: Base output directory
    """
    from pathlib import Path
    
    # Create corruption-specific directory
    corruption_dir = Path(output_dir) / "corruptions" / corruption_name
    corruption_dir.mkdir(parents=True, exist_ok=True)
    
    # Save the corrupted image
    output_filename = f"{base_filename}_{corruption_name}.png"
    output_path = corruption_dir / output_filename
    
    corrupted_image.save(output_path)
    print(f"  Corruption image saved: {output_path}")


def analyze_images(config, invert=False, corruptions_filter=None, merge_results=False):
    vae = AutoencoderKL.from_pretrained(config.MODEL_ID, subfolder="vae", torch_dtype=torch.bfloat16).to(config.DEVICE)
    image_processor = VaeImageProcessor(vae_scale_factor=config.VAE_SCALE_FACTOR)

    # Initialize DDIM inversion for SD models (SDXL, SD2.0, SD1.4) if invert flag is True
    ddim_inverter = None
    if invert and config.MODEL_TYPE in ["sdxl", "sd2_0", "sd1_4"]:
        try:
            # Create a temporary config file path that DDIMInversion can use
            import tempfile
            import yaml
            
            # Convert config object to dict for YAML serialization  
            # Use lowercase keys to match expected YAML format
            config_dict = {
                'model_id': config.MODEL_ID,
                'model_type': config.MODEL_TYPE,
                'image_width': config.IMAGE_WIDTH,
                'image_height': config.IMAGE_HEIGHT,
                'image_generation_count': 10,  # dummy value
                'output_dir': config.OUTPUT_DIR,
                'latent_dir': config.LATENT_DIR,
                'results_file': config.RESULTS_FILE,
                'num_inference_steps': 50,  # dummy value
                'guidance_scale': 7.5,  # dummy value
            }
            
            # Create temporary config file
            temp_config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
            yaml.dump(config_dict, temp_config_file)
            temp_config_file.close()
            
            ddim_inverter = DDIMInversion(temp_config_file.name)
            print("DDIM inversion initialized for SDXL model")
            
            # Clean up temp file
            os.unlink(temp_config_file.name)
            
        except Exception as e:
            print(f"Warning: Failed to initialize DDIM inversion: {str(e)}")
            ddim_inverter = None

    results = []

    image_files = [f for f in os.listdir(config.OUTPUT_DIR) if f.endswith(".png")]

    for img_idx, image_file in enumerate(image_files):
        image_path = os.path.join(config.OUTPUT_DIR, image_file)
        info_path = os.path.join(config.OUTPUT_DIR, image_file.replace(".png", ".txt"))

        with open(info_path, "r") as f:
            lines = f.readlines()
            seed = int(lines[1].split("Seed: ")[1].strip())

        image = Image.open(image_path)

        # Get original latents and noise for comparison
        latent_file = image_file.replace('.png', '.pt')
        latent_path = os.path.join(config.LATENT_DIR, latent_file)
        original_latents = torch.load(latent_path).to(config.DEVICE)

        generator = torch.Generator(device=config.DEVICE).manual_seed(seed)
        if config.MODEL_TYPE == "flux":
            original_noise = torch.randn(config.ORIGINAL_NOISE_SHAPE, generator=generator, dtype=torch.float16, device=config.DEVICE)
        else:  # sdxl, sd1_4, or sd2_0
            original_noise = torch.randn(config.ORIGINAL_NOISE_SHAPE, generator=generator, dtype=torch.bfloat16, device=config.DEVICE)

        print(f"Processing image {img_idx + 1}/{len(image_files)}")
        
        # Get corruptions dynamically including SDEdit 
        from seed_watermark.robustness_tests.config import get_base_corruptions
        from seed_watermark.robustness_tests.sdedit_corruption import get_sdedit_corruptions
        from seed_watermark.robustness_tests.inversion_corruption import get_inversion_corruptions
        corruptions = (
            get_base_corruptions(config)
            + get_sdedit_corruptions(config, config.SDEDIT_CONFIG)
            + get_inversion_corruptions(config, getattr(config, 'INVERSION_ATTACK_CONFIG', {}))
        )
        
        # Filter corruptions if specified
        if corruptions_filter:
            requested = [name.strip() for name in corruptions_filter.split(",")]
            print(f"Available corruptions: {[c['name'] for c in corruptions]}")
            corruptions = [c for c in corruptions if c["name"] in requested]
            print(f"Running only selected corruptions: {[c['name'] for c in corruptions]}")
        
        # First, apply all corruptions and store corrupted images
        print(f"Applying corruptions for {image_file}...")
        corrupted_images = {}
        
        # Store baseline image
        corrupted_images["baseline"] = {"image": image, "metadata": {}}
        
        # Apply each corruption
        for corruption in corruptions:
            print(f"  Applying {corruption['name']}...")
            
            # Prepare context for corruption function
            base_filename = os.path.splitext(image_file)[0]
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
        
        # Now analyze all corrupted images (baseline + corruptions)
        print(f"Analyzing corrupted images for {image_file}...")
        
        # Analyze baseline
        print(f"  Analyzing baseline...")
        baseline_stats = encode_and_check(image, original_latents, original_noise, vae, image_processor, config)
        # Similarity metrics vs. original (baseline vs. itself)
        try:
            ssim_val, psnr_val, lpips_val = compute_ssim_psnr_lpips(image, image)
        except Exception:
            ssim_val, psnr_val, lpips_val = float('nan'), float('nan'), float('nan')
        baseline_stats.update({"ssim": float(ssim_val), "psnr": float(psnr_val), "lpips": float(lpips_val)})
        
        # Add inversion analysis for baseline
        if ddim_inverter is not None:
            print(f"    Performing DDIM inversion for baseline...")
            inversion_stats = invert_and_check(image, original_noise, ddim_inverter, config)
            if inversion_stats:
                baseline_stats.update(inversion_stats)
        
        results.append({"image": image_file, "corruption": "baseline", **baseline_stats})
        
        # Analyze each corruption
        for corruption_name, corruption_data in corrupted_images.items():
            if corruption_name == "baseline":
                continue  # Already handled above
                
            print(f"  Analyzing {corruption_name}...")
            corrupted_image = corruption_data["image"]
            
            stats = encode_and_check(corrupted_image, original_latents, original_noise, vae, image_processor, config)
            # Add SSIM/PSNR vs original image
            try:
                ssim_val, psnr_val, lpips_val = compute_ssim_psnr_lpips(image, corrupted_image)
            except Exception:
                ssim_val, psnr_val, lpips_val = float('nan'), float('nan'), float('nan')
            stats.update({"ssim": float(ssim_val), "psnr": float(psnr_val), "lpips": float(lpips_val)})
            
            
            # Add corruption metadata to stats if available (skip SDEdit and error metadata to avoid CSV field issues)
            if corruption_data["metadata"]:
                for key, value in corruption_data["metadata"].items():
                    if key != "error" and not corruption_name.startswith('sdedit'):  # Skip error and SDEdit fields to avoid CSV field mismatches
                        stats[f"corruption_{key}"] = value
            
            # Add inversion analysis for corrupted image
            if ddim_inverter is not None:
                print(f"    Performing DDIM inversion for {corruption_name}...")
                inversion_stats = invert_and_check(corrupted_image, original_noise, ddim_inverter, config)
                if inversion_stats:
                    stats.update(inversion_stats)
            
            results.append({"image": image_file, "corruption": corruption_name, **stats})
            
            # Perform cleanup if needed
            if corruption_data.get("cleanup"):
                corruption_data["cleanup"]()

    # Save results to CSV
    if merge_results and os.path.exists(config.RESULTS_FILE):
        try:
            import pandas as pd
            # Load existing results
            existing_df = pd.read_csv(config.RESULTS_FILE)
            new_df = pd.DataFrame(results)
            
            # Remove old results for same corruption types
            corruption_types = new_df['corruption'].unique()
            existing_df = existing_df[~existing_df['corruption'].isin(corruption_types)]
            
            # Combine and save
            merged_df = pd.concat([existing_df, new_df], ignore_index=True)
            merged_df.to_csv(config.RESULTS_FILE, index=False)
            print(f"Results merged with existing CSV. Updated corruption types: {list(corruption_types)}")
        except ImportError:
            print("Warning: pandas not available for merging. Writing new CSV instead.")
            # Build unified fieldnames across all rows
            all_keys = set()
            for r in results:
                all_keys.update(r.keys())
            # Ensure 'image' and 'corruption' first
            other_keys = sorted(k for k in all_keys if k not in ("image", "corruption"))
            fieldnames = ["image", "corruption"] + other_keys
            with open(config.RESULTS_FILE, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for row in results:
                    writer.writerow({k: row.get(k) for k in fieldnames})
    else:
        # Standard CSV writing
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

    print(f"Analysis complete. Results saved to {config.RESULTS_FILE}")

    # Print aggregated results
    aggregated_results = {}
    # Get corruptions dynamically for aggregated results
    from seed_watermark.robustness_tests.config import get_base_corruptions  
    from seed_watermark.robustness_tests.sdedit_corruption import get_sdedit_corruptions
    from seed_watermark.robustness_tests.inversion_corruption import get_inversion_corruptions
    corruptions = (
        get_base_corruptions(config)
        + get_sdedit_corruptions(config, config.SDEDIT_CONFIG)
        + get_inversion_corruptions(config, getattr(config, 'INVERSION_ATTACK_CONFIG', {}))
    )
    
    for corruption in ["baseline"] + [c["name"] for c in corruptions]:
        corruption_results = [r for r in results if r["corruption"] == corruption]
        if corruption_results:
            avg_cosine_latents = sum(r["cosine_similarity_with_original_latents"] for r in corruption_results) / len(corruption_results)
            avg_cosine_noise = sum(r["cosine_similarity_with_original_noise"] for r in corruption_results) / len(corruption_results)
            avg_max_corr = sum(r["max_cosine_similarity_with_random_noise"] for r in corruption_results) / len(corruption_results)
            avg_prob_higher = sum(r["probability_higher_cosine_similarity"] for r in corruption_results) / len(corruption_results)
            
            aggregated_data = {
                "avg_cosine_similarity_with_original_latents": avg_cosine_latents,
                "avg_cosine_similarity_with_original_noise": avg_cosine_noise,
                "avg_max_cosine_similarity_with_random_noise": avg_max_corr,
                "avg_probability_higher_cosine_similarity": avg_prob_higher,
            }
            
            # Add inversion metrics if available
            inversion_results = [r for r in corruption_results if "inversion_recovered_vs_original_noise" in r]
            if inversion_results:
                avg_inversion_recovered = sum(r["inversion_recovered_vs_original_noise"] for r in inversion_results) / len(inversion_results)
                avg_inversion_max_random = sum(r["inversion_max_random_correlation"] for r in inversion_results) / len(inversion_results)
                avg_inversion_prob = sum(r["inversion_probability_higher_cosine_similarity"] for r in inversion_results) / len(inversion_results)
                
                aggregated_data.update({
                    "avg_inversion_recovered_vs_original_noise": avg_inversion_recovered,
                    "avg_inversion_max_random_correlation": avg_inversion_max_random,
                    "avg_inversion_probability_higher_cosine_similarity": avg_inversion_prob,
                })
            
            aggregated_results[corruption] = aggregated_data

    print("\n--- Aggregated Results ---")
    for corruption, data in aggregated_results.items():
        print(f"\nCorruption: {corruption}")
        for key, value in data.items():
            print(f"  {key}: {value}")

def main():
    """Main function for analyze command."""
    parser = argparse.ArgumentParser(description="Analyze generated images for robustness")
    parser.add_argument("config", help="Path to YAML configuration file")
    parser.add_argument("--invert", action="store_true", help="Enable DDIM inversion analysis (SDXL only)")
    parser.add_argument("--corruptions", help="Comma-separated list of corruptions to run (default: all)")
    parser.add_argument("--merge", action="store_true", help="Merge with existing results CSV")
    args = parser.parse_args()

    config = load_config(args.config)

    analyze_images(config, invert=args.invert, corruptions_filter=args.corruptions, merge_results=args.merge)

if __name__ == "__main__":
    main()
