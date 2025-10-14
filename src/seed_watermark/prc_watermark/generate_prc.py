#!/usr/bin/env python3
"""
PRC Watermark Generation Script

Generates watermarked images using PRC (Pseudo-Random Correlation) watermarking.
Based on the same structure as Gaussian Shading generation.
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
import logging

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from src.seed_watermark.prc_watermark.prc_watermark import PRCWatermark
from diffusers import StableDiffusionPipeline, StableDiffusionXLPipeline, DDIMScheduler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_prompts(prompt_file: str, count: int) -> list:
    """Load prompts from YAML file."""
    with open(prompt_file, 'r') as f:
        prompts_data = yaml.safe_load(f)
    
    prompts = prompts_data.get('prompts', [])
    if len(prompts) > count:
        prompts = prompts[:count]
    elif len(prompts) < count:
        logger.warning(f"Only {len(prompts)} prompts available, requested {count}")
    
    return prompts


def generate_watermarked_images(config_path: str, prompt_file: str, count: int = None):
    """
    Generate watermarked images using PRC watermarking.
    
    Args:
        config_path: Path to configuration file
        prompt_file: Path to prompts YAML file
        count: Number of images to generate (overrides config if provided)
    """
    # Load configuration
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Override count if provided
    if count is not None:
        config['image_generation_count'] = count
    
    # Create output directories
    output_dir = Path(config['output_dir'])
    latent_dir = Path(config['latent_dir'])
    watermark_dir = Path(config['watermark_dir'])
    
    output_dir.mkdir(parents=True, exist_ok=True)
    latent_dir.mkdir(parents=True, exist_ok=True)
    watermark_dir.mkdir(parents=True, exist_ok=True)
    
    # Load prompts
    prompts = load_prompts(prompt_file, config['image_generation_count'])
    
    # Initialize PRC watermark system (true scheme)
    prc_config = config['prc_watermark']
    device = "cuda" if torch.cuda.is_available() else "cpu"
    watermark_system = PRCWatermark(
        latent_h=prc_config['latent_h'],
        latent_w=prc_config['latent_w'],
        channels=prc_config['channels'],
        fpr=prc_config['fpr'],
        device=device,
        posterior_scale=prc_config.get('posterior_scale', 1.0),
        clamp_eps=prc_config.get('clamp_eps', 1e-3),
        posterior_mapping=prc_config.get('posterior_mapping', 'erf'),
        posterior_variance=prc_config.get('posterior_variance', 1.5),
    )
    
    # Key generation
    key_seed = prc_config.get('key_seed', None)
    watermark_system.keygen(
        message_length=prc_config.get('message_length', 512),
        false_positive_rate=prc_config.get('design_fpr', prc_config.get('fpr')),
        t=prc_config.get('t', 3),
        g=prc_config.get('g', None),
        r=prc_config.get('r', None),
        noise_rate=prc_config.get('noise_rate', None),
        seed=key_seed,
    )
    
    # Save watermark keys
    if prc_config.get('save_keys', True):
        watermark_system.save_keys(str(watermark_dir))
        logger.info(f"Saved PRC keys to {watermark_dir}")
    
    # Initialize Stable Diffusion pipeline
    logger.info(f"Loading {config['model_type'].upper()} model: {config['model_id']}")
    
    if config['model_type'] == "sd2_0":
        pipeline = StableDiffusionPipeline.from_pretrained(
            config['model_id'],
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            safety_checker=None,
            requires_safety_checker=False
        )
    elif config['model_type'] == "sdxl":
        pipeline = StableDiffusionXLPipeline.from_pretrained(
            config['model_id'],
            torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
            use_safetensors=True
        )
    else:
        raise ValueError(f"PRC watermarking supports SD2.0 and SDXL, got: {config['model_type']}")
    
    # Use DDIM scheduler for consistency with detection
    pipeline.scheduler = DDIMScheduler.from_config(pipeline.scheduler.config)
    
    pipeline = pipeline.to(device)
    
    # Generation metadata
    metadata = {
        "config": config,
        "watermark_params": {
            "latent_dim": watermark_system.latent_dim,
            "t": watermark_system.t,
            "g": watermark_system.g_dim,
            "r": watermark_system.r,
            "fpr": watermark_system.fpr,
            "noise_rate": watermark_system.noise_rate,
            "posterior_scale": watermark_system.posterior_scale,
            "clamp_eps": watermark_system.clamp_eps,
        },
        "prompts": [],
        "generation_info": []
    }
    
    logger.info(f"Generating {len(prompts)} watermarked images...")
    
    for idx, prompt in enumerate(tqdm(prompts, desc="Generating images")):
        try:
            # Generate watermarked initial latents (true PRC)
            generator = torch.Generator(device=device).manual_seed(idx)
            watermarked_latents = watermark_system.embed_watermarked_latents(generator=generator)
            
            # Ensure correct dtype and shape
            watermarked_latents = watermarked_latents.to(device, dtype=pipeline.unet.dtype)
            
            # Generate image with watermarked latents
            with torch.no_grad():
                result = pipeline(
                    prompt=prompt,
                    num_inference_steps=config['num_inference_steps'],
                    guidance_scale=config['guidance_scale'],
                    latents=watermarked_latents,
                    output_type="pil"
                )
            
            image = result.images[0]
            
            # Save generated image
            image_path = output_dir / f"watermarked_{idx}.png"
            image.save(str(image_path))
            
            # Save watermarked latents for analysis
            latent_path = latent_dir / f"watermarked_latent_{idx}.pt"
            torch.save(watermarked_latents.cpu(), str(latent_path))
            
            # Store metadata
            metadata["prompts"].append(prompt)
            metadata["generation_info"].append({
                "index": idx,
                "prompt": prompt,
                "seed": idx,
                "image_path": str(image_path),
                "latent_path": str(latent_path)
            })
            
            logger.debug(f"Generated image {idx}: {image_path}")
            
        except Exception as e:
            logger.error(f"Error generating image {idx}: {e}")
            continue
    
    # Save metadata
    metadata_path = output_dir.parent / "generation_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"Generation complete! Images saved to {output_dir}")
    logger.info(f"Metadata saved to {metadata_path}")
    
    # Print summary statistics
    logger.info(f"\nPRC Watermark Summary:")
    logger.info(f"  - Latent dimension: {watermark_system.latent_dim}")
    logger.info(f"  - Parity sparsity (t): {watermark_system.t}")
    logger.info(f"  - Message length (k - g - test_bits): configured")
    logger.info(f"  - Target FPR: {watermark_system.fpr}")
    logger.info(f"  - Noise rate: {watermark_system.noise_rate:.4f}")
    logger.info(f"  - Images generated: {len(metadata['generation_info'])}")


def main():
    parser = argparse.ArgumentParser(description="Generate PRC watermarked images")
    parser.add_argument("--config", type=str, required=True,
                        help="Path to configuration file")
    parser.add_argument("--prompts", type=str, required=True,
                        help="Path to prompts YAML file")
    parser.add_argument("--count", type=int, default=None,
                        help="Number of images to generate (overrides config)")
    
    args = parser.parse_args()
    
    generate_watermarked_images(args.config, args.prompts, args.count)


if __name__ == "__main__":
    main()
