"""
Gaussian Shading Watermark Generation Script

This script generates images with Gaussian Shading watermarks embedded in the initial noise.
It follows the same pattern as the main generation script but uses watermarked initial latents.
"""

import os
import sys
import argparse
import random
import numpy as np
import torch
import yaml
import pickle
from pathlib import Path
from diffusers import StableDiffusionPipeline, StableDiffusionXLPipeline
from diffusers.image_processor import VaeImageProcessor
import logging

# Add the gaussian_shading module to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from gaussian_shading import Gaussian_Shading, Gaussian_Shading_chacha

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_gs_config(config_path: str):
    """Load configuration from YAML file for Gaussian Shading."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    class GSConfig:
        def __init__(self, config_dict):
            # General Configuration
            self.DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
            self.MODEL_TYPE = config_dict["model_type"]
            self.MODEL_ID = config_dict["model_id"]
            self.IMAGE_GENERATION_COUNT = config_dict["image_generation_count"]
            self.OUTPUT_DIR = config_dict["output_dir"]
            self.LATENT_DIR = config_dict["latent_dir"]
            self.WATERMARK_DIR = config_dict["watermark_dir"]
            self.RESULTS_FILE = config_dict["results_file"]
            
            # Image Generation
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
            
            # Model-specific parameters
            if self.MODEL_TYPE == "sd2_0":
                self.ORIGINAL_NOISE_SHAPE = (1, 4, self.IMAGE_HEIGHT // 8, self.IMAGE_WIDTH // 8)
                self.VAE_SCALE_FACTOR = 8
            elif self.MODEL_TYPE == "sdxl":
                self.ORIGINAL_NOISE_SHAPE = (1, 4, self.IMAGE_HEIGHT // 8, self.IMAGE_WIDTH // 8)
                self.VAE_SCALE_FACTOR = 8
            else:
                raise ValueError(f"Gaussian Shading supports SD2.0 and SDXL, got: {self.MODEL_TYPE}")
    
    return GSConfig(config)


def create_gs_pipeline(config):
    """Create pipeline for Gaussian Shading watermarking (SD2.0 or SDXL)."""
    logger.info(f"Loading {config.MODEL_TYPE.upper()} pipeline from {config.MODEL_ID}...")
    
    if config.MODEL_TYPE == "sd2_0":
        pipeline = StableDiffusionPipeline.from_pretrained(
            config.MODEL_ID, 
            torch_dtype=torch.bfloat16,
            use_safetensors=True
        )
    elif config.MODEL_TYPE == "sdxl":
        pipeline = StableDiffusionXLPipeline.from_pretrained(
            config.MODEL_ID,
            torch_dtype=torch.bfloat16,
            use_safetensors=True
        )
    else:
        raise ValueError(f"Gaussian Shading supports SD2.0 and SDXL, got: {config.MODEL_TYPE}")
    
    pipeline = pipeline.to(config.DEVICE)
    # Don't use model CPU offload for watermarking to ensure consistent device placement
    logger.info(f"{config.MODEL_TYPE.upper()} pipeline loaded successfully")
    return pipeline


def generate_watermarked_images(config, prompts):
    """Generate images with Gaussian Shading watermarks."""
    
    # Create output directories
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    os.makedirs(config.LATENT_DIR, exist_ok=True)
    os.makedirs(config.WATERMARK_DIR, exist_ok=True)
    
    # Create pipeline
    pipeline = create_gs_pipeline(config)
    
    # Initialize Gaussian Shading watermarking
    if config.GS_ENCRYPTION == "chacha":
        watermark_system = Gaussian_Shading_chacha(
            ch_factor=config.GS_CH_FACTOR,
            hw_factor=config.GS_HW_FACTOR, 
            fpr=config.GS_FPR,
            user_number=config.GS_USER_NUMBER,
            image_size=config.IMAGE_HEIGHT,
            device=config.DEVICE
        )
        logger.info("Using ChaCha20 encryption for watermarks")
    else:
        watermark_system = Gaussian_Shading(
            ch_factor=config.GS_CH_FACTOR,
            hw_factor=config.GS_HW_FACTOR,
            fpr=config.GS_FPR, 
            user_number=config.GS_USER_NUMBER,
            image_size=config.IMAGE_HEIGHT,
            device=config.DEVICE
        )
        logger.info("Using simple XOR encryption for watermarks")
    
    # Generate watermarked images
    for i in range(config.IMAGE_GENERATION_COUNT):
        seed = np.random.randint(0, 2**32, dtype=np.uint32).item()  # Use 32-bit seed for consistency
        prompt = prompts[i % len(prompts)]
        
        logger.info(f"Generating watermarked image {i+1}/{config.IMAGE_GENERATION_COUNT}")
        logger.info(f"  Seed: {seed}")
        logger.info(f"  Prompt: {prompt}")
        
        # Set random seed for reproducibility
        torch.manual_seed(seed)
        np.random.seed(seed)
        random.seed(seed)
        
        # Create watermarked initial noise
        watermarked_noise = watermark_system.create_watermark_and_return_w()
        logger.info(f"  Created watermarked noise with shape: {watermarked_noise.shape}")
        
        # Generate image with watermarked noise
        with torch.no_grad():
            result = pipeline(
                prompt=prompt,
                width=config.IMAGE_WIDTH,
                height=config.IMAGE_HEIGHT,
                num_inference_steps=config.NUM_INFERENCE_STEPS,
                guidance_scale=config.GUIDANCE_SCALE,
                latents=watermarked_noise.to(pipeline.device, dtype=pipeline.unet.dtype),
                output_type="pil"
            )
            
        image = result.images[0]
        
        # Save image
        image_path = os.path.join(config.OUTPUT_DIR, f"watermarked_{i}.png")
        image.save(image_path)
        logger.info(f"  Saved image: {image_path}")
        
        # Save watermarked noise for later detection
        noise_path = os.path.join(config.LATENT_DIR, f"watermarked_{i}.pt")
        torch.save(watermarked_noise.cpu(), noise_path)
        
        # Save watermark system state for detection
        watermark_path = os.path.join(config.WATERMARK_DIR, f"watermark_{i}.pkl")
        watermark_data = {
            'watermark': watermark_system.watermark.cpu() if watermark_system.watermark is not None else None,
            'key': watermark_system.key.cpu() if hasattr(watermark_system, 'key') and watermark_system.key is not None else None,
            'nonce': watermark_system.nonce if hasattr(watermark_system, 'nonce') else None,
            'encryption_key': watermark_system.key if hasattr(watermark_system, 'key') and isinstance(watermark_system.key, bytes) else None,
            'ch_factor': config.GS_CH_FACTOR,
            'hw_factor': config.GS_HW_FACTOR,
            'fpr': config.GS_FPR,
            'user_number': config.GS_USER_NUMBER,
            'encryption': config.GS_ENCRYPTION,
            'tau_onebit': watermark_system.tau_onebit,
            'tau_bits': watermark_system.tau_bits,
            'image_size': config.IMAGE_HEIGHT
        }
        
        with open(watermark_path, 'wb') as f:
            pickle.dump(watermark_data, f)
        
        # Save metadata
        info_path = os.path.join(config.OUTPUT_DIR, f"watermarked_{i}.txt")
        with open(info_path, "w") as f:
            f.write(f"Prompt: {prompt}\n")
            f.write(f"Seed: {seed}\n")
            f.write(f"Encryption: {config.GS_ENCRYPTION}\n")
            f.write(f"Ch factor: {config.GS_CH_FACTOR}\n")
            f.write(f"HW factor: {config.GS_HW_FACTOR}\n")
            f.write(f"FPR: {config.GS_FPR}\n")
            f.write(f"Tau onebit: {watermark_system.tau_onebit}\n")
            f.write(f"Tau bits: {watermark_system.tau_bits}\n")
        
        logger.info(f"  Saved watermark data: {watermark_path}")
        logger.info(f"  Saved metadata: {info_path}")
    
    logger.info(f"Generated {config.IMAGE_GENERATION_COUNT} watermarked images successfully!")
    logger.info(f"Images saved to: {config.OUTPUT_DIR}")
    logger.info(f"Watermark data saved to: {config.WATERMARK_DIR}")


def main():
    """Main function for Gaussian Shading generation."""
    parser = argparse.ArgumentParser(description="Generate images with Gaussian Shading watermarks")
    parser.add_argument("--config", help="Path to YAML configuration file", 
                       default="configs/gaussian_shading_sd2_config.yaml")
    parser.add_argument("--prompts", help="Path to YAML prompts file", 
                       default="prompts/image_prompts.yaml")
    args = parser.parse_args()
    
    # Load configuration
    config = load_gs_config(args.config)
    logger.info(f"Loaded configuration from {args.config}")
    
    # Load prompts from YAML file
    with open(args.prompts, 'r') as f:
        prompts_data = yaml.safe_load(f)
        prompts = prompts_data['prompts']
    
    logger.info(f"Loaded {len(prompts)} prompts from {args.prompts}")
    
    # Generate watermarked images
    generate_watermarked_images(config, prompts)


if __name__ == "__main__":
    main()