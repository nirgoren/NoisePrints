

import os
import sys
import argparse
import random
import numpy as np
import torch
import yaml
from diffusers import FluxPipeline, StableDiffusionXLPipeline, StableDiffusionPipeline, AutoencoderKL
from diffusers.image_processor import VaeImageProcessor
from transformers import CLIPTextModel, CLIPTokenizer, T5EncoderModel, T5Tokenizer
import gc
from seed_watermark.robustness_tests.config import load_config

def encode_all_prompts(config, prompts):
    """Pre-encode only the needed prompts for FLUX models to save VRAM."""
    if config.MODEL_TYPE != "flux":
        return None  # Only for FLUX models
    
    # Calculate which unique prompts we'll actually need
    unique_prompts_needed = set()
    for i in range(config.IMAGE_GENERATION_COUNT):
        prompt_idx = i % len(prompts)
        unique_prompts_needed.add(prompt_idx)
    
    unique_prompts_list = sorted(list(unique_prompts_needed))
    print(f"Pre-encoding {len(unique_prompts_list)} unique prompts (out of {len(prompts)} total) for FLUX model...")
    device = config.DEVICE
    
    # Load text encoders separately - keep on CPU initially to save memory
    print("Loading CLIP text encoder...")
    text_encoder = CLIPTextModel.from_pretrained(
        config.MODEL_ID, subfolder="text_encoder", torch_dtype=torch.bfloat16
    )
    tokenizer = CLIPTokenizer.from_pretrained(
        config.MODEL_ID, subfolder="tokenizer"
    )
    print("Loading T5 text encoder...")
    text_encoder_2 = T5EncoderModel.from_pretrained(
        config.MODEL_ID, subfolder="text_encoder_2", torch_dtype=torch.bfloat16
    )
    tokenizer_2 = T5Tokenizer.from_pretrained(
        config.MODEL_ID, subfolder="tokenizer_2"
    )
    
    # First encode with CLIP (smaller memory footprint)
    print("Encoding prompts with CLIP...")
    text_encoder = text_encoder.to(device)
    encoded_prompts = {}
    
    for i, prompt_idx in enumerate(unique_prompts_list):
        prompt = prompts[prompt_idx]
        print(f"CLIP encoding prompt {i+1}/{len(unique_prompts_list)} (index {prompt_idx})...")
        
        # CLIP encoding (pooled output)
        text_inputs = tokenizer(
            prompt,
            padding="max_length",
            max_length=77,  # CLIP max length
            truncation=True,
            return_tensors="pt"
        )
        text_input_ids = text_inputs.input_ids.to(device)
        with torch.no_grad():
            clip_outputs = text_encoder(text_input_ids, output_hidden_states=False)
            pooled_prompt_embeds = clip_outputs.pooler_output.to(dtype=torch.bfloat16).cpu()
        
        encoded_prompts[prompt_idx] = {'pooled_prompt_embeds': pooled_prompt_embeds}
    
    # Free CLIP encoder memory
    del text_encoder
    gc.collect()
    torch.cuda.empty_cache()
    
    # Now encode with T5 (larger memory footprint)
    print("Encoding prompts with T5...")
    text_encoder_2 = text_encoder_2.to(device)
    
    for i, prompt_idx in enumerate(unique_prompts_list):
        prompt = prompts[prompt_idx]
        print(f"T5 encoding prompt {i+1}/{len(unique_prompts_list)} (index {prompt_idx})...")
        
        # T5 encoding
        text_inputs_2 = tokenizer_2(
            prompt,
            padding="max_length",
            max_length=512,  # T5 max length
            truncation=True,
            return_tensors="pt"
        )
        text_input_ids_2 = text_inputs_2.input_ids.to(device)
        with torch.no_grad():
            t5_outputs = text_encoder_2(text_input_ids_2, output_hidden_states=False)
            prompt_embeds = t5_outputs.last_hidden_state.to(dtype=torch.bfloat16).cpu()
        
        # Create text_ids tensor
        text_ids = torch.zeros(prompt_embeds.shape[1], 3, dtype=torch.bfloat16)
        
        # Update the existing entry
        encoded_prompts[prompt_idx].update({
            'prompt_embeds': prompt_embeds,
            'text_ids': text_ids
        })
    
    # Clean up remaining text encoders
    del text_encoder_2, tokenizer, tokenizer_2
    gc.collect()
    torch.cuda.empty_cache()
    
    print(f"Successfully pre-encoded {len(unique_prompts_list)} unique prompts.")
    return encoded_prompts

def create_pipeline(config, skip_text_encoders=False, skip_vae=False):
    """Create the appropriate pipeline based on model type."""
    if config.MODEL_TYPE == "flux":
        if skip_text_encoders:
            # Load without text encoders and optionally without VAE to save memory
            load_kwargs = {
                "torch_dtype": torch.bfloat16,
                "text_encoder": None,
                "text_encoder_2": None,
                "tokenizer": None,
                "tokenizer_2": None
            }
            if skip_vae:
                load_kwargs["vae"] = None
            
            pipeline = FluxPipeline.from_pretrained(config.MODEL_ID, **load_kwargs)
            
            if skip_vae:
            # If we skipped VAE, keep everything on GPU without offloading
                pipeline.to(config.DEVICE)
            else:
                pipeline.enable_model_cpu_offload()
        else:
            pipeline = FluxPipeline.from_pretrained(config.MODEL_ID, torch_dtype=torch.bfloat16)
            pipeline.enable_model_cpu_offload()
    elif config.MODEL_TYPE == "sdxl":
        pipeline = StableDiffusionXLPipeline.from_pretrained(
            config.MODEL_ID, 
            torch_dtype=torch.bfloat16,
            variant="fp16",
            use_safetensors=True
        )
        # Load LoRA weights if specified
        if hasattr(config, 'LORA_WEIGHTS') and config.LORA_WEIGHTS:
            pipeline.load_lora_weights(config.LORA_WEIGHTS)
        pipeline.enable_model_cpu_offload()
    elif config.MODEL_TYPE in ["sd1_4", "sd2_0"]:
        pipeline = StableDiffusionPipeline.from_pretrained(
            config.MODEL_ID,
            torch_dtype=torch.bfloat16,
            use_safetensors=True
        )
        pipeline.enable_model_cpu_offload()
    else:
        raise ValueError(f"Unsupported model type: {config.MODEL_TYPE}")
    return pipeline

def generate_latents(config, prompts, encoded_prompts=None):
    """Generates and saves latents based on the configuration."""
    if not os.path.exists(config.LATENT_DIR):
        os.makedirs(config.LATENT_DIR)

    # Create pipeline with or without text encoders based on whether we have pre-encoded prompts
    use_preencoded = config.MODEL_TYPE == "flux" and encoded_prompts is not None
    # For FLUX with pre-encoded prompts, skip VAE to keep transformer on GPU without offloading
    skip_vae = use_preencoded
    if skip_vae:
        print("Loading FLUX pipeline without VAE for maximum GPU efficiency...")
    pipeline = create_pipeline(config, skip_text_encoders=use_preencoded, skip_vae=skip_vae)

    for i in range(config.IMAGE_GENERATION_COUNT):
        seed = np.random.randint(0, 2**64, dtype=np.uint64).item()
        prompt = prompts[i % len(prompts)]
        prompt_idx = i % len(prompts)

        print(f"Generating latent {i+1}/{config.IMAGE_GENERATION_COUNT} with seed {seed}...")
        print(f"Using prompt: {prompt}")
        
        generator = torch.Generator(device=config.DEVICE).manual_seed(seed)
        if config.MODEL_TYPE == "flux":
            original_noise = torch.randn(config.ORIGINAL_NOISE_SHAPE, generator=generator, dtype=torch.float16, device=config.DEVICE)
        else:  # sdxl, sd1_4, or sd2_0
            original_noise = torch.randn(config.ORIGINAL_NOISE_SHAPE, generator=generator, dtype=torch.bfloat16, device=config.DEVICE)
        
        # Generate using pre-encoded prompts for FLUX or regular prompts for other models
        if use_preencoded:
            print("Using pre-encoded prompt embeddings for FLUX model...")
            # Use pre-encoded embeddings for FLUX
            encoded_data = encoded_prompts[prompt_idx]
            # Move embeddings to the correct device and ensure proper shape
            prompt_embeds = encoded_data['prompt_embeds'].to(config.DEVICE)
            pooled_prompt_embeds = encoded_data['pooled_prompt_embeds'].to(config.DEVICE)
            
            latents = pipeline(
                prompt_embeds=prompt_embeds,
                pooled_prompt_embeds=pooled_prompt_embeds,
                width=config.IMAGE_WIDTH,
                height=config.IMAGE_HEIGHT,
                num_inference_steps=config.NUM_INFERENCE_STEPS,
                guidance_scale=config.GUIDANCE_SCALE,
                latents=original_noise,
                output_type="latent",
            ).images
        else:
            # Use regular prompt encoding for other models
            latents = pipeline(
                prompt=prompt,
                width=config.IMAGE_WIDTH,
                height=config.IMAGE_HEIGHT,
                num_inference_steps=config.NUM_INFERENCE_STEPS,
                guidance_scale=config.GUIDANCE_SCALE,
                latents=original_noise,
                output_type="latent",
            ).images

        latent_path = os.path.join(config.LATENT_DIR, f"latent_{i}.pt")
        info_path = os.path.join(config.LATENT_DIR, f"latent_{i}.txt")

        torch.save(latents, latent_path)
        with open(info_path, "w") as f:
            f.write(f"Prompt: {prompt}\nSeed: {seed}")

    print(f"Generated {config.IMAGE_GENERATION_COUNT} latents in {config.LATENT_DIR}")
    
    # delete the pipeline to free up memory
    del pipeline
    gc.collect()
    torch.cuda.empty_cache()

def decode_latents(config, prompts):
    """Decodes latents into images."""
    if not os.path.exists(config.OUTPUT_DIR):
        os.makedirs(config.OUTPUT_DIR)

    vae = AutoencoderKL.from_pretrained(config.MODEL_ID, subfolder="vae", torch_dtype=torch.bfloat16).to(config.DEVICE)
    image_processor = VaeImageProcessor(vae_scale_factor=config.VAE_SCALE_FACTOR)

    latent_files = [f for f in os.listdir(config.LATENT_DIR) if f.endswith(".pt")]

    for i, latent_file in enumerate(latent_files):
        latent_path = os.path.join(config.LATENT_DIR, latent_file)
        image_file = latent_file.replace(".pt", ".png")
        image_path = os.path.join(config.OUTPUT_DIR, image_file)

        print(f"Decoding {latent_file}...")
        print(f"Decoding {i+1}/{len(latent_files)} latents...")

        latents = torch.load(latent_path)

        with torch.no_grad():
            if config.MODEL_TYPE == "flux":
                latents = FluxPipeline._unpack_latents(latents, config.IMAGE_HEIGHT, config.IMAGE_WIDTH, config.VAE_SCALE_FACTOR)
                latents = (latents / vae.config.scaling_factor) + vae.config.shift_factor
            else:  # sdxl, sd1_4, or sd2_0
                latents = latents / vae.config.scaling_factor
            
            image = vae.decode(latents, return_dict=False)[0]
            image = image_processor.postprocess(image, output_type="pil")[0]

        image.save(image_path)

        # Also save the corresponding txt file
        info_path_source = os.path.join(config.LATENT_DIR, latent_file.replace(".pt", ".txt"))
        info_path_dest = os.path.join(config.OUTPUT_DIR, latent_file.replace(".pt", ".txt"))
        os.rename(info_path_source, info_path_dest)

    print(f"Decoded {len(latent_files)} latents into images in {config.OUTPUT_DIR}")

def main():
    """Main function for generate command."""
    parser = argparse.ArgumentParser(description="Generate latents and decode them to images")
    parser.add_argument("--config", help="Path to YAML configuration file", default="configs/flux_config.yaml")
    parser.add_argument("--prompts", help="Path to YAML prompts file", default="prompts/image_prompts.yaml")
    args = parser.parse_args()
    
    config = load_config(args.config)
    
    # Load prompts from YAML file
    with open(args.prompts, 'r') as f:
        prompts_data = yaml.safe_load(f)
        prompts = prompts_data['prompts']
    
    # Pre-encode prompts for FLUX models to save VRAM
    encoded_prompts = None
    if config.MODEL_TYPE == "flux":
        encoded_prompts = encode_all_prompts(config, prompts)

    generate_latents(config, prompts, encoded_prompts)
    decode_latents(config, prompts)

if __name__ == "__main__":
    main()

