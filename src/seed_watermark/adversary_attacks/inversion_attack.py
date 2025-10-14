import os
import torch
import numpy as np
from PIL import Image
from typing import Union, Optional, Dict, Any, List, Tuple
import logging
from pathlib import Path

try:
    from diffusers import StableDiffusionXLPipeline, StableDiffusionPipeline, DDIMScheduler, DDIMInverseScheduler
except ImportError:
    from diffusers.pipelines.stable_diffusion_xl.pipeline_stable_diffusion_xl import StableDiffusionXLPipeline
    from diffusers.pipelines.stable_diffusion.pipeline_stable_diffusion import StableDiffusionPipeline
    from diffusers.schedulers.scheduling_ddim import DDIMScheduler
    from diffusers.schedulers.scheduling_ddim_inverse import DDIMInverseScheduler

from diffusers.image_processor import VaeImageProcessor
import yaml

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DDIMInversion:
    """
    DDIM Inversion implementation for diffusion models.
    
    This class implements DDIM inversion to estimate the original noise that 
    generated an image and supports optimization attacks against seed watermarking.
    """
    
    def __init__(self, config_path: str):
        """
        Initialize DDIM Inversion with model configuration.
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config = self._load_inversion_config(config_path)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Initialize pipeline and schedulers
        self.pipeline = self._create_pipeline()
        self.ddim_inverse_scheduler = DDIMInverseScheduler.from_pretrained(
            self.config.MODEL_ID, subfolder="scheduler"
        )
        
        self.image_processor = VaeImageProcessor(vae_scale_factor=self.config.VAE_SCALE_FACTOR)

    @staticmethod
    def _load_inversion_config(config_path: str):
        """Minimal config loader to avoid circular imports.
        Reads YAML and exposes only the fields needed by DDIMInversion.
        """
        with open(config_path, 'r') as f:
            cfg = yaml.safe_load(f)

        class SimpleConfig:
            pass

        sc = SimpleConfig()
        sc.MODEL_ID = cfg.get('model_id')
        sc.MODEL_TYPE = cfg.get('model_type')
        sc.IMAGE_WIDTH = int(cfg.get('image_width', 512))
        sc.IMAGE_HEIGHT = int(cfg.get('image_height', 512))

        # Model-specific params
        if sc.MODEL_TYPE in ("sdxl", "sd1_4", "sd2_0"):
            sc.VAE_SCALE_FACTOR = 8
            sc.ORIGINAL_NOISE_SHAPE = (1, 4, sc.IMAGE_HEIGHT // 8, sc.IMAGE_WIDTH // 8)
        elif sc.MODEL_TYPE == "flux":
            # DDIM inversion not supported for FLUX in this implementation,
            # but define shape for any downstream metrics that may reference it.
            sc.VAE_SCALE_FACTOR = 8
            sc.ORIGINAL_NOISE_SHAPE = (1, 4096, 64)
        else:
            raise ValueError(f"Unsupported model_type in inversion config: {sc.MODEL_TYPE}")

        return sc
    
    def _get_add_time_ids(self, original_size, crops_coords_top_left, target_size, dtype):
        """Get additional time IDs for SDXL conditioning."""
        add_time_ids = list(original_size + crops_coords_top_left + target_size)
        add_time_ids = torch.tensor([add_time_ids], dtype=dtype, device=self.device)
        return add_time_ids
        
    def _create_pipeline(self):
        """Create the appropriate pipeline based on model type."""
        if self.config.MODEL_TYPE == "sdxl":
            pipeline = StableDiffusionXLPipeline.from_pretrained(
                self.config.MODEL_ID,
                torch_dtype=torch.bfloat16,
                variant="fp16",
                use_safetensors=True
            )
        elif self.config.MODEL_TYPE in ["sd1_4", "sd2_0"]:
            pipeline = StableDiffusionPipeline.from_pretrained(
                self.config.MODEL_ID,
                torch_dtype=torch.bfloat16,
                use_safetensors=True
            )
        else:
            raise ValueError(f"DDIM inversion supports SDXL, SD2.0, and SD1.4, got: {self.config.MODEL_TYPE}")
            
        pipeline = pipeline.to(self.device)
        pipeline.enable_model_cpu_offload()
        return pipeline
    
    def _prepare_image(self, image: Union[str, Image.Image, np.ndarray, torch.Tensor]) -> Image.Image:
        """
        Prepare input image for processing.
        
        Args:
            image: Input image in various formats
            
        Returns:
            PIL Image object
        """
        if isinstance(image, str):
            pil_image = Image.open(image).convert("RGB")
        elif isinstance(image, np.ndarray):
            pil_image = Image.fromarray(image).convert("RGB")
        elif isinstance(image, torch.Tensor):
            processed = self.image_processor.postprocess(image, output_type="pil")
            pil_image = processed[0] if isinstance(processed, list) else processed
        elif isinstance(image, Image.Image):
            pil_image = image.convert("RGB")
        else:
            raise ValueError(f"Unsupported image type: {type(image)}")
            
        # Resize to target dimensions
        target_size = (self.config.IMAGE_WIDTH, self.config.IMAGE_HEIGHT)
        if pil_image.size != target_size:
            pil_image = pil_image.resize(target_size, Image.Resampling.LANCZOS)
            
        return pil_image
    
    def encode_image_to_latents(self, image: Image.Image) -> torch.Tensor:
        """
        Encode PIL image to latent representation using VAE.
        
        Args:
            image: PIL Image to encode
            
        Returns:
            Latent tensor representation
        """
        with torch.no_grad():
            # Preprocess image
            image_tensor = self.image_processor.preprocess(image)
            image_tensor = image_tensor.to(device=self.device, dtype=self.pipeline.vae.dtype)
            
            # Encode to latents
            latents = self.pipeline.vae.encode(image_tensor).latent_dist.sample()
            latents = latents * self.pipeline.vae.config.scaling_factor
            
            return latents
    
    def decode_latents_to_image(self, latents: torch.Tensor) -> Image.Image:
        """
        Decode latent representation to PIL image using VAE.
        
        Args:
            latents: Latent tensor to decode
            
        Returns:
            Decoded PIL Image
        """
        with torch.no_grad():
            # Scale latents
            latents = latents / self.pipeline.vae.config.scaling_factor
            
            # Decode to image
            image = self.pipeline.vae.decode(latents).sample
            image = self.image_processor.postprocess(image, output_type="pil")[0]
            
            return image
    
    def invert_image(
        self, 
        image: Union[str, Image.Image],
        prompt: str = "",
        num_inference_steps: int = 50,
        guidance_scale: float = 1.0,
        seed: Optional[int] = None
    ) -> torch.Tensor:
        """
        Perform DDIM inversion to estimate original noise from image.
        
        Args:
            image: Input image to invert
            prompt: Text prompt used during inversion (usually empty for attacks)
            num_inference_steps: Number of inversion steps
            guidance_scale: Guidance scale for inversion (usually 1.0)
            seed: Random seed for reproducibility
            
        Returns:
            Inverted noise tensor
        """
        # Prepare image and encode to latents
        pil_image = self._prepare_image(image)
        latents = self.encode_image_to_latents(pil_image)
        
        # Setup generator
        generator = None
        if seed is not None:
            generator = torch.Generator(device=self.device).manual_seed(seed)
        
        # Setup schedulers for inversion
        self.ddim_inverse_scheduler.set_timesteps(num_inference_steps, device=self.device)
        timesteps = self.ddim_inverse_scheduler.timesteps
        
        # Encode text prompts (method differs by model type)
        if self.config.MODEL_TYPE == "sdxl":
            prompt_embeds, negative_prompt_embeds, pooled_prompt_embeds, negative_pooled_prompt_embeds = self.pipeline.encode_prompt(
                prompt=prompt or "",
                device=self.device,
                num_images_per_prompt=1,
                do_classifier_free_guidance=(guidance_scale > 1.0)
            )
        else:  # SD1.4 and SD2.0
            prompt_embeds, negative_prompt_embeds = self.pipeline.encode_prompt(
                prompt=prompt or "",
                device=self.device,
                num_images_per_prompt=1,
                do_classifier_free_guidance=(guidance_scale > 1.0)
            )
            pooled_prompt_embeds = None
            negative_pooled_prompt_embeds = None
        
        # Perform inversion
        current_latents = latents.clone()
        
        logger.info(f"Starting DDIM inversion with {len(timesteps)} steps...")
        
        for i, t in enumerate(timesteps):
            # Expand latents for classifier-free guidance
            latent_model_input = torch.cat([current_latents] * 2) if guidance_scale > 1.0 else current_latents
            latent_model_input = self.ddim_inverse_scheduler.scale_model_input(latent_model_input, t)
            
            # Predict noise residual
            with torch.no_grad():
                if self.config.MODEL_TYPE == "sdxl":
                    # For SDXL, we need to prepare the encoder hidden states and added_cond_kwargs
                    if guidance_scale > 1.0:
                        encoder_hidden_states = torch.cat([prompt_embeds, negative_prompt_embeds])
                        added_cond_kwargs = {
                            "text_embeds": torch.cat([pooled_prompt_embeds, negative_pooled_prompt_embeds]),
                            "time_ids": torch.cat([
                                self._get_add_time_ids(
                                    (self.config.IMAGE_HEIGHT, self.config.IMAGE_WIDTH), (0, 0), 
                                    (self.config.IMAGE_HEIGHT, self.config.IMAGE_WIDTH), dtype=prompt_embeds.dtype
                                )
                            ] * 2)
                        }
                    else:
                        encoder_hidden_states = prompt_embeds
                        added_cond_kwargs = {
                            "text_embeds": pooled_prompt_embeds,
                            "time_ids": self._get_add_time_ids(
                                (self.config.IMAGE_HEIGHT, self.config.IMAGE_WIDTH), (0, 0), 
                                (self.config.IMAGE_HEIGHT, self.config.IMAGE_WIDTH), dtype=prompt_embeds.dtype
                            )
                        }
                    
                    noise_pred = self.pipeline.unet(
                        latent_model_input,
                        t,
                        encoder_hidden_states=encoder_hidden_states,
                        added_cond_kwargs=added_cond_kwargs,
                    ).sample
                    
                else:  # SD1.4 and SD2.0
                    # For SD models, simpler call without added_cond_kwargs
                    if guidance_scale > 1.0:
                        encoder_hidden_states = torch.cat([prompt_embeds, negative_prompt_embeds])
                    else:
                        encoder_hidden_states = prompt_embeds
                    
                    noise_pred = self.pipeline.unet(
                        latent_model_input,
                        t,
                        encoder_hidden_states=encoder_hidden_states,
                        return_dict=False
                    )[0]
            
            # Perform classifier-free guidance
            if guidance_scale > 1.0:
                noise_pred_uncond, noise_pred_text = noise_pred.chunk(2)
                noise_pred = noise_pred_uncond + guidance_scale * (noise_pred_text - noise_pred_uncond)
            
            # Compute previous sample
            current_latents = self.ddim_inverse_scheduler.step(
                noise_pred, t, current_latents, return_dict=False
            )[0]
            
        logger.info("DDIM inversion completed")
        return current_latents

