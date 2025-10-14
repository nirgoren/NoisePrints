import os
import torch
import numpy as np
from PIL import Image
from typing import Union, Optional, Dict, Any
try:
    from diffusers import FluxPipeline, StableDiffusionXLPipeline, StableDiffusionPipeline
except ImportError:
    from diffusers.pipelines.flux.pipeline_flux import FluxPipeline
    from diffusers.pipelines.stable_diffusion_xl.pipeline_stable_diffusion_xl import StableDiffusionXLPipeline
    from diffusers.pipelines.stable_diffusion.pipeline_stable_diffusion import StableDiffusionPipeline
from diffusers.image_processor import VaeImageProcessor
from seed_watermark.robustness_tests.config import load_config


class SDEdit:
    """
    SDEdit (Stochastic Differential Editing) implementation for diffusion models.
    
    This class provides functionality to edit images using the SDEdit algorithm,
    which adds noise to an input image and then denoises it through a reverse
    diffusion process to achieve realistic image editing while preserving structure.
    """
    
    def __init__(self, config_path: str):
        """
        Initialize SDEdit with model configuration.
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config = load_config(config_path)
        self.pipeline = self._create_pipeline()
        self.image_processor = VaeImageProcessor(vae_scale_factor=self.config.VAE_SCALE_FACTOR)
        
    def _create_pipeline(self):
        """Create the appropriate pipeline based on model type."""
        if self.config.MODEL_TYPE == "flux":
            # For FLUX, we need to use the img2img variant if available
            try:
                from diffusers import FluxImg2ImgPipeline
                pipeline = FluxImg2ImgPipeline.from_pretrained(
                    self.config.MODEL_ID, 
                    torch_dtype=torch.bfloat16
                )
            except ImportError:
                # Fallback to regular FluxPipeline
                pipeline = FluxPipeline.from_pretrained(
                    self.config.MODEL_ID, 
                    torch_dtype=torch.bfloat16
                )
        elif self.config.MODEL_TYPE == "sdxl":
            from diffusers import StableDiffusionXLImg2ImgPipeline
            pipeline = StableDiffusionXLImg2ImgPipeline.from_pretrained(
                self.config.MODEL_ID, 
                torch_dtype=torch.bfloat16,
                variant="fp16",
                use_safetensors=True
            )
        elif self.config.MODEL_TYPE in ["sd1_4", "sd2_0"]:
            from diffusers import StableDiffusionImg2ImgPipeline
            pipeline = StableDiffusionImg2ImgPipeline.from_pretrained(
                self.config.MODEL_ID, 
                torch_dtype=torch.bfloat16,
                use_safetensors=True
            )
        else:
            raise ValueError(f"Unsupported model type: {self.config.MODEL_TYPE}")
            
        pipeline.enable_model_cpu_offload()
        return pipeline
    
    def _prepare_image(self, image: Union[str, Image.Image, np.ndarray, torch.Tensor]) -> tuple[Image.Image, tuple[int, int]]:
        """
        Prepare input image for processing.
        
        Args:
            image: Input image in various formats
            
        Returns:
            Tuple of (PIL Image object resized to target size, original (width, height))
        """
        if isinstance(image, str):
            pil_image = Image.open(image).convert("RGB")
            original_size = pil_image.size
        elif isinstance(image, np.ndarray):
            pil_image = Image.fromarray(image).convert("RGB")
            original_size = pil_image.size
        elif isinstance(image, torch.Tensor):
            processed = self.image_processor.postprocess(image, output_type="pil")
            pil_image = processed[0] if isinstance(processed, list) else processed
            original_size = pil_image.size
        elif isinstance(image, Image.Image):
            pil_image = image.convert("RGB")
            original_size = pil_image.size
        else:
            raise ValueError(f"Unsupported image type: {type(image)}")
            
        # Resize to target dimensions
        target_size = (self.config.IMAGE_WIDTH, self.config.IMAGE_HEIGHT)
        if pil_image.size != target_size:
            pil_image = pil_image.resize(target_size, Image.Resampling.LANCZOS)
            
        return pil_image, original_size
    
    
    def sdedit(
        self,
        image: Union[str, Image.Image, np.ndarray, torch.Tensor],
        prompt: str = "",
        negative_prompt: str = "",
        noise_strength: float = 0.5,
        guidance_scale: Optional[float] = None,
        num_inference_steps: Optional[int] = None,
        seed: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Apply SDEdit to an input image.
        
        Args:
            image: Input image for editing
            prompt: Text prompt to guide the editing (optional)
            negative_prompt: Negative text prompt
            noise_strength: Amount of noise to add (0.0 to 1.0). Higher values = more editing
            guidance_scale: Guidance scale for diffusion process
            num_inference_steps: Number of denoising steps
            seed: Random seed for reproducibility
            **kwargs: Additional arguments passed to the pipeline
            
        Returns:
            Dictionary containing:
                - 'edited_image': The final edited PIL Image
                - 'original_image': The original input PIL Image
                - 'parameters': Dictionary of parameters used
            Note: The returned 'edited_image' is resized back to the original
            input image size after the SDEdit process completes.
        """
        # Use config defaults if not specified
        if guidance_scale is None:
            guidance_scale = self.config.GUIDANCE_SCALE
        if num_inference_steps is None:
            num_inference_steps = self.config.NUM_INFERENCE_STEPS
            
        # Prepare input image (and record the original size before resizing)
        original_image, original_size = self._prepare_image(image)
        
        # Set up generator for reproducibility
        generator = None
        if seed is not None:
            generator = torch.Generator(device=self.pipeline.device).manual_seed(seed)
        
        # Apply SDEdit using img2img pipeline
        with torch.no_grad():
            if self.config.MODEL_TYPE == "flux":
                # FLUX pipeline
                result = self.pipeline(
                    prompt=prompt or "high quality image",
                    image=original_image,
                    strength=noise_strength,
                    height=self.config.IMAGE_HEIGHT,
                    width=self.config.IMAGE_WIDTH,
                    num_inference_steps=num_inference_steps,
                    guidance_scale=guidance_scale,
                    generator=generator,
                    **kwargs
                )
            else:
                # SDXL/SD pipelines
                pipeline_args = {
                    "image": original_image,
                    "strength": noise_strength,
                    "num_inference_steps": num_inference_steps,
                    "guidance_scale": guidance_scale,
                    "generator": generator,
                    **kwargs
                }
                
                # Add prompts if provided
                if prompt is not None:
                    pipeline_args["prompt"] = prompt
                if negative_prompt is not None:
                    pipeline_args["negative_prompt"] = negative_prompt
                    
                result = self.pipeline(**pipeline_args)
            
            # Extract the edited image
            edited_image = result.images[0] if hasattr(result, 'images') else result[0]

        # Resize edited image back to the original input size
        if edited_image.size != original_size:
            edited_image = edited_image.resize(original_size, Image.Resampling.LANCZOS)
        
        return {
            'edited_image': edited_image,
            'original_image': original_image,
            'parameters': {
                'noise_strength': noise_strength,
                'guidance_scale': guidance_scale,
                'num_inference_steps': num_inference_steps,
                'prompt': prompt,
                'negative_prompt': negative_prompt,
                'seed': seed,
                'original_size': original_size,
                'edited_size': edited_image.size
            }
        }
    


def apply_sdedit(
    image_path: str,
    config_path: str,
    prompt: str = "",
    noise_strength: float = 0.5,
    output_path: Optional[str] = None,
    seed: Optional[int] = None
) -> str:
    """
    Convenience function to apply SDEdit to an image.
    
    Args:
        image_path: Path to input image
        config_path: Path to model configuration YAML
        prompt: Text prompt for editing
        noise_strength: Amount of noise/editing (0.0 to 1.0)
        output_path: Path to save edited image (optional)
        seed: Random seed for reproducibility
        
    Returns:
        Path to saved edited image
    """
    sdedit = SDEdit(config_path)
    result = sdedit.sdedit(
        image=image_path,
        prompt=prompt,
        noise_strength=noise_strength,
        seed=seed
    )
    
    # Save edited image
    if output_path is None:
        base_name = os.path.splitext(os.path.basename(image_path))[0]
        output_path = f"{base_name}_sdedit_{noise_strength:.2f}.png"
    
    result['edited_image'].save(output_path)
    return output_path
