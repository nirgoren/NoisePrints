"""
SDEdit Corruption Module

This module provides SDEdit as a corruption type for the robustness testing framework.
It supports both same-model and cross-model adversarial attacks.
"""

import gc
from pathlib import Path
from typing import Dict, Any, Optional
import torch
from PIL import Image


def apply_sdedit_corruption(
    image: Image.Image,
    noise_strength: float,
    attack_model_config: str,
    output_dir: str,
    base_filename: str,
    prompt: str = "",
    guidance_scale: float = 1.0,
    seed: Optional[int] = None
) -> Dict[str, Any]:
    """
    Apply SDEdit corruption to an image.
    
    Args:
        image: Input PIL Image
        noise_strength: Noise strength for SDEdit (0.0-1.0)
        attack_model_config: Path to attack model configuration
        output_dir: Directory to save the corrupted image
        base_filename: Base filename for the corrupted image
        prompt: Text prompt for SDEdit (empty for unconditional)
        guidance_scale: Guidance scale for diffusion
        num_inference_steps: Number of denoising steps
        seed: Random seed for reproducibility
        
    Returns:
        Dictionary containing the corrupted image and metadata
    """
    sdedit = None
    try:
        print(f"Loading SDEdit pipeline: {attack_model_config}")
        # Lazy import to avoid circular dependency
        from seed_watermark.adversary_attacks.SDEdit import SDEdit
        sdedit = SDEdit(attack_model_config)
        
        # Generate a seed if not provided
        if seed is None:
            seed = torch.randint(0, 2**32, (1,)).item()
        
        # Apply SDEdit
        sdedit_result = sdedit.sdedit(
            image=image,
            prompt=prompt,
            noise_strength=noise_strength,
            guidance_scale=guidance_scale,
            seed=seed
        )
        edited_image = sdedit_result['edited_image']
        
        # Create output directory
        corruption_dir = Path(output_dir) / "corruptions" / f"sdedit_ns{noise_strength}"
        corruption_dir.mkdir(parents=True, exist_ok=True)
        
        # Save the edited image
        attack_model_name = Path(attack_model_config).stem
        output_filename = f"{base_filename}_sdedit_{attack_model_name}_ns{noise_strength}_seed{seed}.png"
        output_path = corruption_dir / output_filename
        
        edited_image.save(output_path)
        
        print(f"SDEdit result saved: {output_path}")
        
        return {
            "image": edited_image,
            "output_path": str(output_path),
            "metadata": {
                "noise_strength": noise_strength,
                "attack_model": attack_model_name,
                "seed": seed,
                "prompt": prompt,
                "guidance_scale": guidance_scale,
            }
        }
        
    except Exception as e:
        print(f"SDEdit corruption failed: {str(e)}")
        # Return the original image if SDEdit fails
        return {
            "image": image,
            "output_path": None,
            "metadata": {"error": str(e)}
        }
    finally:
        # Clean up the pipeline and free GPU memory
        if sdedit is not None:
            if hasattr(sdedit, 'pipe') and sdedit.pipe is not None:
                del sdedit.pipe
            del sdedit
        gc.collect()
        torch.cuda.empty_cache()


def create_sdedit_corruption(
    noise_strength: float,
    attack_model_config: str,
    prompt: str = "",
    guidance_scale: float = 1.0,
):
    """
    Create an SDEdit corruption function for the CORRUPTIONS list.
    
    Args:
        noise_strength: Noise strength for SDEdit (0.0-1.0)
        attack_model_config: Path to attack model configuration
        prompt: Text prompt for SDEdit (empty for unconditional)
        guidance_scale: Guidance scale for diffusion
        num_inference_steps: Number of denoising steps
        
    Returns:
        Corruption function compatible with the robustness testing framework
    """
    def sdedit_corruption_function(image: Image.Image, **context) -> Dict[str, Any]:
        """
        SDEdit corruption function.
        
        Args:
            image: Input PIL Image
            **context: Additional context including output_dir, base_filename
            
        Returns:
            Dictionary with 'image' and optional 'cleanup' function
        """
        # Extract context information
        output_dir = context.get('output_dir', 'temp_sdedit_output')
        base_filename = context.get('base_filename', 'image')
        
        # Apply SDEdit corruption
        result = apply_sdedit_corruption(
            image=image,
            noise_strength=noise_strength,
            attack_model_config=attack_model_config,
            output_dir=output_dir,
            base_filename=base_filename,
            prompt=prompt,
            guidance_scale=guidance_scale,
        )
        
        return {
            "image": result["image"],
            "output_path": result.get("output_path"),
            "metadata": result.get("metadata", {})
        }
    
    return sdedit_corruption_function


def get_sdedit_corruptions(
    config,
    sdedit_config: Dict[str, Any]
) -> list:
    """
    Generate a list of SDEdit corruptions based on configuration.
    
    Args:
        config: Main model configuration object
        sdedit_config: SDEdit-specific configuration
        
    Returns:
        List of corruption dictionaries for the CORRUPTIONS list
    """
    corruptions = []
    
    if not sdedit_config.get('enabled', False):
        return corruptions
    
    noise_strengths = sdedit_config.get('noise_strengths', [0.2, 0.3])
    attack_models = sdedit_config.get('attack_models', ['same'])
    cross_model_config = sdedit_config.get('cross_model_config')
    
    for noise_strength in noise_strengths:
        for attack_model in attack_models:
            if attack_model == 'same':
                # Use the same model as the generation config
                # This requires creating a temporary config file path
                attack_config_path = f"configs/{config.MODEL_TYPE}_config.yaml"
                model_name = config.MODEL_TYPE
            elif attack_model == 'cross' and cross_model_config:
                # Use a different model for cross-model attack
                attack_config_path = cross_model_config
                model_name = Path(cross_model_config).stem.replace('_config', '')
            else:
                continue  # Skip invalid configurations
                
            corruption_name = f"sdedit_{model_name}_ns{noise_strength}"
            
            corruption = {
                "name": corruption_name,
                "function": create_sdedit_corruption(
                    noise_strength=noise_strength,
                    attack_model_config=attack_config_path,
                    prompt="",  # Unconditional editing
                    guidance_scale=1.0,
                )
            }
            
            corruptions.append(corruption)
    
    return corruptions