
import os
import torch
import yaml
from PIL import ImageFilter, ImageEnhance, Image
from torchvision import transforms
import numpy as np
from seed_watermark.robustness_tests.sdedit_corruption import get_sdedit_corruptions
from seed_watermark.robustness_tests.inversion_corruption import get_inversion_corruptions

def load_config(config_path: str):
    """Load configuration from YAML file and return config object with all parameters."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    # Create a configuration object with all parameters
    class Config:
        def __init__(self, config_dict):
            # General Configuration
            self.DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
            self.MODEL_TYPE = config_dict["model_type"]
            self.MODEL_ID = config_dict["model_id"]
            self.LORA_WEIGHTS = config_dict.get("lora_weights", None)  # Optional LoRA weights
            self.IMAGE_GENERATION_COUNT = config_dict["image_generation_count"]
            self.OUTPUT_DIR = config_dict["output_dir"]
            self.LATENT_DIR = config_dict["latent_dir"]
            self.RESULTS_FILE = config_dict["results_file"]
            
            # Image Generation
            self.IMAGE_WIDTH = config_dict["image_width"]
            self.IMAGE_HEIGHT = config_dict["image_height"]
            self.NUM_INFERENCE_STEPS = config_dict["num_inference_steps"]
            self.GUIDANCE_SCALE = config_dict["guidance_scale"]
            
            # Model-specific parameters
            if self.MODEL_TYPE == "flux":
                self.ORIGINAL_NOISE_SHAPE = (1, 4096, 64)
                self.VAE_SCALE_FACTOR = 8
                self.USES_SHIFT_FACTOR = True
            elif self.MODEL_TYPE == "sdxl":
                self.ORIGINAL_NOISE_SHAPE = (1, 4, self.IMAGE_HEIGHT // 8, self.IMAGE_WIDTH // 8)
                self.VAE_SCALE_FACTOR = 8
                self.USES_SHIFT_FACTOR = False
            elif self.MODEL_TYPE in ["sd1_4", "sd2_0"]:
                self.ORIGINAL_NOISE_SHAPE = (1, 4, self.IMAGE_HEIGHT // 8, self.IMAGE_WIDTH // 8)
                self.VAE_SCALE_FACTOR = 8
                self.USES_SHIFT_FACTOR = False
            else:
                raise ValueError(f"Unsupported model type: {self.MODEL_TYPE}")
            
            # Base corruptions parameterization (optional)
            self.BASE_CORRUPTIONS_CONFIG = config_dict.get("base_corruptions", None)

            # SDEdit corruption configuration
            self.SDEDIT_CONFIG = config_dict.get("sdedit_corruptions", {
                "enabled": False,
                "noise_strengths": [0.2, 0.3],
                "attack_models": ["same"],
                "cross_model_config": None
            })
            # Inversion-attack corruption configuration
            self.INVERSION_ATTACK_CONFIG = config_dict.get("inversion_corruptions", {
                "enabled": False,
                "similarity_weights": [0.3],
                "fidelity_weight": 1.0,
                "attack_models": ["same"],
                "cross_model_config": None,
                "inversion_steps": 50,
                "inversion_guidance": 1.0,
                "optimization_steps": 100,
                "learning_rate": 0.01,
            })
    
    config_obj = Config(config)
    
    # Generate dynamic corruptions list including SDEdit and inversion attacks
    global CORRUPTIONS
    CORRUPTIONS = (
        get_base_corruptions(config_obj)
        + get_sdedit_corruptions(config_obj, config_obj.SDEDIT_CONFIG)
        + get_inversion_corruptions(config_obj, config_obj.INVERSION_ATTACK_CONFIG)
    )
    
    return config_obj

# --- Analysis ---
# Define the corruptions to be applied to the images.
# Each corruption is a dictionary with a 'name' and a 'function' that takes a PIL image and returns a corrupted PIL image.
def get_base_corruptions(config_or_dict=None):
    """Get parameterized base corruptions (non-SDEdit).

    Reads settings from `base_corruptions` YAML block when available. Falls back to
    previous defaults if not specified.
    """

    # Resolve settings from config object or dict
    settings = None
    if config_or_dict is not None:
        if isinstance(config_or_dict, dict):
            settings = config_or_dict.get("base_corruptions")
        else:
            settings = getattr(config_or_dict, "BASE_CORRUPTIONS_CONFIG", None)

    # Defaults (match previous behavior)
    if not settings:
        settings = {
            "jpeg_corruption": {"quality": [25]},
            "gaussian_blur": {"radius": [8]},
            "gaussian_noise": {"std": [0.1]},
            "brightness_change": {"factor": [4.0]},
            "contrast_change": {"factor": [4.0]},
            "resize": {"scale": [0.25]},  # downsample then upsample
        }

    def make_jpeg(quality: int):
        def fn(img: Image.Image, **kwargs):
            from io import BytesIO
            buf = BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=int(quality))
            buf.seek(0)
            out = Image.open(buf).convert("RGB")
            return {"image": out, "metadata": {"quality": int(quality)}}
        return fn

    def make_blur(radius: float):
        def fn(img: Image.Image, **kwargs):
            return {"image": img.filter(ImageFilter.GaussianBlur(radius=float(radius))),
                    "metadata": {"radius": float(radius)}}
        return fn

    def make_noise(std: float):
        def fn(img: Image.Image, **kwargs):
            arr = np.array(img, dtype=np.float32) / 255.0
            noise = np.random.normal(0.0, float(std), arr.shape).astype(np.float32)
            out = np.clip(arr + noise, 0.0, 1.0)
            out_img = Image.fromarray((out * 255).astype(np.uint8))
            return {"image": out_img, "metadata": {"std": float(std)}}
        return fn

    def make_brightness(factor: float):
        def fn(img: Image.Image, **kwargs):
            out = ImageEnhance.Brightness(img).enhance(float(factor))
            return {"image": out, "metadata": {"factor": float(factor)}}
        return fn

    def make_contrast(factor: float):
        def fn(img: Image.Image, **kwargs):
            out = ImageEnhance.Contrast(img).enhance(float(factor))
            return {"image": out, "metadata": {"factor": float(factor)}}
        return fn

    def make_resize(scale: float):
        def fn(img: Image.Image, **kwargs):
            # Downscale by scale then upscale back to original size
            dw = max(1, int(img.width * float(scale)))
            dh = max(1, int(img.height * float(scale)))
            small = transforms.Resize((dh, dw))(img)
            back = transforms.Resize((img.height, img.width))(small)
            return {"image": back, "metadata": {"scale": float(scale)}}
        return fn

    corruptions = []

    # JPEG
    for q in settings.get("jpeg_corruption", {}).get("quality", []):
        corruptions.append({
            "type": "jpeg_corruption",
            "name": f"jpeg_corruption_q{q}",
            "function": make_jpeg(q),
        })

    # Gaussian Blur
    for r in settings.get("gaussian_blur", {}).get("radius", []):
        corruptions.append({
            "type": "gaussian_blur",
            "name": f"gaussian_blur_r{r}",
            "function": make_blur(r),
        })

    # Gaussian Noise
    for s in settings.get("gaussian_noise", {}).get("std", []):
        corruptions.append({
            "type": "gaussian_noise",
            "name": f"gaussian_noise_std{s}",
            "function": make_noise(s),
        })

    # Brightness
    for f in settings.get("brightness_change", {}).get("factor", []):
        corruptions.append({
            "type": "brightness_change",
            "name": f"brightness_change_f{f}",
            "function": make_brightness(f),
        })

    # Contrast
    for f in settings.get("contrast_change", {}).get("factor", []):
        corruptions.append({
            "type": "contrast_change",
            "name": f"contrast_change_f{f}",
            "function": make_contrast(f),
        })

    # Resize (downsample/upsample)
    for s in settings.get("resize", {}).get("scale", []):
        corruptions.append({
            "type": "resize",
            "name": f"resize_s{s}",
            "function": make_resize(s),
        })

    return corruptions


# Initialize with default base corruptions (will be updated by load_config)
CORRUPTIONS = get_base_corruptions(None)
