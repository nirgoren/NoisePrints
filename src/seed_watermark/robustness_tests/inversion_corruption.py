"""
Inversion Attack Corruption Module

This module exposes an "inversion_attack" corruption similar in spirit to SDEdit
so it can be scheduled from analyze/detection flows. It performs:

1) DDIM inversion to estimate the noise of the input image
2) Latent optimization to reduce cosine similarity w.r.t. inverted noise
   while preserving fidelity to the original latents

Corruptions are configured via a new `inversion_corruptions:` YAML block, where
you can specify:
- enabled: bool
- similarity_weights: [floats]
- fidelity_weight: float
- attack_models: ["same", "cross"]
- cross_model_config: path to another YAML for cross-model inversion
- inversion_steps, inversion_guidance, optimization_steps, learning_rate
"""

from __future__ import annotations

import gc
from pathlib import Path
from typing import Dict, Any, Optional, List

import torch
from PIL import Image

from seed_watermark.adversary_attacks.inversion_attack import DDIMInversion
import yaml


def _run_inversion_attack(
    image: Image.Image,
    attack_model_config: str,
    similarity_weight: float,
    fidelity_weight: float,
    inversion_steps: int,
    inversion_guidance: float,
    optimization_steps: int,
    learning_rate: float,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Perform a single inversion-attack optimization producing a corrupted image.

    Returns a dict with keys:
    - image: the edited PIL image
    - metadata: parameters and any metrics computed here
    """
    inverter: Optional[DDIMInversion] = None
    try:
        inverter = DDIMInversion(attack_model_config)

        # Prepare inputs
        pil_image = image.convert("RGB")
        original_latents = inverter.encode_image_to_latents(pil_image)

        inverted_noise = inverter.invert_image(
            image=pil_image,
            prompt="",
            num_inference_steps=inversion_steps,
            guidance_scale=inversion_guidance,
            seed=seed,
        )

        # Optimize latents to reduce similarity to inverted noise
        optimized_latents = original_latents.clone().detach().requires_grad_(True)
        optimizer = torch.optim.Adam([optimized_latents], lr=learning_rate)

        for _ in range(int(optimization_steps)):
            optimizer.zero_grad()
            # Minimize cosine similarity to inverted noise, plus fidelity MSE
            cos_sim = torch.nn.functional.cosine_similarity(
                optimized_latents.flatten(), inverted_noise.flatten(), dim=0
            )
            similarity_loss = similarity_weight * cos_sim
            fidelity_loss = fidelity_weight * torch.nn.functional.mse_loss(
                optimized_latents, original_latents
            )
            total_loss = similarity_loss + fidelity_loss
            total_loss.backward()
            optimizer.step()

        edited_image = inverter.decode_latents_to_image(optimized_latents)

        # Minimal metrics for logging
        with torch.no_grad():
            final_inverted_similarity = torch.nn.functional.cosine_similarity(
                optimized_latents.flatten(), inverted_noise.flatten(), dim=0
            ).item()
            original_inverted_similarity = torch.nn.functional.cosine_similarity(
                original_latents.flatten(), inverted_noise.flatten(), dim=0
            ).item()

        return {
            "image": edited_image,
            "metadata": {
                "similarity_weight": similarity_weight,
                "fidelity_weight": fidelity_weight,
                "inversion_steps": inversion_steps,
                "inversion_guidance": inversion_guidance,
                "optimization_steps": optimization_steps,
                "learning_rate": learning_rate,
                "original_vs_inverted_similarity": original_inverted_similarity,
                "optimized_vs_inverted_similarity": final_inverted_similarity,
                "similarity_reduction": original_inverted_similarity - final_inverted_similarity,
                "seed": seed,
            },
        }
    finally:
        # Free GPU memory if possible
        if inverter is not None:
            if hasattr(inverter, "pipeline") and inverter.pipeline is not None:
                del inverter.pipeline
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()


def apply_inversion_corruption(
    image: Image.Image,
    attack_model_config: str,
    similarity_weight: float,
    fidelity_weight: float,
    output_dir: str,
    base_filename: str,
    inversion_steps: int = 50,
    inversion_guidance: float = 1.0,
    optimization_steps: int = 100,
    learning_rate: float = 0.01,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Apply a single inversion attack as a corruption and save the result.
    """
    # Execute the attack
    result = _run_inversion_attack(
        image=image,
        attack_model_config=attack_model_config,
        similarity_weight=similarity_weight,
        fidelity_weight=fidelity_weight,
        inversion_steps=inversion_steps,
        inversion_guidance=inversion_guidance,
        optimization_steps=optimization_steps,
        learning_rate=learning_rate,
        seed=seed,
    )

    # Persist image under a corruption subdir
    corruption_name = f"inversion_attack_sw{similarity_weight}"
    corruption_dir = Path(output_dir) / "corruptions" / corruption_name
    corruption_dir.mkdir(parents=True, exist_ok=True)

    attack_model_name = Path(attack_model_config).stem
    out_name = f"{base_filename}_inversion_{attack_model_name}_sw{similarity_weight}.png"
    out_path = corruption_dir / out_name
    result["image"].save(out_path)

    return {
        "image": result["image"],
        "output_path": str(out_path),
        "metadata": {
            **result.get("metadata", {}),
            "attack_model": attack_model_name,
        },
    }


def create_inversion_corruption(
    attack_model_config: str,
    similarity_weight: float,
    fidelity_weight: float,
    inversion_steps: int,
    inversion_guidance: float,
    optimization_steps: int,
    learning_rate: float,
):
    """
    Factory returning a corruption function compatible with the robustness interface.
    """
    def corruption_fn(image: Image.Image, **context) -> Dict[str, Any]:
        output_dir = context.get("output_dir", "out")
        base_filename = context.get("base_filename", "image")
        return apply_inversion_corruption(
            image=image,
            attack_model_config=attack_model_config,
            similarity_weight=similarity_weight,
            fidelity_weight=fidelity_weight,
            output_dir=output_dir,
            base_filename=base_filename,
            inversion_steps=inversion_steps,
            inversion_guidance=inversion_guidance,
            optimization_steps=optimization_steps,
            learning_rate=learning_rate,
        )

    return corruption_fn


def get_inversion_corruptions(config, inv_config: Dict[str, Any]) -> List[dict]:
    """
    Build a list of inversion-attack corruptions from configuration.

    inv_config schema (example):
      enabled: true
      similarity_weights: [0.2, 0.4]
      fidelity_weight: 1.0
      attack_models: ["same", "cross"]
      cross_model_config: "configs/sd2_0_config.yaml"
      inversion_steps: 50
      inversion_guidance: 1.0
      optimization_steps: 100
      learning_rate: 0.01
    """
    corruptions: List[dict] = []

    if not inv_config or not inv_config.get("enabled", False):
        return corruptions

    # DDIM inversion currently supports SDXL/SD1.4/SD2.0
    supported_types = {"sdxl", "sd1_4", "sd2_0"}

    # Helper to resolve an attack config path and a short model name
    def resolve_attack_config(attack_model: str) -> Optional[tuple[str, str]]:
        if attack_model == "same":
            # Use a stock config file for the same model_type
            if config.MODEL_TYPE not in supported_types:
                return None
            path = f"configs/{config.MODEL_TYPE}_config.yaml"
            return path, config.MODEL_TYPE
        elif attack_model == "cross":
            cross_path = inv_config.get("cross_model_config")
            if not cross_path:
                return None
            # Parse YAML to ensure supported model_type
            try:
                with open(cross_path, "r") as f:
                    cfg = yaml.safe_load(f)
                mt = cfg.get("model_type")
                if mt not in supported_types:
                    return None
                model_name = Path(cross_path).stem.replace("_config", "")
                return cross_path, model_name
            except Exception:
                # If parsing fails, skip to be safe
                return None
        return None

    similarity_weights = inv_config.get("similarity_weights", [0.3])
    fidelity_weight = inv_config.get("fidelity_weight", 1.0)
    inversion_steps = inv_config.get("inversion_steps", 50)
    inversion_guidance = inv_config.get("inversion_guidance", 1.0)
    optimization_steps = inv_config.get("optimization_steps", 100)
    learning_rate = inv_config.get("learning_rate", 0.01)

    for attack_model in inv_config.get("attack_models", ["same"]):
        resolved = resolve_attack_config(attack_model)
        if not resolved:
            continue
        attack_config_path, model_name = resolved

        for sw in similarity_weights:
            name = f"inversion_{model_name}_sw{sw}"
            fn = create_inversion_corruption(
                attack_model_config=attack_config_path,
                similarity_weight=sw,
                fidelity_weight=fidelity_weight,
                inversion_steps=inversion_steps,
                inversion_guidance=inversion_guidance,
                optimization_steps=optimization_steps,
                learning_rate=learning_rate,
            )
            corruptions.append({
                "name": name,
                "function": fn,
            })

    return corruptions
