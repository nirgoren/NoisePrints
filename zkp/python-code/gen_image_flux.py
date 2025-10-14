import torch
import numpy as np
from diffusers.pipelines.flux.pipeline_flux import FluxPipeline
from diffusers import AutoencoderKL
from diffusers.image_processor import VaeImageProcessor
import argparse

def generate_from_noise(noise_vector, output_prefix="output", prompt="", save_latents=True):
    """
    Generate an image from a noise vector using Flux

    Args:
        noise_vector: numpy array or torch tensor of shape matching latent space
        output_prefix: prefix for output files
        prompt: text prompt for generation
        save_latents: whether to save the output latents
    """
    device = "cuda" if torch.cuda.is_available() else "cpu"

    # Load Flux without VAE to save memory
    pipe = FluxPipeline.from_pretrained(
        "black-forest-labs/FLUX.1-schnell",
        torch_dtype=torch.bfloat16,
        vae=None
    )
    pipe.enable_model_cpu_offload()

    if isinstance(noise_vector, np.ndarray):
        latents = torch.from_numpy(noise_vector)
    else:
        latents = noise_vector

    latents = latents.reshape(1, 4096, 64)
    latents = latents.to(device, dtype=torch.bfloat16)


    print("Running Flux pipeline to generate output latents...")
    with torch.no_grad():
        output_latents = pipe(
            prompt=prompt,
            height=1024,
            width=1024,
            latents=latents,
            num_inference_steps=4,
            guidance_scale=0.0,
            output_type="latent"
        ).images

    if save_latents:
        latents_flat = output_latents.cpu().float().numpy().flatten()
        np.save(f"{output_prefix}_latents.npy", latents_flat)
        print(f"Saved latents to {output_prefix}_latents.npy")
        print(f"Latents shape (flattened): {latents_flat.shape}")

    del pipe
    torch.cuda.empty_cache()

    print("Loading VAE for decoding...")
    vae = AutoencoderKL.from_pretrained(
        "black-forest-labs/FLUX.1-schnell",
        subfolder="vae",
        torch_dtype=torch.bfloat16
    ).to(device)
    image_processor = VaeImageProcessor(vae_scale_factor=16)

    print("Decoding latents to image...")
    with torch.no_grad():

        output_latents = output_latents.to(device, dtype=torch.bfloat16)

        batch_size = output_latents.shape[0]
        unpacked_latents = output_latents.view(batch_size, 64, 64, 64)
        unpacked_latents = unpacked_latents.view(batch_size, 64, 64, 16, 2, 2)
        unpacked_latents = unpacked_latents.permute(0, 3, 1, 4, 2, 5)
        unpacked_latents = unpacked_latents.reshape(batch_size, 16, 128, 128)

        unpacked_latents = (unpacked_latents / vae.config.scaling_factor) + vae.config.shift_factor

        image_tensor = vae.decode(unpacked_latents, return_dict=False)[0]
        image = image_processor.postprocess(image_tensor, output_type="pil")[0]

    image.save(f"{output_prefix}.png")
    print(f"Saved image to {output_prefix}.png")

    # Clean up VAE
    del vae
    torch.cuda.empty_cache()

    if save_latents:
        return image, latents_flat
    return image


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate image from noise vector using Flux")
    parser.add_argument("--noise", type=str, required=True, help="Path to .npy file containing noise vector")
    parser.add_argument("--output_prefix", type=str, default="output", help="Prefix for output files")
    parser.add_argument("--prompt", type=str, default="", help="Optional text prompt")
    parser.add_argument("--no-save-latents", action="store_true", help="Don't save output latents")

    args = parser.parse_args()

    noise = np.load(args.noise)
    print(f"Loaded noise from {args.noise}, shape: {noise.shape}")

    result = generate_from_noise(
        noise,
        output_prefix=args.output_prefix,
        prompt=args.prompt,
        save_latents=not args.no_save_latents
    )

    if not args.no_save_latents:
        image, latents = result
        print(f"Generated image and saved {len(latents)} latent values")
    else:
        image = result
        print("Generated image without saving latents")
