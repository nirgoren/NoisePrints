"""
Gaussian Shading Watermarking Implementation

This module implements the Gaussian Shading watermarking method for diffusion models.
It includes two variants:
1. Gaussian_Shading: Simple XOR-based encryption
2. Gaussian_Shading_chacha: ChaCha20-based encryption

Based on the reference implementation but adapted for integration with the existing pipeline.
"""

import torch
import numpy as np
from scipy.stats import norm, truncnorm
from functools import reduce
from scipy.special import betainc
import logging

# Optional ChaCha20 support
try:
    from Crypto.Cipher import ChaCha20
    from Crypto.Random import get_random_bytes
    HAS_CHACHA20 = True
except ImportError:
    HAS_CHACHA20 = False
    ChaCha20 = None
    get_random_bytes = None

logger = logging.getLogger(__name__)


class Gaussian_Shading_chacha:
    """
    Gaussian Shading watermarking with ChaCha20 encryption.
    
    This implementation uses ChaCha20 stream cipher to encrypt the watermark bits
    before embedding them through truncated sampling.
    
    Supports both SD2.0 (512x512) and SDXL (1024x1024) image sizes.
    """
    
    def __init__(self, ch_factor=1, hw_factor=8, fpr=0.000001, user_number=1000000, image_size=512, device="cuda"):
        """
        Initialize Gaussian Shading with ChaCha20 encryption.
        
        Args:
            ch_factor: Channel repetition factor (default: 1)
            hw_factor: Height/Width downsampling factor (default: 8)  
            fpr: Target false positive rate (default: 1e-6)
            user_number: Number of potential users for multi-user scenario
            image_size: Image size in pixels (512 for SD2.0, 1024 for SDXL)
            device: Device to use for computations (default: "cuda")
        """
        if not HAS_CHACHA20:
            raise ImportError("ChaCha20 encryption requires pycryptodome: pip install pycryptodome")
        self.ch = ch_factor
        self.hw = hw_factor
        self.device = device
        self.nonce = None
        self.key = None
        self.watermark = None
        
        # Calculate dimensions for given image size
        # For SD2.0: 512x512 -> latent 64x64 -> 4x64x64 = 16,384 elements
        # For SDXL: 1024x1024 -> latent 128x128 -> 4x128x128 = 65,536 elements
        self.latent_h = image_size // 8
        self.latent_w = image_size // 8
        self.latentlength = 4 * self.latent_h * self.latent_w
        self.marklength = self.latentlength // (self.ch * self.hw * self.hw)

        self.threshold = 1 if self.hw == 1 and self.ch == 1 else self.ch * self.hw * self.hw // 2
        self.tp_onebit_count = 0
        self.tp_bits_count = 0
        self.tau_onebit = None
        self.tau_bits = None

        # Calculate detection thresholds based on FPR
        for i in range(self.marklength):
            fpr_onebit = betainc(i+1, self.marklength-i, 0.5)
            fpr_bits = betainc(i+1, self.marklength-i, 0.5) * user_number
            if fpr_onebit <= fpr and self.tau_onebit is None:
                self.tau_onebit = i / self.marklength
            if fpr_bits <= fpr and self.tau_bits is None:
                self.tau_bits = i / self.marklength

        logger.info(f"Gaussian Shading ChaCha initialized:")
        logger.info(f"  - Image size: {image_size}x{image_size}")
        logger.info(f"  - Latent size: {self.latent_h}x{self.latent_w}")
        logger.info(f"  - Ch factor: {ch_factor}, HW factor: {hw_factor}")
        logger.info(f"  - Mark length: {self.marklength}")
        logger.info(f"  - Detection thresholds: onebit={self.tau_onebit:.6f}, bits={self.tau_bits:.6f}")

    def stream_key_encrypt(self, sd):
        """Encrypt watermark bits using ChaCha20 stream cipher."""
        self.key = get_random_bytes(32)
        self.nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=self.key, nonce=self.nonce)
        m_byte = cipher.encrypt(np.packbits(sd).tobytes())
        m_bit = np.unpackbits(np.frombuffer(m_byte, dtype=np.uint8))
        return m_bit

    def truncSampling(self, message):
        """
        Generate watermarked noise through truncated sampling.
        
        This is the core embedding function that converts binary message
        into Gaussian noise with specific statistical properties.
        """
        z = np.zeros(self.latentlength)
        denominator = 2.0
        ppf = [norm.ppf(j / denominator) for j in range(int(denominator) + 1)]
        for i in range(self.latentlength):
            dec_mes = reduce(lambda a, b: 2 * a + b, message[i : i + 1])
            dec_mes = int(dec_mes)
            z[i] = truncnorm.rvs(ppf[dec_mes], ppf[dec_mes + 1])
        z = torch.from_numpy(z).reshape(1, 4, self.latent_h, self.latent_w).half()
        return z.to(self.device)

    def create_watermark_and_return_w(self):
        """
        Create watermark and return watermarked initial noise.
        
        Returns:
            torch.Tensor: Watermarked initial noise for diffusion process
        """
        self.watermark = torch.randint(0, 2, [1, 4 // self.ch, self.latent_h // self.hw, self.latent_w // self.hw]).to(self.device)
        sd = self.watermark.repeat(1, self.ch, self.hw, self.hw)
        m = self.stream_key_encrypt(sd.flatten().cpu().numpy())
        w = self.truncSampling(m)
        return w

    def stream_key_decrypt(self, reversed_m):
        """Decrypt recovered bits using ChaCha20."""
        cipher = ChaCha20.new(key=self.key, nonce=self.nonce)
        sd_byte = cipher.decrypt(np.packbits(reversed_m).tobytes())
        sd_bit = np.unpackbits(np.frombuffer(sd_byte, dtype=np.uint8))
        sd_tensor = torch.from_numpy(sd_bit).reshape(1, 4, self.latent_h, self.latent_w).to(torch.uint8)
        return sd_tensor.to(self.device)

    def diffusion_inverse(self, watermark_r):
        """
        Inverse the diffusion process to recover watermark bits through voting.
        
        This function implements the key detection mechanism by splitting the
        recovered latents into blocks and voting on watermark bits.
        """
        ch_stride = 4 // self.ch
        hw_stride = self.latent_h // self.hw
        ch_list = [ch_stride] * self.ch
        hw_list = [hw_stride] * self.hw
        split_dim1 = torch.cat(torch.split(watermark_r, tuple(ch_list), dim=1), dim=0)
        split_dim2 = torch.cat(torch.split(split_dim1, tuple(hw_list), dim=2), dim=0)
        split_dim3 = torch.cat(torch.split(split_dim2, tuple(hw_list), dim=3), dim=0)
        vote = torch.sum(split_dim3, dim=0).clone()
        vote[vote <= self.threshold] = 0
        vote[vote > self.threshold] = 1
        return vote

    def eval_watermark(self, reversed_w):
        """
        Evaluate watermark detection from recovered noise.
        
        Args:
            reversed_w: Recovered noise from DDIM inversion
            
        Returns:
            float: Watermark detection accuracy (0-1)
        """
        reversed_m = (reversed_w > 0).int()
        reversed_sd = self.stream_key_decrypt(reversed_m.flatten().cpu().numpy())
        reversed_watermark = self.diffusion_inverse(reversed_sd)
        correct = (reversed_watermark == self.watermark).float().mean().item()
        
        # Update detection counts
        if correct >= self.tau_onebit:
            self.tp_onebit_count = self.tp_onebit_count + 1
        if correct >= self.tau_bits:
            self.tp_bits_count = self.tp_bits_count + 1
        
        return correct

    def get_tpr(self):
        """Get true positive rate for both detection modes."""
        return self.tp_onebit_count, self.tp_bits_count


class Gaussian_Shading:
    """
    Gaussian Shading watermarking with simple XOR encryption.
    
    This implementation uses simple XOR with a random key for encryption,
    making it lighter weight than the ChaCha20 variant.
    
    Supports both SD2.0 (512x512) and SDXL (1024x1024) image sizes.
    """
    
    def __init__(self, ch_factor=1, hw_factor=8, fpr=0.000001, user_number=1000000, image_size=512, device="cuda"):
        """
        Initialize Gaussian Shading with XOR encryption.
        
        Args:
            ch_factor: Channel repetition factor (default: 1)
            hw_factor: Height/Width downsampling factor (default: 8)
            fpr: Target false positive rate (default: 1e-6)  
            user_number: Number of potential users for multi-user scenario
            image_size: Image size in pixels (512 for SD2.0, 1024 for SDXL)
            device: Device to use for computations (default: "cuda")
        """
        self.ch = ch_factor
        self.hw = hw_factor
        self.device = device
        self.key = None
        self.watermark = None
        
        # Calculate dimensions for given image size
        self.latent_h = image_size // 8
        self.latent_w = image_size // 8
        self.latentlength = 4 * self.latent_h * self.latent_w
        self.marklength = self.latentlength // (self.ch * self.hw * self.hw)

        self.threshold = 1 if self.hw == 1 and self.ch == 1 else self.ch * self.hw * self.hw // 2
        self.tp_onebit_count = 0
        self.tp_bits_count = 0
        self.tau_onebit = None
        self.tau_bits = None

        # Calculate detection thresholds based on FPR
        for i in range(self.marklength):
            fpr_onebit = betainc(i+1, self.marklength-i, 0.5)
            fpr_bits = betainc(i+1, self.marklength-i, 0.5) * user_number
            if fpr_onebit <= fpr and self.tau_onebit is None:
                self.tau_onebit = i / self.marklength
            if fpr_bits <= fpr and self.tau_bits is None:
                self.tau_bits = i / self.marklength

        logger.info(f"Gaussian Shading (XOR) initialized:")
        logger.info(f"  - Image size: {image_size}x{image_size}")
        logger.info(f"  - Latent size: {self.latent_h}x{self.latent_w}")
        logger.info(f"  - Ch factor: {ch_factor}, HW factor: {hw_factor}")
        logger.info(f"  - Mark length: {self.marklength}")
        logger.info(f"  - Detection thresholds: onebit={self.tau_onebit:.6f}, bits={self.tau_bits:.6f}")

    def truncSampling(self, message):
        """Generate watermarked noise through truncated sampling."""
        z = np.zeros(self.latentlength)
        denominator = 2.0
        ppf = [norm.ppf(j / denominator) for j in range(int(denominator) + 1)]
        for i in range(self.latentlength):
            dec_mes = reduce(lambda a, b: 2 * a + b, message[i : i + 1])
            dec_mes = int(dec_mes)
            z[i] = truncnorm.rvs(ppf[dec_mes], ppf[dec_mes + 1])
        z = torch.from_numpy(z).reshape(1, 4, self.latent_h, self.latent_w).half()
        return z.to(self.device)

    def create_watermark_and_return_w(self):
        """
        Create watermark and return watermarked initial noise.
        
        Returns:
            torch.Tensor: Watermarked initial noise for diffusion process
        """
        self.key = torch.randint(0, 2, [1, 4, self.latent_h, self.latent_w]).to(self.device)
        self.watermark = torch.randint(0, 2, [1, 4 // self.ch, self.latent_h // self.hw, self.latent_w // self.hw]).to(self.device)
        sd = self.watermark.repeat(1, self.ch, self.hw, self.hw)
        m = ((sd + self.key) % 2).flatten().cpu().numpy()
        w = self.truncSampling(m)
        return w

    def diffusion_inverse(self, watermark_sd):
        """Inverse the diffusion process to recover watermark bits through voting."""
        ch_stride = 4 // self.ch
        hw_stride = self.latent_h // self.hw
        ch_list = [ch_stride] * self.ch
        hw_list = [hw_stride] * self.hw
        split_dim1 = torch.cat(torch.split(watermark_sd, tuple(ch_list), dim=1), dim=0)
        split_dim2 = torch.cat(torch.split(split_dim1, tuple(hw_list), dim=2), dim=0)
        split_dim3 = torch.cat(torch.split(split_dim2, tuple(hw_list), dim=3), dim=0)
        vote = torch.sum(split_dim3, dim=0).clone()
        vote[vote <= self.threshold] = 0
        vote[vote > self.threshold] = 1
        return vote

    def eval_watermark(self, reversed_m):
        """
        Evaluate watermark detection from recovered noise.
        
        Args:
            reversed_m: Recovered noise from DDIM inversion
            
        Returns:
            float: Watermark detection accuracy (0-1)
        """
        reversed_m = (reversed_m > 0).int()
        reversed_sd = (reversed_m + self.key) % 2
        reversed_watermark = self.diffusion_inverse(reversed_sd)
        correct = (reversed_watermark == self.watermark).float().mean().item()
        
        # Update detection counts
        if correct >= self.tau_onebit:
            self.tp_onebit_count = self.tp_onebit_count + 1
        if correct >= self.tau_bits:
            self.tp_bits_count = self.tp_bits_count + 1
        
        return correct

    def get_tpr(self):
        """Get true positive rate for both detection modes."""
        return self.tp_onebit_count, self.tp_bits_count