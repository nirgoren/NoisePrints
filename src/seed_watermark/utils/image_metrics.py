"""
Lightweight image quality metrics: SSIM, PSNR, and LPIPS.

Implements SSIM using a Gaussian window via scipy.ndimage and PSNR via MSE.
LPIPS is provided on a best-effort basis: if an LPIPS implementation
(`lpips` package or torchvision VGG features) is available locally,
it is used; otherwise, the function returns NaN and logs a debug note.
"""

from __future__ import annotations

from typing import Optional, Tuple

import numpy as np
from PIL import Image
from scipy.ndimage import gaussian_filter
import logging

logger = logging.getLogger(__name__)


def _to_uint8_rgb(arr_or_img: Image.Image | np.ndarray) -> np.ndarray:
    """Convert input PIL image or ndarray to RGB uint8 numpy array (H, W, 3).

    - If input is grayscale, expands to 3 channels.
    - If dtype is float, assumes range [0, 1] and scales to [0, 255].
    - If dtype is uint8, uses as-is.
    """
    if isinstance(arr_or_img, Image.Image):
        img = arr_or_img.convert("RGB")
        arr = np.asarray(img)
    else:
        arr = np.asarray(arr_or_img)
        # Handle channel dimensionality
        if arr.ndim == 2:
            arr = np.stack([arr, arr, arr], axis=-1)
        elif arr.ndim == 3 and arr.shape[2] == 4:
            # Drop alpha if present
            arr = arr[..., :3]

        if arr.dtype != np.uint8:
            # Assume in [0, 1] if float, otherwise clip sensibly
            arr = np.clip(arr, 0.0, 1.0) if np.issubdtype(arr.dtype, np.floating) else np.clip(arr, 0, 255)
            arr = (arr * 255.0).round().astype(np.uint8) if arr.dtype != np.uint8 else arr

    # Ensure RGB channels
    if arr.ndim == 2:
        arr = np.stack([arr, arr, arr], axis=-1)
    return arr


def _resize_to_match(img: Image.Image, target_size: Tuple[int, int]) -> Image.Image:
    if img.size != target_size:
        return img.resize(target_size, Image.Resampling.LANCZOS)
    return img


def compute_psnr(img1: Image.Image, img2: Image.Image) -> float:
    """Compute PSNR between two images.

    Args:
        img1: Reference PIL Image
        img2: Distorted PIL Image
    Returns:
        PSNR value in dB (float('inf') if identical)
    """
    img2r = _resize_to_match(img2, img1.size)
    a = _to_uint8_rgb(img1).astype(np.float64)
    b = _to_uint8_rgb(img2r).astype(np.float64)
    mse = np.mean((a - b) ** 2)
    if mse == 0:
        return float("inf")
    PIXEL_MAX = 255.0
    psnr = 10.0 * np.log10((PIXEL_MAX ** 2) / mse)
    return float(psnr)


def _ssim_per_channel(x: np.ndarray, y: np.ndarray, data_range: float = 255.0, sigma: float = 1.5) -> float:
    """Compute SSIM for a single channel using Gaussian window.

    x, y are 2D arrays in [0, 255].
    """
    x = x.astype(np.float64)
    y = y.astype(np.float64)

    # Gaussian smoothing for local means and variances
    mu_x = gaussian_filter(x, sigma=sigma)
    mu_y = gaussian_filter(y, sigma=sigma)

    mu_x2 = mu_x * mu_x
    mu_y2 = mu_y * mu_y
    mu_xy = mu_x * mu_y

    sigma_x2 = gaussian_filter(x * x, sigma=sigma) - mu_x2
    sigma_y2 = gaussian_filter(y * y, sigma=sigma) - mu_y2
    sigma_xy = gaussian_filter(x * y, sigma=sigma) - mu_xy

    K1, K2 = 0.01, 0.03
    C1 = (K1 * data_range) ** 2
    C2 = (K2 * data_range) ** 2

    numerator = (2 * mu_xy + C1) * (2 * sigma_xy + C2)
    denominator = (mu_x2 + mu_y2 + C1) * (sigma_x2 + sigma_y2 + C2)

    # Avoid division by zero
    ssim_map = numerator / (denominator + 1e-12)
    return float(np.mean(ssim_map))


def compute_ssim(img1: Image.Image, img2: Image.Image) -> float:
    """Compute SSIM between two images.

    Args:
        img1: Reference PIL Image
        img2: Distorted PIL Image
    Returns:
        SSIM value in [-1, 1]
    """
    img2r = _resize_to_match(img2, img1.size)
    a = _to_uint8_rgb(img1)
    b = _to_uint8_rgb(img2r)

    # Compute per-channel SSIM and average
    if a.ndim == 3 and a.shape[2] == 3:
        vals = [
            _ssim_per_channel(a[..., c], b[..., c])
            for c in range(3)
        ]
        return float(np.mean(vals))
    else:
        return _ssim_per_channel(a.squeeze(), b.squeeze())


def compute_ssim_psnr(img1: Image.Image, img2: Image.Image) -> Tuple[float, float]:
    """Compute SSIM and PSNR between two PIL Images.

    Returns a tuple (ssim, psnr).
    """
    ssim = compute_ssim(img1, img2)
    psnr = compute_psnr(img1, img2)
    return float(ssim), float(psnr)


# --- LPIPS support (best-effort, optional deps) ---
_LPIPS_MODEL = None
_LPIPS_IMPL = None  # one of {"lpips", "torchvision", None}


def _init_lpips_model(device: Optional[str] = None):
    """Initialize a global LPIPS model if available.

    Tries `lpips` package first; falls back to a VGG-feature variant if torchvision
    pretrained weights are available locally. If neither works, leaves model as None.
    """
    global _LPIPS_MODEL, _LPIPS_IMPL
    if _LPIPS_MODEL is not None:
        return

    # Choose device: prefer CUDA if available; otherwise CPU
    try:
        import torch
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        device = "cpu"

    # Try richzhang/lpips package first
    try:
        import torch  # noqa: F401
        import lpips  # type: ignore
        _LPIPS_MODEL = lpips.LPIPS(net='alex')
        try:
            _LPIPS_MODEL = _LPIPS_MODEL.to(device)
        except Exception:
            _LPIPS_MODEL = _LPIPS_MODEL.to('cpu')
            device = 'cpu'
        _LPIPS_MODEL.eval()
        _LPIPS_IMPL = "lpips"
        logger.info("LPIPS: using `lpips` package with alex backbone on %s", device)
        return
    except Exception as e:
        logger.debug("LPIPS: `lpips` package not available or failed to load: %s", e)

    # Fallback: torchvision VGG features (requires local pretrained weights)
    try:
        import torch
        from torchvision import models
        weights = models.VGG16_Weights.IMAGENET1K_FEATURES
        vgg = models.vgg16(weights=weights).features
        for p in vgg.parameters():
            p.requires_grad_(False)
        try:
            vgg = vgg.eval().to(device)
        except Exception:
            vgg = vgg.eval().to('cpu')
            device = 'cpu'
        _LPIPS_MODEL = vgg
        _LPIPS_IMPL = "torchvision"
        logger.info("LPIPS: using torchvision VGG16 features on %s", device)
        return
    except Exception as e:
        logger.debug("LPIPS fallback (torchvision VGG16) unavailable: %s", e)
        _LPIPS_MODEL = None
        _LPIPS_IMPL = None


def compute_lpips(img1: Image.Image, img2: Image.Image) -> float:
    """Compute LPIPS distance between two PIL Images.

    Returns a float distance (lower is more similar). If no LPIPS implementation
    is available locally, returns NaN.
    """
    _init_lpips_model()
    if _LPIPS_MODEL is None:
        return float('nan')

    # Resize second to first for consistency
    img2r = _resize_to_match(img2, img1.size)

    # Convert to torch tensors in [-1, 1], NCHW
    try:
        import torch
        a = np.asarray(img1.convert('RGB'), dtype=np.float32) / 255.0
        b = np.asarray(img2r.convert('RGB'), dtype=np.float32) / 255.0
        a = torch.from_numpy(a).permute(2, 0, 1).unsqueeze(0)  # 1x3xHxW
        b = torch.from_numpy(b).permute(2, 0, 1).unsqueeze(0)
        a = a * 2.0 - 1.0
        b = b * 2.0 - 1.0

        if _LPIPS_IMPL == "lpips":
            # Use package's forward
            device = next(_LPIPS_MODEL.parameters()).device
            a = a.to(device)
            b = b.to(device)
            with torch.no_grad():
                dist = _LPIPS_MODEL(a, b)
            return float(dist.item())
        elif _LPIPS_IMPL == "torchvision":
            # Simple VGG feature L2 across a few layers as rough proxy
            device = next(_LPIPS_MODEL.parameters()).device if list(_LPIPS_MODEL.parameters()) else torch.device('cpu')
            a = a.to(device)
            b = b.to(device)

            # Normalize to ImageNet mean/std expected by VGG
            mean = torch.tensor([0.485, 0.456, 0.406], device=device).view(1, 3, 1, 1)
            std = torch.tensor([0.229, 0.224, 0.225], device=device).view(1, 3, 1, 1)
            a_imnet = (a / 2.0 + 0.5 - mean) / std
            b_imnet = (b / 2.0 + 0.5 - mean) / std

            layers = [3, 8, 15, 22]  # relu1_2, relu2_2, relu3_3, relu4_3
            feats_a = a_imnet
            feats_b = b_imnet
            dists = []
            with torch.no_grad():
                for i, m in enumerate(_LPIPS_MODEL):
                    feats_a = m(feats_a)
                    feats_b = m(feats_b)
                    if i in layers:
                        # Normalize channels then L2 distance
                        fa = torch.nn.functional.normalize(feats_a, dim=1, eps=1e-10)
                        fb = torch.nn.functional.normalize(feats_b, dim=1, eps=1e-10)
                        d = torch.mean((fa - fb) ** 2)
                        dists.append(d)
            if not dists:
                return float('nan')
            dist = torch.mean(torch.stack(dists))
            return float(dist.item())
        else:
            return float('nan')
    except Exception as e:
        logger.debug("LPIPS compute failed: %s", e)
        return float('nan')


def compute_ssim_psnr_lpips(img1: Image.Image, img2: Image.Image) -> Tuple[float, float, float]:
    """Compute SSIM, PSNR, and LPIPS between two PIL Images.

    Returns a tuple (ssim, psnr, lpips). LPIPS may be NaN if not available.
    """
    ssim = compute_ssim(img1, img2)
    psnr = compute_psnr(img1, img2)
    lpips = compute_lpips(img1, img2)
    return float(ssim), float(psnr), float(lpips)
