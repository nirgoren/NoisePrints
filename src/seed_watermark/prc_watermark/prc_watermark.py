"""
PRC (Pseudo-Random Correlation) Watermarking Implementation (True Scheme)

This module implements the true PRC watermark method based on
"An Undetectable Watermark for Generative Image Models" (ICLR 2025).

Core components implemented:
- Key generation (sparse parity checks, generator matrix, one-time pad)
- Encoding to codeword signs in {±1}
- Detection statistic and threshold for a desired FPR

We intentionally omit message decoding to keep scope focused on pass/fail
watermark detection at configurable false positive rates.
"""

from __future__ import annotations

import os
import json
import logging
from typing import Optional, Tuple, Dict, Any

import numpy as np
import torch
from scipy.sparse import csr_matrix
from scipy.special import binom, erf
import galois

logger = logging.getLogger(__name__)


GF2 = galois.GF(2)


class PRCWatermark:
    """
    True PRC watermarking implementation (no simplified mode).

    Usage:
      - Call keygen(...) once to create and persist keys.
      - For each image: call encode_signs(...), then build latents as z = signs * |N(0,1)|.
      - For detection: invert image to latents, map to posteriors in (-1,1), run detect(...).
    """

    def __init__(
        self,
        latent_h: int,
        latent_w: int,
        channels: int,
        fpr: float,
        device: str = "cuda",
        posterior_scale: float = 1.0,
        clamp_eps: float = 1e-3,
        posterior_mapping: str = "erf",  # "erf" (reference), or "tanh" or "sign"
        posterior_variance: float = 1.5,  # used by erf mapping
    ):
        self.latent_h = latent_h
        self.latent_w = latent_w
        self.channels = channels
        self.latent_dim = channels * latent_h * latent_w
        self.fpr = float(fpr)
        self.device = device
        self.posterior_scale = float(posterior_scale)
        self.clamp_eps = float(clamp_eps)
        self.posterior_mapping = str(posterior_mapping)
        self.posterior_variance = float(posterior_variance)

        # Keys (set by keygen or load_keys)
        self.generator_matrix: Optional[np.ndarray] = None  # (n,k) uint8
        self.parity_check_matrix: Optional[csr_matrix] = None  # r x n CSR
        self.one_time_pad: Optional[np.ndarray] = None  # (n,) uint8
        self.test_bits: Optional[np.ndarray] = None  # (num_test_bits,) uint8
        self.g_dim: Optional[int] = None  # g
        self.noise_rate: Optional[float] = None
        self.permutation: Optional[np.ndarray] = None  # (n,) int

        # Derived
        self.k: Optional[int] = None
        self.r: Optional[int] = None
        self.t: Optional[int] = None
        self.max_bp_iter: Optional[int] = None  # kept for compatibility with paper; unused here

        logger.info(
            f"Initialized PRC watermark: n={self.latent_dim}, fpr={self.fpr}, posterior_scale={self.posterior_scale}"
        )

    # --------------------------- Key generation --------------------------- #
    def keygen(
        self,
        *,
        message_length: int = 512,
        false_positive_rate: Optional[float] = None,
        t: int = 3,
        g: Optional[int] = None,
        r: Optional[int] = None,
        noise_rate: Optional[float] = None,
        seed: Optional[int] = None,
    ) -> None:
        """Generate encoding/decoding keys following the reference algorithm.

        Stores keys in the instance for later use.
        """
        n = self.latent_dim
        if false_positive_rate is None:
            fpr = self.fpr
        else:
            fpr = float(false_positive_rate)

        rng = np.random.default_rng(seed)

        # Basic scheme parameters
        num_test_bits = int(np.ceil(np.log2(1.0 / fpr)))
        secpar = int(np.log2(binom(n, t)))
        if g is None:
            g_dim = secpar
        else:
            g_dim = int(g)

        if noise_rate is None:
            # 1 - 2 ** (-secpar / g^2)
            nr = 1.0 - 2.0 ** (-secpar / (g_dim ** 2))
        else:
            nr = float(noise_rate)

        k = message_length + g_dim + num_test_bits
        if r is None:
            r_val = n - k - secpar
        else:
            r_val = int(r)
        if r_val < 0:
            raise ValueError("r computed negative; choose smaller message_length or adjust parameters")

        # Sample n x k generator matrix over GF(2)
        G = GF2.Random((n, k))

        # Sample sparse parity-check matrix with t ones per row;
        # and set the last n-r rows of G as XOR of chosen earlier rows (as in reference)
        row_indices: list[int] = []
        col_indices: list[int] = []
        data: list[int] = []
        for row in range(r_val):
            chosen = rng.choice(n - r_val + row, size=t - 1, replace=False)
            chosen = np.append(chosen, n - r_val + row)
            row_indices.extend([row] * t)
            col_indices.extend(chosen.tolist())
            data.extend([1] * t)
            if t - 1 > 0:
                G[n - r_val + row] = G[chosen[:-1]].sum(axis=0)
            else:
                G[n - r_val + row] = GF2.Zeros(k)

        H = csr_matrix((np.array(data, dtype=np.uint8), (np.array(row_indices), np.array(col_indices))), shape=(r_val, n))

        # One-time pad and test bits
        otp = GF2.Random(n)
        test_bits = GF2.Random(num_test_bits)

        # Permutation
        perm = rng.permutation(n)
        G = G[perm]
        otp = otp[perm]
        # Permute columns of H (variables) by perm
        H = H[:, perm]

        # Store
        self.generator_matrix = G
        self.parity_check_matrix = H
        self.one_time_pad = otp
        self.test_bits = test_bits
        self.g_dim = g_dim
        self.noise_rate = nr
        self.permutation = perm
        self.k = k
        self.r = r_val
        self.t = int(t)
        self.max_bp_iter = int(np.log(n) / np.log(t)) if t > 1 else 1

        logger.info(
            f"KeyGen complete: n={n}, k={k}, r={r_val}, t={t}, g={g_dim}, num_test_bits={num_test_bits}, noise_rate={nr:.4f}"
        )

    # ------------------------------ Encoding ------------------------------ #
    def _build_payload(self, message: Optional[np.ndarray]) -> GF2.Array:
        """Build payload bits [test_bits | g_rand | message_padding] (uint8)."""
        if self.generator_matrix is None or self.test_bits is None or self.k is None or self.g_dim is None:
            raise RuntimeError("Keys not initialized; call keygen() or load_keys() first")

        k = self.k
        g_dim = self.g_dim
        test_bits = self.test_bits
        num_test_bits = test_bits.shape[0]

        msg_space = k - num_test_bits - g_dim
        if message is None:
            # Test bits + random filler for the rest
            tail = GF2.Random(k - num_test_bits)
            payload = np.concatenate([test_bits, tail])
        else:
            message = np.asarray(message, dtype=np.uint8)
            if message.ndim != 1:
                raise ValueError("message must be a 1D array of bits")
            if len(message) > msg_space:
                raise AssertionError("Message is too long for chosen parameters")
            g_rand = GF2.Random(g_dim)
            pad_len = msg_space - len(message)
            if pad_len > 0:
                pad = GF2.Zeros(pad_len)
                tail = np.concatenate([g_rand, GF2(message), pad])
            else:
                tail = np.concatenate([g_rand, GF2(message)])
            payload = np.concatenate([test_bits, tail])
        return payload

    def encode_signs(self, message: Optional[np.ndarray] = None) -> torch.Tensor:
        """Encode payload to codeword signs in {±1}, length n as torch.float32."""
        if (
            self.generator_matrix is None
            or self.one_time_pad is None
            or self.k is None
            or self.noise_rate is None
        ):
            raise RuntimeError("Keys not initialized; call keygen() or load_keys() first")

        G = self.generator_matrix  # (n,k) GF2
        otp = self.one_time_pad  # (n,) GF2
        n = G.shape[0]

        payload = self._build_payload(message)  # (k,) GF2

        # error ~ Bernoulli(noise_rate) in GF2
        error = GF2(np.random.binomial(1, self.noise_rate, n))

        # Compute codeword bits in GF(2): payload @ G^T + otp + error
        cw = payload @ G.T + otp + error

        signs = 1.0 - 2.0 * np.array(cw, dtype=np.float32)  # 0 -> +1, 1 -> -1
        return torch.from_numpy(signs)

    def embed_watermarked_latents(self, message: Optional[np.ndarray] = None, generator: Optional[torch.Generator] = None) -> torch.Tensor:
        """Construct watermarked latents z = signs * |N(0,1)| with shape [1,C,H,W]."""
        signs = self.encode_signs(message)  # (n,)
        signs_reshaped = signs.view(1, self.channels, self.latent_h, self.latent_w)
        if generator is not None:
            gen_device = getattr(generator, "device", self.device)
            noise = torch.randn(
                (1, self.channels, self.latent_h, self.latent_w),
                generator=generator,
                device=gen_device,
            )
        else:
            noise = torch.randn((1, self.channels, self.latent_h, self.latent_w), device=self.device)
        # Ensure devices match before multiply
        signs_reshaped = signs_reshaped.to(noise.device)
        latents = torch.abs(noise) * signs_reshaped
        return latents

    # ------------------------------ Detection ----------------------------- #
    @staticmethod
    def _clamp(v: np.ndarray, eps: float) -> np.ndarray:
        return np.clip(v, -1.0 + eps, 1.0 - eps)

    def latents_to_posteriors(self, latents: torch.Tensor) -> np.ndarray:
        """Map inverted latents to posterior expectations E[sign(z)].

        Reference-aligned default uses an erf-based mapping with variance=1.5:
            posteriors = erf(z / sqrt(2 * var * (1 + var)))
        Alternative mappings: tanh (sign(z) * tanh(alpha*|z|)) or sign-only.
        """
        z = latents.detach().float().cpu().numpy().reshape(-1)
        if self.posterior_mapping.lower() == "erf":
            denom = np.sqrt(2.0 * self.posterior_variance * (1.0 + self.posterior_variance))
            p = erf(z / denom)
            return self._clamp(p, self.clamp_eps)
        else:
            s = np.sign(z)
            s[s == 0.0] = 1.0
            if self.posterior_mapping.lower() == "tanh":
                m = np.tanh(self.posterior_scale * np.abs(z))
                p = s * m
                return self._clamp(p, self.clamp_eps)
            elif self.posterior_mapping.lower() == "sign":
                return s
            else:
                # Fallback to erf if unknown mapping
                denom = np.sqrt(2.0 * self.posterior_variance * (1.0 + self.posterior_variance))
                p = erf(z / denom)
                return self._clamp(p, self.clamp_eps)

    def _apply_channel_and_pad(self, posteriors: np.ndarray) -> np.ndarray:
        """Apply channel noise scaling and one-time pad as in the reference Detect."""
        if self.one_time_pad is None or self.noise_rate is None:
            raise RuntimeError("Keys not initialized; call keygen() or load_keys() first")
        pad_bits = np.array(self.one_time_pad, dtype=np.int8)
        pad = (1.0 - 2.0 * pad_bits.astype(np.float64))
        return (1.0 - 2.0 * self.noise_rate) * pad * posteriors.astype(np.float64)

    def _detection_terms(self, adjusted_posteriors: np.ndarray) -> Tuple[float, float, float]:
        """Compute sum_log_plus, sum_log_prod, const from adjusted posteriors.

        adjusted_posteriors must already have the channel scaling and pad applied.
        """
        if self.parity_check_matrix is None or self.t is None:
            raise RuntimeError("Keys not initialized; call keygen() or load_keys() first")
        H: csr_matrix = self.parity_check_matrix
        r = H.shape[0]
        t = self.t

        # Collect indices per row; the CSR matrix was built with exactly t ones per row
        # and in that order, so indices.reshape(r, t) is valid.
        idx = H.indices.reshape(r, t)
        Pi = np.prod(adjusted_posteriors[idx], axis=1)  # (r,)
        # Clamp Pi into (-1+eps,1-eps) for numerical safety
        Pi = self._clamp(Pi, 1e-12)

        log_plus = np.log((1.0 + Pi) / 2.0)
        log_minus = np.log((1.0 - Pi) / 2.0)
        log_prod = log_plus + log_minus  # = log((1 - Pi^2)/4)

        # const = 0.5 * sum( log_plus^2 + log_minus^2 - 0.5 * log_prod^2 )
        const = 0.5 * np.sum(np.square(log_plus) + np.square(log_minus) - 0.5 * np.square(log_prod))

        return float(np.sum(log_plus)), float(np.sum(log_prod)), float(const)

    def detect(self, latents: torch.Tensor, false_positive_rate: Optional[float] = None) -> Tuple[bool, Dict[str, Any]]:
        """Run detection on inverted latents and return pass/fail and metrics.

        Returns:
          (detected, metrics) where metrics contains:
            sum_log_plus, sum_log_prod, const, threshold, margin
        """
        fpr = float(false_positive_rate) if false_positive_rate is not None else self.fpr
        p = self.latents_to_posteriors(latents)
        p_adj = self._apply_channel_and_pad(p)
        sum_log_plus, sum_log_prod, const = self._detection_terms(p_adj)
        const_clamped = max(const, 0.0)
        threshold = float(np.sqrt(2.0 * const_clamped * np.log(1.0 / fpr)) + 0.5 * sum_log_prod)
        margin = float(sum_log_plus - threshold)
        detected = bool(sum_log_plus >= threshold)
        return detected, {
            "sum_log_plus": sum_log_plus,
            "sum_log_prod": sum_log_prod,
            "const": const,
            "threshold": threshold,
            "margin": margin,
        }

    # ---------------------------- Persistence ----------------------------- #
    def save_keys(self, directory: str) -> None:
        """Save encoding/decoding keys to directory as NPZ + JSON metadata."""
        os.makedirs(directory, exist_ok=True)
        if (
            self.generator_matrix is None
            or self.parity_check_matrix is None
            or self.one_time_pad is None
            or self.test_bits is None
            or self.g_dim is None
            or self.noise_rate is None
            or self.permutation is None
            or self.k is None
            or self.r is None
            or self.t is None
        ):
            raise RuntimeError("Keys not initialized; call keygen() first")

        # Save arrays
        H = self.parity_check_matrix
        np.savez_compressed(
            os.path.join(directory, "encoding_key.npz"),
            generator_matrix=np.array(self.generator_matrix, dtype=np.uint8),
            one_time_pad=np.array(self.one_time_pad, dtype=np.uint8),
            test_bits=np.array(self.test_bits, dtype=np.uint8),
            permutation=self.permutation.astype(np.int64),
        )
        np.savez_compressed(
            os.path.join(directory, "decoding_key.npz"),
            parity_indices=H.indices.astype(np.int64),
            parity_indptr=H.indptr.astype(np.int64),
            parity_shape=np.array(H.shape, dtype=np.int64),
        )
        meta = {
            "latent_dim": self.latent_dim,
            "latent_h": self.latent_h,
            "latent_w": self.latent_w,
            "channels": self.channels,
            "k": self.k,
            "r": self.r,
            "t": self.t,
            "g": self.g_dim,
            "noise_rate": self.noise_rate,
            "fpr": self.fpr,
            "posterior_scale": self.posterior_scale,
            "clamp_eps": self.clamp_eps,
            "posterior_mapping": self.posterior_mapping,
            "posterior_variance": self.posterior_variance,
            "max_bp_iter": self.max_bp_iter,
        }
        with open(os.path.join(directory, "key_meta.json"), "w") as f:
            json.dump(meta, f)
        logger.info(f"Saved PRC keys to {directory}")

    def load_keys(self, directory: str) -> None:
        """Load encoding/decoding keys from directory."""
        enc = np.load(os.path.join(directory, "encoding_key.npz"))
        dec = np.load(os.path.join(directory, "decoding_key.npz"))
        with open(os.path.join(directory, "key_meta.json"), "r") as f:
            meta = json.load(f)

        self.generator_matrix = GF2(enc["generator_matrix"].astype(np.uint8))
        self.one_time_pad = GF2(enc["one_time_pad"].astype(np.uint8))
        self.test_bits = GF2(enc["test_bits"].astype(np.uint8))
        self.permutation = enc["permutation"].astype(np.int64)
        parity_indices = dec["parity_indices"].astype(np.int64)
        parity_indptr = dec["parity_indptr"].astype(np.int64)
        parity_shape = tuple(dec["parity_shape"].tolist())
        self.parity_check_matrix = csr_matrix((np.ones_like(parity_indices, dtype=np.uint8), parity_indices, parity_indptr), shape=parity_shape)

        self.latent_dim = int(meta["latent_dim"])
        self.latent_h = int(meta["latent_h"])
        self.latent_w = int(meta["latent_w"])
        self.channels = int(meta["channels"])
        self.k = int(meta["k"])
        self.r = int(meta["r"])
        self.t = int(meta["t"])
        self.g_dim = int(meta["g"])
        self.noise_rate = float(meta["noise_rate"])
        self.fpr = float(meta["fpr"])
        self.posterior_scale = float(meta.get("posterior_scale", self.posterior_scale))
        self.clamp_eps = float(meta.get("clamp_eps", self.clamp_eps))
        self.posterior_mapping = str(meta.get("posterior_mapping", self.posterior_mapping))
        self.posterior_variance = float(meta.get("posterior_variance", self.posterior_variance))
        self.max_bp_iter = int(meta.get("max_bp_iter", 1))
        logger.info(f"Loaded PRC keys from {directory}")
