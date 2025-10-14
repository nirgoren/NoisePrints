
import numpy as np
from math import log2

import numpy as np
import math
import matplotlib.pyplot as plt

# ---------- Acklam inverse normal approximation (float) for LUT build ----------
# Source: P. J. Acklam, "An algorithm for computing the inverse normal CDF" (2003)
def invnorm_acklam(p: float) -> float:
    # Coefficients
    a = [-3.969683028665376e+01,  2.209460984245205e+02,
         -2.759285104469687e+02,  1.383577518672690e+02,
         -3.066479806614716e+01,  2.506628277459239e+00]
    b = [-5.447609879822406e+01,  1.615858368580409e+02,
         -1.556989798598866e+02,  6.680131188771972e+01,
         -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01,
         -2.400758277161838e+00, -2.549732539343734e+00,
          4.374664141464968e+00,  2.938163982698783e+00]
    d = [ 7.784695709041462e-03,  3.224671290700398e-01,
          2.445134137142996e+00,  3.754408661907416e+00]
    plow  = 0.02425
    phigh = 1 - plow
    if p <= 0.0:
        return -math.inf
    if p >= 1.0:
        return math.inf
    if p < plow:
        q = math.sqrt(-2*math.log(p))
        return (((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) / \
               ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1)
    if p > phigh:
        q = math.sqrt(-2*math.log(1-p))
        return -(((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) / \
                 ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1)
    q = p - 0.5
    r = q*q
    return (((((a[0]*r + a[1])*r + a[2])*r + a[3])*r + a[4])*r + a[5]) * q / \
           (((((b[0]*r + b[1])*r + b[2])*r + b[3])*r + b[4])*r + 1)

# ---------- Build LUT in Q32.32 (int64) ----------
def build_quantile_LUT_Q32_32(L=1<<16):
    # p grid: i/L, i=0..L  (L+1 entries so j+1 is always valid)
    ps = (np.arange(L+1, dtype=np.float64) + 0.5) / (L+1)  # midpoints to avoid ±inf
    qs = np.array([invnorm_acklam(float(p)) for p in ps], dtype=np.float64)
    scale = float(1<<32)
    q_fixed = np.round(qs * scale).astype(np.int64)
    return q_fixed  # length L+1

# ---------- Integer-only sampler at runtime ----------
def sample_normal_fixedpoint_u64(n, rng, lut_q32, k=16, r=16):
    """
    Integer-only sampling:
      - u64 -> index j (top k bits), fraction f (next r bits)
      - xQ = LUT[j] + ((LUT[j+1]-LUT[j]) * f) >> r   (Q32.32 arithmetic)
    Returns int64 fixed-point Q32.32 values.
    """
    L = 1 << k
    u = rng.integers(0, 1<<(64), size=n, dtype=np.uint64)
    #u = rng.integers(0, 1<<63, size=n, dtype=np.uint64)
    sign_bit = (u & 0x1).astype(np.bool_)
    signs = np.ones(n)
    signs[sign_bit] = -1
    j = (u >> (64 - (k-1))).astype(np.int64)                      # 0..L-1 / 2
    #print('Max and min sampled index ', max(j), min(j))
    fmask = (1 << r) - 1
    f = ((u >> (64 - (k-1) - r)) & fmask).astype(np.int64)        # 0..2^r-1
    x0 = lut_q32[j]
    x1 = lut_q32[j + 1]
    dx = (x1 - x0).astype(np.int64)
    #print(dx)
    xQ = x0 + ((dx * f) >> r)     
    return xQ * signs

def split_into_chunks(u: int, chunk_size=32, total_bits=254):
    chunks = []
    for i in range(0, 224, chunk_size):
        chunk = (u >> i) & ((1 << chunk_size) - 1)
        chunks.append(chunk)
    return chunks

def sample_normal_fixedpoint_from_val_without_sign(u, lut_q32, k=15, r=16):
    u = np.int64(u)
    
    j = ((u) & ((1 << k) - 1) ).astype(np.int64)
    f = ((u >> (k)) & ((1 << r) - 1) ).astype(np.int64)
    # sign_bit = (u >> (k+r) & 0x1).astype(np.bool_)
    x0 = lut_q32[j]
    x1 = lut_q32[j + 1]
    dx = (x1 - x0).astype(np.int64)
    xQ = x0 + ((dx * f) >> r)
    return xQ

def get_signs(val):
    signs = (val >> 224) & ((1 << 7) - 1)
    return [np.bool_((signs >> i) & 0x1) for i in range(7)]

def sample_normal_fixedpoint_from_val(val, lut_q32, k=15, r=16):
    integers = []
    integer_chunks = (split_into_chunks(val))
    for i in range(0,7):   
        integers.append(sample_normal_fixedpoint_from_val_without_sign(integer_chunks[i], lut_q32)) 
    return integers, get_signs(val)
