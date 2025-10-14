import os
from poseidon_hash import poseidon_hash
from sample import build_quantile_LUT_Q32_32, sample_normal_fixedpoint_from_val
import numpy as np
import math
import sys


L = 1<<16
lut_q32 = build_quantile_LUT_Q32_32(L)
lut_q32 = lut_q32[1<<15:]

import time

start = time.time()


if len(sys.argv) > 1:
    arg = sys.argv[1]   # take first argument
    print("Seed 1 received:", arg)
else:
    print("No seed rovided.")
    
seed1 = int(arg)
os.makedirs("files/vec_1", exist_ok=True)
with open("files/vec_1/seed1.txt", "w") as f:
    f.write(str(seed1))
        
#changed to mult-core using CHATGPT
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial

MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

def _worker(idx, a1, seed1, lut_q32, k, r):
    """
    Worker computes the two hash values for iteration idx (0-based),
    calls sample_normal_fixedpoint_from_val for each, and returns
    the lists of magnitudes and signs for vec1 and vec2 for that index.
    """
    # compute the hash value that would be used in iteration idx
    # in the sequential code hash is updated as: hash <- (a * hash) % MOD then used
    # so the value used at iteration idx (0-based) is a^(idx+1) * seed % MOD
    exp = idx + 1
    hash_val_1 = (pow(a1, exp, MOD) * seed1) % MOD
    
    integer1, sign1 = sample_normal_fixedpoint_from_val(hash_val_1, lut_q32, k=k, r=r)

    # integer* and sign* are expected to be indexable sequences of length >=4
    vec1_mag = [int(integer1[i]) for i in range(4)]
    vec1_sign = [bool(sign1[i]) for i in range(4)]

    # return idx so we can re-order results deterministically
    return idx, vec1_mag, vec1_sign

def generate_vectors_parallel(len_vec,
                              a1,
                              initial_hash1,
                              lut_q32,
                              k=15, r=16,
                              max_workers=None):
    """
    Returns (vec1_mag, vec1_sign, vec2_mag, vec2_sign)
    where each vec*_mag is a flat list (7 items per iteration) and vec*_sign likewise.
    - initial_hash1 and initial_hash2 are the seed values (the hash state before the first iteration).
    - max_workers controls number of worker processes (None => default).
    """

    # submit tasks
    futures = []
    results = [None] * len_vec  # will store results by index

    with ProcessPoolExecutor(max_workers=max_workers) as ex:
        # partial worker with fixed args (so we only pass idx in the executor)
        worker_partial = partial(_worker, a1=a1,
                                 seed1=initial_hash1,
                                 lut_q32=lut_q32, k=k, r=r)

        # submit all tasks
        for idx in range(len_vec):
            futures.append(ex.submit(worker_partial, idx))

        # collect results
        for fut in as_completed(futures):
            idx, v1_mag, v1_sign = fut.result()
            results[idx] = (v1_mag, v1_sign)

    # now build final vectors in order
    vec1_mag = []
    vec1_sign = []
    
    for idx in range(len_vec):
        v1_mag, v1_sign = results[idx]
        vec1_mag.extend(v1_mag)
        vec1_sign.extend(v1_sign)
        
    return vec1_mag, vec1_sign

#### --------
#### Generate all vectors
#### --------

def generate_vector_1():
    complete_vec_1_mag = []
    complete_vec_1_sign = []
    
    for i in range(0,512):
        hash_val_1 = poseidon_hash([seed1+i])

        a1 = 7
        
        vec1_mag, vec1_sign = generate_vectors_parallel(
            # total len_vec = 38000*7 ~ 2**18
            len_vec = 128,
            a1 = a1,
            initial_hash1 = hash_val_1,   # value before the loop begins
            lut_q32 = lut_q32,
            k = 15, r = 16,
            max_workers = 8
        )

        complete_vec_1_mag.extend(vec1_mag)
        complete_vec_1_sign.extend(vec1_sign)
        
    # write to the file
    with open("files/vec_1/vec_1_mag.txt", "w") as f:
        f.write(str(complete_vec_1_mag))
        
    with open("files/vec_1/vec_1_sign.txt", "w") as f:
        f.write(str(complete_vec_1_sign))

    # Save floating point representation for convenience (Q32.32 -> float)
    scale = float(1 << 32)
    vec_mags = np.array(complete_vec_1_mag, dtype=np.int64)
    vec_signs = np.array(complete_vec_1_sign, dtype=np.int8)
    vec_float = vec_mags.astype(np.float64)
    vec_float[vec_signs == 1] *= -1.0
    vec_float /= scale
    np.save("files/vec_1/vec_1_float.npy", vec_float)

generate_vector_1()
end = time.time()

print(f"Time to generate vector 1: {end - start:.6f} seconds")
