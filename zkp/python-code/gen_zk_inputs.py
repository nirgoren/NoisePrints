from poseidon_hash import poseidon_hash
from sample import build_quantile_LUT_Q32_32, sample_normal_fixedpoint_from_val
import argparse
import ast
import numpy as np
import math
import sys
import time
import os


TOTAL_CHUNKS = 512
VALUES_PER_HASH = 4
HASHES_PER_CHUNK = 128
CHUNK_SIZE = VALUES_PER_HASH * HASHES_PER_CHUNK
FLOAT_SCALE = 1 << 32
DEFAULT_THRESHOLD_FIXED = -2747351321

L = 1 << 16
lut_q32 = build_quantile_LUT_Q32_32(L)
lut_q32 = lut_q32[1 << 15 :]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate circuit inputs for the NoisePrint ZKP pipeline."
    )
    parser.add_argument(
        "seed2_pos",
        nargs="?",
        type=int,
        help="Seed for generating the public vector (legacy positional argument).",
    )
    parser.add_argument(
        "--seed2",
        dest="seed2_arg",
        type=int,
        help="Seed for generating the public vector using the sampler.",
    )
    parser.add_argument(
        "--public-vector",
        dest="public_vector",
        type=str,
        help="Path to a .npy or .pt/.pth file containing the public vector as floating point values.",
    )
    parser.add_argument(
        "--threshold",
        dest="threshold",
        type=float,
        help="Cosine similarity threshold as a floating point value (converted to Q32.32).",
    )
    parser.add_argument(
        "--threshold-fixed",
        dest="threshold_fixed",
        type=int,
        help="Cosine similarity threshold already expressed in Q32.32 fixed point.",
    )
    return parser.parse_args()


args = parse_args()

seed2 = args.seed2_arg if args.seed2_arg is not None else args.seed2_pos
use_public_vector = args.public_vector is not None

if not use_public_vector and seed2 is None:
    raise ValueError("Provide a seed (positional or --seed2) or a --public-vector numpy file.")

if use_public_vector and seed2 is not None:
    print("Public vector provided; ignoring seed for vector 2 generation.", file=sys.stderr)

if args.threshold is not None and args.threshold_fixed is not None:
    raise ValueError("Specify either --threshold or --threshold-fixed, not both.")

if args.threshold_fixed is not None:
    threshold = int(args.threshold_fixed)
elif args.threshold is not None:
    threshold = int(np.rint(args.threshold * FLOAT_SCALE))
else:
    threshold = DEFAULT_THRESHOLD_FIXED

start = time.time()


def float_tensor_to_fixed_components(vector, scale=FLOAT_SCALE):
    """Convert a floating point numpy tensor to Q32.32 magnitudes and sign bits."""
    arr = np.asarray(vector, dtype=np.float64).ravel()
    if np.isnan(arr).any() or np.isinf(arr).any():
        raise ValueError("Public vector contains NaN or infinite values.")
    mags = np.rint(np.abs(arr) * scale).astype(np.int64)
    if (mags > ((1 << 63) - 1)).any():
        raise ValueError("Public vector contains values too large for 64-bit fixed point encoding.")
    signs = (arr < 0).astype(np.int8)
    return mags.tolist(), signs.tolist()


def load_public_vector(path, expected_length=None):
    """
    Load public vector from either NumPy (.npy) or PyTorch (.pt, .pth) file.
    """
    _, ext = os.path.splitext(path)
    ext = ext.lower()

    if ext == '.npy':
        public_vector = np.load(path)
    elif ext in ['.pt', '.pth']:
        try:
            import torch
        except ImportError:
            raise ImportError(
                "PyTorch is required to load .pt/.pth files. "
                "Install it with: pip install torch"
            )
        tensor = torch.load(path, map_location='cpu', weights_only=True)
        # Convert torch tensor to numpy array
        if isinstance(tensor, torch.Tensor):
            public_vector = tensor.numpy()
        else:
            raise ValueError(f"Expected a torch.Tensor in {path}, got {type(tensor)}")
    else:
        raise ValueError(
            f"Unsupported file format: {ext}. "
            "Supported formats: .npy (NumPy), .pt/.pth (PyTorch)"
        )

    mags, signs = float_tensor_to_fixed_components(public_vector)
    if expected_length is not None and len(mags) != expected_length:
        raise ValueError(
            f"Public vector length {len(mags)} does not match expected length {expected_length}."
        )
    mags = [int(x) for x in mags]
    signs = [int(x) for x in signs]
    return mags, signs

        
def signed_inner_product(abs1, signs1, abs2, signs2):
    """
    Computes the cosine of the angle between two signed vectors.
    Each tuple contains:
      - A list of absolute integer values
      - A list of sign bits (0 for positive, 1 for negative)
    """

    dot_product = 0
    mag1_sq = int(0)
    mag2_sq = int(0)
    for a, s1, b, s2 in zip(abs1, signs1, abs2, signs2):
        product = a * b
        
        result_sign = s1 ^ s2  # XOR to determine sign of product
        
        dot_product += product if result_sign == 0 else -product
        
        mag1_sq += a * a

    return dot_product, mag1_sq

def signed_inner_product_cosine(abs1, signs1, abs2, signs2):
    """
    Computes the cosine of the angle between two signed vectors.
    Each tuple contains:
      - A list of absolute integer values
      - A list of sign bits (0 for positive, 1 for negative)
    """

    dot_product = 0
    mag1_sq = int(0)
    mag2_sq = int(0)
    for a, s1, b, s2 in zip(abs1, signs1, abs2, signs2):
        product = a * b
        
        result_sign = s1 ^ s2  # XOR to determine sign of product
    
        dot_product += product if result_sign == 0 else -product
        
        mag1_sq += a * a
        
        mag2_sq += b * b

    mag1_sq_root = math.floor(math.sqrt(mag1_sq))

    mag2_sq_root = math.floor(math.sqrt(mag2_sq))

    if mag1_sq_root == 0 or mag1_sq_root == 0:
        return float('nan')  # Avoid division by zero
    
    cosine_angle = math.floor((dot_product*2**32) / (mag1_sq_root * mag2_sq_root))
    return mag1_sq_root, cosine_angle, mag2_sq_root


#changed to mult-core using CHATGPT
from concurrent.futures import ProcessPoolExecutor, as_completed
from functools import partial

MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

def _worker(idx, a2, seed2, lut_q32, k, r):
    """
    Worker computes the two hash values for iteration idx (0-based),
    calls sample_normal_fixedpoint_from_val for each, and returns
    the lists of magnitudes and signs for vec1 and vec2 for that index.
    """
    # compute the hash value that would be used in iteration idx
    # in the sequential code hash is updated as: hash <- (a * hash) % MOD then used
    # so the value used at iteration idx (0-based) is a^(idx+1) * seed % MOD
    exp = idx + 1
    hash_val_2 = (pow(a2, exp, MOD) * seed2) % MOD
    
    integer2, sign2 = sample_normal_fixedpoint_from_val(hash_val_2, lut_q32, k=k, r=r)


    vec2_mag = [int(integer2[i]) for i in range(4)]
    vec2_sign = [bool(sign2[i]) for i in range(4)]

    # return idx so we can re-order results deterministically
    return idx, vec2_mag, vec2_sign

def generate_vectors_parallel(len_vec,
                              a2,
                              initial_hash2,
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
        worker_partial = partial(_worker, a2=a2,
                                seed2=initial_hash2,
                                 lut_q32=lut_q32, k=k, r=r)

        # submit all tasks
        for idx in range(len_vec):
            futures.append(ex.submit(worker_partial, idx))

        # collect results
        for fut in as_completed(futures):
            idx, v2_mag, v2_sign = fut.result()
            results[idx] = (v2_mag, v2_sign)
            
    vec2_mag = []
    vec2_sign = []

    
    for idx in range(len_vec):
        v2_mag, v2_sign = results[idx]
        vec2_mag.extend(v2_mag)
        vec2_sign.extend(v2_sign)
    return vec2_mag, vec2_sign

#### --------
#### Generate all vectors
#### --------

def generate_vec_2():
    comp_vec2_mag = []
    comp_vec2_sign = []
    for i in range(TOTAL_CHUNKS):
        hash_val_2 = poseidon_hash([seed2+i])

        a2 = 10

        vec2_mag, vec2_sign = generate_vectors_parallel(
            # total len_vec = 38000*7 ~ 2**18
            len_vec = HASHES_PER_CHUNK,
            a2 = a2,
            initial_hash2 = hash_val_2,
            lut_q32 = lut_q32,
            k = 15, r = 16,
            max_workers = 8
        )

        comp_vec2_mag.extend(vec2_mag)
        comp_vec2_sign.extend(vec2_sign)

    new_comp_vec_2_sign = [int(x) for x in comp_vec2_sign]
    return comp_vec2_mag, new_comp_vec_2_sign

def get_vec_1():
    with open("files/vec_1/vec_1_mag.txt", "r") as f:
        comp_vec1_mag = ast.literal_eval(f.read())

    with open("files/vec_1/vec_1_sign.txt", "r") as f:
        comp_vec_1_sign = ast.literal_eval(f.read())
        
    new_comp_vec_1_sign = [int(x) for x in comp_vec_1_sign]
    return comp_vec1_mag, new_comp_vec_1_sign


import secrets

def preprocess(comp_vec1_mag, com_vec_1_sign, comp_vec2_mag, comp_vec2_sign):
    all_commitment = []
    all_dot_product = []
    all_mag1_sq = []
    all_randomness = []
    for i in range(TOTAL_CHUNKS):
        start = i * CHUNK_SIZE
        end = start + CHUNK_SIZE
        dot_product, mag1_sq = signed_inner_product(
            comp_vec1_mag[start:end],
            com_vec_1_sign[start:end],
            comp_vec2_mag[start:end],
            comp_vec2_sign[start:end],
        )
        all_dot_product.append(dot_product)
        all_mag1_sq.append(mag1_sq)

        # compute commitments
        # 1) generate a random 254-bit integer
        r = secrets.randbits(254)
        all_randomness.append(r)
        
        commitment = poseidon_hash([r,dot_product,mag1_sq])
        all_commitment.append(commitment)

    mag1_sq_root, cosine_angle, mag2_sq_root = signed_inner_product_cosine(comp_vec1_mag, com_vec_1_sign, comp_vec2_mag, comp_vec2_sign)

    return all_commitment, all_randomness, all_dot_product, all_mag1_sq, mag1_sq_root, cosine_angle, mag2_sq_root

with open("files/vec_1/seed1.txt", "r") as f:
    seed1 = int(f.read())
    
# create input files for circuit 1 with counter i
def create_inputs_circuit1(counter, all_commitment, all_randomness, seed1, comp_vec1_mag, com_vec_1_sign, comp_vec2_mag, comp_vec2_sign):
    os.makedirs("files/zk", exist_ok=True)
    with open("files/zk/circuit1_inputs.txt", "w") as f:
        f.write(str(counter)+ "\n")
        f.write(str(seed1)+ "\n")
        start = counter * CHUNK_SIZE
        end = start + CHUNK_SIZE
        f.write(str(comp_vec2_mag[start:end])+ "\n")
        f.write(str(comp_vec2_sign[start:end])+ "\n")
        f.write(str(all_commitment[counter])+ "\n")
        f.write(str(all_randomness[counter])+ "\n")



def create_inputs_circuit2(all_commitment, all_randomness, all_dot_product, all_mag1_sq, mag1_sq_root, cosine_angle, mag2_sq_root):
    os.makedirs("files/zk", exist_ok=True)
    with open("files/zk/circuit2_inputs.txt", "w") as f:
        f.write(str(all_commitment)+ "\n")
        f.write(str(all_randomness)+ "\n")
        f.write(str(all_dot_product)+ "\n")
        f.write(str(all_mag1_sq)+ "\n")
        f.write(str(mag1_sq_root)+ "\n")
        f.write(str(cosine_angle)+ "\n")
        f.write(str(mag2_sq_root)+ "\n")
        f.write(str(threshold)+"\n")
        
counter = 0

comp_vec1_mag, com_vec_1_sign = get_vec_1()
expected_length = TOTAL_CHUNKS * CHUNK_SIZE

if len(comp_vec1_mag) != expected_length or len(com_vec_1_sign) != expected_length:
    raise ValueError("vec_1 magnitude and sign vectors do not match expected length.")

if counter >= TOTAL_CHUNKS:
    raise ValueError(f"Counter {counter} exceeds available chunks ({TOTAL_CHUNKS}).")

if use_public_vector:
    comp_vec2_mag, comp_vec2_sign = load_public_vector(args.public_vector, expected_length)
else:
    comp_vec2_mag, comp_vec2_sign = generate_vec_2()

if len(comp_vec2_mag) != expected_length or len(comp_vec2_sign) != expected_length:
    raise ValueError("Generated vec_2 length does not match vec_1 length.")

all_commitment, all_randomness, all_dot_product, all_mag1_sq, mag1_sq_root, cosine_angle, mag2_sq_root = preprocess(comp_vec1_mag, com_vec_1_sign, comp_vec2_mag, comp_vec2_sign)
create_inputs_circuit1(counter, all_commitment, all_randomness, seed1, comp_vec1_mag, com_vec_1_sign, comp_vec2_mag, comp_vec2_sign)
create_inputs_circuit2(all_commitment, all_randomness, all_dot_product, all_mag1_sq, mag1_sq_root, cosine_angle, mag2_sq_root)

end = time.time()

print(f"Time to generate ZKP input files: {end - start:.6f} seconds")
