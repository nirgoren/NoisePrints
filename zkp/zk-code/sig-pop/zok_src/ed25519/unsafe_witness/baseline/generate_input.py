import ed25519
import random
import math
import struct
import itertools
import sys
import hashlib

# set message length in bytes here
MSG_LEN = 64

LIMBWIDTH = [7,7,7,7,11,11,11,3]
Q_SIZE = 253
Q = 2**252+27742317777372353535851937790883648493

def nToLimbs(n, limbwidths):
    if n == 0:
        return [0] * len(limbwidths)
    digits = []
    for lw in limbwidths:
        digits.append(n % (1 << lw))
        n //= (1 << lw)
    return digits

def limbsToN(n, limbwidths):
    assert(len(n) == len(limbwidths))
    output = 0
    width = 0
    for i, lw in zip(n, limbwidths):
        output += i * 2**width
        width += lw
    return output



SK = b"\xf6n?9\x1d\xd2`\xfc\xf1\xf9\x08\x98?\x88\x9b\xf6\x0f\xb7\xe1\x1b`|\x8c*-\xe2\xf7;\x04\x14\xab\xccO\xb51\xd3\x87yF\xd9\xb4\x1ec\xfaD\x07Q(\xc1\xc8\x1e\xe6\x8d\x80\x0fW\x14S\xac\\\xe9/'@"
# pk =b"O\xb51\xd3\x87yF\xd9\xb4\x1ec\xfaD\x07Q(\xc1\xc8\x1e\xe6\x8d\x80\x0fW\x14S\xac\\\xe9/'@"
PK = ed25519.publickey_unsafe(SK)

def bytes_to_bits(h):
    return [ed25519.bit(h,i) for i in range(8*len(h))]

def int_to_bits(y, n):
    bits = list(map(int, bin(y)[2:]))[::-1]
    return bits + [0] * (n - len(bits))


def chunker(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)

def sha512_pad(m):
    message_array = bytearray(m)
    mdi = len(message_array) % 128
    padding_len = 119 - mdi if mdi < 112 else 247 - mdi
    ending = struct.pack("!Q", len(message_array) << 3)
    message_array.append(0x80)
    message_array.extend([0] * padding_len)
    message_array.extend(bytearray(ending))
    return bytes(message_array)


def change_endianness(m, chunksize=8):
    return list(itertools.chain.from_iterable(reversed(chunk) for chunk in chunker(m,chunksize)))

def shape_m(m):
    # Pad m like sha512 would and then reshape it into
    output = []
    for chunk in chunker(m, 128):
        inner_arr = []
        for u64 in chunker(chunk,8):
            val = limbsToN(u64, [8]*8)
            inner_arr.append(nToLimbs(val, LIMBWIDTH))
        output.append(inner_arr)
    return output



def change_bit_endianness(input):
    output = [0] * len(input)
    ws = len(input) // 64
    for i in range(ws):
        for j in range(8):
            for k in range(8):
                output[64 * i + 8*j + k] = input[64 * i + 8*(8-1-j) + k]
    return output



def mkinput(sig, m, limbwidth):
    encoded_r_bytes = sig[:32]
    encoded_r = bytes_to_bits(encoded_r_bytes)
    R_x_bytes, _, _, _ = ed25519.decodepoint(encoded_r_bytes)
    R_x = int_to_bits(R_x_bytes, 255)
    assert(R_x[0] == encoded_r[255])
    pk_bits = bytes_to_bits(PK)
    A = [nToLimbs(coord, limbwidth) for coord in ed25519.to_simple(ed25519.decodepoint(PK))]
    S = int_to_bits((ed25519.decodeint(sig[32:64])), 255)
    hash_input = encoded_r_bytes + PK + m
    h = bytes_to_bits(hashlib.sha512(hash_input).digest())
    h_val = nToLimbs(sum(2**i * bit for i,bit in enumerate(h)) % Q, [1] * Q_SIZE)
    input_m = change_endianness(sha512_pad(b"\x00" * 64 + m))
    shaped_m = shape_m(input_m)
    return encoded_r, R_x, pk_bits, A, S, h_val, shaped_m

m = bytes([i % 256 for i in range(MSG_LEN)])
point_limbwidth = [60] * 5

sig = ed25519.signature_unsafe(m, SK, PK)
ed25519.checkvalid(sig,m,PK)
print("(set_default_modulus 52435875175126190479447740508185965837690552500527637822603658699938581184513")
print("(let (")
encoded_r, r_x, pk_bits, a, s, h, m_arr = mkinput(sig,m,point_limbwidth)
for i, bit in enumerate(pk_bits):
    print(f"(pk.{i} {'true' if bit else 'false'})", end=" ")

for lbl, limbs in zip(["x","y"], a):
    for i, limb in enumerate(limbs):
        print(f"(a_u.{lbl}.limbs.{i} #f{limb})", end=" ")

# commend out the below for vin file
for i, bit in enumerate(encoded_r):
    print(f"(encoded_r.{i} {'true' if bit else 'false'})", end= " ")

for i, bit in enumerate(r_x):
    print(f"(r_x.{i} {'true' if bit else 'false'})", end= " ")

for i, bit in enumerate(s):
    print(f"(s.{i} {'true' if bit else 'false'})", end=" ")

for i, bit in enumerate(h):
    print(f"(h.{i} {'true' if bit else 'false'})")

for i, outer_arr in enumerate(m_arr):
  for j, inner_arr in enumerate(outer_arr):
      for k, val in enumerate(inner_arr):
          print(f"(m.{i}.{j}.{k} #f{val})", end=" ")

print(") false ))")
print(f"M = {len(m_arr)}", file=sys.stderr)
print(f"M_LEN = {(MSG_LEN+64)}", file=sys.stderr)
print(f"M_ARR = {m_arr}", file=sys.stderr);
