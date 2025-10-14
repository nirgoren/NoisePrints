# Script for generating test inputs for sha512
import random
import math
import struct
import itertools
import sys
import hashlib

# set message length in bytes here (must be a multiple of 8)
MSG_LEN = 64

LIMBWIDTH = [7,7,7,7,11,11,11,3]

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

def changeRepr(limbs, old_limbwidths, new_limbwidths):
    return nToLimbs(limbsToN(limbs, old_limbwidths), new_limbwidths)



def chunks(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return itertools.zip_longest(*args, fillvalue=fillvalue)

def sha512_pad(m):
    # taken from https://gist.github.com/illia-v/7883be942da5d416521375004cecb68f
    message_array = bytearray(m)
    mdi = len(message_array) % 128
    padding_len = 119 - mdi if mdi < 112 else 247 - mdi
    ending = struct.pack("!Q", len(message_array) << 3)
    message_array.append(0x80)
    message_array.extend([0] * padding_len)
    message_array.extend(bytearray(ending))
    return bytes(message_array)


def prepare_message(m):
    """
    Take message bytes, pad them, then reshape
    into a N x 16 array of big-endian 8-byte values in limbwidth representation
    where N = len(padded_m) // 128
    """
    return [[changeRepr(u64[::-1], [8] * 8, LIMBWIDTH) for u64 in chunks(round_chunk, 8)] for round_chunk in chunks(sha512_pad(m), 128)]


m = random.randbytes(MSG_LEN)

padded_message = prepare_message(m)
expected_hash = [limbsToN(chunk[::-1], [8] * 8) for chunk in chunks(hashlib.sha512(m).digest(), 8)]


print("(set_default_modulus 52435875175126190479447740508185965837690552500527637822603658699938581184513")
print("(let (")

for i, outer_arr in enumerate(padded_message):
  for j, inner_arr in enumerate(outer_arr):
      for k, val in enumerate(inner_arr):
          print(f"(padded_message.{i}.{j}.{k} #f{val})")
for i, val in enumerate(expected_hash):
    print(f"(expected_hash.{i} #f{val})")

print(") false ))")
print(f"N={len(padded_message)}", file=sys.stderr)
print(f"MSG_LEN={MSG_LEN}", file=sys.stderr)
