import math
import ed25519

def nToLimb(n, b, l):
    if n == 0:
        return [0] * l
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits + [0]*(l-len(digits))

def limbPoint(p,b,l=None):
    assert(len(p) == 2)
    return nToLimb(p[0],b,l), nToLimb(p[1],b,l)

def two_rep(p):
    if len(p) == 2:
        return p
    x,y,z,t = p
    invz = ed25519.inv(z)
    return (x * invz) % ed25519.q, (y * invz) % ed25519.q

def four_rep(p):
    if len(p) == 4:
        return p
    x,y = p
    return (x,y,1,(x*y)%ed25519.q)

def compute_table(value, n_limbs, limb_width, stride):
    total_bits = n_limbs * limb_width
    value = four_rep(value)
    base_powers = []
    n_vec = math.ceil(total_bits / stride)
    for i in range(n_vec):
        initial_point = []
        if i == n_vec - 1:
            initial_point = value
        else:
            width = total_bits - (i+1) * stride
            initial_point = ed25519.scalarmult(value, 2**width)
        base_powers_inner = [ed25519.ident, initial_point]
        cur_stride = (total_bits) % stride if i == n_vec - 1 and (total_bits)%stride else stride
        for _ in range(2, (1<<cur_stride)):
            base_powers_inner.append(ed25519.edwards_add(base_powers_inner[-1], initial_point))
        base_powers.append([[nToLimb(coord, 2**limb_width, n_limbs) for coord in two_rep(p)] for p in base_powers_inner])
    return base_powers

def fmt_base_power(p):
    return str(list(p))

K = (1762111443891090791368278727835417445876156968440962720682012045122899982082,47240211860419521472386239205418660784548983831370547238086037072188890696733,1,7621438586536496291701674192254521334502009470544648632016447376917447272733)

assert(ed25519.isoncurve(K))
import sys
basepowers = [(5,55,6)]
assert(len(set(basepowers)) == len(basepowers))

print('from "../baseline/struct" import BasePowers')
print("""def base_powers_default<N,LW,STRIDE>() -> BasePowers<N,LW,STRIDE>:
    print("N: {}, LW: {}, STRIDE: {}", N, LW, STRIDE)
    assert(false, "no such base powers")
""")

for n_limbs, limb_width, stride in basepowers:
    table = compute_table(K,n_limbs, limb_width, stride)
    base_powers = "[" + ",\n    ".join("[" + ",\n    ".join(fmt_base_power(p) for p in inner) + "]" for inner in table[:-1]) + "]"
    last_base_powers = "[" + ",\n    ".join(fmt_base_power(p) for p in table[-1]) + "]"
    print(f"const BasePowers<{n_limbs},{limb_width},{stride}> Kpow{n_limbs}_{limb_width}_{stride} = BasePowers {{ base_powers: {base_powers},\n    last_base_powers: {last_base_powers}\n }}")

print("def get_K_base_powers<N,LW,STRIDE>() -> BasePowers<N,LW,STRIDE>:\n    return ", end="")


for n, lw, stride in basepowers:
    print(f"if N == {n} && LW == {lw} && STRIDE == {stride} then Kpow{n}_{lw}_{stride} \\\n        else ", end="")

print("base_powers_default::<N,LW,STRIDE>() \\\n      ", end="")
print(" ".join(["fi"] * len(basepowers)))
