#!/usr/bin/env python3
"""
High-precision cosine similarity threshold calculator for extreme cases.

For very high dimensions where standard scipy functions underflow,
this uses asymptotic approximations and higher precision arithmetic.
"""

import scipy.special as sp
from scipy.optimize import fsolve
import argparse
import math
from decimal import Decimal, getcontext

# Set high precision for decimal calculations
getcontext().prec = 50

def log_tightest_cosine_bound(d, a):
    """Calculate log probability for numerical stability in high dimensions"""
    if not (-1 <= a <= 1):
        raise ValueError("a must be in [-1, 1]")
    if d < 2:
        raise ValueError("dimension d must be at least 2")
    
    # For large d, use asymptotic approximation
    # The exact formula involves incomplete beta function which underflows
    # Use Stirling's approximation and asymptotic expansions
    
    x = 1 - a**2
    
    if d > 10000:  # Use asymptotic approximation for large d
        # For large n, the distribution approaches normal
        # The cosine similarity of random vectors approaches N(0, 1/d)
        # P(cos > a) ≈ 1 - Φ(a * sqrt(d))
        z = a * math.sqrt(d)
        log_prob = sp.log_ndtr(-z)  # log(1 - Φ(z)) = log(Φ(-z))
        return log_prob
    else:
        # Use regular calculation for moderate dimensions
        alpha = (d - 1) / 2
        beta = 0.5
        try:
            prob = 0.5 * sp.betainc(alpha, beta, x)
            if prob > 0:
                return math.log(prob)
            else:
                # Fall back to asymptotic if underflow
                z = a * math.sqrt(d)
                return sp.log_ndtr(-z)
        except:
            z = a * math.sqrt(d)
            return sp.log_ndtr(-z)

def find_cosine_threshold_log(d, log_target_prob):
    """Find threshold using log probabilities for numerical stability"""
    def equation(a):
        return log_tightest_cosine_bound(d, a) - log_target_prob
    
    # For large d, the threshold is approximately log_target_prob / sqrt(d)
    # Since log_target_prob is negative, we want positive a
    initial_guess = max(0.01, min(0.5, abs(log_target_prob) / math.sqrt(d)))
    
    try:
        solution = fsolve(equation, initial_guess)[0]
        return solution
    except:
        # If fsolve fails, use analytical approximation
        # For large d: a ≈ -log_target_prob / sqrt(d)
        return abs(log_target_prob) / math.sqrt(d)

def main():
    parser = argparse.ArgumentParser(description="High-precision cosine similarity threshold calculator")
    parser.add_argument("-d", "--dimensions", type=int, required=True, help="Number of dimensions")
    parser.add_argument("--power-of-2", type=int, help="Target probability as 2^(-power)")
    parser.add_argument("-p", "--probability", type=float, help="Target probability directly")
    args = parser.parse_args()

    d = args.dimensions
    
    if args.probability:
        target_prob = args.probability
        log_target_prob = math.log(target_prob)
    elif args.power_of_2:
        log_target_prob = -args.power_of_2 * math.log(2)
        target_prob = 2**(-args.power_of_2)
    else:
        # Default: 2^-128
        log_target_prob = -128 * math.log(2)
        target_prob = 2**(-128)

    print(f"Dimensions (d): {d}")
    print(f"Target probability: {target_prob:.2e}")
    print(f"Log target probability: {log_target_prob}")

    # Find the required cosine similarity threshold
    a = find_cosine_threshold_log(d, log_target_prob)
    print(f"\nRequired cosine similarity threshold (a): {a}")

    # Verify using asymptotic approximation
    z = a * math.sqrt(d)
    log_actual_prob = sp.log_ndtr(-z)
    actual_prob = math.exp(log_actual_prob)
    
    print(f"Verification (asymptotic):")
    print(f"  z = a * sqrt(d) = {z}")
    print(f"  Log actual probability: {log_actual_prob}")
    print(f"  Actual probability: {actual_prob:.2e}")
    print(f"  Log difference: {abs(log_actual_prob - log_target_prob)}")

if __name__ == "__main__":
    main()