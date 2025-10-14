#!/usr/bin/env python3
"""
Utility to calculate cosine similarity thresholds for given probabilities.

This script solves for the cosine similarity threshold 'a' such that the probability
of a random Gaussian vector having higher cosine similarity than 'a' with a fixed
vector equals a target probability.

Uses the tightest cosine bound formula and scipy's fsolve for numerical root finding.
"""

import scipy.special as sp
from scipy.optimize import fsolve
import argparse

def tightest_cosine_bound(d, a):
    """Calculate probability that random Gaussian sample has higher cosine similarity than a"""
    if not (-1 <= a <= 1):
        raise ValueError("a must be in [-1, 1]")
    if d < 2:
        raise ValueError("dimension d must be at least 2")
    x = 1 - a**2
    alpha = (d - 1) / 2
    beta = 0.5
    prob = 0.5 * sp.betainc(alpha, beta, x)
    return prob

def find_cosine_threshold(d, target_prob):
    """
    Find cosine similarity threshold a such that P(random > a) = target_prob
    
    Uses scipy's fsolve which employs a hybrid Powell dogleg method:
    1. Combines Newton's method with trust region techniques
    2. Iteratively improves initial guess until finding root within tolerance
    3. Solves: tightest_cosine_bound(d, a) - target_prob = 0
    """
    def equation(a):
        return tightest_cosine_bound(d, a) - target_prob
    
    # Initial guess - start near 0, in valid range [-1, 1]
    initial_guess = 0.1
    solution = fsolve(equation, initial_guess)[0]
    return solution

def main():
    parser = argparse.ArgumentParser(description="Calculate cosine similarity threshold for target probability")
    parser.add_argument("-d", "--dimensions", type=int, help="Number of dimensions")
    parser.add_argument("-p", "--probability", type=float, help="Target probability (e.g., 2e-39)")
    parser.add_argument("--power-of-2", type=int, help="Target probability as 2^(-power) (e.g., 128 for 2^-128)")
    args = parser.parse_args()

    # Default example: SDXL with 512x512 images
    if args.dimensions:
        d = args.dimensions
    else:
        d = 4 * 64 * 64  # SDXL: (1, 4, 64, 64) = 16,384 dimensions
        print("Using default: SDXL with 512x512 images")

    if args.probability:
        target_prob = args.probability
    elif args.power_of_2:
        target_prob = 2**(-args.power_of_2)
        print(f"Using 2^(-{args.power_of_2})")
    else:
        target_prob = 2**(-128)  # Default: 2^-128
        print("Using default: 2^(-128)")

    print(f"Dimensions (d): {d}")
    print(f"Target probability: {target_prob}")
    print(f"Target probability (scientific): {target_prob:.2e}")

    # Find the required cosine similarity threshold
    a = find_cosine_threshold(d, target_prob)

    print(f"\nRequired cosine similarity threshold (a): {a}")

    # Verify the result
    actual_prob = tightest_cosine_bound(d, a)
    print(f"Verification - actual probability: {actual_prob}")
    print(f"Verification - actual probability (scientific): {actual_prob:.2e}")
    print(f"Difference: {abs(actual_prob - target_prob):.2e}")

if __name__ == "__main__":
    main()