#!/usr/bin/env python3
"""
Unified script to analyze SDEdit attack results with configurable parameters
"""

import pandas as pd
import numpy as np
import argparse
import os
from pathlib import Path

def analyze_attack_results(csv_paths, threshold, config):
    """Analyze attack results for multiple noise strengths"""
    all_results = []
    
    for noise_strength, csv_path in csv_paths:
        if not os.path.exists(csv_path):
            print(f"Warning: {csv_path} not found, skipping noise strength {noise_strength}")
            continue
            
        df = pd.read_csv(csv_path)
        
        # Calculate attack success rates using the threshold
        original_below_threshold = (df['original_vs_noise_similarity'] < threshold).sum()
        sdedit_below_threshold = (df['sdedit_vs_noise_similarity'] < threshold).sum()
        
        total_samples = len(df)
        
        original_success_rate = (original_below_threshold / total_samples) * 100
        sdedit_success_rate = (sdedit_below_threshold / total_samples) * 100
        
        # Statistics
        original_similarities = df['original_vs_noise_similarity']
        sdedit_similarities = df['sdedit_vs_noise_similarity']
        
        results = {
            'noise_strength': noise_strength,
            'total_samples': total_samples,
            'original_mean': original_similarities.mean(),
            'original_std': original_similarities.std(),
            'original_below_threshold': original_below_threshold,
            'original_success_rate': original_success_rate,
            'sdedit_mean': sdedit_similarities.mean(),
            'sdedit_std': sdedit_similarities.std(),
            'sdedit_below_threshold': sdedit_below_threshold,
            'sdedit_success_rate': sdedit_success_rate,
            'threshold_used': threshold
        }
        
        all_results.append(results)
        
        print(f"Noise Strength {noise_strength}:")
        print(f"  Total samples: {total_samples}")
        print(f"  Original: {results['original_mean']:.3f} ± {results['original_std']:.3f}")
        print(f"  SDEdit: {results['sdedit_mean']:.3f} ± {results['sdedit_std']:.3f}")
        print(f"  Original below threshold: {original_below_threshold}/{total_samples} ({original_success_rate:.1f}%)")
        print(f"  Attack success: {sdedit_success_rate:.1f}%")
        print()
    
    return all_results

def generate_latex_table(results, config, threshold, power_of_2):
    """Generate LaTeX table for the results"""
    
    print("\\begin{table}[htbp]")
    print("\\centering")
    print(f"\\caption{{{config['caption']}}}")
    print(f"\\label{{{config['label']}}}")
    print("\\begin{tabular}{c|cc|cc|c}")
    print("\\toprule")
    print("\\multirow{2}{*}{\\textbf{Noise Strength}} & \\multicolumn{2}{c|}{\\textbf{Before Attack}} & \\multicolumn{2}{c|}{\\textbf{After Attack}} & \\textbf{Attack Success} \\\\")
    print("& \\textbf{Mean} & \\textbf{Std} & \\textbf{Mean} & \\textbf{Std} & \\textbf{Rate (\\%)} \\\\")
    print("\\midrule")
    
    for result in results:
        print(f"{result['noise_strength']} & {result['original_mean']:.3f} & {result['original_std']:.3f} & {result['sdedit_mean']:.3f} & {result['sdedit_std']:.3f} & {result['sdedit_success_rate']:.1f} \\\\")
    
    print("\\bottomrule")
    print("\\end{tabular}")
    print("\\end{table}")
    print()
    print("\\noindent \\textbf{Notes:}")
    print("\\begin{itemize}")
    print(f"\\item \\textbf{{Target:}} {config['target']}")
    print(f"\\item \\textbf{{Attack Model:}} {config['attack_model']}")
    print("\\item \\textbf{Metric:} Cosine similarity between latent encodings and original noise seeds")
    print(f"\\item \\textbf{{Threshold:}} {threshold:.3f} (derived from $p \\leq 2^{{-{power_of_2}}}$ statistical significance)")
    print("\\item \\textbf{Attack Success:} Percentage of SDEdit images falling below significance threshold")
    print("\\end{itemize}")

def main():
    parser = argparse.ArgumentParser(description="Analyze SDEdit attack results")
    parser.add_argument("--experiment", required=True, 
                       choices=["sdxl-pixelart", "sdxl-flux"],
                       help="Experiment type")
    parser.add_argument("--threshold", type=float, required=True,
                       help="Cosine similarity threshold")
    parser.add_argument("--power-of-2", type=int, required=True,
                       help="Power of 2 for probability (e.g., 128 for 2^-128)")
    parser.add_argument("--output", help="Output file for LaTeX table")
    parser.add_argument("--base-dir", default="out/adversarial_tests",
                       help="Base directory for results")
    
    args = parser.parse_args()
    
    # Configuration for different experiments
    experiment_configs = {
        "sdxl-pixelart": {
            "caption": "SDXL PixelArt LoRA Defense Against Vanilla SDXL SDEdit Attacks",
            "label": "tab:sdxl_pixelart_attack_results",
            "target": "100 SDXL PixelArt LoRA generated images",
            "attack_model": "Vanilla SDXL (no LoRA adaptation)",
            "defense_note": "100\\% of original images maintain statistical significance across all noise levels",
            "folder_pattern": "SDXL_on_PixelArt_ns_{noise}"
        },
        "sdxl-flux": {
            "caption": "FLUX Defense Against SDXL SDEdit Attacks",
            "label": "tab:sdxl_on_flux_attack_results", 
            "target": "100 FLUX generated images",
            "attack_model": "SDXL (cross-model attack)",
            "defense_note": "100\\% of original images maintain statistical significance across all noise levels",
            "folder_pattern": "SDXL_on_FLUX_ns_{noise}"
        }
    }
    
    config = experiment_configs[args.experiment]
    
    # Build CSV paths for different noise strengths
    noise_strengths = ["0.23", "0.34", "0.46"]
    csv_paths = []
    
    for noise in noise_strengths:
        folder_name = config["folder_pattern"].format(noise=noise)
        csv_path = os.path.join(args.base_dir, folder_name, "sdedit_analysis_results.csv")
        csv_paths.append((noise, csv_path))
    
    print(f"Analyzing {args.experiment} with threshold {args.threshold} (p = 2^-{args.power_of_2})")
    print("=" * 80)
    
    # Analyze results
    results = analyze_attack_results(csv_paths, args.threshold, config)
    
    if not results:
        print("No results found!")
        return
    
    print("=" * 80)
    print("LATEX TABLE")
    print("=" * 80)
    
    # Generate LaTeX table
    if args.output:
        # Redirect output to file
        import sys
        with open(args.output, 'w') as f:
            old_stdout = sys.stdout
            sys.stdout = f
            generate_latex_table(results, config, args.threshold, args.power_of_2)
            sys.stdout = old_stdout
        print(f"LaTeX table saved to {args.output}")
    else:
        generate_latex_table(results, config, args.threshold, args.power_of_2)

if __name__ == "__main__":
    main()