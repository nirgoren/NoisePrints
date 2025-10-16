# NoisePrints: Distortion-Free Watermarks for Authorship in Private Diffusion Models

> **Nir Goren, Oren Katzir, Abhinav Nakarmi, Eyal Ronen, Mahmood Sharif, Or Patashnik**
>
> With the rapid adoption of diffusion models for visual content generation, proving authorship and protecting copyright have become critical. This challenge is particularly important when model owners keep their models private and may be unwilling or unable to handle authorship issues, making third-party verification essential. A natural solution is to embed watermarks for later verification. However, existing methods require access to model weights and rely on computationally heavy procedures, rendering them impractical and non-scalable. To address these challenges, we propose , a lightweight watermarking scheme that utilizes the random seed used to initialize the diffusion process as a proof of authorship without modifying the generation process. Our key observation is that the initial noise derived from a seed is highly correlated with the generated visual content. By incorporating a hash function into the noise sampling process, we further ensure that recovering a valid seed from the content is infeasible. We also show that sampling an alternative seed that passes verification is infeasible, and demonstrate the robustness of our method under various manipulations. Finally, we show how to use cryptographic zero-knowledge proofs to prove ownership without revealing the seed. By keeping the seed secret, we increase the difficulty of watermark removal. In our experiments, we validate NoisePrints on multiple state-of-the-art diffusion models for images and videos, demonstrating efficient verification using only the seed and output, without requiring access to model weights.

<a href="https://arxiv.org/abs/2510.13793"><img src="https://img.shields.io/badge/arXiv-NoisePrints-b31b1b.svg" height=20.5></a>

## Description
Official implementation of our NoisePrints paper.

## Running Pipelines

Execute complete watermarking pipelines for different models:

```bash
# Stable Diffusion 2.0 pipeline
./scripts/run_sd2_0_pipeline.sh

# SDXL pipeline
./scripts/run_sdxl_pipeline.sh

# FLUX Schnell pipeline
./scripts/run_flux_schnell_pipeline.sh

```

Each pipeline generates base images, applies watermarks, runs robustness analysis, and produces plots. The SD2.0 and SDXL pipelines also compare against baseline inversion based methods.

## Zero-Knowledge Proof (ZKP)

ZKP code for verifiable watermarking is located in the `zkp/` directory. See `zkp/README.md` for setup and usage instructions.

## Citation
If you use this code for your research, please cite the following work: 
```
@misc{goren2025noiseprintsdistortionfreewatermarksauthorship,
      title={NoisePrints: Distortion-Free Watermarks for Authorship in Private Diffusion Models}, 
      author={Nir Goren and Oren Katzir and Abhinav Nakarmi and Eyal Ronen and Mahmood Sharif and Or Patashnik},
      year={2025},
      eprint={2510.13793},
      archivePrefix={arXiv},
      primaryClass={cs.CV},
      url={https://arxiv.org/abs/2510.13793}, 
}
```
