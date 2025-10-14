## NoisePrints

## Running Pipelines

Execute complete watermarking pipelines for different models:

```bash
# FLUX Schnell pipeline
./scripts/run_flux_schnell_pipeline.sh

# Stable Diffusion 2.0 pipeline
./scripts/run_sd2_0_pipeline.sh

# SDXL pipeline
./scripts/run_sdxl_pipeline.sh
```

Each pipeline generates base images, applies watermarks, runs robustness analysis, and produces plots.

## Zero-Knowledge Proof (ZKP)

ZKP code for verifiable watermarking is located in the `zkp/` directory. See `zkp/README.md` for setup and usage instructions.
