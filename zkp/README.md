# ZKP code for NoisePrints

## Installation
Tested on AMD Ryzen Threadripper 5995WX 1.8GHz CPU (w. 256GB RAM) running Ubuntu 22.04.3 LTS. Make sure cargo version is 1.89.0 and cvc4 is installed. 

```bash
cd scripts

# setup CirC infrastructure
chmod +x ./circ_setup.sh 
source ./circ_setup.sh 

# generate prover and verifier key of all circuits
chmod +x ./key_gen.sh
./key_gen.sh

# generate test inputs (this takes a min in total)
# will as for user input for seeds
chmod +x ./input_gen.sh
./input_gen.sh

# benchmark
chmod +x ./benchmark.sh
./benchmark.sh
```

## Custom Input Workflow

1. Set up the CirC environment (if not already done):
   ```bash
   cd scripts
   chmod +x ./circ_setup.sh 
   source ./circ_setup.sh 
   ```

1. Create the prover's noise vector from a seed (and capture a float tensor for generation):
   ```bash
   ./generate_noise_from_seed.sh <seed1>
   ```
   This runs `python-code/gen_vec_1.py`, writing the fixed-point representation plus a convenience tensor at `python-code/files/vec_1/vec_1_float.npy`.

1. Generate an image from the noise and save the latents:
```bash
./generate_image_from_noise.sh
```

1. Convert the public image latents to fixed point, set the desired cosine threshold, and write the circuit inputs:
   ```bash
   ./prepare_inputs_from_public_vector.sh \
     --public-vector ../python-code/files/output_latents.npy \
     --threshold 0.025500
   ```

Circuit inputs are emitted in `python-code/files/zk/`.

1. Produce and verify the proofs with the freshly generated inputs:
   ```bash
   ./prove_and_verify.sh
   ```
   This script runs a single Miró/Mirage proof + verification cycle for both circuits using the current contents of `python-code/files/zk/circuit{1,2}_inputs.txt`. 
   
While the same input files are used for both proving and verifying, in practice the verification process ignores the private fields that should remain hidden. Additionally, note that for this demonstration only the commitment for the first chunk will be verified by circuit 1.
