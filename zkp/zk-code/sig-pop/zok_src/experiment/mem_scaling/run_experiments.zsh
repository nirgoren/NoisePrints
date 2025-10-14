#!/usr/bin/env zsh
set -e

file="gpows_scan.zok"
script_dir=${0:a:h}
circ_bin="$script_dir/../../../target/release/examples/circ"

echo "First, let's do a cost model for smaller parameters:"
reads=4
ramsize=266
valsize=$((2 * 8))
accesses=$(($reads + $ramsize))
echo " number of reads (R): $reads"
echo " RAM size (N): $ramsize"
echo " scalars per value (L): $valsize"
echo " predicted scan cost: $(( $reads * $valsize * $ramsize )) = R * N * L"
echo " predicted transcript cost: $(( $accesses * (24 + $valsize) )) = (R + N) * (24 + L)"
echo
echo "Now, let's actually compile:"

for file in gpows_scan.zok gpows_transcript.zok
do
    echo "Compiling file $file..."
    echo
    RUST_LOG=circ::ir::opt::mem=debug $circ_bin $file r1cs
    echo
    echo
done


echo
echo
echo "Now, let's do the cost model for real parameters:"
reads=43
ramsize=2662
valsize=$((2 * 8))
accesses=$(($reads + $ramsize))
echo " number of reads (R): $reads"
echo " RAM size (N): $ramsize"
echo " scalars per value (L): $valsize"
echo " predicted scan cost: $(( $reads * $valsize * $ramsize )) = R * N * L"
echo "  somehow this model must be wrong, because even the whole circuit isn't this big!"
echo " predicted transcript cost: $(( $accesses * (24 + $valsize) )) = (R + N) * (24 + L)"
