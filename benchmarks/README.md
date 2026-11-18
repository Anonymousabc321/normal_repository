# CW310 benchmark data

These tables cover the Kintex-7 XC7K410T on the CW310 with an Ibex RV32IMC processor running at 25 MHz. The signature timings come from SHAKE256 benchmark firmware. The final persistent endpoint has a separate routed-resource entry. Its protected signing latency was not measured in this benchmark matrix.

## Signature cycles

[signature_cycles.csv](signature_cycles.csv) contains one observation per configuration, scheme, parameter set and operation. The accelerated builds cover Winternitz widths 1, 2, 4 and 8 and LMS tree heights 5, 10 and 15. The software baseline covers heights 5 and 10 for LMS and all three fixture heights for LM-OTS. LM-OTS itself has no tree-height parameter. Each result comes from a fixed test vector. Signing and verification times depend on the vector.

| Configuration | Execution path | Bitstream SHA-256 prefix |
| --- | --- | --- |
| `single_core` | One hash-accelerator core | `D1C85B6D` |
| `dual_core` | Two hash-accelerator cores | `C4509A2A` |
| `software_only` | Ibex software SHAKE256 (XKCP), with the tree cache enabled | `74BA87BA` |

The two accelerated builds ran the same benchmark firmware. The software baseline used the single-core routed design with replacement program RAM contents. LMS signing used the ordinary signing command with a prepared tree. Each command's response header reports the accelerator's active cycles and the low 32 bits of the firmware's total cycle measurement. Host serial transfer and wall-clock turnaround are outside the definition of latency used for comparison.

- `accelerator_cycles` is the hardware work counter. It is zero for software-only operations.
- `counter_u32` is the raw total returned by the board. For long software key generation, the host determined the number of counter wraps from elapsed time at 25 MHz. `total_cycles = counter_u32 + wraps * 4294967296`.
- `output_check` records the associated functional check. In the single-core LM-OTS W1/H5 signing run, the board returned its cycle counters but the host received only 8,514 of 8,516 signature bytes. The row is marked `short_read`.

For example, at LMS W4/H10 the single-core signer recorded 8,993 accelerator cycles and 17,321 total cycles. The software-only signer recorded 20,921,974 total cycles. Dividing the two total counts gives approximately 1,208x for this vector. To compare configurations, match the scheme, width, fixture height and operation.

## Classical software comparison

[classical_software.csv](classical_software.csv) reports software-only board cycle counts for mbedTLS 2.28.9 on the same processor. The benchmark firmware used RV32IMC with `-O2` in the single-core routed design (bitstream SHA-256 prefix `E5F88A81`). The five commands returned success. The SHA-256 row measures hashing a 64-byte message. RSA uses a 2,048-bit key and ECDSA uses P-256.

## Routed resources

[routed_resources.csv](routed_resources.csv) reports Vivado 2020.2 post-route utilization for the complete SoC. The four `area_sweep` images share the same source, firmware, 25 MHz target and measurement instrumentation. The two build parameters varied are the number of hash cores and datapath masking. The `persistent_endpoint` row is the separately routed single-core deployment configuration with the host persistence interface and masking disabled. BRAM is expressed in 36-Kbit tile equivalents.
