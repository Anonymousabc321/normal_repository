# SecLMS

SecLMS implements stateful hash-based signatures in C and on a ChipWhisperer CW310 FPGA. The C library provides LM-OTS, LMS and multi-level HSS. The FPGA firmware provides single-tree LMS, including protected signing. The CW310 build targets a 25 MHz Ibex RV32IMC processor, one unmasked SHAKE256 accelerator and a hardware signing-state controller.

## Host library

Use GNU Make, a C99 compiler and an archiver from a POSIX shell. Run these commands from the release root.

```sh
make library
make test
```

Run `make test-xkcp` to exercise the 32-bit XKCP SHAKE256 software backend used in the software benchmark. This target builds a separate host library and runs the same LMS and HSS tests.

The build produces `build/libseclms.a`. The public interfaces are in [lms.h](include/lms.h) and [hss.h](include/hss.h). The [LMS tests](tests/test_lms.c) exercise key generation, signing and verification. The [HSS tests](tests/test_hss.c) also cover switching to a new child tree. Host applications must persist the updated private signing state and prevent concurrent reuse of a one-time key index. The Python persistence service below is specific to the FPGA protocol.

## CW310 build

The firmware requires a bare-metal RISC-V GCC toolchain with RV32IMC, Zicsr and the ILP32 ABI, plus Python 3. The hardware build uses Vivado 2020.2 with Kintex-7 device support. Set `RISCV_PREFIX` to the tool prefix on your system and `VIVADO` to the Vivado executable, if needed.

```sh
make firmware RISCV_PREFIX=riscv64-unknown-elf-
make bitstream RISCV_PREFIX=riscv64-unknown-elf-
```

The first command builds the RAM initialization file at `build/firmware.hex`. The second produces `build/cw310/lms_cw310.bit` and the post-route timing and utilization reports. The [build script](flow/impl_lms_cw310.tcl) sets the deployment parameters. HSS runs in host software. The firmware reserves its HSS command numbers for future use.

## Signing state

The hardware reserves a leaf index before signing. A trusted management process commits the 112-byte state record to SQLite before acknowledging the device over a dedicated USB mailbox. The [storage module](management/ksd_persistence.py) offers single-record and authenticated dual-slot stores. The dual-slot store binds each record to its slot, reads back the new record and updates the authenticated active-slot pointer in the same transaction. The FPGA prototype models the device root secret in firmware and relies on the management host for durable state. Restoring an entire older host database can roll back this state.

On an already provisioned system, open the registered store with its external integrity key, attach the [USB endpoint](management/ksd_usb_endpoint.py) to the UART transport's service hook, and call `recover()` before issuing the firmware boot command. A recovered reservation consumes its leaf index. Each database belongs to one registered key generation. Creating a database for an existing signing key that has lost its state can reuse a one-time index.

The management tests run on Python 3.10 or later and use its standard SQLite module. They exercise process restarts, slot selection and mailbox acknowledgments with a simulated USB target. Physical board access uses the ChipWhisperer Python SDK.

```sh
python3 -m unittest discover -s management/tests
```

## Performance

The [benchmark guide](benchmarks/README.md) lists the board configurations, workloads and measurement boundaries for each table.

| Table | Measurements |
| --- | --- |
| [Signature cycles](benchmarks/signature_cycles.csv) | SHAKE256 LM-OTS and LMS key generation, signing and verification on single-core, dual-core and software-only configurations |
| [Classical software](benchmarks/classical_software.csv) | RSA-2048, ECDSA P-256 and SHA-256 on the same processor |
| [Routed resources](benchmarks/routed_resources.csv) | Whole-SoC utilization for the masking and core-count sweep, and for the persistent endpoint deployment |

The signature-cycle table contains measurements from the benchmark firmware. It does not measure protected signing with a SQLite commit on the deployment build.

## Licenses

Project code is distributed under the [MIT license](LICENSE). See the [third-party notices](NOTICE.md) for the processor, hash functions and board-interface components.
