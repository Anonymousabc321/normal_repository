# Third-party notices

The project's own code is distributed under the [MIT license](LICENSE).
The following notices apply to components included in this distribution.

## Ibex processor

`rtl/ibex/` contains the RV32 core and the modules selected for this FPGA
configuration. The integration supplies local primitive and coverage stubs.
Ibex and its lowRISC components are licensed under [Apache 2.0](licenses/Apache-2.0.txt).
The source files retain their upstream copyright lines.

The `ibex_*.sv` modules correspond to
[upstream revision 5da1679f](https://github.com/lowRISC/ibex/tree/5da1679f360b00ae330aab33cc8d79d73dfabb98/rtl).
The [Ibex project notice](licenses/Ibex-NOTICE.txt) is included in full.
See also the [upstream credits](https://github.com/lowRISC/ibex/blob/5da1679f360b00ae330aab33cc8d79d73dfabb98/CREDITS.md).

## SLotH hardware

The following modules incorporate or adapt RTL from SLotH under the
[BSD 3-Clause license](licenses/SLotH-BSD-3-Clause.txt).

| Local file | Use of upstream RTL |
| --- | --- |
| `rtl/uart_tx.v` | Adds a pending-byte buffer to the transmitter. |
| `rtl/uart_rx.v` | Preserves the interface and ready signaling. Uses a rewritten receiver with 16x oversampling and an eight-byte FIFO. |
| `rtl/lms_fpga_ram.v` | Adapts the dual-port RAM with byte write enables, configurable depth and optional firmware initialization. |
| `rtl/lms_sha256_round.v` | Adapts the combinational SHA-256 round and message schedule. |
| `rtl/kecti3_round.v` | Uses the three masked Keccak round modules with the upstream configuration guards removed. |

[SLotH RTL](https://github.com/slh-dsa/sloth/tree/main/rtl).

## neoTRNG

`rtl/lms_trng.v` ports the neoTRNG v3.3 entropy-source architecture to
Verilog and adds online health checks. The package license carries a 2023
copyright notice and the upstream RTL carries a 2025 notice, both for
Stephan Nolting. [BSD 3-Clause license](licenses/neoTRNG-BSD-3-Clause.txt)
and [upstream RTL](https://github.com/stnolting/neoTRNG).

## NewAE USB interface and board pinout

The `cw305_usb_reg_fe` module in `rtl/lms_cw305_usb_uart.v` comes from the
ChipWhisperer reference design. Its copyright and redistribution terms appear
in the [module header](rtl/lms_cw305_usb_uart.v). The UART mailbox and FIFO
integration are local. The pin assignments in `flow/cw310.xdc` follow the
[NewAE CW310 Bergen pinout](https://github.com/newaetech/cw310-bergen-board/blob/main/pins/bergen.xdc).

## Software hash functions

- `hashs/fips202.c` and `hashs/fips202.h` provide the public-domain FIPS 202
  routines used for SHAKE256. The source header credits the Keccak and
  TweetFips202 implementations. [Upstream license](https://github.com/pq-crystals/kyber/blob/main/LICENSE).
- `hashs/haraka.c` and `hashs/haraka.h` supply the SPHINCS+ reference
  implementation of Haraka for host software. SPHINCS+ places this code
  in the public domain except for the bitsliced AES routines derived from
  BearSSL, which carry the [BearSSL MIT license](licenses/BearSSL-MIT.txt).
  [Upstream licensing statement](https://github.com/sphincs/sphincsplus#license).
- The optional `hashs/xkcp/` software backend uses the 32-bit in-place Keccak
  permutation from [XKCP](https://github.com/XKCP/XKCP). The upstream CC0
  dedications appear in `KeccakP-1600-inplace32BI.c`, `KeccakP-1600-SnP.h`
  and `SnP-Relaned.h`. The local permutation copy corrects the second
  half-lane input index in the big-endian extract-and-add path. The byte
  order header `brg_endian.h` adds little-endian target checks for x86-64
  and RISC-V and carries its own [Gladman redistribution
  terms](licenses/Gladman-endian.txt). The SHAKE wrapper (`xkcp_shake.c`
  and `xkcp_shake.h`), `load-store.h` and `SnP-common.h` are local adapters.
