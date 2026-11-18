"""Format a little-endian RV32 image for the FPGA RAM initialization port."""

import argparse
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("hex_file", type=Path)
    args = parser.parse_args()

    data = args.binary.read_bytes()
    data += bytes(-len(data) % 4)
    # The entry point starts at 0x80, after 32 RISC-V NOP words.
    with args.hex_file.open("w", encoding="ascii", newline="\n") as stream:
        stream.write("00000013\n" * 32)
        for (word,) in struct.iter_unpack("<I", data):
            stream.write(f"{word:08x}\n")


if __name__ == "__main__":
    main()
