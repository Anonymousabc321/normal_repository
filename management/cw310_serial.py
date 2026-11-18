"""CW310 register transport."""
from cw305_serial import Cw305Serial, _CRYPT_TYPE_EXPECT, _IDENTIFY_EXPECT, _REG_DEFS


class Cw310Serial(Cw305Serial):
    """CW310 adapter for the same register mailbox."""

    def open(self):
        if self._cw305 is None:
            import chipwhisperer as cw
            with self.usb_lock:
                self._cw305 = cw.target(None, cw.targets.CW310, defines_files=[_REG_DEFS])
        self._closed = False
        if self.check_bitstream:
            ident = self._fpga_read("REG_IDENTIFY", 1)[0]
            ctype = self._fpga_read("REG_CRYPT_TYPE", 1)[0]
            if ident != _IDENTIFY_EXPECT or ctype != _CRYPT_TYPE_EXPECT:
                raise RuntimeError(
                    f"Unexpected FPGA identifiers: {ident:#04x}, {ctype:#04x} "
                    f"(expected {_IDENTIFY_EXPECT:#04x}, {_CRYPT_TYPE_EXPECT:#04x})")
