"""ChipWhisperer UART register transport."""
from pathlib import Path
import threading
import time

_REG_DEFS = str(Path(__file__).resolve().parents[1] / "rtl" / "lms_cw305_regs.vh")
_IDENTIFY_EXPECT = 0x4C
_CRYPT_TYPE_EXPECT = 0x4D


class Cw305Serial:
    """UART-compatible access to the CW305 register mailbox."""

    def __init__(self, port="cw305", baud=115200, timeout=3.0, write_timeout=3.0,
                 check_bitstream=True, poll_hook=None, usb_lock=None, target=None):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.write_timeout = write_timeout
        self.check_bitstream = check_bitstream
        self._cw305 = target
        self._owns_target = target is None
        self.usb_lock = usb_lock if usb_lock is not None else threading.RLock()
        self.poll_hook = poll_hook
        self._polling = False
        self._closed = False


    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    def open(self):
        if self._cw305 is None:
            import chipwhisperer as cw
            with self.usb_lock:
                self._cw305 = cw.target(None, cw.targets.CW305,
                                        defines_files=[_REG_DEFS])
        self._closed = False
        if self.check_bitstream:
            ident = self._fpga_read("REG_IDENTIFY", 1)[0]
            ctype = self._fpga_read("REG_CRYPT_TYPE", 1)[0]
            if ident != _IDENTIFY_EXPECT or ctype != _CRYPT_TYPE_EXPECT:
                raise RuntimeError(
                    f"Unexpected FPGA identifiers: {ident:#04x}, {ctype:#04x} "
                    f"(expected {_IDENTIFY_EXPECT:#04x}, {_CRYPT_TYPE_EXPECT:#04x})")

    def close(self):
        with self.usb_lock:
            self.poll_hook = None
            if self._cw305 is not None and self._owns_target:
                try:
                    self._cw305.dis()
                except Exception:
                    pass
            self._cw305 = None
        self._closed = True

    @property
    def usb_target(self):
        """The already-open target shared by UART and the trusted KSD service."""
        if self._cw305 is None:
            raise OSError("port not open")
        return self._cw305

    @property
    def service_hook(self):
        return self.poll_hook

    @service_hook.setter
    def service_hook(self, callback):
        self.poll_hook = callback

    def _poll_service(self):
        # A persistence callback must use this target and RLock, never open a
        # second USB connection. Callback errors propagate; UART must not carry
        # on after the durable endpoint failed. The guard prevents recursion.
        with self.usb_lock:
            if self.poll_hook is None or self._polling:
                return
            self._polling = True
            try:
                self.poll_hook()
            finally:
                self._polling = False


    def _fpga_read(self, regname, n):
        with self.usb_lock:
            return self._cw305.fpga_read(getattr(self._cw305, regname), n)

    def _fpga_write(self, regname, data):
        with self.usb_lock:
            self._cw305.fpga_write(getattr(self._cw305, regname), data)


    @property
    def in_waiting(self):
        """Return the current TX FIFO depth."""
        if self._cw305 is None:
            return 0
        self._poll_service()
        return self._fpga_read("REG_TX_IDX", 1)[0]

    def read(self, n=1):
        """Read up to n bytes within the configured timeout."""
        if self._cw305 is None or n <= 0:
            return b""
        deadline = time.monotonic() + self.timeout
        while True:
            self._poll_service()
            cnt = self._fpga_read("REG_TX_IDX", 1)[0]
            if cnt > 0:
                # pBYTECNT_SIZE=7: a burst beyond 128 bytes crosses into
                # REG_TX_IDX instead of continuing to pop REG_TX_BYTE.
                take = min(cnt, n, 128)
                data = bytes(self._fpga_read("REG_TX_BYTE", take))
                return data
            if time.monotonic() >= deadline:
                return b""
            time.sleep(0.0005)

    def write(self, data):
        """Push the supplied bytes, then wait for the device to drain its RX FIFO."""
        if self._cw305 is None:
            raise OSError("port not open")
        data = bytes(data)
        if not data:
            return 0

        for b in data:
            self._poll_service()
            self._fpga_write("REG_RX_BYTE", [b])

        deadline = time.monotonic() + self.write_timeout
        while self._fpga_read("REG_RX_POS", 1)[0] != 0:
            self._poll_service()
            if time.monotonic() >= deadline:
                raise TimeoutError("RX FIFO did not drain before the write timeout")
            time.sleep(0.0005)
        return len(data)

    def flush(self):
        pass

    def reset_input_buffer(self):
        """Discard pending bytes from the device."""
        if self._cw305 is None:
            return
        cnt = self._fpga_read("REG_TX_IDX", 1)[0]
        while cnt > 0:
            take = min(cnt, 128)
            self._fpga_read("REG_TX_BYTE", take)
            cnt -= take

    def reset_output_buffer(self):
        pass


    def get_status(self):
        st = self._fpga_read("REG_STATUS", 1)[0]
        return {"trap": bool(st & 0x01)}

    def get_buildtime(self):
        with self.usb_lock:
            return self._cw305.get_fpga_buildtime()
