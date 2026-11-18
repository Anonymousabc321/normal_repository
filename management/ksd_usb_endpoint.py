"""Trusted-host KSD endpoint over the CPU-independent CW305/CW310 USB mailbox.

This transport shares the UART port's existing target and lock. It never opens,
programs or resets a board. The caller must complete firmware PROVISION before
calling recover(). USB access is trusted management access, not an authenticated
channel for an untrusted business client.

    service = KsdUsbEndpoint(port, store)
    port.service_hook = service.poll_once
    # WRAP_LOAD -> PROVISION through this same port
    recovered_record = service.recover()
    # BOOT -> public KEYGEN -> SIGN; UART wait loops service durable requests
"""
from dataclasses import dataclass
import struct
import threading
import time


REG_STATUS = 0x10
REG_OUTGOING = 0x11
REG_STAGING = 0x12
REG_DOORBELL = 0x13
MAGIC = 0x4B534432
RECORD_BYTES = 112
CMD_RECOVER = 1
CMD_ACK = 2
OUTGOING_VALID = 1 << 0
INBOX_BUSY = 1 << 1
ALL_STAGED = 1 << 2
COMPLETION_VALID = 1 << 3
LAST_ACCEPT = 1 << 4
RECOVERED = 1 << 5
BUSY_WRITE_ERROR = 1 << 6
TRANSPORT_FAULT = 1 << 7


class EndpointError(RuntimeError):
    pass


class DeviceReset(EndpointError):
    """The FPGA reset; a fresh PROVISION and explicit recovery are required."""


@dataclass(frozen=True)
class MailboxStatus:
    flags: int
    generation: int
    completion_counter: int
    result: int
    last_command: int

    @property
    def busy(self):
        return bool(self.flags & INBOX_BUSY)

    @property
    def recovered(self):
        return bool(self.flags & RECOVERED)


@dataclass(frozen=True)
class PersistRequest:
    record: bytes
    generation: int


@dataclass(frozen=True)
class PendingCommand:
    command: int
    counter_before: int
    record: bytes
    generation: int | None
    started: float


class KsdUsbTransport:
    """Raw mailbox protocol. Production callers use KsdUsbEndpoint for ACKs."""

    def __init__(self, target, lock=None):
        self.target = target
        self.lock = lock if lock is not None else threading.RLock()
        # On the CW310 SAM3X/EBI path, the 112-byte USB bulk transfer did not
        # populate the mailbox's complete byte mask. Individual control writes
        # at raw byte addresses were verified on the board. Require that exact
        # transport; fpga_write shifts a register index and cannot select an
        # offset within its 128-byte window.
        if getattr(target, "platform", None) not in ("cw305", "cw310"):
            raise EndpointError("KSD staging requires a CW305 or CW310 target")
        if getattr(target, "bytecount_size", None) != 7:
            raise EndpointError("KSD staging requires bytecount_size=7")
        self._raw_write = getattr(getattr(target, "_naeusb", None), "cmdWriteMem", None)
        if not callable(self._raw_write):
            raise EndpointError("KSD staging requires the target's raw cmdWriteMem API")

    def _stage_record(self, record):
        """Write every byte through a control transfer using the shared target.

        A failed byte write propagates before the caller can ring the doorbell.
        There is deliberately no bulk-write fallback.
        """
        if len(record) != RECORD_BYTES:
            raise ValueError("KSD record must contain exactly 112 bytes")
        with self.lock:
            base = REG_STAGING << 7
            for offset, value in enumerate(record):
                self._raw_write(base + offset, [value])

    def _read(self, register, length):
        data = bytes(self.target.fpga_read(register, length))
        if len(data) != length:
            raise EndpointError(f"short KSD register read: {register:#x} ({len(data)}/{length})")
        return data

    def read_status(self):
        with self.lock:
            magic, flags, generation, counter, result, command = struct.unpack("<6I", self._read(REG_STATUS, 24))
            if magic != MAGIC:
                raise EndpointError(f"KSD mailbox identity mismatch: {magic:#010x}")
            if flags & ~0xFF:
                raise EndpointError(f"unknown KSD status flags: {flags:#x}")
            if flags & TRANSPORT_FAULT:
                raise EndpointError("KSD mailbox transport fault; reset and trusted recovery are required")
            if flags & BUSY_WRITE_ERROR:
                raise EndpointError("KSD mailbox detected writes while busy; exclusive USB ownership was violated")
            return MailboxStatus(flags, generation, counter, result, command)

    def read_request(self):
        """Return an immutable outgoing record only across a stable generation."""
        with self.lock:
            before = self.read_status()
            if not before.recovered or not before.flags & OUTGOING_VALID or before.busy:
                return None
            record = self._read(REG_OUTGOING, RECORD_BYTES)
            after = self.read_status()
            if (not after.recovered or after.busy or not after.flags & OUTGOING_VALID or
                    before.generation != after.generation):
                return None
            return PersistRequest(record, after.generation)

    def _start(self, command, record, generation=None):
        record = bytes(record)
        if len(record) != RECORD_BYTES:
            raise ValueError("KSD record must contain exactly 112 bytes")
        with self.lock:
            before = self.read_status()
            if before.busy:
                raise EndpointError("KSD inbox is already busy")
            if command == CMD_RECOVER and before.recovered:
                raise EndpointError("KSD is already recovered; reset and PROVISION are required")
            if command == CMD_ACK:
                request = self.read_request()
                if request is None or request.generation != generation or request.record != record:
                    raise EndpointError("outgoing KSD request changed before ACK submission")
            self._stage_record(record)
            staged = self.read_status()
            if staged.busy or not staged.flags & ALL_STAGED:
                raise EndpointError(f"KSD staging is incomplete or busy (flags={staged.flags:#010x})")
            if staged.completion_counter != before.completion_counter or staged.recovered != before.recovered:
                raise DeviceReset("KSD state changed while staging a receipt")
            if command == CMD_ACK and (not staged.flags & OUTGOING_VALID or staged.generation != generation):
                raise DeviceReset("KSD outgoing generation changed while staging ACK")
            self.target.fpga_write(REG_DOORBELL, [command])
            return PendingCommand(command, before.completion_counter, record, generation, time.monotonic())

    def start_recovery(self, record):
        return self._start(CMD_RECOVER, record)

    def start_ack(self, record, generation):
        return self._start(CMD_ACK, record, generation)

    def completed(self, pending, status=None):
        with self.lock:
            status = status if status is not None else self.read_status()
            if pending.command == CMD_ACK and not status.recovered:
                raise DeviceReset("FPGA reset before the pending durable receipt completed")
            if status.completion_counter == pending.counter_before:
                return False
            expected = (pending.counter_before + 1) & 0xFFFFFFFF
            if status.completion_counter != expected or not status.flags & COMPLETION_VALID:
                raise EndpointError("KSD completion sequence changed unexpectedly")
            if status.last_command != pending.command or status.result != 1 or not status.flags & LAST_ACCEPT:
                raise EndpointError(f"KSD command {pending.command} rejected (result={status.result})")
            if status.busy:
                return False
            return True


class KsdUsbEndpoint:
    """Single-owner service: durable store commit strictly precedes ACK writes.

    after_commit(record) is an optional test/observation hook called after the
    store returns a committed receipt and BEFORE any ACK staging or doorbell.
    An exception propagates unchanged and permanently stops this service object;
    recovery must use a fresh object after FPGA reset and firmware PROVISION.
    """

    def __init__(self, port, store, after_commit=None, timeout=5.0):
        if timeout <= 0:
            raise ValueError("endpoint timeout must be positive")
        self.transport = KsdUsbTransport(port.usb_target, port.usb_lock)
        self.store = store
        self.after_commit = after_commit
        self.timeout = timeout
        self._pending = None
        self._ready = False
        self._stopped = False
        self._last_acked_generation = None
        self._last_acked_record = None
        self.committed_requests = 0
        self.accepted_receipts = 0

    @property
    def ready(self):
        return self._ready and not self._stopped

    def _check_running(self):
        if self._stopped:
            raise EndpointError("KSD service stopped after an error; reset/reprovision and create a new service")

    def _poll_once(self):
        status = self.transport.read_status()
        if self._pending is not None:
            pending = self._pending
            if self.transport.completed(pending, status):
                self._pending = None
                if pending.command == CMD_RECOVER:
                    if not status.recovered:
                        raise EndpointError("accepted recovery did not establish the mailbox recovery state")
                    self._ready = True
                else:
                    self.accepted_receipts += 1
                    self._last_acked_generation = pending.generation
                    self._last_acked_record = pending.record
            elif time.monotonic() - pending.started > self.timeout:
                raise TimeoutError("KSD mailbox command did not complete within endpoint timeout")
            else:
                return False
        if not self._ready:
            return False  # Never infer recovery or trust from UART/software state.
        if not status.recovered:
            raise DeviceReset("FPGA reset; durable state retained, fresh PROVISION/recovery required")
        request = self.transport.read_request()
        if request is None or request.generation == self._last_acked_generation:
            return False
        receipt = bytes(self.store.persist(request.record))
        if receipt != request.record:
            raise EndpointError("durable store returned a receipt for a different request")
        self.committed_requests += 1
        if self.after_commit is not None:
            self.after_commit(receipt)
        # No ACK-side USB write above this line. A failed commit or observation
        # hook leaves the FPGA waiting and the independently saved q consumed.
        self._pending = self.transport.start_ack(receipt, request.generation)
        return True

    def poll_once(self):
        with self.transport.lock:
            self._check_running()
            try:
                return self._poll_once()
            except BaseException:
                self._stopped = True
                self._ready = False
                raise

    poll = poll_once

    def recover(self):
        """After firmware PROVISION, restore durable state; return sent 112B record.

        For RESERVED recovery, wait also for the hardware's burn/finalization
        request to be durably committed and acknowledged before returning.
        """
        with self.transport.lock:
            self._check_running()
            if self._pending is not None or self._ready:
                raise EndpointError("cannot begin recovery while service is active")
            status = self.transport.read_status()
            if status.busy or status.recovered:
                raise EndpointError("recovery requires a reset, idle mailbox after PROVISION")
            try:
                record = bytes(self.store.recover())
                if len(record) != RECORD_BYTES:
                    raise EndpointError("durable store returned a malformed recovery record")
                words = struct.unpack("<28I", record)
                if words[0] not in (1, 2):
                    raise EndpointError("durable recovery operation is invalid")
                self._pending = self.transport.start_recovery(record)
            except BaseException:
                self._stopped = True
                raise
        deadline = time.monotonic() + self.timeout
        while True:
            self.poll_once()
            with self.transport.lock:
                done = self._ready and self._pending is None
                if words[0] == 1:
                    saved = self._last_acked_record
                    done = done and saved is not None and int.from_bytes(saved[:4], "little") == 2 and \
                        int.from_bytes(saved[40:44], "little") == words[10] + 1
                if done:
                    return record
                if time.monotonic() >= deadline:
                    self._stopped = True
                    self._ready = False
                    raise TimeoutError("trusted recovery/burn did not complete within endpoint timeout")
            time.sleep(0.001)
