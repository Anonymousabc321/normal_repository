"""Offline USB endpoint tests; no ChipWhisperer connection or programming.

The fake register target models independently delayed mailbox acceptance. The
disk-backed case reopens the actual authority after the commit-before-ACK seam.
"""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "management"))
from ksd_persistence import Persistence, Record, Registration
from ksd_usb_endpoint import (ALL_STAGED, BUSY_WRITE_ERROR, CMD_ACK, CMD_RECOVER,
                              COMPLETION_VALID, DeviceReset, EndpointError,
                              INBOX_BUSY, KsdUsbEndpoint, KsdUsbTransport,
                              LAST_ACCEPT, MAGIC, OUTGOING_VALID, RECOVERED,
                              REG_DOORBELL, REG_OUTGOING, REG_STAGING, REG_STATUS,
                              TRANSPORT_FAULT)

from cw305_serial import Cw305Serial
from cw310_serial import Cw310Serial


REG = Registration(0x1234, 7, 0x020208, 0x11223344, 4, b"S" * 32)
KEY = b"USB endpoint offline integrity key"


def record(op=2, q=0, tx=0, session=100):
    return Record(op, REG.key_id, REG.epoch, session, q, tx, 0,
                  REG.params, REG.identifier, REG.q_limit).to_bytes()


class FakeTarget:
    REG_TX_IDX, REG_TX_BYTE, REG_RX_BYTE, REG_RX_POS = range(4)

    def __init__(self, events=None):
        self.events = events if events is not None else []
        self.platform = "cw310"
        self.bytecount_size = 7
        self._naeusb = self
        self.flags = self.generation = self.counter = self.result = self.command = 0
        self.staged = self.outgoing = None
        self.written = set()
        self.fail_raw_offset = None
        self.pending = None
        self.accept = True
        self.hang = False
        self.keep_old_output = False
        self.mutate_output_read = False
        self.reset_on_staging = False
        self.tx = bytearray()
        self.rx = bytearray()
        self.disconnected = False

    def publish(self, raw):
        self.outgoing = raw
        self.generation += 1
        self.flags |= OUTGOING_VALID

    def reset(self):
        self.flags = self.generation = self.counter = self.result = self.command = 0
        self.staged = self.outgoing = self.pending = None
        self.written.clear()

    def _complete(self):
        if self.pending is None or self.hang:
            return
        command, raw = self.pending
        self.pending = None
        self.counter += 1
        self.result = 1 if self.accept else 4
        self.flags &= ~INBOX_BUSY
        self.flags |= COMPLETION_VALID
        if self.accept:
            self.flags |= LAST_ACCEPT
            if command == CMD_RECOVER:
                self.flags |= RECOVERED
                rec = Record.from_bytes(raw)
                if rec.op == 1:
                    self.publish(replace(rec, op=2, q=rec.q + 1, tx=rec.tx + 1).to_bytes())
            elif not self.keep_old_output:
                self.flags &= ~OUTGOING_VALID
                self.generation += 1
        else:
            self.flags &= ~LAST_ACCEPT
        self.events.append(("accepted" if self.accept else "rejected", command, raw))

    def fpga_read(self, register, length):
        if register == REG_STATUS:
            self._complete()
            return struct.pack("<6I", MAGIC, self.flags, self.generation,
                               self.counter, self.result, self.command)[:length]
        if register == REG_OUTGOING:
            result = self.outgoing
            if self.mutate_output_read:
                self.generation += 1
            return result[:length]
        if register == self.REG_TX_IDX:
            return bytes([len(self.tx)])
        if register == self.REG_TX_BYTE:
            result = self.tx[:length]
            del self.tx[:length]
            return result
        if register == self.REG_RX_POS:
            return bytes([len(self.rx)])
        raise AssertionError(f"unexpected logical register {register:#x}")

    def cmdWriteMem(self, address, data):
        offset = address - (REG_STAGING << 7)
        raw = bytes(data)
        assert 0 <= offset < 112 and len(raw) == 1
        if offset == self.fail_raw_offset:
            raise OSError("injected raw byte write failure")
        self.events.append(("raw_write", address, raw))
        if self.reset_on_staging:
            self.reset()
            return
        if self.staged is None:
            self.staged = bytearray(112)
        self.staged[offset] = raw[0]
        self.written.add(offset)
        if len(self.written) == 112:
            self.flags |= ALL_STAGED

    def fpga_write(self, register, data):
        raw = bytes(data)
        self.events.append(("write", register, raw))
        if register == REG_DOORBELL:
            assert len(raw) == 1 and self.flags & ALL_STAGED
            self.command = raw[0]
            self.pending = self.command, bytes(self.staged)
            self.flags = (self.flags & ~ALL_STAGED) | INBOX_BUSY
            self.written.clear()
        elif register == self.REG_RX_BYTE:
            self.rx.extend(raw)
        else:
            raise AssertionError(f"unexpected logical register {register:#x}")

    def dis(self):
        self.disconnected = True


class FakeStore:
    def __init__(self, events, initial=None):
        self.events = events
        self.raw = record() if initial is None else initial
        self.fail = False
        self.recovery_calls = 0

    def recover(self):
        self.recovery_calls += 1
        self.events.append(("recovery_commit", self.raw))
        return self.raw

    def persist(self, raw):
        if self.fail:
            raise OSError("storage commit failed")
        self.raw = raw
        self.events.append(("commit", raw))
        return raw


class LostAck(Exception):
    pass


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.target = FakeTarget(self.events)
        self.port = SimpleNamespace(usb_target=self.target, usb_lock=threading.RLock())
        self.store = FakeStore(self.events)
        self.service = KsdUsbEndpoint(self.port, self.store, timeout=0.1)

    def recover(self):
        self.assertEqual(self.store.raw, self.service.recover())
        self.assertTrue(self.service.ready)
        self.events.clear()

    def test_recovery_commit_before_submission_and_no_implicit_recovery(self):
        self.assertFalse(self.service.poll_once())
        self.assertEqual([], self.events)
        self.service.recover()
        self.assertEqual("recovery_commit", self.events[0][0])
        self.assertEqual([( "raw_write", (REG_STAGING << 7) + offset, bytes([value]))
                          for offset, value in enumerate(record())], self.events[1:113])
        self.assertEqual(("write", REG_DOORBELL, b"\x01"), self.events[113])
        self.assertEqual(1, self.store.recovery_calls)

    def test_durable_commit_and_callback_precede_every_ack_write(self):
        self.recover()
        raw = record(1, tx=1)
        self.service.after_commit = lambda data: self.events.append(("hook", data))
        self.target.publish(raw)
        self.assertTrue(self.service.poll_once())
        self.assertEqual(["commit", "hook"] + ["raw_write"] * 112 + ["write"],
                         [x[0] for x in self.events])
        self.assertEqual(("write", REG_DOORBELL, b"\x02"), self.events[-1])
        self.assertEqual(0, self.service.accepted_receipts)
        self.service.poll_once()
        self.assertEqual(1, self.service.accepted_receipts)

    def test_commit_failure_never_stages_ack(self):
        self.recover()
        self.store.fail = True
        self.target.publish(record(1, tx=1))
        with self.assertRaisesRegex(OSError, "commit failed"):
            self.service.poll_once()
        self.assertEqual([], self.events)
        self.assertFalse(self.service.ready)
        with self.assertRaises(EndpointError):
            self.service.poll_once()

    def test_post_commit_exception_propagates_unchanged_without_ack(self):
        self.recover()
        error = LostAck("committed; lose receipt")
        def stop(_):
            raise error
        self.service.after_commit = stop
        raw = record(1, tx=1)
        self.target.publish(raw)
        with self.assertRaises(LostAck) as raised:
            self.service.poll_once()
        self.assertIs(error, raised.exception)
        self.assertEqual([("commit", raw)], self.events)
        self.assertEqual(raw, self.store.raw)
        self.assertFalse(self.service.ready)

    def test_stale_outgoing_snapshot_not_acknowledged_twice(self):
        self.recover()
        self.target.keep_old_output = True
        self.target.publish(record(1, tx=1))
        for _ in range(5):
            self.service.poll_once()
        self.assertEqual(1, self.service.committed_requests)
        self.assertEqual(1, self.service.accepted_receipts)

    def test_unstable_snapshot_is_not_committed(self):
        self.recover()
        self.target.publish(record(1, tx=1))
        self.target.mutate_output_read = True
        self.assertFalse(self.service.poll_once())
        self.assertEqual([], self.events)

    def test_reset_detected_without_guessing_uart_state(self):
        self.recover()
        self.target.reset()
        with self.assertRaises(DeviceReset):
            self.service.poll_once()
        self.assertEqual(1, self.store.recovery_calls)

    def test_rejected_recovery_stops_without_second_session(self):
        self.target.accept = False
        with self.assertRaisesRegex(EndpointError, "rejected"):
            self.service.recover()
        with self.assertRaises(EndpointError):
            self.service.recover()
        self.assertEqual(1, self.store.recovery_calls)

    def test_recovery_timeout_stops_without_second_session(self):
        self.service.timeout = 0.002
        self.target.hang = True
        with self.assertRaises(TimeoutError):
            self.service.recover()
        with self.assertRaises(EndpointError):
            self.service.recover()
        self.assertEqual(1, self.store.recovery_calls)

    def test_reserved_recovery_waits_for_burn_and_returns_original(self):
        original = record(1, q=1, tx=3)
        self.store.raw = original
        self.assertEqual(original, self.service.recover())
        self.assertEqual(record(2, q=2, tx=4), self.store.raw)
        self.assertEqual(1, self.service.accepted_receipts)

    def test_transport_fault_busy_violation_and_bad_identity_fail_closed(self):
        for flag in (TRANSPORT_FAULT, BUSY_WRITE_ERROR, 1 << 8):
            with self.subTest(flag=flag):
                self.target.flags = flag
                with self.assertRaises(EndpointError):
                    self.service.transport.read_status()
        self.target.fpga_read = lambda register, length: bytes(length)
        with self.assertRaises(EndpointError):
            self.service.transport.read_status()

    def test_ack_rechecks_generation_before_staging(self):
        self.recover()
        raw = record(1, tx=1)
        self.target.publish(raw)
        request = self.service.transport.read_request()
        self.target.publish(record(2, q=1, tx=2))
        with self.assertRaises(EndpointError):
            self.service.transport.start_ack(raw, request.generation)
        self.assertEqual([], self.events)

    def test_staging_uses_all_unique_raw_offsets_with_exact_bytes(self):
        pattern = bytes((offset * 73 + 19) & 255 for offset in range(112))
        self.service.transport.start_recovery(pattern)
        writes = [event for event in self.events if event[0] == "raw_write"]
        self.assertEqual(list(range(0x900, 0x970)), [event[1] for event in writes])
        self.assertEqual(pattern, b"".join(event[2] for event in writes))
        self.assertEqual(("write", REG_DOORBELL, b"\x01"), self.events[-1])
        self.assertFalse(any(event[:2] == ("write", REG_STAGING) for event in self.events))

    def test_mid_staging_failure_never_sends_doorbell(self):
        self.recover()
        self.target.publish(record(1, tx=1))
        self.target.fail_raw_offset = 57
        with self.assertRaisesRegex(OSError, "raw byte write failure"):
            self.service.poll_once()
        self.assertEqual(57, sum(event[0] == "raw_write" for event in self.events))
        self.assertFalse(any(event[:2] == ("write", REG_DOORBELL) for event in self.events))
        self.assertFalse(self.service.ready)

    def test_unsupported_raw_transport_fails_without_fallback(self):
        for field, value in (("platform", "other"), ("bytecount_size", 8), ("_naeusb", None)):
            with self.subTest(field=field):
                target = FakeTarget()
                setattr(target, field, value)
                with self.assertRaises(EndpointError):
                    KsdUsbTransport(target)
                self.assertEqual([], target.events)

    def test_incomplete_staging_error_reports_flags(self):
        self.target.reset_on_staging = True
        with self.assertRaisesRegex(EndpointError, r"flags=0x00000000"):
            self.service.recover()
        self.assertFalse(any(event[:2] == ("write", REG_DOORBELL) for event in self.events))

    def test_disk_reopen_after_lost_ack_burns_reserved_q(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build", prefix="ksd usb ") as folder:
            path = Path(folder) / "authority.sqlite3"
            with Persistence.initialize(path, registration=REG, integrity_key=KEY) as store:
                first = KsdUsbEndpoint(self.port, store)
                recovered = Record.from_bytes(first.recover())
                reserved = replace(recovered, op=1, tx=1).to_bytes()
                self.target.publish(reserved)
                def lost(_):
                    raise LostAck()
                first.after_commit = lost
                with self.assertRaises(LostAck):
                    first.poll_once()
            self.target.reset()
            with Persistence.open(path, registration=REG, integrity_key=KEY) as reopened:
                second = KsdUsbEndpoint(self.port, reopened)
                sent = Record.from_bytes(second.recover())
                saved = Record.from_bytes(reopened.snapshot())
                self.assertEqual((1, 0, 1), (sent.op, sent.q, sent.tx))
                self.assertNotEqual(recovered.session, sent.session)
                self.assertEqual((2, 1, 2), (saved.op, saved.q, saved.tx))
                self.assertEqual(1, second.accepted_receipts)


class SerialHookTests(unittest.TestCase):
    def test_shared_target_read_wait_services_endpoint_without_sdk_connect(self):
        for serial_class in (Cw305Serial, Cw310Serial):
            with self.subTest(board=serial_class.__name__):
                target = FakeTarget()
                calls = []
                port = serial_class(target=target, check_bitstream=False, timeout=0.1)
                def service():
                    calls.append(1)
                    if len(calls) == 2:
                        target.tx.extend(b"R")
                port.service_hook = service
                with port:
                    self.assertIs(target, port.usb_target)
                    self.assertEqual(b"R", port.read())
                self.assertEqual(2, len(calls))
                self.assertFalse(target.disconnected)

    def test_write_drain_wait_services_endpoint_and_hook_error_propagates(self):
        target = FakeTarget()
        port = Cw305Serial(target=target, check_bitstream=False, write_timeout=0.1)
        calls = []
        def service():
            calls.append(1)
            if target.rx:
                target.rx.clear()
        port.service_hook = service
        self.assertEqual(1, port.write(b"X"))
        self.assertEqual(2, len(calls))
        error = LostAck()
        def fail():
            raise error
        port.service_hook = fail
        with self.assertRaises(LostAck) as raised:
            port.read()
        self.assertIs(error, raised.exception)
        self.assertFalse(port._polling)


if __name__ == "__main__":
    unittest.main(verbosity=2)
