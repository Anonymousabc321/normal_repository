"""Disk-backed authority tests, including actual child-process crash/reopen.

Run with Python directly. No board, simulator, network, or secret fixtures needed.
"""
from dataclasses import replace
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE_ROOT / "management"))
from ksd_persistence import (IDLE, RESERVED, MAX_U32, IntegrityError, Persistence,
                             PersistenceError, ProtocolError, Record, Registration,
                             StoreLocked)

KEY = b"KSD test-only integrity key bytes!"
REG = Registration(key_id=0x112233445566778899aabbccddeeff00, epoch=7,
                   params=0x020208, identifier=0x00112233445566778899aabbccddeeff,
                   q_limit=4, seed_identity=b"S" * 32)


def initialize(path, registration=REG, cls=Persistence):
    return cls.initialize(path, registration=registration, integrity_key=KEY)


def reopen(path, registration=REG, cls=Persistence):
    return cls.open(path, registration=registration, integrity_key=KEY)


def reserve(old):
    return replace(old, op=RESERVED, tx=old.tx + 1, context=0)


def finalize(old, context=0xdecafbad):
    return replace(old, op=IDLE, q=old.q + 1, tx=old.tx + 1, context=context)


def child_main(argv):
    action, path = argv[:2]
    if action == "lock":
        try:
            with reopen(path):
                return 0
        except StoreLocked:
            return 19
    stage, operation = argv[2:]

    class CrashStore(Persistence):
        def _checkpoint(self, reached):
            if reached == stage:
                # Bypass finally blocks, database.close(), and Python shutdown.
                # No receipt has been returned to this child at this boundary.
                os._exit(73)

    if operation == "initialize":
        initialize(path, cls=CrashStore)
    else:
        with reopen(path, cls=CrashStore) as store:
            if operation == "recover":
                store.recover()
            else:
                old = Record.from_bytes(store.snapshot())
                next_record = reserve(old) if operation == "reserve" else finalize(old)
                store.persist(next_record.to_bytes())
    return 29  # The selected crash seam was not reached.


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        build = SOURCE_ROOT / "build"
        build.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="ksd disk tests ", dir=build)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "authority.sqlite3"

    def child(self, *args):
        return subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child",
                               *map(str, args)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=20)

    def test_exact_wire_encoding_and_round_trip(self):
        with initialize(self.path) as store:
            raw = store.recover()
        rec = Record.from_bytes(raw)
        self.assertEqual(112, len(raw))
        self.assertEqual(IDLE, int.from_bytes(raw[0:4], "little"))
        self.assertEqual(REG.key_id, int.from_bytes(raw[4:20], "little"))
        self.assertEqual(REG.epoch, int.from_bytes(raw[20:24], "little"))
        self.assertEqual(rec.session, int.from_bytes(raw[24:40], "little"))
        self.assertEqual(REG.params, int.from_bytes(raw[80:88], "little"))
        self.assertEqual(REG.identifier, int.from_bytes(raw[88:104], "little"))
        self.assertEqual(REG.q_limit, int.from_bytes(raw[104:108], "little"))
        self.assertEqual(bytes(4), raw[108:112])
        self.assertEqual(raw, rec.to_bytes())

    def test_public_identifier_matches_real_28_word_usb_layout(self):
        # Public-key fixture: type || OTS type || I[16] || root[32]. This is the
        # existing adapter/USB layout, not conventional big-endian hex packing.
        public_key = bytes.fromhex("0000000500000004") + bytes(range(16)) + bytes(range(32))
        reg = replace(REG, identifier=int.from_bytes(public_key[8:24], "little"))
        with initialize(self.path, reg) as store:
            raw = store.recover()
        record = Record.from_bytes(raw)
        words = [IDLE,
                 0xddeeff00, 0x99aabbcc, 0x55667788, 0x11223344,
                 REG.epoch,
                 *struct.unpack("<4I", record.session.to_bytes(16, "little")),
                 0, 0, *([0] * 8), REG.params, 0,
                 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, REG.q_limit, 0]
        self.assertEqual(28, len(words))
        self.assertEqual(struct.pack("<28I", *words), raw)
        self.assertEqual(public_key[8:24], raw[88:104])

    def test_missing_or_existing_database_never_reinitializes(self):
        with self.assertRaises(FileNotFoundError):
            reopen(self.path)
        self.assertFalse(self.path.exists())
        with initialize(self.path) as store:
            self.assertEqual(0, Record.from_bytes(store.snapshot()).session)
            self.assertEqual(3, store._db.execute("PRAGMA synchronous").fetchone()[0])
            self.assertEqual("delete", store._db.execute("PRAGMA journal_mode").fetchone()[0])
        with self.assertRaises(FileExistsError):
            initialize(self.path)
        self.path.write_bytes(b"")
        with self.assertRaises(IntegrityError):
            reopen(self.path)
        with self.assertRaises(FileExistsError):
            initialize(self.path)

    def test_bad_registration_and_missing_integrity_key_rejected(self):
        for changes in ({"key_id": 0}, {"params": 0x030208}, {"params": 0x020203},
                        {"params": 0x020218}, {"q_limit": 5},
                        {"seed_identity": b""}, {"seed_identity": bytes(32)},
                        {"epoch": -1}, {"key_id": True}):
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                replace(REG, **changes)
        with self.assertRaises(ValueError):
            Persistence.initialize(self.path, registration=REG, integrity_key=b"short")
        self.assertFalse(self.path.exists())

    def test_wrong_key_or_registered_provisioning_identity_rejected(self):
        with initialize(self.path):
            pass
        with self.assertRaises(IntegrityError):
            Persistence.open(self.path, registration=REG, integrity_key=b"X" * 32)
        for changes in ({"seed_identity": b"T" * 32}, {"key_id": REG.key_id + 1},
                        {"identifier": REG.identifier + 1}, {"epoch": REG.epoch + 1},
                        {"params": 0x020204}):
            with self.subTest(changes=changes), self.assertRaises(IntegrityError):
                reopen(self.path, replace(REG, **changes))
        self.assertNotIn(KEY, self.path.read_bytes())

    def test_persist_requires_recovery_and_does_not_mint_initial_ack(self):
        with initialize(self.path) as store:
            initial = Record.from_bytes(store.snapshot())
            for request in (initial, reserve(initial)):
                with self.assertRaises(ProtocolError):
                    store.persist(request.to_bytes())

    def test_full_cycle_and_lost_ack_are_durable_and_idempotent(self):
        with initialize(self.path) as store:
            recovered = Record.from_bytes(store.recover())
            first = reserve(recovered).to_bytes()
            self.assertEqual(first, store.persist(first))
            generation = store._load()[0]
            self.assertEqual(first, store.commit_request(first))
            self.assertEqual(generation, store._load()[0])
        with reopen(self.path) as store:
            # Service restart without an FPGA reset can retry the exact receipt.
            self.assertEqual(first, store.persist(first))
            last = finalize(Record.from_bytes(first)).to_bytes()
            self.assertEqual(last, store.persist(last))
        with reopen(self.path) as store:
            self.assertEqual(last, store.snapshot())
            self.assertEqual(last, store.persist(last))
            with self.assertRaises(ProtocolError):
                store.persist(first)

    def test_recover_rotates_session_without_resetting_q_tx(self):
        with initialize(self.path) as store:
            first = reserve(Record.from_bytes(store.recover()))
            store.persist(first.to_bytes())
            store.persist(finalize(first).to_bytes())
            old = Record.from_bytes(store.snapshot())
            newer = Record.from_bytes(store.recover())
            self.assertNotEqual(old.session, newer.session)
            self.assertNotEqual(0, newer.session)
            self.assertEqual((IDLE, 1, 2, 0), (newer.op, newer.q, newer.tx, newer.context))
            with self.assertRaises(ProtocolError):
                store.persist(reserve(old).to_bytes())
        with reopen(self.path) as store:
            self.assertEqual(newer.to_bytes(), store.snapshot())

    def test_reserved_recovery_requires_rtl_burn_and_rejects_same_q(self):
        with initialize(self.path) as store:
            first = reserve(Record.from_bytes(store.recover()))
            store.persist(first.to_bytes())
        with reopen(self.path) as store:
            recovered = Record.from_bytes(store.recover())
            self.assertEqual((RESERVED, first.q, first.tx),
                             (recovered.op, recovered.q, recovered.tx))
            self.assertNotEqual(first.session, recovered.session)
            with self.assertRaises(ProtocolError):
                store.persist(first.to_bytes())
            with self.assertRaises(ProtocolError):
                store.persist(replace(recovered, tx=recovered.tx + 1).to_bytes())
            burned = finalize(recovered, context=0)
            self.assertEqual(burned.to_bytes(), store.persist(burned.to_bytes()))
            next_reservation = reserve(burned)
            self.assertEqual(first.q + 1, next_reservation.q)
            store.persist(next_reservation.to_bytes())

    def test_every_namespace_and_transition_conflict_is_rejected(self):
        with initialize(self.path) as store:
            old = Record.from_bytes(store.recover())
            valid = reserve(old)
            for changes in ({"key_id": old.key_id + 1}, {"epoch": old.epoch + 1},
                            {"session": old.session ^ 1}, {"session": 0},
                            {"params": 0x020204}, {"identifier": old.identifier + 1},
                            {"q_limit": old.q_limit + 1}, {"q": old.q + 1},
                            {"tx": old.tx}, {"tx": old.tx + 2},
                            {"op": IDLE}, {"context": 1}):
                with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                    store.persist(replace(valid, **changes).to_bytes())
                self.assertEqual(old.to_bytes(), store.snapshot())
            store.persist(valid.to_bytes())
            with self.assertRaises(ProtocolError):
                store.persist(replace(valid, context=1).to_bytes())
            good_final = finalize(valid)
            for changes in ({"q": valid.q}, {"q": valid.q + 2},
                            {"tx": valid.tx}, {"tx": valid.tx + 2}, {"op": RESERVED}):
                with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                    store.persist(replace(good_final, **changes).to_bytes())
            store.persist(good_final.to_bytes())
            with self.assertRaises(ProtocolError):
                store.persist(replace(good_final, context=good_final.context ^ 1).to_bytes())

    def test_invalid_wire_size_op_and_reserved_bits(self):
        with initialize(self.path) as store:
            valid = reserve(Record.from_bytes(store.recover())).to_bytes()
            cases = [valid[:-1], valid + b"\0", bytearray(valid)]
            for offset, value in ((0, 0), (0, 3), (1, 1), (108, 1), (111, 128)):
                broken = bytearray(valid)
                broken[offset] = value
                cases.append(bytes(broken))
            for raw in cases:
                with self.subTest(raw_type=type(raw)), self.assertRaises(ProtocolError):
                    store.persist(raw)

    def test_exhaustion_refuses_further_reservation(self):
        with initialize(self.path) as store:
            state = Record.from_bytes(store.recover())
            for q in range(REG.q_limit):
                reserved = reserve(state)
                self.assertEqual(q, reserved.q)
                store.persist(reserved.to_bytes())
                state = finalize(reserved)
                store.persist(state.to_bytes())
            with self.assertRaises(ProtocolError):
                store.persist(reserve(state).to_bytes())
            recovered = Record.from_bytes(store.recover())
            self.assertEqual((REG.q_limit, 2 * REG.q_limit), (recovered.q, recovered.tx))

    def test_transaction_overflow_never_reserves_unfinalizable_q(self):
        reg = replace(REG, params=0x021f08, q_limit=1 << 31)
        with initialize(self.path, reg) as store:
            old = Record.from_bytes(store.recover())
            # Authenticated boundary fixture, not a public mutation API.
            boundary = replace(old, q=(1 << 31) - 1, tx=MAX_U32 - 1)
            raw = boundary.to_bytes()
            generation = store._load()[0]
            store._db.execute("UPDATE authority SET record=?,mac=?",
                              (raw, store._mac(generation, raw)))
            with self.assertRaises(ProtocolError):
                store.persist(reserve(boundary).to_bytes())
            self.assertEqual(raw, store.snapshot())

    def test_hmac_and_database_corruption_rejected(self):
        with initialize(self.path) as store:
            store.recover()
        with closing(sqlite3.connect(self.path)) as db:
            raw = bytearray(db.execute("SELECT record FROM authority").fetchone()[0])
            raw[40] ^= 1
            db.execute("UPDATE authority SET record=?", (bytes(raw),))
            db.commit()
        with self.assertRaises(IntegrityError):
            reopen(self.path)
        self.path.write_bytes(b"not a sqlite database")
        with self.assertRaises(IntegrityError):
            reopen(self.path)

    def test_live_tamper_is_rechecked_before_ack(self):
        with initialize(self.path) as store:
            state = Record.from_bytes(store.recover())
            store._db.execute("UPDATE authority SET mac=?", (b"X" * 32,))
            with self.assertRaises(IntegrityError):
                store.persist(reserve(state).to_bytes())

    def test_live_row_id_tamper_refuses_ack_and_recovery(self):
        with initialize(self.path) as store:
            state = Record.from_bytes(store.recover())
            with closing(sqlite3.connect(self.path)) as other:
                other.execute("PRAGMA ignore_check_constraints=ON")
                other.execute("UPDATE authority SET id=2 WHERE id=1")
                other.commit()
            for operation in (store.snapshot, store.recover,
                              lambda: store.persist(reserve(state).to_bytes()),
                              lambda: store.persist(state.to_bytes())):
                with self.assertRaises(IntegrityError):
                    operation()
            with closing(sqlite3.connect(self.path)) as other:
                self.assertEqual([(2, state.to_bytes())],
                                 other.execute("SELECT id,record FROM authority").fetchall())

    def test_live_missing_row_refuses_ack_and_recovery(self):
        with initialize(self.path) as store:
            state = Record.from_bytes(store.recover())
            with closing(sqlite3.connect(self.path)) as other:
                other.execute("DELETE FROM authority")
                other.commit()
            for operation in (store.snapshot, store.recover,
                              lambda: store.persist(reserve(state).to_bytes()),
                              lambda: store.persist(state.to_bytes())):
                with self.assertRaises(IntegrityError):
                    operation()

    def test_zero_row_update_is_rejected_before_commit(self):
        with initialize(self.path) as store:
            before = store.recover()
            # A hostile schema change can suppress UPDATE even with id=1.
            # Exercise the rowcount guard via real SQLite, not a fake cursor.
            with closing(sqlite3.connect(self.path)) as other:
                other.execute("CREATE TRIGGER suppress_update BEFORE UPDATE ON authority "
                              "BEGIN SELECT RAISE(IGNORE); END")
                other.commit()
            with self.assertRaises(IntegrityError):
                store.persist(reserve(Record.from_bytes(before)).to_bytes())
            self.assertEqual(before, store.snapshot())
            self.assertFalse(store._db.in_transaction)

    def test_trigger_restoring_authenticated_old_row_cannot_produce_ack(self):
        with initialize(self.path) as store:
            before = store.recover()
            with closing(sqlite3.connect(self.path)) as other:
                other.execute("CREATE TRIGGER restore_old AFTER UPDATE ON authority BEGIN "
                              "UPDATE authority SET generation=OLD.generation,record=OLD.record,"
                              "mac=OLD.mac WHERE id=OLD.id; END")
                other.commit()
            for operation in (store.recover,
                              lambda: store.persist(reserve(Record.from_bytes(before)).to_bytes())):
                with self.assertRaises(IntegrityError):
                    operation()
                self.assertEqual(before, store.snapshot())
                self.assertFalse(store._db.in_transaction)

    def test_commit_failure_returns_no_receipt_and_rolls_back(self):
        with initialize(self.path) as store:
            before = store.recover()
            with patch.object(store, "_checkpoint", side_effect=OSError("test I/O failure")):
                with self.assertRaises(OSError):
                    store.persist(reserve(Record.from_bytes(before)).to_bytes())
            self.assertEqual(before, store.snapshot())
        with reopen(self.path) as store:
            self.assertEqual(before, store.snapshot())

    def test_exclusive_writer_lock_across_process_and_close(self):
        with initialize(self.path):
            with self.assertRaises(StoreLocked):
                reopen(self.path)
            result = self.child("lock", self.path)
            self.assertEqual(19, result.returncode, result.stderr.decode())
        result = self.child("lock", self.path)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        self.assertTrue(Path(str(self.path) + ".lock").exists())

    def test_closed_store_refuses_operations(self):
        store = initialize(self.path)
        raw = store.recover()
        store.close()
        store.close()
        for operation in (store.snapshot, store.recover, lambda: store.persist(raw)):
            with self.assertRaises(PersistenceError):
                operation()

    def test_child_crash_before_and_after_reserve_commit(self):
        for stage in ("before_commit", "after_commit"):
            with self.subTest(stage=stage):
                path = self.path.with_name(stage + ".sqlite3")
                with initialize(path) as store:
                    before = Record.from_bytes(store.recover())
                requested = reserve(before).to_bytes()
                result = self.child("crash", path, stage, "reserve")
                self.assertEqual(73, result.returncode, result.stderr.decode())
                with reopen(path) as store:
                    expected = before.to_bytes() if stage == "before_commit" else requested
                    self.assertEqual(expected, store.snapshot())
                    # If commit succeeded but ACK was lost, byte-for-byte retry
                    # is accepted. If not, the same request commits normally.
                    self.assertEqual(requested, store.persist(requested))
                    recovered = Record.from_bytes(store.recover())
                    self.assertEqual((RESERVED, 0, 1), (recovered.op, recovered.q, recovered.tx))
                    store.persist(finalize(recovered, 0).to_bytes())

    def test_child_crash_before_and_after_finalize_commit(self):
        for stage in ("before_commit", "after_commit"):
            with self.subTest(stage=stage):
                path = self.path.with_name(stage + ".sqlite3")
                with initialize(path) as store:
                    before = reserve(Record.from_bytes(store.recover()))
                    store.persist(before.to_bytes())
                requested = finalize(before).to_bytes()
                result = self.child("crash", path, stage, "finalize")
                self.assertEqual(73, result.returncode, result.stderr.decode())
                with reopen(path) as store:
                    expected = before.to_bytes() if stage == "before_commit" else requested
                    self.assertEqual(expected, store.snapshot())
                    self.assertEqual(requested, store.persist(requested))
                    recovered = Record.from_bytes(store.recover())
                    self.assertEqual((IDLE, 1, 2), (recovered.op, recovered.q, recovered.tx))

    def test_child_crash_before_and_after_session_commit(self):
        for stage in ("before_commit", "after_commit"):
            with self.subTest(stage=stage):
                path = self.path.with_name(stage + ".sqlite3")
                with initialize(path) as store:
                    before = Record.from_bytes(store.recover())
                result = self.child("crash", path, stage, "recover")
                self.assertEqual(73, result.returncode, result.stderr.decode())
                with reopen(path) as store:
                    current = Record.from_bytes(store.snapshot())
                    self.assertEqual((before.op, before.q, before.tx),
                                     (current.op, current.q, current.tx))
                    if stage == "before_commit":
                        self.assertEqual(before.session, current.session)
                    else:
                        self.assertNotEqual(before.session, current.session)
                        with self.assertRaises(ProtocolError):
                            store.persist(reserve(before).to_bytes())

    def test_child_crash_during_initialization_is_never_auto_repaired(self):
        for stage in ("before_commit", "after_commit"):
            with self.subTest(stage=stage):
                path = self.path.with_name(stage + ".sqlite3")
                result = self.child("crash", path, stage, "initialize")
                self.assertEqual(73, result.returncode, result.stderr.decode())
                if stage == "before_commit":
                    with self.assertRaises(IntegrityError):
                        reopen(path)
                else:
                    with reopen(path) as store:
                        rec = Record.from_bytes(store.snapshot())
                        self.assertEqual((IDLE, 0, 0, 0), (rec.op, rec.q, rec.tx, rec.session))
                with self.assertRaises(FileExistsError):
                    initialize(path)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        sys.exit(child_main(sys.argv[2:]))
    unittest.main(verbosity=2)
