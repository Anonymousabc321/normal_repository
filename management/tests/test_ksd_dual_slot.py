"""Functional checks for the optional two-slot SQLite KSD endpoint."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from test_ksd_persistence import SOURCE_ROOT, finalize, initialize, reopen, reserve
from ksd_persistence import DualSlotPersistence, IDLE, RESERVED, IntegrityError, Record


def commit_then_interrupt(path):
    class InterruptedStore(DualSlotPersistence):
        def _checkpoint(self, stage):
            if stage == "after_slot_readback":
                os._exit(73)

    with reopen(path, cls=InterruptedStore) as store:
        reserved = Record.from_bytes(store.snapshot())
        store.persist(finalize(reserved).to_bytes())


class DualSlotTests(unittest.TestCase):
    def setUp(self):
        build = SOURCE_ROOT / "build"
        build.mkdir(exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="ksd-dual-slot-", dir=build)
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "authority.sqlite3"

    def layout(self):
        with closing(sqlite3.connect(self.path)) as db:
            head = db.execute("SELECT slot, generation FROM durable_head").fetchall()
            slots = db.execute("SELECT slot, generation, record FROM durable_slots "
                               "ORDER BY slot").fetchall()
        return head, slots

    def test_reserve_and_finalize_alternate_slots_then_recover_next_q(self):
        with initialize(self.path, cls=DualSlotPersistence) as store:
            initial = store.snapshot()
            self.assertEqual(([(0, 0)], [(0, 0, initial)]), self.layout())
            idle = Record.from_bytes(store.recover())
            reserved = reserve(idle)
            self.assertEqual(reserved.to_bytes(), store.persist(reserved.to_bytes()))
            self.assertEqual(([(0, 2)], [(0, 2, reserved.to_bytes()), (1, 1, idle.to_bytes())]),
                             self.layout())
            complete = finalize(reserved)
            self.assertEqual(complete.to_bytes(), store.persist(complete.to_bytes()))
            layout = ([(1, 3)], [(0, 2, reserved.to_bytes()), (1, 3, complete.to_bytes())])
            self.assertEqual(layout, self.layout())
            self.assertEqual(complete.to_bytes(), store.persist(complete.to_bytes()))
            self.assertEqual(layout, self.layout())  # Repeating the last ACK consumes no slot.

        with reopen(self.path, cls=DualSlotPersistence) as store:
            self.assertEqual(complete.to_bytes(), store.snapshot())
            recovered = Record.from_bytes(store.recover())
            self.assertEqual((IDLE, 1, 2), (recovered.op, recovered.q, recovered.tx))
            self.assertNotEqual(complete.session, recovered.session)
            next_reservation = reserve(recovered)
            self.assertEqual(next_reservation.to_bytes(), store.persist(next_reservation.to_bytes()))

    def test_interrupted_inactive_slot_write_preserves_reservation_until_burn(self):
        with initialize(self.path, cls=DualSlotPersistence) as store:
            reserved = reserve(Record.from_bytes(store.recover()))
            store.persist(reserved.to_bytes())
        before = self.layout()
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--interrupt",
                                str(self.path)], capture_output=True, text=True, timeout=20)
        self.assertEqual(73, child.returncode, child.stderr)

        with reopen(self.path, cls=DualSlotPersistence) as store:
            self.assertEqual(before, self.layout())
            self.assertEqual(reserved.to_bytes(), store.snapshot())
            recovered = Record.from_bytes(store.recover())
            self.assertEqual((RESERVED, 0, 1), (recovered.op, recovered.q, recovered.tx))
            burned = finalize(recovered, context=0)
            self.assertEqual(burned.to_bytes(), store.persist(burned.to_bytes()))
            next_reservation = reserve(burned)
            self.assertEqual(1, next_reservation.q)
            self.assertEqual(next_reservation.to_bytes(), store.persist(next_reservation.to_bytes()))

    def test_invalid_inactive_slot_allows_recovery_of_the_committed_reservation(self):
        with initialize(self.path, cls=DualSlotPersistence) as store:
            reserved = reserve(Record.from_bytes(store.recover()))
            store.persist(reserved.to_bytes())
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE durable_slots SET mac=zeroblob(32) "
                       "WHERE slot<>(SELECT slot FROM durable_head)")
            db.commit()
        with reopen(self.path, cls=DualSlotPersistence) as store:
            self.assertEqual(reserved.to_bytes(), store.snapshot())
            recovered = Record.from_bytes(store.recover())
            self.assertEqual((RESERVED, 0, 1), (recovered.op, recovered.q, recovered.tx))

    def test_invalid_acknowledged_slot_prevents_older_idle_recovery(self):
        with initialize(self.path, cls=DualSlotPersistence) as store:
            reserved = reserve(Record.from_bytes(store.recover()))
            store.persist(reserved.to_bytes())
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE durable_slots SET mac=zeroblob(32) "
                       "WHERE slot=(SELECT slot FROM durable_head)")
            db.commit()
        with self.assertRaises(IntegrityError):
            with reopen(self.path, cls=DualSlotPersistence):
                pass


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--interrupt":
        commit_then_interrupt(sys.argv[2])
    else:
        unittest.main()
