"""Trusted management-host persistence for the KSD hardware sideband.

This database, its host, and the exclusive USB management path are the authority.
They must be outside the signing firmware's control. SQLite EXTRA commits precede
every returned receipt. The external HMAC key detects record alteration; it does
NOT detect restoration of a complete older database, disk snapshot, or host.
Storage must honor SQLite's synchronization requests. This is not a secure-element
or independently anchored monotonic-counter implementation.

Wire records are exactly 112 bytes, least-significant byte of the 896-bit RTL
vector first (28 little-endian words). All Record/Registration integer fields are
RTL vector values. In this project's public-key encoding, the identifier must be
registered as int.from_bytes(public_key[8:24], "little"): wire bytes 88:104 then
equal those original 16 I bytes, and word 22 is LE32(I[0:4]). Do not interpret
the printed I hex as a big-endian integer. A key_id is an opaque numeric identity
whose conversion must likewise match its provisioning/USB registry convention.

Initialize explicitly once for a NEW registered seed generation. A missing or
invalid existing database is an error, never permission to initialize q=0.
recover() is called only while hardware is reset/recovery-locked and provisioning
matches the registration. Retry delivery of its returned bytes without calling
recover() again. Recovery rotates and commits the session, but preserves op/q/tx;
the RTL burns a recovered RESERVED q through its normal IDLE persistence request.
No seed, wrapping key, or HMAC key is stored in this database.
"""

from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
from typing import Union


RECORD_SIZE = 112
RESERVED = 1
IDLE = 2
MAX_U32 = (1 << 32) - 1
_DOMAIN = b"LMS-KSD-HOST-DURABLE-v1\x00"


class PersistenceError(RuntimeError):
    """The authority must withhold ACK/recovery on this error."""


class IntegrityError(PersistenceError):
    pass


class ProtocolError(PersistenceError):
    pass


class StoreLocked(PersistenceError):
    pass


def _uint(name, value, bits):
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ProtocolError(f"{name} is not an unsigned {bits}-bit integer")


@dataclass(frozen=True)
class Registration:
    key_id: int
    epoch: int
    params: int
    identifier: int
    q_limit: int
    seed_identity: bytes

    def __post_init__(self):
        for name, bits in (("key_id", 128), ("epoch", 32), ("params", 64),
                           ("identifier", 128), ("q_limit", 32)):
            _uint(name, getattr(self, name), bits)
        if not self.key_id:
            raise ProtocolError("registration requires a nonzero key identity")
        # Match the actual adapter's supported profile encoding, including its
        # small-height test profiles. Registry ownership establishes the key.
        w, height, hash_id = self.params & 15, (self.params >> 8) & 255, (self.params >> 16) & 255
        if (self.params >> 24 or self.params & 0xf0 or w not in (1, 2, 4, 8)
                or height > 31 or hash_id not in (1, 2)
                or self.q_limit != 1 << height):
            raise ProtocolError("registration has an unsupported profile or q_limit")
        if type(self.seed_identity) is not bytes or len(self.seed_identity) != 32 or not any(self.seed_identity):
            raise ProtocolError("registration requires a nonzero 32-byte seed identity commitment")

    def canonical_bytes(self):
        # seed_identity is an explicit trusted commitment to the registered
        # provisioning material, NOT proof of what was loaded into the FPGA.
        return json.dumps({
            "key_id": f"{self.key_id:032x}", "epoch": self.epoch,
            "params": f"{self.params:016x}", "identifier": f"{self.identifier:032x}",
            "q_limit": self.q_limit, "seed_identity": self.seed_identity.hex(),
        }, sort_keys=True, separators=(",", ":")).encode("ascii")


@dataclass(frozen=True)
class Record:
    op: int
    key_id: int
    epoch: int
    session: int
    q: int
    tx: int
    context: int
    params: int
    identifier: int
    q_limit: int

    def to_bytes(self):
        value = 0
        for name, shift, bits in (
            ("op", 0, 2), ("key_id", 32, 128), ("epoch", 160, 32),
            ("session", 192, 128), ("q", 320, 32), ("tx", 352, 32),
            ("context", 384, 256), ("params", 640, 64),
            ("identifier", 704, 128), ("q_limit", 832, 32),
        ):
            field = getattr(self, name)
            _uint(name, field, bits)
            value |= field << shift
        if self.op not in (RESERVED, IDLE):
            raise ProtocolError("invalid record operation")
        return value.to_bytes(RECORD_SIZE, "little")

    @classmethod
    def from_bytes(cls, raw):
        if type(raw) is not bytes or len(raw) != RECORD_SIZE:
            raise ProtocolError("record must be exactly 112 bytes")
        value = int.from_bytes(raw, "little")
        if (value >> 2) & ((1 << 30) - 1) or value >> 864:
            raise ProtocolError("reserved record bits are nonzero")
        fields = {}
        for name, shift, bits in (
            ("op", 0, 2), ("key_id", 32, 128), ("epoch", 160, 32),
            ("session", 192, 128), ("q", 320, 32), ("tx", 352, 32),
            ("context", 384, 256), ("params", 640, 64),
            ("identifier", 704, 128), ("q_limit", 832, 32),
        ):
            fields[name] = (value >> shift) & ((1 << bits) - 1)
        result = cls(**fields)
        result.to_bytes()
        return result


class _ExclusiveLock:
    """Lifetime process lock, additional to SQLite's transaction locks.

    Keep the lock file permanently: unlinking it permits two different locked
    inodes for the same database. OS locks disappear automatically on a crash.
    """

    def __init__(self, path):
        self.file = open(str(path) + ".lock", "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0, os.SEEK_END)
                if self.file.tell() == 0:
                    self.file.write(b"\x00")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            raise StoreLocked("another process owns this persistence database") from None

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file = None


class Persistence:
    """One registered key generation per explicitly initialized database."""

    def __init__(self):
        raise TypeError("use Persistence.initialize() or Persistence.open()")

    @classmethod
    def _connect(cls, path, registration, integrity_key, initialize):
        if not isinstance(registration, Registration):
            raise TypeError("registration must be a Registration")
        if type(integrity_key) is not bytes or len(integrity_key) < 32:
            raise ValueError("an external integrity key of at least 32 bytes is required")
        obj = object.__new__(cls)
        obj.path = Path(path).resolve()
        obj.registration = registration
        obj._registration = registration.canonical_bytes()
        obj._key = integrity_key
        obj._db = None
        obj._lock = _ExclusiveLock(obj.path)
        try:
            if initialize:
                # O_EXCL prevents accidental reinitialization, including empty
                # or corrupt databases. Failed initialization stays fail-closed.
                fd = os.open(obj.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
            elif not obj.path.is_file():
                raise FileNotFoundError("persistence database is missing; explicit new-key initialization required")
            obj._db = sqlite3.connect(obj.path.as_uri() + "?mode=rw", uri=True,
                                      isolation_level=None, timeout=0)
            obj._db.execute("PRAGMA busy_timeout=0")
            mode = obj._db.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            obj._db.execute("PRAGMA synchronous=EXTRA")
            if mode.lower() != "delete" or obj._db.execute("PRAGMA synchronous").fetchone()[0] != 3:
                raise PersistenceError("SQLite durable commit settings were not applied")
            if initialize:
                obj._initialize()
                if os.name != "nt":
                    # SQLite EXTRA syncs rollback-journal deletion. Also persist
                    # creation of the database's directory entry on POSIX.
                    directory = os.open(obj.path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
            else:
                if obj._db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise IntegrityError("database structural integrity check failed")
                obj._load()
            return obj
        except sqlite3.DatabaseError as error:
            obj.close()
            raise IntegrityError("cannot open or validate persistence database") from error
        except BaseException:
            obj.close()
            raise

    @classmethod
    def initialize(cls, path: Union[str, Path], *, registration: Registration, integrity_key: bytes):
        """Explicitly register a NEW key generation at IDLE(q=0, tx=0).

        Never use this to replace missing state for a previously used key. The
        trusted operator must keep key-generation registration outside rollback
        or deletion of this database. Existing paths are always rejected.
        """
        return cls._connect(path, registration, integrity_key, True)

    @classmethod
    def open(cls, path: Union[str, Path], *, registration: Registration, integrity_key: bytes):
        """Open existing authenticated state; do not create or reset authority."""
        return cls._connect(path, registration, integrity_key, False)

    def _mac(self, generation, raw):
        message = (_DOMAIN + len(self._registration).to_bytes(4, "little") +
                   self._registration + generation.to_bytes(8, "little") + raw)
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def _initial_record(self):
        reg = self.registration
        return Record(IDLE, reg.key_id, reg.epoch, 0, 0, 0, 0,
                      reg.params, reg.identifier, reg.q_limit).to_bytes()

    def _initialize(self):
        record = self._initial_record()
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("CREATE TABLE authority (id INTEGER PRIMARY KEY CHECK(id=1), "
                             "version INTEGER NOT NULL, registration BLOB NOT NULL, "
                             "generation INTEGER NOT NULL, record BLOB NOT NULL, mac BLOB NOT NULL)")
            self._db.execute("INSERT INTO authority VALUES(1,1,?,?,?,?)",
                             (self._registration, 0, record, self._mac(0, record)))
            self._commit()
        except BaseException:
            self._rollback()
            raise

    def _load(self):
        if self._db is None:
            raise PersistenceError("persistence database is closed")
        rows = self._db.execute("SELECT id,version,registration,generation,record,mac FROM authority").fetchall()
        if len(rows) != 1:
            raise IntegrityError("invalid authority row count")
        row_id, version, registration, generation, raw, mac = rows[0]
        if row_id != 1:
            raise IntegrityError("invalid authority row identity")
        if version != 1 or registration != self._registration:
            raise IntegrityError("database version or registered key identity does not match")
        if (type(generation) is not int or not 0 <= generation < (1 << 63)
                or type(raw) is not bytes or len(raw) != RECORD_SIZE
                or type(mac) is not bytes or len(mac) != 32
                or not hmac.compare_digest(mac, self._mac(generation, raw))):
            raise IntegrityError("persistence record authentication failed")
        return generation, self._decode_record(generation, raw), raw

    def _decode_record(self, generation, raw):
        try:
            record = Record.from_bytes(raw)
            self._validate_identity(record)
            if record.tx != 2 * record.q + (record.op == RESERVED):
                raise ProtocolError("q/tx history is inconsistent")
            if not record.session and (generation != 0 or record.op != IDLE or record.q or record.tx or record.context):
                raise ProtocolError("uninitialized session has noninitial state")
        except ProtocolError as error:
            raise IntegrityError("authenticated persistence record is invalid") from error
        return record

    def _validate_identity(self, record):
        reg = self.registration
        if (record.key_id, record.epoch, record.params, record.identifier, record.q_limit) != (
                reg.key_id, reg.epoch, reg.params, reg.identifier, reg.q_limit):
            raise ProtocolError("record differs from the registered key/profile/identifier/range")
        if record.q > reg.q_limit or (record.op == RESERVED and record.q == reg.q_limit):
            raise ProtocolError("q is outside the registered range")
        if record.op == RESERVED and record.tx == MAX_U32:
            raise ProtocolError("reservation cannot be finalized without transaction overflow")

    def _checkpoint(self, stage):
        """Internal crash-test seam. Production does not override this method."""

    def _commit(self):
        self._checkpoint("before_commit")
        self._db.execute("COMMIT")
        self._checkpoint("after_commit")

    def _rollback(self):
        if self._db is not None and self._db.in_transaction:
            self._db.execute("ROLLBACK")

    def _store(self, generation, record):
        if generation >= (1 << 63) - 1:
            raise PersistenceError("storage generation exhausted")
        raw = record.to_bytes()
        generation += 1
        cursor = self._db.execute("UPDATE authority SET generation=?,record=?,mac=? WHERE id=1",
                                  (generation, raw, self._mac(generation, raw)))
        if cursor.rowcount != 1:
            raise IntegrityError("durable authority update did not change exactly one row")
        # rowcount alone cannot detect a changed schema's AFTER UPDATE trigger
        # restoring an older, still-authenticated row. Verify actual state while
        # BEGIN IMMEDIATE still excludes other SQLite writers, before committing.
        saved_generation, _, saved_raw = self._load()
        if saved_generation != generation or saved_raw != raw:
            raise IntegrityError("durable authority update did not retain the requested state")
        self._commit()
        return raw

    def snapshot(self):
        """Read authenticated durable bytes for diagnostics; does not authorize recovery."""
        return self._load()[2]

    def recover(self):
        """Commit a fresh session before returning the hardware recovery record.

        q/tx/op are preserved, including RESERVED; context is reset because RTL
        recovery burns that reservation without resuming its signing operation.
        """
        if self._db is None:
            raise PersistenceError("persistence database is closed")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            generation, old, _ = self._load()
            session = secrets.randbits(128)
            while session == 0 or session == old.session:
                session = secrets.randbits(128)
            return self._store(generation, replace(old, session=session, context=0))
        except BaseException:
            self._rollback()
            raise

    def persist(self, record_bytes):
        """Validate one hardware transition and return its bytes only after commit.

        Exact repeats of the most recent record in the current session are
        idempotent (lost ACK). Older sessions, old transactions, and conflicting
        contents never receive a receipt. RESERVED carries context=0 for this
        adapter's late-binding mode. IDLE may bind the signing digest or zero for
        an abort/recovery burn; the host does not independently verify that digest.
        """
        request = Record.from_bytes(record_bytes)
        self._validate_identity(request)
        if self._db is None:
            raise PersistenceError("persistence database is closed")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            generation, old, raw = self._load()
            if not request.session or request.session != old.session:
                raise ProtocolError("request has an inactive or stale session")
            if record_bytes == raw:
                self._db.execute("COMMIT")
                return record_bytes
            if old.tx == MAX_U32 or request.tx != old.tx + 1:
                raise ProtocolError("transaction is not the next transaction")
            if old.op == IDLE:
                if (request.op != RESERVED or request.q != old.q or request.context != 0
                        or old.q >= old.q_limit or old.tx >= MAX_U32 - 1):
                    raise ProtocolError("invalid IDLE to RESERVED transition")
            elif request.op != IDLE or request.q != old.q + 1:
                raise ProtocolError("invalid RESERVED to IDLE transition")
            return self._store(generation, request)
        except BaseException:
            self._rollback()
            raise

    commit_request = persist

    def close(self):
        try:
            if self._db is not None:
                self._db.close()
                self._db = None
        finally:
            self._key = b""
            if self._lock is not None:
                self._lock.close()
                self._lock = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class DualSlotPersistence(Persistence):
    """Two alternating logical SQLite slots on the trusted management host.

    Slot A holds even storage generations, slot B odd ones. A generation also
    advances on session rotation, where the hardware transaction number stays
    constant. The authenticated head names the last committed slot. Its loss,
    or loss of that slot, must never authorize reuse of an acknowledged q.
    """

    def _slot_mac(self, slot, generation, raw):
        return self._mac(generation, b"KSD-slot-v1\x00" + bytes([slot]) + raw)

    def _head_mac(self, slot, generation, slot_mac):
        return self._mac(generation, b"KSD-head-v1\x00" + bytes([slot]) + slot_mac)

    def _initialize(self):
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute("CREATE TABLE durable_slots (slot INTEGER PRIMARY KEY CHECK(slot IN (0,1)), "
                             "generation INTEGER NOT NULL, record BLOB NOT NULL, mac BLOB NOT NULL)")
            self._db.execute("CREATE TABLE durable_head (id INTEGER PRIMARY KEY CHECK(id=1), "
                             "slot INTEGER NOT NULL, generation INTEGER NOT NULL, mac BLOB NOT NULL)")
            tag = self._write_slot(0, self._initial_record())
            self._db.execute("INSERT INTO durable_head VALUES(1,0,0,?)", (self._head_mac(0, 0, tag),))
            self._load()
            self._commit()
        except BaseException:
            self._rollback()
            raise

    def _write_slot(self, generation, raw):
        slot = generation % 2
        tag = self._slot_mac(slot, generation, raw)
        self._db.execute(
            "INSERT INTO durable_slots(slot,generation,record,mac) VALUES(?,?,?,?) "
            "ON CONFLICT(slot) DO UPDATE SET generation=excluded.generation, "
            "record=excluded.record, mac=excluded.mac", (slot, generation, raw, tag))
        saved = self._db.execute("SELECT generation,record,mac FROM durable_slots WHERE slot=?",
                                 (slot,)).fetchone()
        if saved != (generation, raw, tag):
            raise IntegrityError("inactive slot read-back failed")
        return tag

    def _load(self):
        if self._db is None:
            raise PersistenceError("persistence database is closed")
        # Read the head and both slots in a single SQLite snapshot.
        rows = self._db.execute(
            "SELECT h.id,h.slot,h.generation,h.mac,s.slot,s.generation,s.record,s.mac "
            "FROM durable_head AS h CROSS JOIN durable_slots AS s").fetchall()
        if not 1 <= len(rows) <= 2 or any(row[:4] != rows[0][:4] for row in rows):
            raise IntegrityError("invalid dual-slot authority")
        head_id, active, committed, head_tag = rows[0][:4]
        if (head_id != 1 or type(committed) is not int or not 0 <= committed < (1 << 63)
                or active != committed % 2 or type(head_tag) is not bytes):
            raise IntegrityError("invalid dual-slot commit pointer")

        selected = None
        for _, _, _, _, slot, generation, raw, tag in rows:
            if (slot not in (0, 1) or type(generation) is not int or not 0 <= generation < (1 << 63)
                    or slot != generation % 2 or type(raw) is not bytes or len(raw) != RECORD_SIZE
                    or type(tag) is not bytes or not hmac.compare_digest(tag, self._slot_mac(slot, generation, raw))):
                continue
            # Slot and head are published in one SQLite commit. A valid newer
            # slot alongside an older pointer is inconsistent with that protocol.
            if generation > committed:
                raise IntegrityError("authenticated slot is newer than the commit pointer")
            if slot == active and generation == committed:
                if not hmac.compare_digest(head_tag, self._head_mac(slot, generation, tag)):
                    raise IntegrityError("dual-slot commit pointer authentication failed")
                selected = raw
        if selected is None:
            raise IntegrityError("committed slot is missing or invalid")
        return committed, self._decode_record(committed, selected), selected

    def _store(self, generation, record):
        if generation >= (1 << 63) - 1:
            raise PersistenceError("storage generation exhausted")
        generation += 1
        slot = generation % 2
        raw = record.to_bytes()
        tag = self._write_slot(generation, raw)
        self._checkpoint("after_slot_readback")
        self._db.execute("UPDATE durable_head SET slot=?,generation=?,mac=? WHERE id=1",
                         (slot, generation, self._head_mac(slot, generation, tag)))
        saved_generation, _, saved_raw = self._load()
        if (saved_generation, saved_raw) != (generation, raw):
            raise IntegrityError("commit pointer read-back failed")
        self._commit()
        return raw
