"""Ed25519 evidence and transactional, hash-chained local audit records."""
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import EraseProofError


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class EvidenceStore:
    def __init__(self, directory):
        self.root = Path(directory).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = self.root / "evidence.sqlite3"
        with self.connect() as connection:
            connection.executescript("""
            CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY, record TEXT NOT NULL);
            """)

    def connect(self):
        connection = sqlite3.connect(self.db, timeout=30)
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def key(self):
        path = self.root / "operator-ed25519.key"
        if not path.exists():
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as file:
                    file.write(raw)
                    file.flush()
                    os.fsync(file.fileno())
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes())

    def _append(self, connection, event, detail):
        row = connection.execute("SELECT sequence,hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        payload = {"sequence": row[0]+1 if row else 1, "previous_hash": row[1] if row else "0"*64,
                   "at": now(), "event": event, "detail": detail}
        connection.execute("INSERT INTO events VALUES(?,?,?)", (payload["sequence"], canonical(payload).decode(), digest(payload)))
        return payload

    def append(self, event, detail):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not self.check(connection):
                raise EraseProofError("Audit integrity failed; new evidence is blocked.")
            return self._append(connection, event, detail)

    def certify(self, payload):
        if not payload.get("verification", {}).get("passed"):
            raise EraseProofError("A failed verification cannot be certified.")
        key = self.key()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not self.check(connection):
                raise EraseProofError("Audit integrity failed; certification is blocked.")
            row = connection.execute("SELECT hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
            payload = {**payload, "previous_audit_hash": row[0] if row else "0"*64}
            record = {"payload": payload, "payload_sha256": digest(payload), "algorithm": "Ed25519",
                      "public_key": base64.b64encode(public).decode(), "signer_fingerprint": hashlib.sha256(public).hexdigest(),
                      "signature": base64.b64encode(key.sign(canonical(payload))).decode()}
            connection.execute("INSERT INTO certificates VALUES(?,?)", (payload["id"], canonical(record).decode()))
            self._append(connection, "erasure.verified", {"certificate_id": payload["id"], "payload_sha256": record["payload_sha256"]})
        return record

    def check(self, connection=None):
        if connection is None:
            with self.connect() as connection:
                return self.check(connection)
        previous = "0"*64
        for expected, row in enumerate(connection.execute("SELECT sequence,payload,hash FROM events ORDER BY sequence"), 1):
            seq, raw, hash_value = row
            payload = json.loads(raw)
            if seq != expected or payload["sequence"] != seq or payload["previous_hash"] != previous or digest(payload) != hash_value:
                return False
            previous = hash_value
        return True

    def records(self):
        with self.connect() as connection:
            return [json.loads(row[0]) for row in connection.execute("SELECT record FROM certificates ORDER BY rowid DESC")]

    def events(self):
        with self.connect() as connection:
            return [{"payload": json.loads(row[0]), "hash": row[1]} for row in connection.execute("SELECT payload,hash FROM events ORDER BY sequence")]


def verify_record(record):
    if record.get("algorithm") != "Ed25519" or record.get("payload", {}).get("schema") != "eraseproof.native-evidence.v1":
        raise EraseProofError("Unsupported evidence record.")
    if digest(record["payload"]) != record.get("payload_sha256"):
        return False
    try:
        raw = base64.b64decode(record["public_key"], validate=True)
        if hashlib.sha256(raw).hexdigest() != record.get("signer_fingerprint"):
            return False
        Ed25519PublicKey.from_public_bytes(raw).verify(base64.b64decode(record["signature"], validate=True), canonical(record["payload"]))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False
