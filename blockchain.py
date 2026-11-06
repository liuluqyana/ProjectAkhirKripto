"""Buku besar (ledger) rantai blok sederhana untuk audit trail rilis soal.

* Setiap blok: index, timestamp (UTC), data, prev_hash, hash.
* hash = SHA-256( serialisasi_deterministik({index, timestamp, data, prev_hash}) )
* Serialisasi deterministik: JSON dengan kunci terurut, tanpa spasi, ASCII.
* Mengubah satu blok manapun akan mematahkan hash blok itu dan seluruh rantai setelahnya.
"""
import hashlib
import json
from datetime import datetime, timezone

import config

GENESIS_PREV_HASH = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def compute_hash(index: int, timestamp: str, data: dict, prev_hash: str) -> str:
    return hashlib.sha256(
        canonical({"index": index, "timestamp": timestamp, "data": data, "prev_hash": prev_hash})
    ).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_block(db, data: dict) -> dict:
    """Tambah blok baru. Aman dipanggil di dalam transaksi pemanggil maupun mandiri."""
    own_tx = not db.in_transaction
    if own_tx:
        db.execute("BEGIN IMMEDIATE")
    try:
        last = db.execute("SELECT idx, hash FROM blockchain ORDER BY idx DESC LIMIT 1").fetchone()
        index = 0 if last is None else last["idx"] + 1
        prev_hash = GENESIS_PREV_HASH if last is None else last["hash"]
        timestamp = _now()
        digest = compute_hash(index, timestamp, data, prev_hash)
        db.execute(
            "INSERT INTO blockchain(idx, timestamp, data_json, prev_hash, hash) VALUES (?,?,?,?,?)",
            (index, timestamp, canonical(data).decode("ascii"), prev_hash, digest),
        )
        if own_tx:
            db.execute("COMMIT")
    except Exception:
        if own_tx and db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return {"index": index, "timestamp": timestamp, "data": data, "prev_hash": prev_hash, "hash": digest}


def ensure_genesis(db) -> None:
    if db.execute("SELECT 1 FROM blockchain LIMIT 1").fetchone() is None:
        add_block(db, {"type": "GENESIS", "note": "Secure Exam Distribution Vault ledger"})


def get_chain(db) -> list[dict]:
    rows = db.execute("SELECT idx, timestamp, data_json, prev_hash, hash FROM blockchain ORDER BY idx").fetchall()
    return [
        {"index": r["idx"], "timestamp": r["timestamp"], "data": json.loads(r["data_json"]),
         "prev_hash": r["prev_hash"], "hash": r["hash"]}
        for r in rows
    ]


def verify_chain(db) -> dict:
    errors, prev_hash = [], GENESIS_PREV_HASH
    chain = get_chain(db)
    for expected_index, block in enumerate(chain):
        if block["index"] != expected_index:
            errors.append(f"Blok #{expected_index}: urutan index tidak berurutan (ditemukan {block['index']}).")
        if block["prev_hash"] != prev_hash:
            errors.append(f"Blok #{block['index']}: prev_hash tidak cocok dengan hash blok sebelumnya.")
        recomputed = compute_hash(block["index"], block["timestamp"], block["data"], block["prev_hash"])
        if recomputed != block["hash"]:
            errors.append(f"Blok #{block['index']}: isi blok telah diubah (hash tidak cocok).")
        prev_hash = block["hash"]
    return {"valid": not errors, "length": len(chain), "errors": errors}


def _file_sha256(path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def verify_packages(db) -> list[str]:
    """Cocokkan setiap blok RELEASE dengan berkas paket di disk."""
    issues = []
    for block in get_chain(db):
        data = block["data"]
        if data.get("type") != "RELEASE":
            continue
        row = db.execute(
            "SELECT enc_path, stego_path FROM packages WHERE id = ?", (data.get("package_id"),)
        ).fetchone()
        if row is None:
            issues.append(f"Blok #{block['index']}: paket {data.get('package_id')} tidak ada di database.")
            continue
        if _file_sha256(config.PACKAGE_DIR / row["enc_path"]) != data.get("encrypted_sha256"):
            issues.append(f"Blok #{block['index']}: berkas .kgp paket {data['package_id']} berubah/hilang.")
        if _file_sha256(config.PACKAGE_DIR / row["stego_path"]) != data.get("stego_sha256"):
            issues.append(f"Blok #{block['index']}: gambar stego paket {data['package_id']} berubah/hilang.")
    return issues
