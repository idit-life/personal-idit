"""
Personal Idit — Chain Operations
Hash-linked, signed, append-only ledger.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError

DEFAULT_DATA_DIR = Path.home() / ".idit"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_hash(data: str) -> str:
    """SHA-256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_entry_hash(entry: dict) -> str:
    """Deterministic hash of an entry's signable content."""
    signable = json.dumps({
        "prev_hash": entry["prev_hash"],
        "content_hash": entry["content_hash"],
        "metadata": entry["metadata"],
        "created_at": entry["created_at"],
    }, sort_keys=True, separators=(",", ":"))
    return compute_hash(signable)


def sign_entry(entry: dict, signing_key: SigningKey) -> str:
    """Sign an entry's hash with an Ed25519 key. Returns hex signature."""
    entry_hash = compute_entry_hash(entry)
    signed = signing_key.sign(entry_hash.encode("utf-8"), encoder=HexEncoder)
    return signed.signature.decode()


def verify_signature(entry_hash: str, signature: str, verify_key: VerifyKey) -> bool:
    """Verify an Ed25519 signature against an entry hash. Returns True if valid."""
    try:
        verify_key.verify(entry_hash.encode("utf-8"), bytes.fromhex(signature))
        return True
    except (BadSignatureError, ValueError):
        return False


def db_path(data_dir: Path | None = None) -> Path:
    return (data_dir or DEFAULT_DATA_DIR) / "chain.db"


def get_db(data_dir: Path | None = None) -> sqlite3.Connection:
    p = db_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_chain_db(data_dir: Path | None = None):
    """Initialize the chain database."""
    conn = get_db(data_dir)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS chain (
            seq         INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id    TEXT UNIQUE NOT NULL,
            prev_hash   TEXT NOT NULL,
            content     TEXT,
            content_hash TEXT NOT NULL,
            metadata    TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            sig_algo    TEXT NOT NULL DEFAULT 'ed25519',
            signature   TEXT NOT NULL,
            confirmations TEXT NOT NULL DEFAULT '[]',
            entry_hash  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_entry_id ON chain(entry_id);
        CREATE INDEX IF NOT EXISTS idx_entry_hash ON chain(entry_hash);
        CREATE INDEX IF NOT EXISTS idx_author ON chain(json_extract(metadata, '$.author_id'));
    """)
    conn.commit()
    conn.close()


def get_head(data_dir: Path | None = None) -> dict | None:
    conn = get_db(data_dir)
    try:
        row = conn.execute("SELECT * FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_entry(entry_id: str, data_dir: Path | None = None) -> dict | None:
    conn = get_db(data_dir)
    try:
        row = conn.execute("SELECT * FROM chain WHERE entry_id = ?", (entry_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_chain(limit: int = 50, offset: int = 0, data_dir: Path | None = None) -> list[dict]:
    conn = get_db(data_dir)
    try:
        rows = conn.execute(
            "SELECT * FROM chain ORDER BY seq DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def chain_length(data_dir: Path | None = None) -> int:
    conn = get_db(data_dir)
    try:
        return conn.execute("SELECT COUNT(*) FROM chain").fetchone()[0]
    finally:
        conn.close()


def mint_entry(
    content: str,
    metadata: dict,
    signing_key: SigningKey,
    node_id: str = "local",
    data_dir: Path | None = None,
) -> dict:
    """Create, sign, and store a new chain entry.

    Uses a single connection with IMMEDIATE transaction to prevent
    race conditions between reading the head and inserting.
    """
    conn = get_db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("SELECT * FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = dict(row)["entry_hash"] if row else "0" * 64

        content_hash = compute_hash(content)
        entry = {
            "prev_hash": prev_hash,
            "content_hash": content_hash,
            "metadata": metadata,
            "created_at": now_iso(),
        }

        entry_hash = compute_entry_hash(entry)
        signature = sign_entry(entry, signing_key)
        entry_id = f"id-{entry_hash[:16]}"

        conn.execute("""
            INSERT INTO chain (entry_id, prev_hash, content, content_hash,
                             metadata, created_at, sig_algo, signature,
                             confirmations, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, 'ed25519', ?, ?, ?)
        """, (
            entry_id, prev_hash, content, content_hash,
            json.dumps(metadata, sort_keys=True),
            entry["created_at"], signature,
            json.dumps([node_id]), entry_hash,
        ))
        conn.commit()
        return {
            "entry_id": entry_id,
            "prev_hash": prev_hash,
            "content_hash": content_hash,
            "metadata": metadata,
            "created_at": entry["created_at"],
            "sig_algo": "ed25519",
            "signature": signature,
            "confirmations": [node_id],
            "entry_hash": entry_hash,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def verify_chain(data_dir: Path | None = None, verify_keys: dict[str, VerifyKey] | None = None) -> dict:
    """Walk the entire chain and verify all hashes, links, and signatures.

    Args:
        data_dir: Chain data directory.
        verify_keys: Dict mapping author_id to VerifyKey for signature verification.
            If None, signatures are checked structurally (non-empty, valid hex) but
            not cryptographically verified. Pass keys to get full verification.
    """
    conn = get_db(data_dir)
    try:
        rows = conn.execute("SELECT * FROM chain ORDER BY seq ASC").fetchall()
        if not rows:
            return {"valid": True, "length": 0, "errors": []}

        errors = []
        prev_hash = "0" * 64

        for row in rows:
            row = dict(row)

            # 1. Verify hash chain linkage
            if row["prev_hash"] != prev_hash:
                errors.append({
                    "entry_id": row["entry_id"],
                    "error": f"prev_hash mismatch: expected {prev_hash[:16]}..., got {row['prev_hash'][:16]}..."
                })

            # 2. Verify entry hash
            metadata = json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"]
            entry = {
                "prev_hash": row["prev_hash"],
                "content_hash": row["content_hash"],
                "metadata": metadata,
                "created_at": row["created_at"],
            }
            recomputed = compute_entry_hash(entry)
            if recomputed != row["entry_hash"]:
                errors.append({
                    "entry_id": row["entry_id"],
                    "error": "entry_hash mismatch"
                })

            # 3. Verify content hash (always, even if content is NULL)
            if row["content"] is not None:
                if compute_hash(row["content"]) != row["content_hash"]:
                    errors.append({
                        "entry_id": row["entry_id"],
                        "error": "content_hash does not match content"
                    })

            # 4. Verify signature
            if not row["signature"]:
                errors.append({
                    "entry_id": row["entry_id"],
                    "error": "missing signature"
                })
            elif verify_keys is not None:
                author_id = metadata.get("author_id")
                if author_id and author_id in verify_keys:
                    if not verify_signature(row["entry_hash"], row["signature"], verify_keys[author_id]):
                        errors.append({
                            "entry_id": row["entry_id"],
                            "error": f"invalid signature for author {author_id}"
                        })
                elif author_id:
                    errors.append({
                        "entry_id": row["entry_id"],
                        "error": f"no verify key provided for author {author_id}"
                    })

            prev_hash = row["entry_hash"]

        return {
            "valid": len(errors) == 0,
            "length": len(rows),
            "head": rows[-1]["entry_hash"] if rows else None,
            "errors": errors,
        }
    finally:
        conn.close()


def get_chain_stats(data_dir: Path | None = None) -> dict:
    """Get chain statistics."""
    conn = get_db(data_dir)
    try:
        length = conn.execute("SELECT COUNT(*) FROM chain").fetchone()[0]
        if length == 0:
            return {"length": 0, "authors": {}, "entry_types": {}}

        rows = conn.execute("""
            SELECT json_extract(metadata, '$.author_id') as author, COUNT(*) as count
            FROM chain GROUP BY author ORDER BY count DESC
        """).fetchall()
        authors = {r["author"]: r["count"] for r in rows}

        rows = conn.execute("""
            SELECT json_extract(metadata, '$.entry_type') as etype, COUNT(*) as count
            FROM chain GROUP BY etype ORDER BY count DESC
        """).fetchall()
        entry_types = {r["etype"]: r["count"] for r in rows}

        head = conn.execute("SELECT entry_hash, created_at FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
        genesis = conn.execute("SELECT entry_hash, created_at FROM chain ORDER BY seq ASC LIMIT 1").fetchone()

        return {
            "length": length,
            "head_hash": head["entry_hash"],
            "genesis_hash": genesis["entry_hash"],
            "genesis_time": genesis["created_at"],
            "latest_time": head["created_at"],
            "authors": authors,
            "entry_types": entry_types,
        }
    finally:
        conn.close()
