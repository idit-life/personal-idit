"""
Personal Idit — Test Suite

Tests the chain library, key management, and server. Focuses on:
- Crypto correctness (signatures actually verified, tamper detection)
- Security boundaries (path traversal, auth, signer name validation)
- Data integrity (hash links, race conditions)
- Edge cases (empty chains, null content, malformed data)
"""
import json
import os
import sqlite3
import pytest
from pathlib import Path

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder


# ── Key Management ──────────────────────────────────────────────────


class TestKeyManagement:
    def test_generate_keypair_creates_files(self, tmp_path):
        from idit.keys import generate_keypair
        result = generate_keypair("alice", tmp_path)
        assert result["status"] == "generated"
        assert result["name"] == "alice"
        assert len(result["public_key"]) == 64  # 32 bytes hex
        assert (tmp_path / "keys" / "alice.key").exists()
        assert (tmp_path / "keys" / "alice.pub").exists()

    def test_generate_keypair_returns_existing(self, tmp_path):
        from idit.keys import generate_keypair
        r1 = generate_keypair("bob", tmp_path)
        r2 = generate_keypair("bob", tmp_path)
        assert r1["public_key"] == r2["public_key"]
        assert r2["status"] == "existing"

    def test_key_file_permissions(self, tmp_path):
        from idit.keys import generate_keypair
        generate_keypair("secure", tmp_path)
        key_file = tmp_path / "keys" / "secure.key"
        mode = oct(key_file.stat().st_mode & 0o777)
        assert mode == "0o600", f"Private key has wrong permissions: {mode}"

    def test_keys_dir_permissions(self, tmp_path):
        from idit.keys import generate_keypair
        generate_keypair("test", tmp_path)
        keys_dir = tmp_path / "keys"
        mode = oct(keys_dir.stat().st_mode & 0o777)
        assert mode == "0o700", f"Keys directory has wrong permissions: {mode}"

    def test_load_signing_key(self, tmp_path):
        from idit.keys import generate_keypair, load_signing_key
        generate_keypair("carol", tmp_path)
        sk = load_signing_key("carol", tmp_path)
        assert isinstance(sk, SigningKey)

    def test_load_signing_key_not_found(self, tmp_path):
        from idit.keys import load_signing_key
        with pytest.raises(FileNotFoundError, match="no-such-signer"):
            load_signing_key("no-such-signer", tmp_path)

    def test_load_verify_key(self, tmp_path):
        from idit.keys import generate_keypair, load_verify_key
        generate_keypair("dave", tmp_path)
        vk = load_verify_key("dave", tmp_path)
        # Verify the key can actually verify a signature from the signing key
        from idit.keys import load_signing_key
        sk = load_signing_key("dave", tmp_path)
        signed = sk.sign(b"test message", encoder=HexEncoder)
        vk.verify(b"test message", bytes.fromhex(signed.signature.decode()))

    def test_load_verify_key_not_found(self, tmp_path):
        from idit.keys import load_verify_key
        with pytest.raises(FileNotFoundError, match="ghost"):
            load_verify_key("ghost", tmp_path)

    def test_list_signers_empty(self, tmp_path):
        from idit.keys import list_signers
        result = list_signers(tmp_path)
        assert result == []

    def test_list_signers(self, tmp_path):
        from idit.keys import generate_keypair, list_signers
        generate_keypair("alice", tmp_path)
        generate_keypair("bob", tmp_path)
        signers = list_signers(tmp_path)
        names = [s["name"] for s in signers]
        assert "alice" in names
        assert "bob" in names
        assert len(signers) == 2

    def test_keypair_roundtrip(self, tmp_path):
        """Key generated, saved, loaded back produces same public key."""
        from idit.keys import generate_keypair, load_signing_key
        result = generate_keypair("roundtrip", tmp_path)
        sk = load_signing_key("roundtrip", tmp_path)
        reloaded_pub = sk.verify_key.encode(encoder=HexEncoder).decode()
        assert reloaded_pub == result["public_key"]


# ── Chain Core ──────────────────────────────────────────────────────


class TestChainCore:
    def _setup_chain(self, tmp_path):
        from idit.chain import init_chain_db
        from idit.keys import generate_keypair, load_signing_key
        init_chain_db(tmp_path)
        generate_keypair("tester", tmp_path)
        sk = load_signing_key("tester", tmp_path)
        return sk

    def test_init_creates_db(self, tmp_path):
        from idit.chain import init_chain_db, db_path
        init_chain_db(tmp_path)
        assert db_path(tmp_path).exists()

    def test_init_creates_tables(self, tmp_path):
        from idit.chain import init_chain_db, get_db
        init_chain_db(tmp_path)
        conn = get_db(tmp_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t["name"] for t in tables]
        assert "chain" in table_names
        conn.close()

    def test_init_idempotent(self, tmp_path):
        from idit.chain import init_chain_db
        init_chain_db(tmp_path)
        init_chain_db(tmp_path)  # should not raise

    def test_empty_chain_head(self, tmp_path):
        from idit.chain import init_chain_db, get_head
        init_chain_db(tmp_path)
        assert get_head(tmp_path) is None

    def test_empty_chain_length(self, tmp_path):
        from idit.chain import init_chain_db, chain_length
        init_chain_db(tmp_path)
        assert chain_length(tmp_path) == 0

    def test_empty_chain_verify(self, tmp_path):
        from idit.chain import init_chain_db, verify_chain
        init_chain_db(tmp_path)
        result = verify_chain(tmp_path)
        assert result["valid"] is True
        assert result["length"] == 0

    def test_mint_first_entry(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry, chain_length
        entry = mint_entry("Hello world", {"author_id": "tester", "entry_type": "note"}, sk, data_dir=tmp_path)
        assert entry["entry_id"].startswith("id-")
        assert entry["prev_hash"] == "0" * 64  # genesis links to null
        assert entry["sig_algo"] == "ed25519"
        assert len(entry["signature"]) == 128  # 64 bytes hex
        assert chain_length(tmp_path) == 1

    def test_mint_chain_links(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry
        e1 = mint_entry("First", {"author_id": "tester"}, sk, data_dir=tmp_path)
        e2 = mint_entry("Second", {"author_id": "tester"}, sk, data_dir=tmp_path)
        assert e2["prev_hash"] == e1["entry_hash"]

    def test_mint_content_hash(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry, compute_hash
        entry = mint_entry("Exact content", {"author_id": "tester"}, sk, data_dir=tmp_path)
        assert entry["content_hash"] == compute_hash("Exact content")

    def test_get_entry_by_id(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry, get_entry
        entry = mint_entry("Findable", {"author_id": "tester"}, sk, data_dir=tmp_path)
        found = get_entry(entry["entry_id"], tmp_path)
        assert found is not None
        assert found["content"] == "Findable"
        assert found["entry_hash"] == entry["entry_hash"]

    def test_get_entry_not_found(self, tmp_path):
        from idit.chain import init_chain_db, get_entry
        init_chain_db(tmp_path)
        assert get_entry("id-nonexistent", tmp_path) is None

    def test_get_chain_order(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry, get_chain
        e1 = mint_entry("First", {"author_id": "tester"}, sk, data_dir=tmp_path)
        e2 = mint_entry("Second", {"author_id": "tester"}, sk, data_dir=tmp_path)
        e3 = mint_entry("Third", {"author_id": "tester"}, sk, data_dir=tmp_path)
        chain = get_chain(data_dir=tmp_path)
        # get_chain returns DESC order (newest first)
        assert chain[0]["entry_hash"] == e3["entry_hash"]
        assert chain[2]["entry_hash"] == e1["entry_hash"]

    def test_get_chain_limit_offset(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry, get_chain
        for i in range(5):
            mint_entry(f"Entry {i}", {"author_id": "tester"}, sk, data_dir=tmp_path)
        page = get_chain(limit=2, offset=1, data_dir=tmp_path)
        assert len(page) == 2

    def test_get_head(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry, get_head
        e1 = mint_entry("First", {"author_id": "tester"}, sk, data_dir=tmp_path)
        head = get_head(tmp_path)
        assert head["entry_hash"] == e1["entry_hash"]
        e2 = mint_entry("Second", {"author_id": "tester"}, sk, data_dir=tmp_path)
        head = get_head(tmp_path)
        assert head["entry_hash"] == e2["entry_hash"]

    def test_chain_stats(self, tmp_path):
        sk = self._setup_chain(tmp_path)
        from idit.chain import mint_entry, get_chain_stats
        mint_entry("A", {"author_id": "tester", "entry_type": "note"}, sk, data_dir=tmp_path)
        mint_entry("B", {"author_id": "tester", "entry_type": "memory"}, sk, data_dir=tmp_path)
        stats = get_chain_stats(tmp_path)
        assert stats["length"] == 2
        assert "tester" in stats["authors"]
        assert stats["authors"]["tester"] == 2
        assert stats["genesis_hash"] != stats["head_hash"]

    def test_chain_stats_empty(self, tmp_path):
        from idit.chain import init_chain_db, get_chain_stats
        init_chain_db(tmp_path)
        stats = get_chain_stats(tmp_path)
        assert stats["length"] == 0


# ── Signature Verification ──────────────────────────────────────────


class TestSignatureVerification:
    """The most critical tests. These verify that the crypto actually works."""

    def _setup(self, tmp_path):
        from idit.chain import init_chain_db
        from idit.keys import generate_keypair, load_signing_key, load_verify_key
        init_chain_db(tmp_path)
        generate_keypair("signer1", tmp_path)
        sk = load_signing_key("signer1", tmp_path)
        vk = load_verify_key("signer1", tmp_path)
        return sk, vk

    def test_verify_signature_valid(self, tmp_path):
        from idit.chain import compute_entry_hash, sign_entry, verify_signature
        from idit.keys import generate_keypair, load_signing_key, load_verify_key
        generate_keypair("v", tmp_path)
        sk = load_signing_key("v", tmp_path)
        vk = load_verify_key("v", tmp_path)
        entry = {
            "prev_hash": "0" * 64,
            "content_hash": "abc123",
            "metadata": {"author_id": "v"},
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        sig = sign_entry(entry, sk)
        entry_hash = compute_entry_hash(entry)
        assert verify_signature(entry_hash, sig, vk) is True

    def test_verify_signature_wrong_key(self, tmp_path):
        from idit.chain import compute_entry_hash, sign_entry, verify_signature
        from idit.keys import generate_keypair, load_signing_key, load_verify_key
        generate_keypair("real", tmp_path)
        generate_keypair("impostor", tmp_path)
        sk_real = load_signing_key("real", tmp_path)
        vk_impostor = load_verify_key("impostor", tmp_path)
        entry = {
            "prev_hash": "0" * 64,
            "content_hash": "abc123",
            "metadata": {"author_id": "real"},
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        sig = sign_entry(entry, sk_real)
        entry_hash = compute_entry_hash(entry)
        assert verify_signature(entry_hash, sig, vk_impostor) is False

    def test_verify_signature_tampered_hash(self, tmp_path):
        from idit.chain import compute_entry_hash, sign_entry, verify_signature
        from idit.keys import generate_keypair, load_signing_key, load_verify_key
        generate_keypair("t", tmp_path)
        sk = load_signing_key("t", tmp_path)
        vk = load_verify_key("t", tmp_path)
        entry = {
            "prev_hash": "0" * 64,
            "content_hash": "abc123",
            "metadata": {"author_id": "t"},
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        sig = sign_entry(entry, sk)
        # Tamper with the hash — signature should fail
        assert verify_signature("tampered_hash", sig, vk) is False

    def test_verify_signature_garbage_signature(self, tmp_path):
        from idit.chain import verify_signature
        from idit.keys import generate_keypair, load_verify_key
        generate_keypair("g", tmp_path)
        vk = load_verify_key("g", tmp_path)
        assert verify_signature("somehash", "00" * 64, vk) is False

    def test_verify_chain_checks_signatures(self, tmp_path):
        """verify_chain with keys detects forged signatures."""
        sk, vk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain, get_db
        mint_entry("Legit", {"author_id": "signer1"}, sk, data_dir=tmp_path)

        # Tamper: replace the signature with garbage
        conn = get_db(tmp_path)
        conn.execute("UPDATE chain SET signature = ? WHERE seq = 1", ("00" * 64,))
        conn.commit()
        conn.close()

        result = verify_chain(tmp_path, verify_keys={"signer1": vk})
        assert result["valid"] is False
        assert any("invalid signature" in e["error"] for e in result["errors"])

    def test_verify_chain_detects_content_tamper(self, tmp_path):
        """Changing content after minting breaks content_hash verification."""
        sk, vk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain, get_db
        mint_entry("Original content", {"author_id": "signer1"}, sk, data_dir=tmp_path)

        conn = get_db(tmp_path)
        conn.execute("UPDATE chain SET content = 'Tampered content' WHERE seq = 1")
        conn.commit()
        conn.close()

        result = verify_chain(tmp_path, verify_keys={"signer1": vk})
        assert result["valid"] is False
        assert any("content_hash" in e["error"] for e in result["errors"])

    def test_verify_chain_detects_hash_link_break(self, tmp_path):
        """Breaking the prev_hash chain is detected."""
        sk, vk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain, get_db
        mint_entry("First", {"author_id": "signer1"}, sk, data_dir=tmp_path)
        mint_entry("Second", {"author_id": "signer1"}, sk, data_dir=tmp_path)

        conn = get_db(tmp_path)
        conn.execute("UPDATE chain SET prev_hash = ? WHERE seq = 2", ("ff" * 32,))
        conn.commit()
        conn.close()

        result = verify_chain(tmp_path, verify_keys={"signer1": vk})
        assert result["valid"] is False
        assert any("prev_hash mismatch" in e["error"] for e in result["errors"])

    def test_verify_chain_detects_entry_hash_tamper(self, tmp_path):
        """Changing entry_hash without recomputing is detected."""
        sk, vk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain, get_db
        mint_entry("Test", {"author_id": "signer1"}, sk, data_dir=tmp_path)

        conn = get_db(tmp_path)
        conn.execute("UPDATE chain SET entry_hash = ? WHERE seq = 1", ("aa" * 32,))
        conn.commit()
        conn.close()

        result = verify_chain(tmp_path, verify_keys={"signer1": vk})
        assert result["valid"] is False

    def test_verify_chain_valid_chain(self, tmp_path):
        """A properly minted chain passes all verification."""
        sk, vk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain
        for i in range(5):
            mint_entry(f"Entry {i}", {"author_id": "signer1"}, sk, data_dir=tmp_path)
        result = verify_chain(tmp_path, verify_keys={"signer1": vk})
        assert result["valid"] is True
        assert result["length"] == 5
        assert len(result["errors"]) == 0

    def test_verify_chain_without_keys_still_checks_hashes(self, tmp_path):
        """Without verify_keys, hashes and links are still checked."""
        sk, _ = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain, get_db
        mint_entry("Content", {"author_id": "signer1"}, sk, data_dir=tmp_path)

        # Tamper content — should be caught even without keys
        conn = get_db(tmp_path)
        conn.execute("UPDATE chain SET content = 'Bad' WHERE seq = 1")
        conn.commit()
        conn.close()

        result = verify_chain(tmp_path)  # no keys passed
        assert result["valid"] is False

    def test_verify_chain_missing_signature(self, tmp_path):
        """Entry with empty signature is flagged."""
        sk, vk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain, get_db
        mint_entry("Test", {"author_id": "signer1"}, sk, data_dir=tmp_path)

        conn = get_db(tmp_path)
        conn.execute("UPDATE chain SET signature = '' WHERE seq = 1")
        conn.commit()
        conn.close()

        result = verify_chain(tmp_path, verify_keys={"signer1": vk})
        assert result["valid"] is False
        assert any("missing signature" in e["error"] for e in result["errors"])

    def test_verify_chain_unknown_author(self, tmp_path):
        """Entry from unknown author (no key provided) is flagged."""
        sk, vk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain
        mint_entry("Test", {"author_id": "signer1"}, sk, data_dir=tmp_path)

        # Pass keys dict that doesn't include signer1
        result = verify_chain(tmp_path, verify_keys={"someone_else": vk})
        assert result["valid"] is False
        assert any("no verify key" in e["error"] for e in result["errors"])


# ── Hash Functions ──────────────────────────────────────────────────


class TestHashFunctions:
    def test_compute_hash_deterministic(self):
        from idit.chain import compute_hash
        assert compute_hash("hello") == compute_hash("hello")

    def test_compute_hash_different_input(self):
        from idit.chain import compute_hash
        assert compute_hash("hello") != compute_hash("world")

    def test_compute_entry_hash_deterministic(self):
        from idit.chain import compute_entry_hash
        entry = {
            "prev_hash": "0" * 64,
            "content_hash": "abc",
            "metadata": {"key": "value"},
            "created_at": "2026-01-01",
        }
        h1 = compute_entry_hash(entry)
        h2 = compute_entry_hash(entry)
        assert h1 == h2

    def test_compute_entry_hash_key_order_irrelevant(self):
        """Metadata key order shouldn't affect hash (sort_keys=True)."""
        from idit.chain import compute_entry_hash
        e1 = {"prev_hash": "0"*64, "content_hash": "x", "metadata": {"a": 1, "b": 2}, "created_at": "t"}
        e2 = {"prev_hash": "0"*64, "content_hash": "x", "metadata": {"b": 2, "a": 1}, "created_at": "t"}
        assert compute_entry_hash(e1) == compute_entry_hash(e2)

    def test_compute_entry_hash_changes_with_content(self):
        from idit.chain import compute_entry_hash
        base = {"prev_hash": "0"*64, "metadata": {}, "created_at": "t"}
        e1 = {**base, "content_hash": "hash1"}
        e2 = {**base, "content_hash": "hash2"}
        assert compute_entry_hash(e1) != compute_entry_hash(e2)


# ── Server ──────────────────────────────────────────────────────────


class TestServer:
    @pytest.fixture
    def client(self, tmp_path):
        from idit.server import create_app
        from idit.keys import generate_keypair
        from idit.chain import init_chain_db
        init_chain_db(tmp_path)
        generate_keypair("testuser", tmp_path)

        app = create_app(tmp_path)
        from starlette.testclient import TestClient
        with TestClient(app) as c:
            yield c

    @pytest.fixture
    def authed_client(self, tmp_path):
        """Client with API key authentication enabled."""
        os.environ["IDIT_API_KEY"] = "test-secret-key"
        os.environ["IDIT_CORS_ORIGIN"] = "*"
        from idit.keys import generate_keypair
        from idit.chain import init_chain_db
        init_chain_db(tmp_path)
        generate_keypair("testuser", tmp_path)

        from idit.server import create_app
        app = create_app(tmp_path)
        from starlette.testclient import TestClient
        with TestClient(app) as c:
            yield c
        del os.environ["IDIT_API_KEY"]
        del os.environ["IDIT_CORS_ORIGIN"]

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["chain_length"] == 0
        assert data["head"] is None

    def test_mint_post(self, client):
        resp = client.post("/mint", json={
            "content": "Test entry",
            "signer": "testuser",
            "entry_type": "note",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["entry_id"].startswith("id-")
        assert data["sig_algo"] == "ed25519"
        assert len(data["signature"]) == 128

    def test_mint_unknown_signer(self, client):
        resp = client.post("/mint", json={
            "content": "Test",
            "signer": "nobody",
        })
        assert resp.status_code == 404

    def test_mint_invalid_signer_name(self, client):
        resp = client.post("/mint", json={
            "content": "Test",
            "signer": "../../etc/shadow",
        })
        assert resp.status_code == 400
        assert "Invalid signer name" in resp.json()["detail"]

    def test_mint_signer_name_empty(self, client):
        resp = client.post("/mint", json={
            "content": "Test",
            "signer": "",
        })
        assert resp.status_code == 400

    def test_mint_signer_name_with_slashes(self, client):
        resp = client.post("/mint", json={
            "content": "Test",
            "signer": "a/b/c",
        })
        assert resp.status_code == 400

    def test_get_mint_removed(self, client):
        """GET /mint/sign endpoint should no longer exist (CSRF vector)."""
        resp = client.get("/mint/sign", params={"signer": "testuser", "content": "test"})
        assert resp.status_code in (404, 405)

    def test_chain_head_empty(self, client):
        resp = client.get("/chain/head")
        assert resp.status_code == 200

    def test_chain_head_after_mint(self, client):
        client.post("/mint", json={"content": "Entry", "signer": "testuser"})
        resp = client.get("/chain/head")
        data = resp.json()
        assert "entry_hash" in data

    def test_chain_list(self, client):
        client.post("/mint", json={"content": "E1", "signer": "testuser"})
        client.post("/mint", json={"content": "E2", "signer": "testuser"})
        resp = client.get("/chain?limit=10")
        data = resp.json()
        assert data["total"] == 2
        assert len(data["entries"]) == 2

    def test_get_entry(self, client):
        r = client.post("/mint", json={"content": "Find me", "signer": "testuser"})
        entry_id = r.json()["entry_id"]
        resp = client.get(f"/chain/entry/{entry_id}")
        assert resp.status_code == 200
        assert resp.json()["content"] == "Find me"

    def test_get_entry_not_found(self, client):
        resp = client.get("/chain/entry/id-nonexistent")
        assert resp.status_code == 404

    def test_verify_endpoint(self, client):
        client.post("/mint", json={"content": "Test", "signer": "testuser"})
        resp = client.get("/chain/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["length"] == 1

    def test_stats_empty(self, client):
        resp = client.get("/chain/stats")
        data = resp.json()
        assert data["length"] == 0

    def test_stats_with_entries(self, client):
        client.post("/mint", json={"content": "T", "signer": "testuser", "entry_type": "note"})
        resp = client.get("/chain/stats")
        data = resp.json()
        assert data["length"] == 1
        assert "testuser" in data["authors"]

    def test_signers_endpoint(self, client):
        resp = client.get("/signers")
        data = resp.json()
        assert len(data["signers"]) >= 1
        names = [s["name"] for s in data["signers"]]
        assert "testuser" in names

    def test_health_after_mint(self, client):
        client.post("/mint", json={"content": "X", "signer": "testuser"})
        resp = client.get("/health")
        data = resp.json()
        assert data["chain_length"] == 1
        assert data["head"] is not None
        assert data["head"].startswith("id-")

    # ── Auth tests ──

    def test_auth_blocks_write_without_key(self, authed_client):
        resp = authed_client.post("/mint", json={
            "content": "Unauthorized",
            "signer": "testuser",
        })
        assert resp.status_code == 401

    def test_auth_allows_write_with_key(self, authed_client):
        resp = authed_client.post("/mint", json={
            "content": "Authorized",
            "signer": "testuser",
        }, headers={"X-API-Key": "test-secret-key"})
        assert resp.status_code == 200

    def test_auth_bearer_header(self, authed_client):
        resp = authed_client.post("/mint", json={
            "content": "Bearer auth",
            "signer": "testuser",
        }, headers={"Authorization": "Bearer test-secret-key"})
        assert resp.status_code == 200

    def test_auth_wrong_key(self, authed_client):
        resp = authed_client.post("/mint", json={
            "content": "Wrong key",
            "signer": "testuser",
        }, headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401

    def test_auth_reads_still_work(self, authed_client):
        resp = authed_client.get("/health")
        assert resp.status_code == 200
        resp = authed_client.get("/chain")
        assert resp.status_code == 200
        resp = authed_client.get("/signers")
        assert resp.status_code == 200

    # ── Timelock tests ──

    def test_timelocked_entry_redacted(self, client):
        resp = client.post("/mint", json={
            "content": "Secret future content",
            "signer": "testuser",
            "opens_at": "2099-01-01T00:00:00+00:00",
        })
        entry_id = resp.json()["entry_id"]
        resp = client.get(f"/chain/entry/{entry_id}")
        assert resp.status_code == 200
        assert "TIMELOCKED" in resp.json()["content"]
        assert "Secret future" not in resp.json()["content"]

    def test_timelocked_entry_unlock_still_locked(self, client):
        resp = client.post("/mint", json={
            "content": "Locked",
            "signer": "testuser",
            "opens_at": "2099-01-01T00:00:00+00:00",
        })
        entry_id = resp.json()["entry_id"]
        resp = client.get(f"/chain/entry/{entry_id}/unlock")
        assert resp.status_code == 403

    def test_past_timelock_not_redacted(self, client):
        resp = client.post("/mint", json={
            "content": "Already open",
            "signer": "testuser",
            "opens_at": "2020-01-01T00:00:00+00:00",
        })
        entry_id = resp.json()["entry_id"]
        resp = client.get(f"/chain/entry/{entry_id}")
        assert resp.json()["content"] == "Already open"


# ── Edge Cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    def _setup(self, tmp_path):
        from idit.chain import init_chain_db
        from idit.keys import generate_keypair, load_signing_key
        init_chain_db(tmp_path)
        generate_keypair("edge", tmp_path)
        return load_signing_key("edge", tmp_path)

    def test_unicode_content(self, tmp_path):
        sk = self._setup(tmp_path)
        from idit.chain import mint_entry, get_entry, verify_chain
        entry = mint_entry("Hello \U0001f30d \u4e16\u754c", {"author_id": "edge"}, sk, data_dir=tmp_path)
        found = get_entry(entry["entry_id"], tmp_path)
        assert found["content"] == "Hello \U0001f30d \u4e16\u754c"
        assert verify_chain(tmp_path)["valid"] is True

    def test_empty_string_content(self, tmp_path):
        sk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain
        entry = mint_entry("", {"author_id": "edge"}, sk, data_dir=tmp_path)
        assert entry["content_hash"] is not None
        assert verify_chain(tmp_path)["valid"] is True

    def test_large_content(self, tmp_path):
        sk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain
        big = "x" * 100_000
        entry = mint_entry(big, {"author_id": "edge"}, sk, data_dir=tmp_path)
        assert entry["entry_id"].startswith("id-")
        assert verify_chain(tmp_path)["valid"] is True

    def test_special_chars_in_content(self, tmp_path):
        sk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain
        content = 'He said "hello" & she said <goodbye> \' \\ \n\t\0'
        mint_entry(content, {"author_id": "edge"}, sk, data_dir=tmp_path)
        assert verify_chain(tmp_path)["valid"] is True

    def test_many_entries(self, tmp_path):
        sk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain, chain_length
        from idit.keys import load_verify_key
        vk = load_verify_key("edge", tmp_path)
        for i in range(50):
            mint_entry(f"Entry {i}", {"author_id": "edge"}, sk, data_dir=tmp_path)
        assert chain_length(tmp_path) == 50
        result = verify_chain(tmp_path, verify_keys={"edge": vk})
        assert result["valid"] is True
        assert result["length"] == 50

    def test_metadata_with_nested_objects(self, tmp_path):
        sk = self._setup(tmp_path)
        from idit.chain import mint_entry, verify_chain
        meta = {"author_id": "edge", "nested": {"deep": {"value": [1, 2, 3]}}}
        entry = mint_entry("Nested", meta, sk, data_dir=tmp_path)
        assert entry["entry_id"].startswith("id-")
        assert verify_chain(tmp_path)["valid"] is True
