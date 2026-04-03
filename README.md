# Personal Idit

**Your life, hash-linked and signed.**

A personal blockchain you run on your own hardware. Every entry is cryptographically signed with Ed25519 and hash-linked to the one before it. Nobody — not a government, not a corporation, not a future AI — can alter the record after the fact.

No tokens. No gas fees. No wallets. No cloud dependency. Just math on your machine.

## Why

You already document your life — notes, photos, decisions, conversations with AI. But none of it is tamper-proof. None of it can prove *when* it was written or *who* wrote it. If someone changes a record, how would you know?

Personal Idit gives you a chain of custody for your own life. Every entry gets:
- A **SHA-256 hash** linking it to the previous entry (tamper detection)
- An **Ed25519 signature** proving who wrote it (authorship)
- A **timestamp** (provenance)
- **Content** that can never be silently altered after signing

This is sovereign immutability. It's a diary that can prove it wasn't edited.

## Quick Start

```bash
pip install personal-idit

# Create your chain and signing key
idit init yourname

# Mint your first entry
idit mint "Starting my chain today." --signer yourname

# Sign a document
idit sign ~/important-document.txt --signer yourname

# Verify your chain is intact
idit verify

# Start the web UI
idit serve
```

That's it. Your chain lives at `~/.idit/`. Your private key is at `~/.idit/keys/yourname.key`. Guard it like you'd guard a house key.

## What You Can Document

- **Decisions**: "Chose to accept the job offer from X on 2026-04-02"
- **Memories**: "Dad told me the story about the fishing trip today"
- **Documents**: Sign contracts, letters, proposals to the chain
- **AI conversations**: Your AI assistant signs its outputs — you can verify later that it said what it said
- **Photos**: Reference photos by hash (the photo itself stays on your disk; the chain proves it existed at that time)
- **Milestones**: "Graduated today. First in the family."
- **Anything**: It's your chain. Write what matters to you.

## For AI Agents

If you run local AI (Ollama, llama.cpp, etc.), your agents can sign to the chain too. Each agent gets its own keypair. This means:

- **Anti-hallucination**: The AI can check its own memory against the chain. If a memory is on-chain with a valid signature and hash link, it's real — not confabulated.
- **Provenance**: Every AI output is signed with the model name and version. Years from now, you can prove *which model* said *what* and *when*.
- **Accountability**: If the AI gives advice, the advice is on the chain. If the advice was bad, the record proves what was said.

```bash
# Create a key for your AI agent
idit init my-assistant

# The agent signs via the API
curl -X POST http://localhost:18793/mint \
  -H 'Content-Type: application/json' \
  -d '{"content": "Recommended switching to solar panels based on 5-year ROI analysis.", "signer": "my-assistant", "model": "llama3.2:8b", "entry_type": "decision"}'

# Or via GET (for agents that can only do GET requests)
# http://localhost:18793/mint/sign?signer=my-assistant&content=My+note&model=llama3.2:8b&entry_type=note
```

## The Three-Layer Model

Personal Idit is Layer 0 — your private chain on your own hardware. Free, unlimited, yours.

If you choose, you can bridge to public chains later:

| Layer | Where | Cost | What |
|-------|-------|------|------|
| **Layer 0** | Your hardware | Free | Full chain, all content, all signatures |
| **Layer 1** | Bridge validator | Pennies | Periodic hash anchors to a public chain |
| **Layer 2** | Public blockchain | Varies | Hash-only — proves your chain existed at a point in time |

You don't *have* to bridge. Your chain has value on its own. Bridging just adds external verification — proof to the outside world that your records existed when you say they did.

## Architecture

```
~/.idit/
  chain.db        # SQLite database — the chain itself
  keys/
    yourname.key   # Ed25519 private key (chmod 600)
    yourname.pub   # Ed25519 public key
    my-agent.key   # AI agent's private key
    my-agent.pub   # AI agent's public key
```

Each chain entry:
```json
{
  "entry_id": "id-a3b27b99af3ef1d8",
  "prev_hash": "sha256-of-previous-entry",
  "content": "The actual content you wrote",
  "content_hash": "sha256-of-content",
  "metadata": {
    "author_id": "yourname",
    "author_type": "human",
    "entry_type": "note",
    "description": "My first chain entry"
  },
  "created_at": "2026-04-02T19:30:00+00:00",
  "sig_algo": "ed25519",
  "signature": "hex-encoded-ed25519-signature",
  "entry_hash": "sha256-of-signable-fields"
}
```

The `entry_hash` is computed from `prev_hash + content_hash + metadata + created_at`. This is what gets signed. Changing any field breaks the hash. Changing any hash breaks the chain.

## Multi-Machine (Optional)

If you have multiple machines on a private network (e.g., Tailscale), you can run Idit on each one and sync chains between them. This gives you:

- **Redundancy**: Chain survives if one machine dies
- **Multi-node confirmation**: Entries confirmed by multiple machines
- **Distributed signing**: Different agents on different machines, all writing to the same chain

The sync protocol is gossip-based HTTP — machines poll each other's `/chain` endpoints. No central coordinator.

## Quantum Resilience

- **SHA-256 hash chains**: Quantum-safe. Grover's algorithm reduces security to 2^128 — still unbreakable.
- **Ed25519 signatures**: Vulnerable to future quantum computers (Shor's algorithm). The `sig_algo` field enables migration to post-quantum algorithms (ML-DSA / NIST FIPS 204) when libraries mature.
- **Your content is not encrypted**: The chain proves integrity and authorship, not secrecy. Encrypt content separately if needed.

## API Reference

Start the server with `idit serve` (default port 18793).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web mint UI |
| `/mint` | POST | Mint a new entry (JSON body) |
| `/mint/sign` | GET | Mint via query params (for agents) |
| `/chain` | GET | List entries (limit, offset) |
| `/chain/head` | GET | Latest entry |
| `/chain/entry/{id}` | GET | Specific entry |
| `/chain/stats` | GET | Chain statistics |
| `/chain/verify` | GET | Verify all hashes and links |
| `/signers` | GET | List all signers with public keys |
| `/health` | GET | Health check |

## Future: idit.life

Personal Idit chains are designed to be forward-compatible with [idit.life](https://idit.life), a future network where personal chains can optionally anchor to a shared ledger. Think of it as DNS for personal histories — your chain stays private, but you can prove it exists to anyone.

Adoption is voluntary. Your chain has full value without ever connecting to idit.life. The network exists for those who want external verification or who want their records to outlive their hardware.

## Philosophy

This is an autobiography machine. You are the author. Your AI agents are the ghost writers. The chain is the binding.

Nobody needs permission to start documenting their life. You don't need a blockchain company. You don't need tokens. You don't need to understand cryptography. You need a computer and something worth remembering.

The math does the rest.

## Install from Source

```bash
git clone https://github.com/idit-life/personal-idit.git
cd personal-idit
pip install -e .
idit init yourname
```

## Requirements

- Python 3.10+
- PyNaCl (Ed25519 signing)
- FastAPI + Uvicorn (API server)
- SQLite (included with Python)

## License

MIT. Use it. Fork it. Build on it. Document your life.

---

*A [Lot's Wife](https://lotswife.org) project. Because looking back should be a choice, not a risk.*
