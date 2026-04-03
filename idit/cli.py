"""
Personal Idit — Command Line Interface

Usage:
    idit init [name]         Create your chain and signing key
    idit serve [--port PORT] Start the API server
    idit sign <file>         Sign a file to the chain
    idit mint <text>         Mint text directly to the chain
    idit feel <text>         Mint a feeling entry
    idit letter <text>       Mint a timelocked letter
    idit seal <entry_id>     Seal an existing entry
    idit verify              Verify chain integrity
    idit status              Show chain stats
    idit signers             List all signers
    idit export              Export chain as JSON
"""
import argparse
import json
import sys
from pathlib import Path

from .keys import generate_keypair, list_signers
from .chain import (
    init_chain_db, mint_entry, verify_chain, get_chain_stats,
    chain_length, get_chain, compute_hash,
)


def cmd_init(args):
    """Initialize a new chain with a signing key."""
    data_dir = Path(args.data_dir)
    name = args.name or _ask("Your signer name (e.g., your first name): ")
    if not name:
        print("Error: signer name required.")
        sys.exit(1)

    name = name.strip().lower().replace(" ", "-")

    init_chain_db(data_dir)
    result = generate_keypair(name, data_dir)

    if result["status"] == "existing":
        print(f"Key already exists for '{name}'.")
    else:
        print(f"Generated Ed25519 keypair for '{name}'.")

    print(f"  Public key: {result['public_key'][:32]}...")
    print(f"  Data dir:   {data_dir}")

    # Create genesis if chain is empty
    length = chain_length(data_dir)
    if length == 0:
        print("\nCreating genesis block...")
        from .keys import load_signing_key

        sk = load_signing_key(name, data_dir)
        genesis_content = (
            f"IDIT GENESIS\n\n"
            f"Chain initialized by {name} on {__import__('datetime').datetime.now().isoformat()[:10]}.\n"
            f"This is the first entry. Every entry that follows is hash-linked\n"
            f"and cryptographically signed. The chain is the record. The record is yours.\n\n"
            f"Future network compatibility: idit.life\n"
        )
        metadata = {
            "author_type": "human",
            "author_id": name,
            "agent_model": "",
            "node_id": "local",
            "entry_type": "genesis",
            "description": "Chain genesis",
            "tags": ["genesis"],
        }
        entry = mint_entry(
            content=genesis_content, metadata=metadata,
            signing_key=sk, node_id="local", data_dir=data_dir,
        )
        print(f"  Genesis:  {entry['entry_id']}")
        print(f"  Hash:     {entry['entry_hash'][:32]}...")
        print()
        print("Your chain is live. Start writing.")
        print(f"  idit mint \"My first entry\" --signer {name}")
        print(f"  idit serve")
    else:
        print(f"\nChain already has {length} entries.")


def cmd_serve(args):
    """Start the API server."""
    import uvicorn
    from .server import create_app

    data_dir = Path(args.data_dir) if args.data_dir != str(Path.home() / ".idit") else None
    app = create_app(data_dir)
    print(f"Starting Idit server on port {args.port}...")
    print(f"  Mint UI: http://localhost:{args.port}/")
    print(f"  API:     http://localhost:{args.port}/chain/stats")
    uvicorn.run(app, host=args.host, port=args.port)


def cmd_sign(args):
    """Sign a file to the chain."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)
    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}")
        sys.exit(1)

    content = path.read_text()
    from .keys import load_signing_key
    try:
        sk = load_signing_key(args.signer, data_dir)
    except FileNotFoundError:
        print(f"Error: no key for signer '{args.signer}'. Run: idit init {args.signer}")
        sys.exit(1)

    metadata = {
        "author_type": "human" if args.model in ("", "human") else "agent",
        "author_id": args.signer,
        "agent_model": args.model,
        "node_id": "local",
        "entry_type": args.type,
        "description": args.description or f"Signed file: {path.name}",
        "source_file": path.name,
        "tags": [],
    }
    entry = mint_entry(
        content=content, metadata=metadata,
        signing_key=sk, node_id="local", data_dir=data_dir,
    )
    sig_block = f"""
---
IDIT CHAIN SIGNATURE
  Entry:     {entry['entry_id']}
  Hash:      {entry['entry_hash']}
  Content:   {entry['content_hash']}
  Signed by: {args.signer}
  Timestamp: {entry['created_at']}
  Algorithm: {entry['sig_algo']}
  Signature: {entry['signature'][:64]}...
---"""
    print(sig_block)
    print(f"\nMinted to chain as {entry['entry_id']}")


def cmd_mint(args):
    """Mint text directly to the chain."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)

    text = " ".join(args.text)
    if not text:
        print("Error: content required.")
        sys.exit(1)

    from .keys import load_signing_key
    try:
        sk = load_signing_key(args.signer, data_dir)
    except FileNotFoundError:
        print(f"Error: no key for signer '{args.signer}'. Run: idit init {args.signer}")
        sys.exit(1)

    opens_at = getattr(args, "opens_at", "") or ""
    confidential = getattr(args, "confidential", False)

    metadata = {
        "author_type": "human" if args.model in ("", "human") else "agent",
        "author_id": args.signer,
        "agent_model": args.model,
        "node_id": "local",
        "entry_type": args.type,
        "description": args.description or "",
        "tags": [],
        "opens_at": opens_at,
        "confidential": confidential,
        "sealed_ref": "",
    }
    entry = mint_entry(
        content=text, metadata=metadata,
        signing_key=sk, node_id="local", data_dir=data_dir,
    )
    print(f"MINTED  {entry['entry_id']}  {entry['entry_hash'][:24]}...  {args.signer}")
    if opens_at:
        print(f"  TIMELOCKED until {opens_at}")
    if confidential:
        print(f"  CONFIDENTIAL entry")


def cmd_feel(args):
    """Mint a feeling entry."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)

    text = " ".join(args.text)
    if not text:
        print("Error: content required.")
        sys.exit(1)

    from .keys import load_signing_key
    try:
        sk = load_signing_key(args.signer, data_dir)
    except FileNotFoundError:
        print(f"Error: no key for signer '{args.signer}'. Run: idit init {args.signer}")
        sys.exit(1)

    metadata = {
        "author_type": "human",
        "author_id": args.signer,
        "agent_model": "",
        "node_id": "local",
        "entry_type": "feeling",
        "description": args.description or "",
        "tags": [],
        "opens_at": "",
        "confidential": False,
        "sealed_ref": "",
    }
    entry = mint_entry(
        content=text, metadata=metadata,
        signing_key=sk, node_id="local", data_dir=data_dir,
    )
    print(f"FELT  {entry['entry_id']}  {entry['entry_hash'][:24]}...  {args.signer}")


def cmd_letter(args):
    """Mint a timelocked letter."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)

    text = " ".join(args.text)
    if not text:
        print("Error: content required.")
        sys.exit(1)

    from .keys import load_signing_key
    try:
        sk = load_signing_key(args.signer, data_dir)
    except FileNotFoundError:
        print(f"Error: no key for signer '{args.signer}'. Run: idit init {args.signer}")
        sys.exit(1)

    opens_at = getattr(args, "opens_at", "") or ""

    metadata = {
        "author_type": "human",
        "author_id": args.signer,
        "agent_model": "",
        "node_id": "local",
        "entry_type": "letter",
        "description": args.description or "",
        "tags": [],
        "opens_at": opens_at,
        "confidential": bool(opens_at),
        "sealed_ref": "",
    }
    entry = mint_entry(
        content=text, metadata=metadata,
        signing_key=sk, node_id="local", data_dir=data_dir,
    )
    print(f"LETTER  {entry['entry_id']}  {entry['entry_hash'][:24]}...  {args.signer}")
    if opens_at:
        print(f"  TIMELOCKED until {opens_at}")


def cmd_seal(args):
    """Seal an existing entry by minting a seal reference."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)

    from .keys import load_signing_key
    try:
        sk = load_signing_key(args.signer, data_dir)
    except FileNotFoundError:
        print(f"Error: no key for signer '{args.signer}'. Run: idit init {args.signer}")
        sys.exit(1)

    # Verify the referenced entry exists
    from .chain import get_entry
    ref = get_entry(args.entry_id, data_dir)
    if not ref:
        print(f"Error: entry '{args.entry_id}' not found in chain.")
        sys.exit(1)

    opens_at = getattr(args, "opens_at", "") or ""
    content = f"SEAL: Entry {args.entry_id} sealed by {args.signer}."
    if opens_at:
        content += f" Opens at {opens_at}."

    metadata = {
        "author_type": "human",
        "author_id": args.signer,
        "agent_model": "",
        "node_id": "local",
        "entry_type": "seal",
        "description": f"Seal of {args.entry_id}",
        "tags": [],
        "opens_at": opens_at,
        "confidential": True,
        "sealed_ref": args.entry_id,
    }
    entry = mint_entry(
        content=content, metadata=metadata,
        signing_key=sk, node_id="local", data_dir=data_dir,
    )
    print(f"SEALED  {args.entry_id}  ->  {entry['entry_id']}  {args.signer}")
    if opens_at:
        print(f"  TIMELOCKED until {opens_at}")


def cmd_verify(args):
    """Verify chain integrity."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)
    result = verify_chain(data_dir)
    if result["valid"]:
        print(f"CHAIN VALID  |  {result['length']} entries  |  head: {result.get('head', 'N/A')[:24] if result.get('head') else 'empty'}...")
    else:
        print(f"CHAIN BROKEN  |  {result['length']} entries  |  {len(result['errors'])} errors:")
        for err in result["errors"]:
            print(f"  {err['entry_id']}: {err['error']}")
        sys.exit(1)


def cmd_status(args):
    """Show chain stats."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)
    length = chain_length(data_dir)
    if length == 0:
        print("Chain is empty. Run: idit init")
        return

    stats = get_chain_stats(data_dir)
    print(f"CHAIN STATUS")
    print(f"  Entries:     {stats['length']}")
    print(f"  Genesis:     {stats['genesis_hash'][:24]}...")
    print(f"  Head:        {stats['head_hash'][:24]}...")
    print(f"  First entry: {stats['genesis_time']}")
    print(f"  Last entry:  {stats['latest_time']}")
    print(f"  Authors:")
    for author, count in stats["authors"].items():
        print(f"    {author}: {count}")
    print(f"  Entry types:")
    for etype, count in stats["entry_types"].items():
        print(f"    {etype}: {count}")


def cmd_signers(args):
    """List all signers."""
    data_dir = Path(args.data_dir)
    signers = list_signers(data_dir)
    if not signers:
        print("No signers. Run: idit init")
        return
    print("SIGNERS:")
    for s in signers:
        print(f"  {s['name']:20s}  {s['public_key'][:32]}...")


def cmd_export(args):
    """Export the full chain as JSON."""
    data_dir = Path(args.data_dir)
    init_chain_db(data_dir)
    length = chain_length(data_dir)
    entries = get_chain(limit=length, offset=0, data_dir=data_dir)
    entries.reverse()  # chronological order
    output = {
        "idit_version": "0.1.0",
        "chain_length": length,
        "entries": entries,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(output, indent=2, default=str))
        print(f"Exported {length} entries to {args.output}")
    else:
        print(json.dumps(output, indent=2, default=str))


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def main():
    default_data = str(Path.home() / ".idit")

    parser = argparse.ArgumentParser(
        prog="idit",
        description="Personal Idit -- Your life, hash-linked and signed.",
    )
    parser.add_argument("--data-dir", default=default_data, help="Data directory (default: ~/.idit)")
    sub = parser.add_subparsers(dest="command")

    # init
    p = sub.add_parser("init", help="Create your chain and signing key")
    p.add_argument("name", nargs="?", help="Your signer name")

    # serve
    p = sub.add_parser("serve", help="Start the API server")
    p.add_argument("--port", type=int, default=18793, help="Port (default: 18793)")
    p.add_argument("--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")

    # sign
    p = sub.add_parser("sign", help="Sign a file to the chain")
    p.add_argument("file", help="File to sign")
    p.add_argument("--signer", required=True, help="Signer name")
    p.add_argument("--model", default="", help="Model name (if AI)")
    p.add_argument("--type", default="document", help="Entry type")
    p.add_argument("--description", default="", help="Description")

    # mint
    p = sub.add_parser("mint", help="Mint text to the chain")
    p.add_argument("text", nargs="+", help="Text to mint")
    p.add_argument("--signer", required=True, help="Signer name")
    p.add_argument("--model", default="", help="Model name (if AI)")
    p.add_argument("--type", default="note", help="Entry type")
    p.add_argument("--description", default="", help="Description")
    p.add_argument("--opens-at", default="", help="ISO date for timelock (e.g., 2036-01-01)")
    p.add_argument("--confidential", action="store_true", help="Mark as confidential")

    # feel
    p = sub.add_parser("feel", help="Mint a feeling entry")
    p.add_argument("text", nargs="+", help="What you're feeling")
    p.add_argument("--signer", required=True, help="Signer name")
    p.add_argument("--description", default="", help="Description")

    # letter
    p = sub.add_parser("letter", help="Mint a timelocked letter")
    p.add_argument("text", nargs="+", help="Letter content")
    p.add_argument("--signer", required=True, help="Signer name")
    p.add_argument("--opens-at", default="", help="ISO date when letter can be read (e.g., 2036-01-01)")
    p.add_argument("--description", default="", help="Description")

    # seal
    p = sub.add_parser("seal", help="Seal an existing entry with a timelock")
    p.add_argument("entry_id", help="Entry ID to seal")
    p.add_argument("--signer", required=True, help="Signer name")
    p.add_argument("--opens-at", default="", help="ISO date when seal opens (e.g., 2101-01-01)")

    # verify
    sub.add_parser("verify", help="Verify chain integrity")

    # status
    sub.add_parser("status", help="Show chain stats")

    # signers
    sub.add_parser("signers", help="List all signers")

    # export
    p = sub.add_parser("export", help="Export chain as JSON")
    p.add_argument("-o", "--output", help="Output file (default: stdout)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print("\nQuick start:")
        print("  idit init yourname    # Create your chain")
        print("  idit serve            # Start the web UI")
        print("  idit mint \"Hello world\" --signer yourname")
        print("\nFuture network: https://idit.life")
        sys.exit(0)

    commands = {
        "init": cmd_init, "serve": cmd_serve, "sign": cmd_sign,
        "mint": cmd_mint, "feel": cmd_feel, "letter": cmd_letter,
        "seal": cmd_seal, "verify": cmd_verify, "status": cmd_status,
        "signers": cmd_signers, "export": cmd_export,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
