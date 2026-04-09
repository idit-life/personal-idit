"""
Personal Idit — Chain API Server
Allows any signer to mint, query, and verify chain entries over HTTP.
"""
import hmac
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .chain import (
    init_chain_db, mint_entry, get_head, get_entry,
    get_chain, chain_length, verify_chain, get_chain_stats,
)
from .keys import load_signing_key, list_signers, generate_keypair

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [idit] %(levelname)s: %(message)s",
)
logger = logging.getLogger("idit")

SIGNER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")
READ_METHODS = {"GET", "HEAD", "OPTIONS"}


def create_app(data_dir: Path | None = None) -> FastAPI:
    api_key = os.environ.get("IDIT_API_KEY", "")

    app = FastAPI(
        title="Personal Idit",
        version="0.1.0",
        description="Your life, hash-linked and signed.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[os.environ.get("IDIT_CORS_ORIGIN", "http://localhost:8000")],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    )

    class ApiKeyMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if not api_key:
                return await call_next(request)
            path = request.url.path
            if path == "/health":
                return await call_next(request)
            if request.method in READ_METHODS:
                return await call_next(request)
            key = request.headers.get("x-api-key") or request.headers.get(
                "authorization", ""
            ).removeprefix("Bearer ").strip()
            if not key or not hmac.compare_digest(key, api_key):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key"},
                )
            return await call_next(request)

    app.add_middleware(ApiKeyMiddleware)

    class MintRequest(BaseModel):
        content: str = Field(max_length=1_000_000)  # 1MB max content
        signer: str = Field(max_length=63)
        model: str = Field(default="", max_length=200)
        node: str = Field(default="local", max_length=200)
        entry_type: str = Field(default="note", max_length=100)
        description: str = Field(default="", max_length=2000)
        tags: list[str] = Field(default=[], max_length=50)
        opens_at: str = Field(default="", max_length=100)
        confidential: bool = False
        sealed_ref: str = Field(default="", max_length=100)

    @app.on_event("startup")
    async def startup():
        init_chain_db(data_dir)
        length = chain_length(data_dir)
        logger.info(f"Idit chain loaded. Length: {length}")

    @app.get("/", response_class=HTMLResponse)
    async def mint_page():
        return _mint_html(data_dir)

    @app.post("/mint")
    async def mint(req: MintRequest):
        if not SIGNER_NAME_RE.match(req.signer):
            raise HTTPException(400, "Invalid signer name. Use alphanumeric, dots, hyphens, underscores (1-63 chars).")
        try:
            sk = load_signing_key(req.signer, data_dir)
        except FileNotFoundError:
            raise HTTPException(404, f"No key found for signer '{req.signer}'")

        metadata = {
            "author_type": "human" if req.model in ("", "human") else "agent",
            "author_id": req.signer,
            "agent_model": req.model,
            "node_id": req.node,
            "entry_type": req.entry_type,
            "description": req.description,
            "tags": req.tags,
            "opens_at": req.opens_at,
            "confidential": req.confidential,
            "sealed_ref": req.sealed_ref,
        }
        entry = mint_entry(
            content=req.content, metadata=metadata,
            signing_key=sk, node_id=req.node, data_dir=data_dir,
        )
        logger.info(f"MINT: {req.signer} -> {entry['entry_id']} ({req.entry_type})")
        sig_block = (
            f"IDIT | {entry['entry_id']} | "
            f"{entry['entry_hash'][:16]}... | "
            f"{req.signer} | {entry['created_at']}"
        )
        return {**entry, "signature_block": sig_block}

    @app.get("/chain/head")
    async def head():
        h = get_head(data_dir)
        return h if h else {"length": 0, "head": None}

    @app.get("/chain/entry/{entry_id}")
    async def entry(entry_id: str):
        e = get_entry(entry_id, data_dir)
        if not e:
            raise HTTPException(404, f"Entry {entry_id} not found")
        return _redact_timelocked(e)

    @app.get("/chain/entry/{entry_id}/unlock")
    async def unlock_entry(entry_id: str):
        e = get_entry(entry_id, data_dir)
        if not e:
            raise HTTPException(404, f"Entry {entry_id} not found")
        meta = e.get("metadata", {})
        if isinstance(meta, str):
            meta = json.loads(meta)
        opens_at = meta.get("opens_at", "")
        if not opens_at:
            return e  # no timelock, return as-is
        if _is_timelocked(meta):
            raise HTTPException(403, f"Entry is timelocked until {opens_at}")
        return e  # timelock expired, return full content

    def _is_timelocked(meta: dict) -> bool:
        """Check if an entry is currently timelocked."""
        opens_at = meta.get("opens_at", "")
        if not opens_at:
            return False
        try:
            lock_dt = datetime.fromisoformat(opens_at)
            if lock_dt.tzinfo is None:
                lock_dt = lock_dt.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) < lock_dt
        except (ValueError, TypeError):
            return False

    def _redact_timelocked(entry: dict) -> dict:
        """Replace content with placeholder if entry is timelocked."""
        meta = entry.get("metadata", {})
        if isinstance(meta, str):
            meta = json.loads(meta)
        if _is_timelocked(meta):
            entry = dict(entry)
            opens_at = meta.get("opens_at", "")
            entry["content"] = f"[TIMELOCKED -- opens {opens_at}]"
        return entry

    @app.get("/chain")
    async def chain(limit: int = 50, offset: int = 0):
        entries = get_chain(limit, offset, data_dir)
        entries = [_redact_timelocked(e) for e in entries]
        return {"entries": entries, "total": chain_length(data_dir)}

    @app.get("/chain/verify")
    async def verify():
        from .keys import load_verify_key
        signers = list_signers(data_dir)
        verify_keys = {}
        for s in signers:
            try:
                verify_keys[s["name"]] = load_verify_key(s["name"], data_dir)
            except FileNotFoundError:
                pass
        return verify_chain(data_dir, verify_keys=verify_keys if verify_keys else None)

    @app.get("/chain/stats")
    async def stats():
        if chain_length(data_dir) == 0:
            return {"length": 0}
        return get_chain_stats(data_dir)

    @app.get("/signers")
    async def signers():
        return {"signers": list_signers(data_dir)}

    @app.get("/health")
    async def health():
        length = chain_length(data_dir)
        h = get_head(data_dir)
        return {
            "status": "ok",
            "chain_length": length,
            "head": h["entry_id"] if h else None,
        }

    return app


def _mint_html(data_dir: Path | None = None) -> str:
    return """<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Idit // Mint</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: 'Share Tech Mono', monospace;
    background: #0a0a0a; color: #33ff33;
    min-height: 100vh; display: flex; flex-direction: column; align-items: center;
    padding: 40px 20px;
  }
  body::before {
    content: ''; position: fixed; top:0; left:0; right:0; bottom:0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.06) 2px, rgba(0,0,0,0.06) 4px);
    pointer-events: none; z-index: 999;
  }
  .banner { text-align:center; margin-bottom:30px; }
  .banner h1 { font-size:24px; letter-spacing:4px; color:#33ff33; text-shadow:0 0 10px rgba(51,255,51,0.4); }
  .banner .sub { color:#1a8a1a; font-size:11px; letter-spacing:3px; margin-top:8px; }
  .mint-box {
    background: #0d1a0d; border: 1px solid #1a3a1a;
    width: 100%; max-width: 700px; padding: 20px;
  }
  .mint-box h2 { font-size:12px; letter-spacing:2px; color:#1a8a1a; margin-bottom:14px; }
  .field { margin-bottom: 12px; }
  .field label { display:block; font-size:10px; color:#1a8a1a; letter-spacing:1px; margin-bottom:4px; }
  .field input, .field select {
    width:100%; background:#050f05; border:1px solid #1a3a1a; color:#33ff33;
    font-family:'Share Tech Mono',monospace; font-size:13px; padding:8px 10px; outline:none;
  }
  .field input:focus, .field select:focus, textarea:focus { border-color:#33ff33; }
  textarea {
    width:100%; min-height:180px; background:#050f05; border:1px solid #1a3a1a;
    color:#33ff33; font-family:'Share Tech Mono',monospace; font-size:13px;
    padding:10px; resize:vertical; outline:none;
  }
  .btn {
    background:#1a3a1a; border:1px solid #33ff33; color:#33ff33;
    font-family:'Share Tech Mono',monospace; font-size:13px;
    padding:10px 24px; cursor:pointer; letter-spacing:1px; margin-top:10px; width:100%;
  }
  .btn:hover { background:#33ff33; color:#0a0a0a; }
  .btn:disabled { opacity:0.3; cursor:wait; }
  .result {
    margin-top:16px; padding:14px; background:#050f05; border:1px solid #1a3a1a;
    font-size:12px; line-height:1.6; display:none; white-space:pre-wrap;
  }
  .result.ok { border-color:#33ff33; }
  .result.err { border-color:#ff3333; color:#ff3333; }
  .chain-info { margin-top:30px; width:100%; max-width:700px; border-top:1px solid #1a3a1a; padding-top:20px; }
  .chain-info h3 { font-size:11px; color:#1a8a1a; letter-spacing:2px; margin-bottom:10px; }
  .entry-row { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid #0d1a0d; font-size:11px; }
  .entry-id { color:#00ffcc; } .entry-author { color:#ffaa00; }
  .entry-type { color:#1a8a1a; } .entry-time { color:#0d5a0d; }
  .stat { display:inline-block; margin-right:20px; margin-bottom:8px; }
  .stat .val { color:#33ff33; font-size:18px; }
  .stat .lbl { color:#1a8a1a; font-size:9px; letter-spacing:1px; }
</style>
</head><body>
<div class="banner">
  <h1>IDIT</h1>
  <div class="sub">YOUR LIFE, HASH-LINKED AND SIGNED</div>
</div>
<div class="mint-box">
  <h2>[ MINT TO CHAIN ]</h2>
  <div class="field">
    <label>SIGNER</label>
    <input type="text" id="signer" placeholder="your-name" value="">
  </div>
  <div class="field">
    <label>TYPE</label>
    <select id="etype">
      <option value="note">Note</option>
      <option value="memory">Memory</option>
      <option value="decision">Decision</option>
      <option value="milestone">Milestone</option>
      <option value="document">Document</option>
      <option value="photo">Photo Reference</option>
      <option value="letter">Letter</option>
      <option value="feeling">Feeling</option>
      <option value="morning_report">Morning Report</option>
      <option value="battle_plan">Battle Plan</option>
      <option value="seal">Seal</option>
    </select>
  </div>
  <div class="field">
    <label>DESCRIPTION</label>
    <input type="text" id="desc" placeholder="Brief description...">
  </div>
  <div class="field">
    <label>CONTENT</label>
    <textarea id="content" placeholder="Write something permanent..."></textarea>
  </div>
  <button class="btn" id="mintBtn" onclick="doMint()">// MINT</button>
  <div class="result" id="result"></div>
</div>
<div class="chain-info">
  <h3>[ CHAIN STATUS ]</h3>
  <div id="chainStats"></div>
  <h3 style="margin-top:16px;">[ RECENT ENTRIES ]</h3>
  <div id="recentEntries"></div>
</div>
<script>
async function doMint() {
  const btn = document.getElementById('mintBtn');
  const res = document.getElementById('result');
  btn.disabled = true; btn.textContent = '// MINTING...';
  res.style.display = 'none';
  try {
    const body = {
      content: document.getElementById('content').value,
      signer: document.getElementById('signer').value,
      entry_type: document.getElementById('etype').value,
      description: document.getElementById('desc').value,
      node: 'local', model: '',
    };
    if (!body.signer || !body.content) throw new Error('Signer and content required');
    const r = await fetch('/mint', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.detail || 'Mint failed');
    res.className = 'result ok'; res.style.display = 'block';
    res.textContent = 'MINTED\\n\\n  Entry ID:  ' + d.entry_id + '\\n  Hash:      ' + d.entry_hash + '\\n  Signed by: ' + body.signer + '\\n  Timestamp: ' + d.created_at;
    document.getElementById('content').value = '';
    document.getElementById('desc').value = '';
    loadChain();
  } catch(e) {
    res.className = 'result err'; res.style.display = 'block';
    res.textContent = 'ERROR: ' + e.message;
  }
  btn.disabled = false; btn.textContent = '// MINT';
}
function esc(s) { var d=document.createElement('div'); d.textContent=s; return d.innerHTML; }
async function loadChain() {
  try {
    const [statsR, chainR] = await Promise.all([fetch('/chain/stats'), fetch('/chain?limit=5')]);
    const stats = await statsR.json(); const chain = await chainR.json();
    document.getElementById('chainStats').innerHTML =
      '<div class="stat"><div class="val">' + parseInt(stats.length||0) + '</div><div class="lbl">BLOCKS</div></div>' +
      '<div class="stat"><div class="val">' + Object.keys(stats.authors||{}).length + '</div><div class="lbl">SIGNERS</div></div>';
    document.getElementById('recentEntries').innerHTML = (chain.entries||[]).map(function(e) {
      var meta = typeof e.metadata === 'string' ? JSON.parse(e.metadata) : e.metadata;
      return '<div class="entry-row"><span class="entry-id">' + esc(e.entry_id||'') + '</span><span class="entry-type">' + esc(meta.entry_type||'?') + '</span><span class="entry-author">' + esc(meta.author_id||'?') + '</span><span class="entry-time">' + esc((e.created_at||'').substring(0,19)) + '</span></div>';
    }).join('');
  } catch(e) { console.error(e); }
}
loadChain(); setInterval(loadChain, 15000);
</script>
</body></html>"""
