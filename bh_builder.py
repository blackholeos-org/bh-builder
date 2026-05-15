#!/usr/bin/env python3
import sys
import os
import sqlite3
import subprocess
import asyncio
import hashlib
import aiohttp
from pathlib import Path

try:
    import tomllib
except ImportError:
    print("==> ERROR: Python 3.11+ is required for the native 'tomllib' module.")
    sys.exit(1)

REPO_DB_PATH = Path("out/repo/sync.db")
REPO_SIG_PATH = Path("out/repo/sync.db.sig")
PRIV_KEY_PATH = Path("configs/keys/repo-priv.pem")

def print_msg(msg: str):
    print(f"\033[1;36m==>\033[0m \033[1m{msg}\033[0m")

def print_err(msg: str):
    print(f"\033[1;31m==> ERROR:\033[0m \033[1m{msg}\033[0m")
    sys.exit(1)

def init_repo():
    REPO_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(REPO_DB_PATH) as conn:
        # Handle schema migration for existing databases
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packages'")
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(packages)")
            columns = [info[1] for info in cursor.fetchall()]
            if "license" not in columns:
                conn.execute("ALTER TABLE packages ADD COLUMN license TEXT DEFAULT 'Unknown'")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS packages (
                name TEXT, version TEXT, repo TEXT, type TEXT, license TEXT, sources TEXT,
                hashes TEXT, depends TEXT, makedepends TEXT, build_script TEXT,
                pre_install TEXT, post_install TEXT, pre_remove TEXT, post_remove TEXT,
                PRIMARY KEY (name, version, repo)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pkg_name ON packages(name)")
        conn.execute("CREATE TABLE IF NOT EXISTS repo_meta (id INTEGER PRIMARY KEY, updated_at INTEGER)")

def sign_database():
    if not PRIV_KEY_PATH.exists():
        print_err(f"Private key not found at {PRIV_KEY_PATH}")
    
    print_msg("Cryptographically signing multi-repo sync.db...")
    with sqlite3.connect(REPO_DB_PATH) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS repo_meta (id INTEGER PRIMARY KEY, updated_at INTEGER)")
        conn.execute("INSERT OR REPLACE INTO repo_meta (id, updated_at) VALUES (1, strftime('%s', 'now'))")

    res = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(PRIV_KEY_PATH), "-out", str(REPO_SIG_PATH), str(REPO_DB_PATH)], capture_output=True)
    if res.returncode != 0:
        print_err(f"Failed to sign repository database: {res.stderr.decode()}")
    print("\033[1;32m  [PASS]\033[0m Repository signed successfully.")

async def fetch_and_hash(session: aiohttp.ClientSession, url: str) -> str:
    print_msg(f"Downloading source from {url} for verification...")
    hasher = hashlib.sha256()
    try:
        async with session.get(url) as resp:
            resp.raise_for_status()
            async for chunk in resp.content.iter_chunked(65536):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        print(f"\033[1;32m  [HASH]\033[0m {digest}")
        return digest
    except Exception as e:
        print_err(f"Network fetch failed for payload: {e}")

async def process_package(repo_name: str, bh_file_path: Path):
    if not bh_file_path.exists():
        print_err(f"Package definition not found: {bh_file_path}")
    
    print_msg(f"Parsing [{repo_name}] {bh_file_path}...")
    with open(bh_file_path, "rb") as f:
        data = tomllib.load(f)

    name = data.get("name")
    version = data.get("version")
    pkg_type = data.get("type", "source")
    license_str = data.get("license", "Unknown")
    depends = data.get("depends", "")
    makedepends = data.get("makedepends", "")
    sources = data.get("sources", [])
    provided_hashes = data.get("hashes", [])
    scripts = data.get("scripts", {})

    build_script = scripts.get("build", "")
    pre_install = scripts.get("pre_install", "")
    post_install = scripts.get("post_install", "")
    pre_remove = scripts.get("pre_remove", "")
    post_remove = scripts.get("post_remove", "")

    if not all([name, version, sources, build_script]):
        print_err("Package TOML is missing required core fields.")

    hashes = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i, url in enumerate(sources):
            if i < len(provided_hashes):
                hashes.append(provided_hashes[i])
                print(f"\033[1;32m  [SKIP]\033[0m Using offline hash for source {i+1}")
            else:
                tasks.append(fetch_and_hash(session, url))
        
        if tasks:
            fetched_hashes = await asyncio.gather(*tasks)
            hashes.extend(fetched_hashes)

    with sqlite3.connect(REPO_DB_PATH) as conn:
        conn.execute("""
            INSERT OR REPLACE INTO packages 
            (name, version, repo, type, license, sources, hashes, depends, makedepends, build_script, pre_install, post_install, pre_remove, post_remove) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, version, repo_name, pkg_type, license_str, ",".join(sources), ",".join(hashes), depends, makedepends, build_script, pre_install, post_install, pre_remove, post_remove))
    print(f"\033[1;32m  [PASS]\033[0m {name} injected into {repo_name} mirror.")

def main():
    if len(sys.argv) < 2:
        print("\033[1;36mBlackholeOS Repository Builder (bh-builder)\033[0m\nUsage:\n  bh-builder init\n  bh-builder add <repo> <pkg.bh>\n  bh-builder sign")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "init":
        init_repo()
    elif cmd == "add":
        if len(sys.argv) < 4: print_err("Specify repo name and package file (.bh)")
        init_repo()
        asyncio.run(process_package(sys.argv[2], Path(sys.argv[3])))
        sign_database()
    elif cmd == "sign":
        sign_database()
    else:
        print_err(f"Unknown command: {cmd}")

if __name__ == "__main__":
    main()