#!/usr/bin/env python3
import sys
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

REPO_OUT_DIR = Path("out/repo")
PRIV_KEY_PATH = Path("configs/keys/repo-priv.pem")
CHUNK_SIZE = 131072  # 128KB
MAX_CONCURRENT_DOWNLOADS = 16

#TUI helpers
def print_msg(msg: str):
    print(f"\033[1;36m==>\033[0m \033[1m{msg}\033[0m")

def print_warn(msg: str):
    print(f"\033[1;33m==> WARNING:\033[0m \033[1m{msg}\033[0m")

def print_err(msg: str):
    print(f"\033[1;31m==> ERROR:\033[0m \033[1m{msg}\033[0m")
    sys.exit(1)

#DB ops
def get_db_path(repo_name: str) -> Path:
    return REPO_OUT_DIR / f"{repo_name}.db"

def init_repo(repo_name: str) -> Path:
    db_path = get_db_path(repo_name)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    with sqlite3.connect(db_path, timeout=15.0) as conn:
        conn.executescript("""
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            
            CREATE TABLE IF NOT EXISTS packages (
                name TEXT, version TEXT, repo TEXT, type TEXT, license TEXT, sources TEXT,
                hashes TEXT, depends TEXT, makedepends TEXT, build_script TEXT,
                pre_install TEXT, post_install TEXT, pre_remove TEXT, post_remove TEXT,
                architecture TEXT, provides TEXT, conflicts TEXT, obsoletes TEXT, subpackages TEXT,
                PRIMARY KEY (name, version, repo)
            );
            CREATE INDEX IF NOT EXISTS idx_pkg_name ON packages(name);
            CREATE TABLE IF NOT EXISTS repo_meta (id INTEGER PRIMARY KEY, updated_at INTEGER);
        """)
    return db_path

def sign_database(repo_name: str):
    db_path = get_db_path(repo_name)
    sig_path = REPO_OUT_DIR / f"{repo_name}.db.sig"

    print_msg(f"Cryptographically signing {repo_name}.db...")
    
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT OR REPLACE INTO repo_meta (id, updated_at) VALUES (1, strftime('%s', 'now'))")
    conn.commit()
    conn.close() 

    res = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(PRIV_KEY_PATH), "-out", str(sig_path), str(db_path)], capture_output=True)
    if res.returncode != 0:
        print_err(f"Failed to sign repository database: {res.stderr.decode()}")

async def fetch_and_hash_mirrors(session: aiohttp.ClientSession, source_string: str, sem: asyncio.Semaphore) -> str:
    mirrors = [u.strip() for u in source_string.split('|')]
    
    for url in mirrors:
        async with sem:
            print_msg(f"Fetching header/hash for {url}...")
            hasher = hashlib.sha256()
            try:
                timeout = aiohttp.ClientTimeout(total=None, connect=15, sock_read=15)
                
                async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                    resp.raise_for_status()
                    async for chunk in resp.content.iter_chunked(CHUNK_SIZE):
                        hasher.update(chunk)
                        
                digest = hasher.hexdigest()
                print(f"\033[1;32m  [HASH]\033[0m {digest}")
                return digest
                
            except asyncio.TimeoutError:
                print_warn(f"Mirror timeout ({url})")
            except aiohttp.ClientError as e:
                print_warn(f"Mirror unreachable ({url}): {e}")
            except Exception as e:
                print_warn(f"Unexpected IO error ({url}): {e}")
                
    print_err(f"Network fetch failed. All mirrors exhausted for: {source_string}")

async def batch_process_packages(repo_name: str, bh_files: list[Path]):
    db_path = init_repo(repo_name)
    packages_to_insert = []
    
    connector = aiohttp.TCPConnector(limit=32, ttl_dns_cache=300)
    headers = {"User-Agent": "bhpkg/1.0 (Blackhole OS Builder) aiohttp"}
    sem = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)
    
    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        for bh_file_path in bh_files:
            if not bh_file_path.exists():
                print_warn(f"Package definition not found, skipping: {bh_file_path}")
                continue
            
            print_msg(f"Parsing [{repo_name}] {bh_file_path.name}...")
            with open(bh_file_path, "rb") as f:
                data = tomllib.load(f)

            name = data.get("name")
            version = data.get("version")
            sources = data.get("sources", [])
            provided_hashes = data.get("hashes", [])
            scripts = data.get("scripts", {})
            subpkg_data = data.get("subpackages", {})
            
            if not all([name, version, sources, scripts.get("build")]):
                print_err(f"Package TOML '{bh_file_path.name}' is missing required core fields.")

            hash_tasks = []
            hashes = []
            
            for i, url_str in enumerate(sources):
                if i < len(provided_hashes):
                    hashes.append(provided_hashes[i])
                    print(f"\033[1;32m  [SKIP]\033[0m Offline hash applied for source {i+1}")
                else:
                    hash_tasks.append(fetch_and_hash_mirrors(session, url_str, sem))
            
            if hash_tasks:
                fetched_hashes = await asyncio.gather(*hash_tasks)
                hashes.extend(fetched_hashes)

            subpkg_str = "|".join([f"{k}:{','.join(v)}" for k, v in subpkg_data.items()])

            packages_to_insert.append((
                name, version, repo_name, 
                data.get("type", "source"), data.get("license", "Unknown"),
                ",".join(sources), ",".join(hashes),
                data.get("depends", ""), data.get("makedepends", ""),
                scripts.get("build", ""), scripts.get("pre_install", ""), scripts.get("post_install", ""),
                scripts.get("pre_remove", ""), scripts.get("post_remove", ""),
                data.get("architecture", "any"), data.get("provides", ""), 
                data.get("conflicts", ""), data.get("obsoletes", ""),
                subpkg_str
            ))

    if packages_to_insert:
        print_msg(f"Committing {len(packages_to_insert)} package(s) to {repo_name}.db...")
        with sqlite3.connect(db_path, timeout=15.0) as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO packages 
                (name, version, repo, type, license, sources, hashes, depends, makedepends, 
                build_script, pre_install, post_install, pre_remove, post_remove, 
                architecture, provides, conflicts, obsoletes, subpackages) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, packages_to_insert)
            
        print(f"\033[1;32m  [PASS]\033[0m Batch injection completed.")

def main():
    if len(sys.argv) < 2:
        print("\033[1;36mBlackholeOS Repository Builder (bh-builder)\033[0m")
        print("Usage:\n  bh-builder init <repo>\n  bh-builder add <repo> <pkg.bh> [pkg2.bh ...]\n  bh-builder sign <repo>")
        sys.exit(0)

    cmd = sys.argv[1]
    
    if cmd == "init" and len(sys.argv) >= 3:
        init_repo(sys.argv[2])
        
    elif cmd == "add" and len(sys.argv) >= 4:
        repo_name = sys.argv[2]
        target_files = [Path(f) for f in sys.argv[3:]]
        
        try:
            asyncio.run(batch_process_packages(repo_name, target_files))
        except KeyboardInterrupt:
            print_err("Operation aborted by user.")
            
    elif cmd == "sign" and len(sys.argv) >= 3:
        sign_database(sys.argv[2])
        
    else:
        print_err("Invalid arguments. Run without arguments for help.")

if __name__ == "__main__":
    main()