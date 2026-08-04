"""Generate a throwaway deployer keypair for testnet use.

    python scripts/gen_wallet.py

Writes ``DEPLOYER_PRIVATE_KEY`` into ``.env`` (git-ignored) and prints the address to fund.

This key controls nothing except test-network gas. It is generated fresh here precisely so that
no real wallet is ever involved: fund it from a faucet, deploy with it, and throw it away. Never
put a key that holds anything you care about into a repository .env, this one included.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import REPO_ROOT  # noqa: E402

ENV_PATH = REPO_ROOT / ".env"
KEY_NAME = "DEPLOYER_PRIVATE_KEY"


def upsert_env(name: str, value: str) -> None:
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    for i, line in enumerate(lines):
        if line.startswith(f"{name}="):
            lines[i] = f"{name}={value}"
            break
    else:
        lines.append(f"{name}={value}")
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    from eth_account import Account

    existing = ""
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{KEY_NAME}=") and len(line.split("=", 1)[1].strip()) > 10:
                existing = line.split("=", 1)[1].strip()

    if existing:
        account = Account.from_key(existing)
        print(f"A deployer key already exists in .env\n\n  address  {account.address}\n")
        print("Delete the DEPLOYER_PRIVATE_KEY line from .env to generate a new one.")
        return 0

    account = Account.create()
    upsert_env(KEY_NAME, account.key.hex())

    print("Generated a throwaway deployer keypair and wrote it to .env\n")
    print(f"  address  {account.address}\n")
    print("Fund it with Sepolia test ETH, then deploy:\n")
    print("  1. Paste the address above into a Sepolia faucet, for example:")
    print("       https://sepoliafaucet.com")
    print("       https://www.alchemy.com/faucets/ethereum-sepolia")
    print("     A small amount is plenty; deployment plus a few transactions costs very little.")
    print("  2. cd contracts && npm run deploy:sepolia\n")
    print("This key holds nothing but test gas. Do not reuse it for anything real.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
