"""Top up the agent wallets from the deployer.

    python scripts/fund_agents.py                      # dry run: report balances, change nothing
    python scripts/fund_agents.py --confirm            # send the transfers
    python scripts/fund_agents.py --amount 0.02 --confirm
    python scripts/fund_agents.py --roles triage,verifier --confirm

Each agent role signs its own transactions -- that is the point of the registry, and it is why a
decision carries the identity of the agent that made it rather than one shared key. The cost is
that six wallets need gas, and a wallet that runs dry fails the anchor with
``insufficient funds for gas * price + value`` while every other part of the system keeps working.
That failure is invisible unless you go looking, which is exactly how it is usually found.

This sends real transactions on whatever network the deployment names. It is a dry run by default
and requires ``--confirm`` to move anything. On Sepolia the balances involved are test ETH from a
faucet and have no monetary value; on any other network, read the plan before confirming.

Stdout is ASCII: the Windows console is cp1252.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.blockchain.client import EXPLORERS, ChainClient, load_deployment  # noqa: E402

#: A plain value transfer is always 21000 gas. Nothing here calls a contract.
TRANSFER_GAS = 21_000

#: Skip a wallet already holding at least this much -- topping up a funded wallet wastes gas and
#: makes the run non-idempotent.
DEFAULT_FLOOR_ETH = 0.005

#: Enough for roughly 25 anchors at the ~0.0004 ETH per transaction observed on Sepolia.
DEFAULT_AMOUNT_ETH = 0.01


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", action="store_true", help="required; sends transactions")
    parser.add_argument(
        "--amount",
        type=float,
        default=DEFAULT_AMOUNT_ETH,
        help=f"ETH to bring each wallet up to (default {DEFAULT_AMOUNT_ETH})",
    )
    parser.add_argument(
        "--floor",
        type=float,
        default=DEFAULT_FLOOR_ETH,
        help=f"skip wallets already at or above this (default {DEFAULT_FLOOR_ETH})",
    )
    parser.add_argument("--roles", default="", help="comma-separated subset; default is all")
    args = parser.parse_args()

    deployment = load_deployment()
    if not deployment:
        print("no deployment recorded; run the contract deploy first", file=sys.stderr)
        return 1

    key = os.getenv("DEPLOYER_PRIVATE_KEY", "")
    if not key:
        print("DEPLOYER_PRIVATE_KEY is not set in .env", file=sys.stderr)
        return 1

    client = ChainClient.connect()
    if not client.available:
        print(f"chain unavailable: {client.unavailable_reason}", file=sys.stderr)
        return 1

    from eth_account import Account

    w3 = client._w3  # noqa: SLF001 - this script is part of the chain tooling
    deployer = Account.from_key(key)

    wanted = [r.strip() for r in args.roles.split(",") if r.strip()]
    targets = {
        role: account.address
        for role, account in client._accounts.items()  # noqa: SLF001
        if role != "rogue" and (not wanted or role in wanted)
    }
    if not targets:
        print("no matching agent roles", file=sys.stderr)
        return 1

    network = deployment.get("network", "unknown")
    target_wei = w3.to_wei(args.amount, "ether")
    floor_wei = w3.to_wei(args.floor, "ether")
    gas_price = w3.eth.gas_price

    print(f"network        {network} (chainId {deployment.get('chainId')})")
    print(f"deployer       {deployer.address}")
    deployer_balance = w3.eth.get_balance(deployer.address)
    print(f"deployer holds {w3.from_wei(deployer_balance, 'ether'):.6f} ETH")
    print(f"gas price      {w3.from_wei(gas_price, 'gwei'):.2f} gwei\n")

    print(f"{'role':16s} {'address':44s} {'balance':>10s} {'top-up':>10s}")
    print("-" * 84)

    plan: list[tuple[str, str, int]] = []
    for role, address in sorted(targets.items()):
        balance = w3.eth.get_balance(address)
        if balance >= floor_wei:
            print(f"{role:16s} {address:44s} {w3.from_wei(balance, 'ether'):10.6f} {'skip':>10s}")
            continue
        top_up = target_wei - balance
        plan.append((role, address, top_up))
        print(
            f"{role:16s} {address:44s} {w3.from_wei(balance, 'ether'):10.6f} "
            f"{w3.from_wei(top_up, 'ether'):10.6f}"
        )
    print("-" * 84)

    if not plan:
        print("\nevery wallet is already above the floor; nothing to do.")
        return 0

    total = sum(amount for _, _, amount in plan)
    fees = TRANSFER_GAS * gas_price * len(plan)
    print(f"\n{len(plan)} transfer(s), {w3.from_wei(total, 'ether'):.6f} ETH plus "
          f"{w3.from_wei(fees, 'ether'):.6f} ETH in fees")

    if deployer_balance < total + fees:
        print(
            f"deployer holds {w3.from_wei(deployer_balance, 'ether'):.6f} ETH but the plan needs "
            f"{w3.from_wei(total + fees, 'ether'):.6f} ETH",
            file=sys.stderr,
        )
        return 1

    if not args.confirm:
        print("\ndry run; nothing was sent. Re-run with --confirm to execute.")
        return 2

    base = EXPLORERS.get(deployment.get("chainId") or 0, "")
    nonce = w3.eth.get_transaction_count(deployer.address)
    failures = 0

    for role, address, amount in plan:
        try:
            tx = {
                "to": address,
                "value": amount,
                "gas": TRANSFER_GAS,
                "gasPrice": gas_price,
                "nonce": nonce,
                "chainId": w3.eth.chain_id,
            }
            signed = deployer.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
            nonce += 1
            digest = tx_hash.hex()
            digest = digest if digest.startswith("0x") else f"0x{digest}"
            status = "ok" if receipt["status"] == 1 else "REVERTED"
            print(f"{role:16s} {status:9s} block {receipt['blockNumber']}  {digest}")
            if base:
                print(f"                 {base}/tx/{digest}")
            if receipt["status"] != 1:
                failures += 1
        except Exception as exc:  # noqa: BLE001 - one bad transfer must not strand the rest
            failures += 1
            print(f"{role:16s} FAILED    {type(exc).__name__}: {exc}"[:160], file=sys.stderr)

    print()
    for role, address in sorted(targets.items()):
        print(f"{role:16s} {w3.from_wei(w3.eth.get_balance(address), 'ether'):.6f} ETH")

    if failures:
        print(f"\n{failures} transfer(s) did not succeed.", file=sys.stderr)
        return 1
    print("\nall wallets funded. Re-run the anchor from the Proof tab.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
