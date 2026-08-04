"""web3.py client for the AgentRegistry / DecisionProof pair.

Reads ``artifacts/chain/deployment.json`` — addresses and ABIs — so nothing about the chain is
hard-coded on the Python side and a redeploy needs no code change.

**It degrades rather than dies.** If no deployment file exists, or the RPC is unreachable, the
client reports itself unavailable and every call returns a recorded no-op instead of raising.
§13.3 lists "network or model API failure during judging" as a risk whose mitigation is a local
fallback: an unreachable testnet must downgrade the proof panel, not take the demo down in front
of judges.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.config import ARTIFACTS

CHAIN_DIR = ARTIFACTS / "chain"
DEPLOYMENT_FILE = CHAIN_DIR / "deployment.json"

#: Solidity enum order in DecisionProof.
RISK_TO_ENUM = {"low": 0, "medium": 1, "high": 2}
ENUM_TO_RISK = {v: k for k, v in RISK_TO_ENUM.items()}
STATE_NAMES = {0: "proposed", 1: "approved", 2: "rejected", 3: "finalized"}

EXPLORERS = {11155111: "https://sepolia.etherscan.io"}


class ChainUnavailable(RuntimeError):
    """Raised only by callers that explicitly demand a chain; the client itself degrades."""


@dataclass
class AnchorResult:
    """What happened when a decision was anchored. ``anchored`` false is a normal outcome."""

    anchored: bool
    decision_id: int | None = None
    tx_hash: str = ""
    block_number: int | None = None
    agent_address: str = ""
    chain_id: int | None = None
    contract_address: str = ""
    gas_used: int | None = None
    reason: str = ""
    #: Decoded Solidity custom error name, e.g. ``ApprovalRequired``. Empty when the failure was
    #: not a contract revert.
    error: str = ""

    @property
    def blocked_by_policy(self) -> bool:
        """True when the *contract* refused, rather than something going wrong.

        A high-risk decision failing to finalise is the control working, not an error, and the
        demo needs to say so in those words.
        """
        return self.error in {"ApprovalRequired", "DecisionWasRejected", "UnauthorisedAgent"}

    @property
    def explorer_url(self) -> str:
        base = EXPLORERS.get(self.chain_id or 0)
        return f"{base}/tx/{self.tx_hash}" if base and self.tx_hash else ""

    def as_dict(self) -> dict:
        return {
            "anchored": self.anchored,
            "decision_id": self.decision_id,
            "tx_hash": self.tx_hash,
            "block_number": self.block_number,
            "agent_address": self.agent_address,
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "gas_used": self.gas_used,
            "explorer_url": self.explorer_url,
            "reason": self.reason,
            "error": self.error,
            "blocked_by_policy": self.blocked_by_policy,
        }


def load_deployment(path: str | Path = DEPLOYMENT_FILE) -> dict | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


@dataclass
class ChainClient:
    """Anchor decisions, record approvals, finalise, and verify."""

    deployment: dict | None = None
    rpc_url: str = ""
    _w3: Any = None
    _registry: Any = None
    _proof: Any = None
    _accounts: dict[str, Any] = field(default_factory=dict)
    _error_selectors: dict[str, str] = field(default_factory=dict)
    unavailable_reason: str = ""

    @classmethod
    def connect(
        cls, deployment_path: str | Path = DEPLOYMENT_FILE, rpc_url: str = ""
    ) -> "ChainClient":
        deployment = load_deployment(deployment_path)
        if deployment is None:
            return cls(
                unavailable_reason=(
                    f"no deployment at {deployment_path}; run contracts/scripts/deploy.ts"
                )
            )

        url = rpc_url or cls._default_rpc(deployment)
        try:
            from web3 import Web3

            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 10}))
            if not w3.is_connected():
                return cls(deployment=deployment, unavailable_reason=f"RPC unreachable at {url}")
        except Exception as exc:  # noqa: BLE001 - any transport problem is "unavailable"
            return cls(deployment=deployment, unavailable_reason=f"{type(exc).__name__}: {exc}")

        client = cls(deployment=deployment, rpc_url=url, _w3=w3)
        client._bind()
        return client

    @staticmethod
    def _default_rpc(deployment: dict) -> str:
        import os

        chain_id = deployment.get("chainId")
        if chain_id == 11155111:
            return os.getenv("SEPOLIA_RPC_URL", "https://ethereum-sepolia-rpc.publicnode.com")
        return os.getenv("LOCAL_RPC_URL", "http://127.0.0.1:8545")

    def _build_error_selectors(self) -> dict[str, str]:
        """Map 4-byte selector -> custom error name, from the deployed ABIs.

        Public RPC providers return the raw revert data rather than a decoded name, so a
        ``ApprovalRequired`` revert arrives as ``0xb0be42d3…``. Matching on the *name* appearing
        in an exception string works against a local Hardhat node and silently stops working on a
        real testnet — which is exactly where the "the contract refused" moment gets demonstrated.
        """
        from eth_utils import function_signature_to_4byte_selector

        selectors: dict[str, str] = {}
        for contract in (self.deployment or {}).get("contracts", {}).values():
            for entry in contract.get("abi", []):
                if entry.get("type") != "error":
                    continue
                types = ",".join(i["type"] for i in entry.get("inputs", []))
                signature = f"{entry['name']}({types})"
                selector = function_signature_to_4byte_selector(signature).hex()
                selectors["0x" + selector.removeprefix("0x")] = entry["name"]
        return selectors

    def _decode_error(self, message: str) -> str:
        """Pull a custom error name out of whatever the provider gave us."""
        for selector, name in self._error_selectors.items():
            if selector in message.lower():
                return name
        # Some providers do decode it; fall back to a name match.
        for name in self._error_selectors.values():
            if name in message:
                return name
        return ""

    def _bind(self) -> None:
        from eth_account import Account

        contracts = self.deployment["contracts"]
        self._registry = self._w3.eth.contract(
            address=self._w3.to_checksum_address(contracts["AgentRegistry"]["address"]),
            abi=contracts["AgentRegistry"]["abi"],
        )
        self._proof = self._w3.eth.contract(
            address=self._w3.to_checksum_address(contracts["DecisionProof"]["address"]),
            abi=contracts["DecisionProof"]["abi"],
        )
        for role, key in (self.deployment.get("agentKeys") or {}).items():
            self._accounts[role] = Account.from_key(key)
        rogue = self.deployment.get("rogue") or {}
        if rogue.get("privateKey"):
            self._accounts["rogue"] = Account.from_key(rogue["privateKey"])

        self._error_selectors = self._build_error_selectors()

    # --- status ------------------------------------------------------------------------

    @property
    def available(self) -> bool:
        return self._proof is not None

    @property
    def chain_id(self) -> int | None:
        return (self.deployment or {}).get("chainId")

    @property
    def contract_address(self) -> str:
        if not self.deployment:
            return ""
        return self.deployment["contracts"]["DecisionProof"]["address"]

    def status(self) -> dict:
        return {
            "available": self.available,
            "reason": self.unavailable_reason,
            "network": (self.deployment or {}).get("network", ""),
            "chain_id": self.chain_id,
            "rpc_url": self.rpc_url,
            "registry_address": (
                self.deployment["contracts"]["AgentRegistry"]["address"]
                if self.deployment
                else ""
            ),
            "decision_proof_address": self.contract_address,
            "agents": (self.deployment or {}).get("agents", {}),
        }

    # --- writes ------------------------------------------------------------------------

    def _send(self, function, account) -> tuple[str, int, int]:
        tx = function.build_transaction(
            {
                "from": account.address,
                "nonce": self._w3.eth.get_transaction_count(account.address),
                "chainId": self._w3.eth.chain_id,
            }
        )
        signed = account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        return tx_hash.hex(), receipt["blockNumber"], receipt["gasUsed"]

    @staticmethod
    def _to_bytes32(digest: str) -> bytes:
        return bytes.fromhex(digest[2:] if digest.startswith("0x") else digest)

    def submit_decision(
        self,
        incident_id: str,
        evidence_hash: str,
        output_hash: str,
        label: str,
        risk: str,
        agent_role: str = "triage",
    ) -> AnchorResult:
        """Anchor a decision. Never raises — an unavailable chain is a reported outcome."""
        if not self.available:
            return AnchorResult(anchored=False, reason=self.unavailable_reason or "no chain")

        account = self._accounts.get(agent_role)
        if account is None:
            return AnchorResult(anchored=False, reason=f"no key for agent role {agent_role!r}")

        try:
            fn = self._proof.functions.submitDecision(
                incident_id,
                self._to_bytes32(evidence_hash),
                self._to_bytes32(output_hash),
                label,
                RISK_TO_ENUM.get(risk, 2),
            )
            tx_hash, block, gas = self._send(fn, account)
            decision_id = self._proof.functions.findByFingerprint(
                incident_id,
                self._to_bytes32(evidence_hash),
                self._to_bytes32(output_hash),
            ).call()
            return AnchorResult(
                anchored=True,
                decision_id=int(decision_id),
                tx_hash=tx_hash if tx_hash.startswith("0x") else f"0x{tx_hash}",
                block_number=block,
                gas_used=gas,
                agent_address=account.address,
                chain_id=self.chain_id,
                contract_address=self.contract_address,
            )
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            return AnchorResult(
                anchored=False, reason=message, error=self._decode_error(message)
            )

    def approve_decision(
        self, decision_id: int, approved: bool, comment_hash: str, approver_role: str = "verifier"
    ) -> AnchorResult:
        if not self.available:
            return AnchorResult(anchored=False, reason=self.unavailable_reason or "no chain")
        account = self._accounts.get(approver_role)
        if account is None:
            return AnchorResult(anchored=False, reason=f"no key for role {approver_role!r}")
        try:
            fn = self._proof.functions.approveDecision(
                decision_id, approved, self._to_bytes32(comment_hash)
            )
            tx_hash, block, gas = self._send(fn, account)
            return AnchorResult(
                anchored=True,
                decision_id=decision_id,
                tx_hash=tx_hash if tx_hash.startswith("0x") else f"0x{tx_hash}",
                block_number=block,
                gas_used=gas,
                agent_address=account.address,
                chain_id=self.chain_id,
                contract_address=self.contract_address,
            )
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            return AnchorResult(
                anchored=False, reason=message, error=self._decode_error(message)
            )

    def finalize_decision(self, decision_id: int, agent_role: str = "triage") -> AnchorResult:
        """Finalise. A high-risk decision without approval reverts — that is the control."""
        if not self.available:
            return AnchorResult(anchored=False, reason=self.unavailable_reason or "no chain")
        account = self._accounts.get(agent_role)
        if account is None:
            return AnchorResult(anchored=False, reason=f"no key for role {agent_role!r}")
        try:
            tx_hash, block, gas = self._send(
                self._proof.functions.finalizeDecision(decision_id), account
            )
            return AnchorResult(
                anchored=True,
                decision_id=decision_id,
                tx_hash=tx_hash if tx_hash.startswith("0x") else f"0x{tx_hash}",
                block_number=block,
                gas_used=gas,
                agent_address=account.address,
                chain_id=self.chain_id,
                contract_address=self.contract_address,
            )
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            return AnchorResult(
                anchored=False, reason=message, error=self._decode_error(message)
            )

    # --- reads -------------------------------------------------------------------------

    def get_decision(self, decision_id: int) -> dict | None:
        if not self.available:
            return None
        try:
            d = self._proof.functions.getDecision(decision_id).call()
        except Exception:  # noqa: BLE001
            return None
        return {
            "incident_id": d[0],
            "evidence_hash": "0x" + d[1].hex(),
            "output_hash": "0x" + d[2].hex(),
            "label": d[3],
            "risk": ENUM_TO_RISK.get(d[4], "unknown"),
            "state": STATE_NAMES.get(d[5], "unknown"),
            "agent": d[6],
            "approver": d[7],
            "comment_hash": "0x" + d[8].hex(),
            "submitted_at": d[9],
            "decided_at": d[10],
            "finalized_at": d[11],
        }

    def verify(self, decision_id: int, evidence_hash: str, output_hash: str) -> bool | None:
        """On-chain recompute-and-compare. ``None`` means the chain could not answer."""
        if not self.available:
            return None
        try:
            return bool(
                self._proof.functions.verify(
                    decision_id,
                    self._to_bytes32(evidence_hash),
                    self._to_bytes32(output_hash),
                ).call()
            )
        except Exception:  # noqa: BLE001
            return None
