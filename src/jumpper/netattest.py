"""Network attestation: an anchor is not a fact until you can say WHICH network.

Found while reading the live relay adapters in the wider estate. Three separate
defects, all of which let a ledger say "anchored" without being able to prove
where. This module is the structural fix, implemented here so it is testable
rather than advisory. Machine-readable form in findings.json as F-02, F-03, F-04.

------------------------------------------------------------------------------
DEFECT 1 - a verifier that can never succeed (certain, code-level)
------------------------------------------------------------------------------
The Solana verifier calls:

    getSignatureStatuses([[txid], { searchTransactionHistory: false }])

With searchTransactionHistory false the node consults only its in-memory recent
status cache, which holds a limited number of recent slots. Once a signature
ages out the call returns null and the verifier reports "not indexed". The
transaction is permanently on chain; the verifier simply cannot see it.

Consequence: verified is structurally pinned at 0 for any anchor older than a few
minutes. The estate ledger shows solana anchored=27, verified=0. That is not 27
failures. It is a verifier that cannot succeed.

------------------------------------------------------------------------------
DEFECT 2 - a default endpoint that is not the production network
------------------------------------------------------------------------------
    Solana   SOL_RPCS = env.SOL_RPC_URL or ["https://api.devnet.solana.com"]
    Ethereum ETH_RPCS = env.ETH_RPC_URL or ["https://ethereum-rpc.publicnode.com",
                                            "https://eth.llamarpc.com"]

Ethereum falls back to MAINNET. Solana falls back to DEVNET. If the variable is
absent at runtime, Solana anchors land on a test network with worthless tokens
while the ledger records them with exactly the same shape as a mainnet anchor.

This is not a claim that it happened. It is a claim that the code permits it and
that nothing downstream would notice.

------------------------------------------------------------------------------
DEFECT 3 - the ledger cannot attest network (structural)
------------------------------------------------------------------------------
The recorded chain state carries status, lastTxid, lastHeight, lastAt, anchored,
verified, mismatches, breaker. It carries NO network identifier and NO endpoint
host. So "anchored" is a claim about no particular network, and the difference
between mainnet and devnet cannot be recovered after the fact.

------------------------------------------------------------------------------
THE RULE THIS MODULE ENFORCES
------------------------------------------------------------------------------
An anchor may only be recorded as verified on a network if the record states
network, endpointHost (hostname only - never a full URL, because public
endpoints sometimes embed keys in query strings), networkMatchesExpected,
finality, and txid.

Missing any of those, the record is `unproven` - not `verified` and not `failed`.
Unproven is the honest third state: the anchor may well be real, and the ledger
says it cannot tell.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

MAINNET = "mainnet"
DEVNET = "devnet"
TESTNET = "testnet"
UNKNOWN = "unknown"


class NetworkAttestationError(ValueError):
    pass


EXPECTED_MAINNET_HOSTS: Dict[str, List[str]] = {
    "ETHEREUM": ["ethereum-rpc.publicnode.com", "eth.llamarpc.com", "cloudflare-eth.com",
                 "eth.drpc.org", "rpc.ankr.com"],
    "SOLANA": ["api.mainnet-beta.solana.com"],
    "HIVE": ["api.openhive.network", "api.deathwing.me", "api.hive.blog",
             "api.developer.witnesses.lol"],
    "STEEM": ["api.steemit.com", "api.justyy.com", "steem.61bts.com"],
    "TRON": ["api.trongrid.io"],
    "BLURT": ["blurtdrpc.blurt.io"],
}

KNOWN_NONMAINNET_HOSTS: List[str] = [
    "api.devnet.solana.com", "api.testnet.solana.com",
    "sepolia", "goerli", "holesky", "testnet", "devnet",
    "api.shasta.trongrid.io", "api.nileex.io",
]

FINALITY: Dict[str, str] = {
    "ETHEREUM": "finalized", "SOLANA": "finalized",
    "HIVE": "irreversible", "STEEM": "irreversible", "BLURT": "irreversible",
    "TRON": "solidity",
}


def host_of(url: str) -> str:
    """Hostname only. Never store a full RPC URL - keys hide in query strings."""
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def classify_host(chain: str, url_or_host: str) -> str:
    h = host_of(url_or_host) if "://" in url_or_host else url_or_host.lower()
    if not h:
        return UNKNOWN
    for marker in KNOWN_NONMAINNET_HOSTS:
        if marker in h:
            return DEVNET if "devnet" in h or "devnet" in marker else TESTNET
    expected = EXPECTED_MAINNET_HOSTS.get(chain.upper(), [])
    if any(h == e or h.endswith("." + e) for e in expected):
        return MAINNET
    return UNKNOWN


def requires_history_search(chain: str) -> bool:
    """Chains whose signature status is ephemeral unless history is searched."""
    return chain.upper() == "SOLANA"


def correct_solana_params(txid: str) -> Dict[str, Any]:
    """The parameter set that can actually confirm an aged Solana signature."""
    return {"method": "getSignatureStatuses",
            "params": [[txid], {"searchTransactionHistory": True}],
            "note": "searchTransactionHistory must be true; false consults only the "
                    "ephemeral recent-status cache and returns null once the signature "
                    "ages out, pinning verified at 0 forever"}


@dataclass(frozen=True)
class AnchorRecord:
    chain: str
    network: str
    endpoint_host: str
    txid: str
    block_ref: Optional[str]
    finality: str
    root: str
    height: int
    verified: bool

    @property
    def network_matches_expected(self) -> bool:
        return self.network == MAINNET

    @property
    def state(self) -> str:
        """The honest three-state verdict."""
        if not self.verified:
            return "unproven"
        if not self.network_matches_expected:
            return "verified-wrong-network"
        return "verified"

    def as_dict(self) -> Dict[str, Any]:
        return {"chain": self.chain, "network": self.network,
                "endpointHost": self.endpoint_host, "txid": self.txid,
                "blockRef": self.block_ref, "finality": self.finality,
                "root": self.root, "height": self.height, "verified": self.verified,
                "networkMatchesExpected": self.network_matches_expected,
                "state": self.state}


def make_record(chain: str, endpoint_url: str, txid: str, root: str, height: int,
                verified: bool, block_ref: Optional[str] = None) -> AnchorRecord:
    if not txid:
        raise NetworkAttestationError("txid required - an anchor without one is not an anchor")
    if not endpoint_url:
        raise NetworkAttestationError("endpoint required - network cannot be attested without it")
    h = host_of(endpoint_url)
    if not h:
        raise NetworkAttestationError("endpoint did not resolve to a hostname")
    return AnchorRecord(chain=chain.upper(), network=classify_host(chain, h),
                        endpoint_host=h, txid=txid, block_ref=block_ref,
                        finality=FINALITY.get(chain.upper(), "unknown"),
                        root=root, height=height, verified=verified)


def audit_records(records: List[AnchorRecord]) -> Dict[str, Any]:
    """Aggregate honestly. Never counts unproven as verified."""
    counts: Dict[str, int] = {}
    for r in records:
        counts[r.state] = counts.get(r.state, 0) + 1
    nonmainnet = [r for r in records if r.network != MAINNET and r.verified]
    return {"total": len(records),
            "verifiedMainnet": counts.get("verified", 0),
            "unproven": counts.get("unproven", 0),
            "verifiedWrongNetwork": counts.get("verified-wrong-network", 0),
            "nonMainnetHosts": sorted({r.endpoint_host for r in nonmainnet}),
            "verdict": ("all verified anchors are on mainnet" if not nonmainnet
                        else "VERIFIED ANCHORS EXIST ON A NON-MAINNET NETWORK")}
