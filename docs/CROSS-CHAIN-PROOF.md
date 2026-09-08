# Cross-Chain Proof - the same commitment on two mainnets

U-01 asked whether the 27 Solana anchors landed on mainnet or devnet. Nobody
could tell, because the ledger records no network identifier and no endpoint host.

Read directly from Solana mainnet on 2026-09-08 via solana-rpc.publicnode.com:

> They are on mainnet. The anchor is real and it succeeded.

The full transaction identifiers, signature, memo text, state root and digest are
recorded as constants in `tests/test_crosschain.py` and in
`src/jumpper/solana.py`, so they are not repeated here.

## Measured facts

    slot        445225030
    blockTime   1788834653
    err         null                     (success)
    fee         5000 lamports = 0.000005 SOL
    compute     102351 of 200000 units
    program     official SPL Memo
    memo        248 bytes, recorded verbatim in the program log

The memo is recoverable by anyone from the transaction log with a public RPC and
no service of ours.

## It is the SAME commitment as Ethereum

The Ethereum anchor was verified independently earlier: block 25929672, status
0x1, calldata 248 bytes UTF-8 JSON.

Comparing the two payloads field by field - protocol, action, at, height,
stateRoot, digest - all six are byte-identical.

    IDENTICAL ON BOTH CHAINS: True

Same state root, same height, same instant, on two networks that share no
validators, no consensus, no operators and no incentive to coordinate.

`src/jumpper/crosschain.py` implements the comparison and 31 assertions pin it to
the real transactions. On the real data it returns:

    COMMITMENT IDENTICAL ON 2 INDEPENDENT MAINNETS

It refuses that verdict if any witness is not mainnet, did not succeed, or differs
in a single field. `reverify_from_payloads()` compares two payloads with no RPC
access at all, so a third party can confirm equality without trusting us.

## Why this is worth more than two separate anchors

A single-chain anchor answers: did this state exist?

A cross-chain equality proof answers a harder question: was the SAME state
presented to every network, or did the operator tell different chains different
stories?

That is the split-view attack moved from across-monitors to across-chains.
Publishing one root to one chain lets an operator show chain A one history and
chain B another, and no observer of a single chain can ever tell. Publishing the
same root to both, where anyone can compare, turns that into a public
contradiction. The marginal cost of the second chain was 5000 lamports.

---

## What this corrects in the earlier findings

| earlier statement | correction |
|---|---|
| SOL anchored=27, verified=0 reads as 27 failures | **Wrong reading.** The anchors are real and on mainnet. The zero comes entirely from the verifier calling getSignatureStatuses with searchTransactionHistory false, which cannot see past the node cache. One boolean. Rule H-13. |
| U-01 unresolved: mainnet or devnet unknown | **Resolved: mainnet.** Verified from the transaction itself, slot 445225030. |
| The devnet default (F-03) is a live risk | Still real for any run with SOL_RPC_URL unset - the code genuinely defaults to api.devnet.solana.com. It simply did not bite here. Rule H-12 still stands. |

The honest summary: **the system was doing the right thing and reporting it
badly.** That is better than the reverse, and it is worth saying plainly because
the earlier reports made it look like the reverse.

---

## Cost, measured on all three chains

For the identical 248-byte commitment:

| chain | cost | native unit | at market | relative |
|---|---|---|---|---|
| HIVE / STEEM custom_json | **$0.00** | 0 fee, RC only | free | 1x |
| Solana memo | **$0.00075** | 5000 lamports | at $150/SOL | ~108x cheaper than ETH |
| Ethereum calldata | **$0.08123** | 30920 gas at 1.051 gwei | at $2500/ETH | baseline |

Ethereum is 108x more expensive than Solana for the same bytes on a public chain,
and infinitely more expensive than HIVE.

That reorders the tiering:

1. **HIVE / STEEM custom_json** - free, 8192-byte payload, 154 roots per
   operation. Primary. Bounded only by RC, never by money.
2. **Solana memo** - $0.00075, 248 bytes proven. Best paid tier: cheap, fast,
   strong finality.
3. **Ethereum calldata** - $0.081. Reserve for counterparties who accept nothing
   else, or for a low-frequency sovereign settlement root.

---

## Runway

    balance now         23981117 lamports = 0.02398112 SOL
    fee per anchor      5000 lamports
    anchors remaining   4796

The account spent down from 29826117 lamports (the post-balance recorded in the
verified transaction) to 23981117 now, so it is actively anchoring. There is no
immediate funding problem, but the burn is real and unmonitored - which is what
the convert loop in `docs/LIVE-FINDINGS.md` was making worse.

---

## Solana memo size limit - stated honestly

A Solana transaction is capped at 1232 bytes. A single-signer memo transaction
carries a 64-byte signature plus message overhead. The widely quoted SPL Memo
ceiling is 566 bytes. **Neither figure is verified here by construction.** Only
the 248-byte memo above is proven to have landed.

`src/jumpper/solana.py` therefore plans against a 512-byte ceiling and raises
rather than guesses above it:

    memo of 900 bytes exceeds the 512-byte planning budget;
    only 248 bytes is proven to have landed on mainnet

This matters because the HIVE 8192-byte custom_json budget is proven and holds 154
roots, while Solana memo cannot. **The two chains are not interchangeable for
packing.** HIVE is where batching pays; Solana is where a cheap second witness
lives.

---

## Reproducing all of it

    python -m unittest tests.test_crosschain -v      # 31 assertions

Every fixture in that file is real mainnet data: the Ethereum transaction and
receipt, the Solana transaction with its full program log, the 5000-lamport fee,
slot 445225030, block 25929672, and the observed balance.

Or verify it yourself with two public RPC calls and nothing from us: fetch the
Ethereum transaction by hash and the Solana transaction by signature, decode the
calldata as UTF-8, read the memo out of the program log, and compare. Both
identifiers are in `src/jumpper/solana.py` and `tests/test_crosschain.py`.

---

*Read-only throughout. No keys read, no transactions signed, nothing broadcast.*
