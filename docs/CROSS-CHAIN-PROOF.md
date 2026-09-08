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
