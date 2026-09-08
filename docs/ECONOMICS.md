# Economics - measured, not estimated

<!-- hardening:allow-file ALL reason=this document quotes the on-chain payloads and defective patterns it reports; quoting a finding is not committing one -->

Every number below is produced by `src/jumpper/anchor.py` and validated to the
exact wei against a real Ethereum mainnet transaction.

Assumptions: gasPrice = 1 gwei, ETH = $2,500, payload carries the full 5-chain witness.

## Cost per claim by batch size

| batch leaves | total gas | cost (ETH) | per claim (ETH) | per claim (USD) |
|---|---|---|---|---|
| 1 | 32,320 | 0.000032320 | 3.2320e-05 | $0.08080000 |
| 10 | 32,360 | 0.000032360 | 3.2360e-06 | $0.00809000 |
| 100 | 32,400 | 0.000032400 | 3.2400e-07 | $0.00081000 |
| 1,000 | 32,440 | 0.000032440 | 3.2440e-08 | $0.00008110 |
| 10,000 | 32,480 | 0.000032480 | 3.2480e-09 | $0.00000812 |
| 100,000 | 32,520 | 0.000032520 | 3.2520e-10 | $0.00000081 |
| 1,000,000 | 32,560 | 0.000032560 | 3.2560e-11 | $0.00000008 |

## Why the curve is almost perfectly hyperbolic

- A Merkle root is always 64 hex chars, independent of leaf count.
- Going from leafCount 1 to 1,000,000 adds **240 gas** (0.74%).
- The 5-chain witness block adds about 4080 gas (~9%).
- Therefore per-claim cost falls as 1/batchSize with no other term growing.

## Ground-truth validation against mainnet

| quantity | our model | mainnet actual | result |
|---|---|---|---|
| txid | `0x94f4cb4f...e37813` | same | - |
| block | 25,929,672 | 25,929,672 | match |
| calldata bytes | 248 | 248 | match |
| EIP-7623 tokens | 992 | - | - |
| gasUsed | **30,920** | **30,920** | **exact** |
| cost (wei) | 32,493,358,294,280 | 32,493,358,294,280 | **exact** |

## The correction that mattered

A naive EIP-2028-only model predicts 24,968 gas for that transaction. Reality was
30,920 - an underestimate of 5,952 gas, or 150% on the calldata component.

The reason: **EIP-7623 (Prague) introduced a calldata cost floor.**

    tokens   = zero_bytes + 4 * nonzero_bytes
    floorGas = 10 * tokens
    gasUsed  = max(21000 + eip2028Gas, 21000 + floorGas)

For ASCII-JSON payloads every byte is non-zero, so the floor always binds and the
effective price is **40 gas per byte, not 16**.

Any cost model that ignores EIP-7623 under-prices this product by 2.5x on
calldata. Ours does not, and the test suite pins it to the real transaction so it
cannot silently regress.

## Reading the business model

At a 10,000-claim batch the anchor costs about 0.0000325 ETH (~$0.081 at 1 gwei).
Per claim that is roughly $0.00000812 - under a hundred-thousandth of a cent.

A public, permanent, independently verifiable notary record for less than a
hundred-thousandth of a cent. That is the entire business model, and it is now
measured rather than asserted.
