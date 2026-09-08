# Live Findings - what the chain says the network is actually doing

Read directly from HIVE mainnet on 2026-09-08, read-only, account headcorner.
Sources: condenser_api.get_account_history (100 entries), rc_api.find_rc_accounts,
condenser_api.get_accounts, condenser_api.get_config. Nodes: api.openhive.network
and api.deathwing.me.

The raw history is committed as a test fixture at
tests/fixtures/hive_headcorner_history.json, so every number below is
reproducible and the detectors are validated against the chain rather than
against invented data. 21 assertions are pinned to it.

Nothing here comes from a self-report. Every figure was read off the chain.

---

## What is actually running: six protocols, not one

94 of the last 100 operations are custom_json, across six protocol ids.

| id | count | bytes | authority used | what it does |
|---|---|---|---|---|
| ssc-mainnet-hive | 32 | 7,896 | active (correct) | Hive-Engine sidechain contract calls |
| saos-dex.anchor.v1 | 23 | 8,829 | ACTIVE | Merkle root anchors |
| saos.attest.v1 | 20 | 8,506 | ACTIVE | state root + last block hash + git commit |
| saos.weave.v1 | 11 | 3,916 | ACTIVE | batched seals with count/from/to range |
| saos | 5 | 1,934 | posting (correct) | value_lock records |
| saos.id.v1 | 3 | 1,530 | ACTIVE | identity bound to an EVM address, EIP-191 signed |

Non-custom_json: delegate_vesting_shares 1, fill_convert_request 1, transfer 2,
vote 1, effective_comment_vote 1.

Three of these were not in any report I was given.

- saos.attest.v1 ANCHORS GIT COMMITS TO THE CHAIN. Real payload carries
  stateRoot, lastBlockHash, commit bbf598a, src agent. Code-provenance
  attestation, already live, already free.
- saos.id.v1 BINDS THE HIVE ACCOUNT TO AN EVM ADDRESS WITH A SIGNATURE. Real
  payload: evm 0xF723186d21179672Ca6d9fc526Ffb718dbD99376, a 65-byte EIP-191
  sig, chains [steem, hive, blurt]. Cross-chain identity binding, on chain, for
  free. Note this EVM address differs from the one used by the dex relay - two
  distinct EVM identities are in play.
- saos.weave.v1 ALREADY HAS A BATCHING SCHEMA. The payload carries count, from
  and to alongside root and height. The packing design built independently in
  packing.py already exists in their protocol.

---

## Finding 1 - a live RC leak on an operation that can never succeed

11 identical calls to Hive-Engine hive.convert with quantity 9.632:

    idx 49696  2026-09-07T11:49:39   hive / convert / quantity 9.632
    idx 49701  2026-09-07T12:34:36   identical
    idx 49703  2026-09-07T13:50:33   identical
    idx 49707  2026-09-07T16:05:33   identical
    idx 49709  2026-09-07T17:35:33   identical
    idx 49710  2026-09-07T19:31:39   identical
    idx 49712  2026-09-07T20:16:36   identical
    idx 49713  2026-09-07T21:01:39   identical
    idx 49714  2026-09-07T21:46:36   identical
    idx 49739  2026-09-08T17:47:03   identical
    idx 49740  2026-09-08T18:28:09   identical  <- minutes before this reading

Evidence that none of them did anything:

- Balance read at 12:46Z: 9.682 HIVE. Balance read at 18:56Z after four more
  attempts: 9.682 HIVE. Unchanged.
- The only successful conversion in the window is a NATIVE fill_convert_request
  at 2026-09-07T09:34:30: amount_in 0.445 HBD to amount_out 9.673 HIVE. That
  plus residual matches the 9.682 balance exactly.
- Hive-Engine hive.convert unwraps SWAP.HIVE into HIVE. It is NOT the native
  HBD-to-HIVE conversion. Same word, different operation, different asset.
- The account had already sent its SWAP.HIVE away on 2026-09-06: tokens.transfer
  symbol SWAP.HIVE quantity 0.05 to tov, memo saos:rc-route.

So the loop tries to unwrap an asset the account does not hold, via a sidechain
contract, when the value it wants already arrived from a native HBD conversion
that completed. Every call fails, every call still lands on chain, and every
call still consumes RC.

The quantity is the tell: 9.632 is within 0.05 of the HIVE balance 9.682.
Something reads the balance field and tries to convert it on the wrong contract
with the wrong asset.

It was still running at the time of reading.

### Cost

Using the measured aggregate cost below (157.7M RC per operation):

    11 attempts x 157.7M RC = ~1.73e9 RC burned
    daily regeneration      =  5.13e9 RC
    => about 34% of one full day of RC budget, on an operation that cannot succeed

This is the largest recoverable waste found anywhere in the estate, and
recovering it costs nothing but stopping a loop.

---

## Finding 2 - 91.9% of attestation operations use the ACTIVE key

| protocol | class | needs | used | total | overprivileged |
|---|---|---|---|---|---|
| ssc-mainnet-hive | value-moving | active | active | 32 | 0 (correct) |
| saos-dex.anchor.v1 | attestation | posting | active | 23 | 23 |
| saos.attest.v1 | attestation | posting | active | 20 | 20 |
| saos.weave.v1 | attestation | posting | active | 11 | 11 |
| saos | attestation | posting | posting | 5 | 0 (correct) |
| saos.id.v1 | attestation | posting | active | 3 | 3 |
| ATTESTATION TOTAL | | | | 62 | 57 (91.9%) |

Hive-Engine calls genuinely move tokens and correctly use ACTIVE. They are
excluded. A naive audit that classified everything as an attestation would have
reported 89 overprivileged operations - an inflated number that would make the
finding easy to dismiss. A test pins the difference between the naive 89 and the
correct 57 so the honest figure cannot drift back.

The fix is already demonstrated in the same account. The five saos value_lock
operations are signed with required_posting_auths. This is not new engineering -
the pattern is live, working and on chain. It is simply not used for the other
four protocols.

| authority | can move funds | can change keys | severity if the signer is compromised |
|---|---|---|---|
| posting | no | no | low - can post and vote |
| active | YES | no | CRITICAL - can transfer every asset |
| owner | yes | YES | total loss - permanent takeover |

Cost of migrating: zero RC. Same resource classes, same payload size.

---

## Finding 3 - one weave seal broadcast ten times

    saos.weave.v1 | net saos-net/0 | seq 2 | root a62ba761584853ad0bb93e1c260b8a64...
        10 broadcasts   2026-09-06T05:52:45 -> 2026-09-07T04:02:15
        9 redundant on-chain records

45 distinct seals were found; one was broadcast ten times. The same logical
commitment now has ten permanent entries in account history and burned RC nine
times for nothing.

This is the idempotency failure class the in-memory batcher already prevents with
an idempotency key and a root-uniqueness check. The on-chain weave protocol has
no equivalent guard.

saos-dex.anchor.v1 and saos.attest.v1 show ZERO duplicates, so the problem is
specific to the weave sealer, not systemic.

---
