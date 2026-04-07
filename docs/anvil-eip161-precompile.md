# Anvil: EIP-161 Empty Account Cleanup for Precompile Addresses

## Problem

When proving blocks on anvil (chain-id 31337) that call EVM precompiles
(e.g. BN254 ecMul at `0x07`), zeth's block validation fails with either:

- `MPT: Unresolved node access` — the witness is incomplete
- `PostStateRootMismatch` — the witness is complete but state roots diverge

## Root Cause

Anvil and reth disagree on EIP-161 behavior for precompile addresses.

When a contract CALLs precompile `0x07`, the EVM "touches" the precompile
address. If the precompile account is empty (nonce=0, balance=0, no code),
EIP-161 requires it to be removed from the state trie at the end of the
transaction.

- **reth** (used by zeth): applies EIP-161 and removes the empty precompile
- **anvil**: does NOT remove the empty precompile from state

This causes their post-state roots to diverge. The block header contains
anvil's state root (precompile still in state), but zeth computes a
different root (precompile removed).

## Affected Precompiles

Any precompile called via CALL that has an empty account in state:
- `0x01` ecRecover
- `0x02` SHA-256
- `0x05` modexp
- `0x06` ecAdd
- `0x07` ecMul
- `0x08` ecPairing
- etc.

The issue manifests after the first block that touches the precompile,
because that block creates the empty account in anvil's state. Subsequent
blocks that call the same precompile touch the existing empty account,
triggering the EIP-161 disagreement.

## Workaround

Fund each precompile address used by your contract with 1 wei during setup.
A non-empty account (balance > 0) is never cleaned up by EIP-161, so both
anvil and reth agree on the post-state.

```solidity
// In your deploy/setup script:
payable(address(0x07)).transfer(1); // BN254 ecMul
payable(address(0x06)).transfer(1); // BN254 ecAdd
// ... any other precompiles your contract uses
```

Or via cast:
```bash
cast send 0x0000000000000000000000000000000000000007 \
  --value 1wei --private-key $DEPLOYER_KEY --rpc-url $ANVIL_RPC
```

## Long-Term Fix

This should be fixed upstream in either:
- **anvil/foundry**: apply EIP-161 empty account cleanup for precompile
  addresses, matching the Ethereum specification
- **reth**: optionally skip EIP-161 for dev chains to match anvil behavior

## References

- EIP-161: <https://eips.ethereum.org/EIPS/eip-161>
- Related zeth issue: <https://github.com/boundless-xyz/zeth/issues/147>
