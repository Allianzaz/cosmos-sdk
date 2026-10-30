# About this fork

Personal fork of [cosmos/cosmos-sdk](https://github.com/cosmos/cosmos-sdk)
(`v0.53.8`) — my playground for Cosmos SDK development, currently featuring
a full **Solana-style ed25519 key integration**.

> Upstream is the source of truth. All credit for the SDK itself belongs to
> the Cosmos SDK contributors. The changes below are my own work.

## What's changed

**New — Solana key support** (`crypto/keys/solana/`)
- `solana/PrivKey` / `solana/PubKey`: ed25519 key types in the Solana model.
- `PubKey.Address()` returns the raw 32-byte public key — the Solana-style
  (base58) address model instead of bech32.

**New — HD derivation** (`crypto/hd/solana.go`)
- SLIP-10 ed25519 derivation, default path `m/44'/501'/0'/0'`
  (Phantom/Solflare compatible).

**New — Protobuf** (`proto/cosmos/crypto/solana/keys.proto`)
- Message definitions for the Solana key types.

**Wiring**
- `crypto/codec/amino.go`, `crypto/codec/proto.go` — register the Solana key
  types with the Amino codec and the protobuf interface registry.
- `crypto/keyring/keyring.go` — `hd.Solana` added to the supported
  signing algorithms.
- `x/auth/ante/sigverify.go` — gas metering for Solana signature
  verification in the ante handler.

## Status

Experimental / learning project. Not intended to track upstream releases.
