package solana

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

const (
	PrivKeyName   = "solana/PrivKey"
	PubKeyName    = "solana/PubKey"
	KeyType       = "solana"
	PubKeySize    = ed25519.PublicKeySize  // 32
	PrivKeySize   = ed25519.PrivateKeySize // 64 (seed + pubkey)
	SeedSize      = ed25519.SeedSize       // 32
	SignatureSize = ed25519.SignatureSize  // 64
)

var (
	_ cryptotypes.PrivKey  = &PrivKey{}
	_ codec.AminoMarshaler = &PrivKey{}
	_ cryptotypes.PubKey   = &PubKey{}
	_ codec.AminoMarshaler = &PubKey{}
)

// ---------------- PrivKey ----------------

// GenPrivKeyFromSeed membuat kunci dari seed 32 byte (hasil derivasi SLIP-10).
func GenPrivKeyFromSeed(seed []byte) *PrivKey {
	if len(seed) != SeedSize {
		panic(fmt.Sprintf("solana: seed harus %d byte, dapat %d", SeedSize, len(seed)))
	}
	return &PrivKey{Key: []byte(ed25519.NewKeyFromSeed(seed))}
}

// GenPrivKey membuat kunci acak.
func GenPrivKey() *PrivKey {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	return GenPrivKeyFromSeed(seed)
}

func (privKey *PrivKey) Bytes() []byte { return privKey.Key }

func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	if len(privKey.Key) != PrivKeySize {
		return nil, fmt.Errorf("solana: ukuran private key salah")
	}
	return ed25519.Sign(ed25519.PrivateKey(privKey.Key), msg), nil
}

func (privKey *PrivKey) PubKey() cryptotypes.PubKey {
	if len(privKey.Key) != PrivKeySize {
		panic("solana: ukuran private key salah")
	}
	pub := ed25519.PrivateKey(privKey.Key).Public().(ed25519.PublicKey)
	return &PubKey{Key: []byte(pub)}
}

func (privKey *PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	return privKey.Type() == other.Type() && bytes.Equal(privKey.Bytes(), other.Bytes())
}

func (privKey *PrivKey) Type() string { return KeyType }

func (privKey PrivKey) MarshalAmino() ([]byte, error) { return privKey.Key, nil }

func (privKey *PrivKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PrivKeySize {
		return fmt.Errorf("solana: ukuran private key salah")
	}
	privKey.Key = bz
	return nil
}

func (privKey PrivKey) MarshalAminoJSON() ([]byte, error) { return privKey.MarshalAmino() }

func (privKey *PrivKey) UnmarshalAminoJSON(bz []byte) error { return privKey.UnmarshalAmino(bz) }

// ---------------- PubKey ----------------

// Address adalah public key mentah 32 byte (gaya Solana).
func (pubKey *PubKey) Address() cryptotypes.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("solana: ukuran pubkey salah")
	}
	addr := make([]byte, PubKeySize)
	copy(addr, pubKey.Key)
	return cryptotypes.Address(addr)
}

func (pubKey *PubKey) Bytes() []byte { return pubKey.Key }

func (pubKey *PubKey) VerifySignature(msg, sig []byte) bool {
	if len(pubKey.Key) != PubKeySize || len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pubKey.Key), msg, sig)
}

func (pubKey *PubKey) String() string {
	return fmt.Sprintf("PubKeySolana{%X}", pubKey.Key)
}

func (pubKey *PubKey) Type() string { return KeyType }

func (pubKey *PubKey) Equals(other cryptotypes.PubKey) bool {
	return pubKey.Type() == other.Type() && bytes.Equal(pubKey.Bytes(), other.Bytes())
}

func (pubKey PubKey) MarshalAmino() ([]byte, error) { return pubKey.Key, nil }

func (pubKey *PubKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PubKeySize {
		return fmt.Errorf("solana: ukuran pubkey salah")
	}
	pubKey.Key = bz
	return nil
}

func (pubKey PubKey) MarshalAminoJSON() ([]byte, error) { return pubKey.MarshalAmino() }

func (pubKey *PubKey) UnmarshalAminoJSON(bz []byte) error { return pubKey.UnmarshalAmino(bz) }
