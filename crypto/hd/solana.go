package hd

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/cosmos/go-bip39"

	"github.com/cosmos/cosmos-sdk/crypto/keys/solana"
	"github.com/cosmos/cosmos-sdk/crypto/types"
)

// SolanaType: ed25519 dengan derivasi SLIP-10, alamat 32 byte gaya Solana.
const SolanaType = PubKeyType("solana")

// DefaultSolanaHDPath sama dengan path default Phantom/Solflare untuk akun pertama.
const DefaultSolanaHDPath = "m/44'/501'/0'/0'"

// Solana adalah algoritma derivasi untuk akun gaya Solana.
var Solana = solanaAlgo{}

type solanaAlgo struct{}

func (s solanaAlgo) Name() PubKeyType { return SolanaType }

func (s solanaAlgo) Derive() DeriveFn {
	return func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error) {
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}
		path, err := parseSlip10Path(hdPath)
		if err != nil {
			return nil, err
		}
		return slip10Ed25519(seed, path), nil
	}
}

func (s solanaAlgo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		return solana.GenPrivKeyFromSeed(bz)
	}
}

// parseSlip10Path menerima "m/44'/501'/0'/0'" (SLIP-10 ed25519 hanya mengenal hardened).
func parseSlip10Path(p string) ([]uint32, error) {
	if p == "" || p == "m" {
		return nil, nil
	}
	parts := strings.Split(strings.TrimPrefix(p, "m/"), "/")
	out := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if !strings.HasSuffix(part, "'") {
			return nil, fmt.Errorf("solana: komponen path %q harus hardened (diakhiri ')", part)
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(part, "'"), 10, 31)
		if err != nil {
			return nil, fmt.Errorf("solana: komponen path %q tidak valid: %w", part, err)
		}
		out = append(out, uint32(n))
	}
	return out, nil
}

func slip10Ed25519(seed []byte, path []uint32) []byte {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	I := h.Sum(nil)
	k, c := I[:32], I[32:]
	for _, idx := range path {
		data := append([]byte{0}, k...)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], idx|0x80000000)
		data = append(data, b[:]...)
		m := hmac.New(sha512.New, c)
		m.Write(data)
		I = m.Sum(nil)
		k, c = I[:32], I[32:]
	}
	return k
}
