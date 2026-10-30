package solana_test

import (
	"math/big"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
)

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	x := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, base, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func TestSolanaDerivationMatchesKnownVector(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	cases := []struct {
		path string
		want string // kosong = hanya dicatat, isi setelah dicocokkan dengan Phantom/solana-keygen
	}{
		{"m/44'/501'/0'/0'", "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"},
		{"m/44'/501'/1'/0'", ""},
	}

	for _, tc := range cases {
		derived, err := hd.Solana.Derive()(mnemonic, "", tc.path)
		if err != nil {
			t.Fatalf("%s: derive: %v", tc.path, err)
		}
		if len(derived) != 32 {
			t.Fatalf("%s: panjang kunci turunan %d, harusnya 32", tc.path, len(derived))
		}
		addr := hd.Solana.Generate()(derived).PubKey().Address()
		if len(addr) != 32 {
			t.Fatalf("%s: panjang alamat %d, harusnya 32", tc.path, len(addr))
		}
		got := base58Encode(addr)
		t.Logf("%s => %s", tc.path, got)
		if tc.want != "" && got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.path, got, tc.want)
		}
	}
}
