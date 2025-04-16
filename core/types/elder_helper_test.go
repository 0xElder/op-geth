package types

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestConvertEcdsaToSecp256k1PrivKey(t *testing.T) {
	// Generate a new ECDSA private key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Convert the ECDSA private key to a secp256k1 private key
	secp256k1Key := ConvertEcdsaToSecp256k1PrivKey(ecdsaKey)

	// Ensure the key is 32 bytes (256 bits) long
	assert.Equal(t, 32, len(secp256k1Key.Key), "Expected key length to be 32 bytes")

	// Ensure the key matches the original ECDSA private key
	expectedKeyBytes := ecdsaKey.D.Bytes()
	if len(expectedKeyBytes) < 32 {
		padding := make([]byte, 32-len(expectedKeyBytes))
		expectedKeyBytes = append(padding, expectedKeyBytes...)
	} else if len(expectedKeyBytes) > 32 {
		expectedKeyBytes = expectedKeyBytes[len(expectedKeyBytes)-32:]
	}

	assert.Equal(t, expectedKeyBytes, secp256k1Key.Key, "Expected key bytes to match")
}

func TestElderTxToEthTx(t *testing.T) {
	elderTxStr := "Cn0KewodL2VsZGVyLnJvdXRlci5Nc2dTdWJtaXRSb2xsVHgSWgosZWxkZXIxcDUwY3pxc3J6c3RzdTUwcTA3M2Y0dXBjZm1hZHZrbmZydWZ6bXoQAhoo54CFBKgXyACDD0JAlAAAAAAAAAAAAAAAAAAAAAAAAN6tgICCpxGAgBJqClAKRgofL2Nvc21vcy5jcnlwdG8uc2VjcDI1NmsxLlB1YktleRIjCiEDha2rv9G4RXTa1YTASxTRiISLtlVJFJWQIpVLykktKGwSBAoCCAEYIBIWChAKBnVlbGRlchIGMjUwMDAwEMCaDBpARDLc50ycOdw1ADFO4H5Fp/xH0O6S2AtD/cWKAHaN7s4RtXJkfTJ9njQyEBXXkln1pa6QDJlkdpVDtrHL/xxw2Q=="
	elderTxBytes, err := Base64toBytes(elderTxStr)
	if err != nil {
		t.Fatalf("Failed to convert base64 string to bytes: %v", err)
	}

	// Mock rawElderTxBytes
	rawElderTxBytes := elderTxBytes

	toAddr := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	// Mock the expected Transaction
	expectedTx := &Transaction{
		inner: &LegacyTx{
			Nonce:    0,
			GasPrice: big.NewInt(20000000000),
			Gas:      1000000,
			To:       &toAddr,
			Value:    big.NewInt(0),
			Data:     []byte{},
			V:        big.NewInt(42769),
			R:        big.NewInt(0),
			S:        big.NewInt(0),
		},
	}

	// Call the function
	tx, _, _, err := ElderTxToEthTx(rawElderTxBytes)

	// Assert no error
	assert.NoError(t, err, "Expected no error")

	// Assert the returned transaction matches the expected transaction
	assert.Equal(t, expectedTx.Nonce(), tx.Nonce(), "Expected transaction nonce to match")
	assert.Equal(t, expectedTx.GasPrice(), tx.GasPrice(), "Expected transaction gas price to match")
	assert.Equal(t, expectedTx.Gas(), tx.Gas(), "Expected transaction gas to match")
	assert.Equal(t, expectedTx.To(), tx.To(), "Expected transaction to address to match")
	assert.Equal(t, expectedTx.Value(), tx.Value(), "Expected transaction value to match")
	assert.Equal(t, expectedTx.Data(), tx.Data(), "Expected transaction data to match")

	// Assert the V, R, and S values are also correct
	vexp, rexp, sexp := expectedTx.RawSignatureValues()
	v, r, s := tx.RawSignatureValues()

	assert.Equal(t, vexp, v, "Expected transaction V value to match")
	assert.Equal(t, rexp, r, "Expected transaction R value to match")
	assert.Equal(t, sexp, s, "Expected transaction S value to match")

}

func TestCosmosPubKeyToEthPubkey(t *testing.T) {
	pubKeyHex := "03c5cc4a4acfea7b519dd8bd7522ce2973eb2b42bf1ebb3320d0f84a59099e1600"
	expectedEthPubKey := "04c5cc4a4acfea7b519dd8bd7522ce2973eb2b42bf1ebb3320d0f84a59099e1600cbafa42a0dc37fda4a8097ee98d1a198719bdb42b9f42943e3671435a8d34159"

	// Call the function
	ethPubKey, err := CosmosPubKeyToEthPubkey(pubKeyHex)

	// Assert no error
	assert.NoError(t, err, "Expected no error")

	// Assert the returned public key matches the expected public key
	assert.Equal(t, expectedEthPubKey, ethPubKey, "Expected public key to match")
}

func TestEthPubKeyToEthAddr(t *testing.T) {
	// Test case with a valid public key
	pubKeyHex := "04c5cc4a4acfea7b519dd8bd7522ce2973eb2b42bf1ebb3320d0f84a59099e1600cbafa42a0dc37fda4a8097ee98d1a198719bdb42b9f42943e3671435a8d34159"
	expectedAddress := "0x45049FFB8457927CaD1d66FCf9B57dc69dE92724"

	// Call the function
	address, err := EthPubKeyToEthAddr(pubKeyHex)

	// Assert no error
	assert.NoError(t, err, "Expected no error")

	// Assert the returned address matches the expected address
	assert.Equal(t, expectedAddress, address, "Expected address to match")
}

func TestElderInnerTxSender(t *testing.T) {
	// Mock the ElderInnerTx
	elderOuterTxBytes, err := Base64toBytes("Crw6Crk6Ch0vZWxkZXIucm91dGVyLk1zZ1N1Ym1pdFJvbGxUeBKXOgosZWxkZXIxcDUwY3pxc3J6c3RzdTUwcTA3M2Y0dXBjZm1hZHZrbmZydWZ6bXoQARriOQL5HN6DAS3VgIRZaC8AhFloMC6DE9lrgIC5HIJggGBAUjSAFWEAD1dfgP1bUDNgQFGAYEABYEBSgGAKgVJgIAF/VHJlYXRUb2tlbgAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUlBgQFGAYEABYEBSgGAFgVJgIAF/VFJFQVQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUlCBYAOQgWEAjJGQYQbZVltQgGAEkIFhAJyRkGEG2VZbUFBQX3P//////////////////////////xaBc///////////////////////////FgNhAQ9XX2BAUX8eT733AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQEGkZBhB+dWW2BAUYCRA5D9W2EBHoFhAT5gIBtgIBxWW1BhATkzadPCG87M7aEAAABhAgFgIBtgIBxWW2EIvVZbX2AFX5BUkGEBAAqQBHP//////////////////////////xaQUIFgBV9hAQAKgVSBc///////////////////////////AhkWkINz//////////////////////////8WAheQVVCBc///////////////////////////FoFz//////////////////////////8Wf4vgB5xTFlkUE0TNH9Ck8oQZSX+XIqPar+O0GG9rZFfgYEBRYEBRgJEDkKNQUFZbX3P//////////////////////////xaCc///////////////////////////FgNhAnFXX2BAUX/sRC8FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQJokZBhB+dWW2BAUYCRA5D9W2ECgl+Dg2EChmAgG2AgHFZbUFBWW19z//////////////////////////8Wg3P//////////////////////////xYDYQLWV4BgAl+CglRhAsqRkGEILVZbklBQgZBVUGEDpFZbX4BfhXP//////////////////////////xZz//////////////////////////8WgVJgIAGQgVJgIAFfIFSQUIGBEBVhA19Xg4GDYEBRf+RQ04wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgVJgBAFhA1aTkpGQYQhvVltgQFGAkQOQ/VuBgQNfgIZz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyCBkFVQUFtfc///////////////////////////FoJz//////////////////////////8WA2ED61eAYAJfgoJUA5JQUIGQVVBhBDVWW4BfgIRz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBfgoJUAZJQUIGQVVBbgXP//////////////////////////xaDc///////////////////////////Fn/d8lKtG+LIm2nCsGj8N42qlSun8WPEoRYo9VpN9SOz74NgQFFhBJKRkGEIpFZbYEBRgJEDkKNQUFBWW1+BUZBQkZBQVlt/Tkh7cQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfUmBBYARSYCRf/Vt/Tkh7cQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfUmAiYARSYCRf/VtfYAKCBJBQYAGCFoBhBRpXYH+CFpFQW2AgghCBA2EFLVdhBSxhBNZWW1tQkZBQVltfgZBQgV9SYCBfIJBQkZBQVltfYCBgH4MBBJBQkZBQVltfgoIbkFCSkVBQVltfYAiDAmEFj3///////////////////////////////////////////4JhBVRWW2EFmYaDYQVUVluVUIAZhBaTUICGFoQXklBQUJOSUFBQVltfgZBQkZBQVltfgZBQkZBQVltfYQXdYQXYYQXThGEFsVZbYQW6VlthBbFWW5BQkZBQVltfgZBQkZBQVlthBfaDYQXDVlthBgphBgKCYQXkVluEhFRhBWBWW4JVUFBQUFZbX5BWW2EGHmEGElZbYQYpgYSEYQXtVltQUFBWW1uBgRAVYQZMV2EGQV+CYQYWVltgAYEBkFBhBi9WW1BQVltgH4IRFWEGkVdhBmKBYQUzVlthBmuEYQVFVluBAWAghRAVYQZ6V4GQUFthBo5hBoaFYQVFVluDAYJhBi5WW1BQW1BQUFZbX4KCHJBQkpFQUFZbX2EGsV8ZhGAIAmEGllZbGYCDFpFQUJKRUFBWW19hBsmDg2EGolZbkVCCYAICgheQUJKRUFBWW2EG4oJhBJ9WW2f//////////4ERFWEG+1dhBvphBKlWW1thBwWCVGEFA1ZbYQcQgoKFYQZQVltfYCCQUGAfgxFgAYEUYQdBV1+EFWEHL1eChwFRkFBbYQc5hYJhBr5WW4ZVUGEHoFZbYB8ZhBZhB0+GYQUzVltfW4KBEBVhB3ZXhIkBUYJVYAGCAZFQYCCFAZRQYCCBAZBQYQdRVluGgxAVYQeTV4SJAVFhB49gH4kWgmEGolZbg1VQW2ABYAKIAgGIVVBQUFtQUFBQUFBWW19z//////////////////////////+CFpBQkZBQVltfYQfRgmEHqFZbkFCRkFBWW2EH4YFhB8dWW4JSUFBWW19gIIIBkFBhB/pfgwGEYQfYVluSkVBQVlt/Tkh7cQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfUmARYARSYCRf/VtfYQg3gmEFsVZbkVBhCEKDYQWxVluSUIKCAZBQgIIRFWEIWldhCFlhCABWW1uSkVBQVlthCGmBYQWxVluCUlBQVltfYGCCAZBQYQiCX4MBhmEH2FZbYQiPYCCDAYVhCGBWW2EInGBAgwGEYQhgVluUk1BQUFBWW19gIIIBkFBhCLdfgwGEYQhgVluSkVBQVlthE7iAYQjKXzlf8/5ggGBAUjSAFWEAD1dfgP1bUGAENhBhAQlXXzVg4ByAY3CggjERYQCgV4BjldibQRFhAG9XgGOV2JtBFGECk1eAY6kFnLsUYQKxV4Bjz4SUQhRhAuFXgGPdYu0+FGEC/1eAY/L944sUYQMvV2EBCVZbgGNwoIIxFGECC1eAY3FQGKYUYQI7V4Bjc7LoDhRhAkVXgGONpctbFGECdVdhAQlWW4BjL/Lp3BFhANxXgGMv8uncFGEBqVeAYzE85WcUYQHHV4BjQMEPGRRhAeVXgGNOcdktFGECAVdhAQlWW4BjBv3eAxRhAQ1XgGMJXqezFGEBK1eAYxgWDd0UYQFbV4BjI7hy3RRhAXlXW1+A/VthARVhA0tWW2BAUWEBIpGQYQ+cVltgQFGAkQOQ81thAUVgBIA2A4EBkGEBQJGQYRBNVlthA9tWW2BAUWEBUpGQYRClVltgQFGAkQOQ81thAWNhA/1WW2BAUWEBcJGQYRDNVltgQFGAkQOQ81thAZNgBIA2A4EBkGEBjpGQYRDmVlthBAZWW2BAUWEBoJGQYRClVltgQFGAkQOQ81thAbFhBDRWW2BAUWEBvpGQYRDNVltgQFGAkQOQ81thAc9hBEJWW2BAUWEB3JGQYRFRVltgQFGAkQOQ81thAf9gBIA2A4EBkGEB+pGQYRBNVlthBEpWWwBbYQIJYQRgVlsAW2ECJWAEgDYDgQGQYQIgkZBhEWpWW2EFI1ZbYEBRYQIykZBhEM1WW2BAUYCRA5DzW2ECQ2EFaFZbAFthAl9gBIA2A4EBkGECWpGQYRFqVlthBXtWW2BAUWECbJGQYRClVltgQFGAkQOQ81thAn1hBfNWW2BAUWECipGQYRGkVltgQFGAkQOQ81thApthBhtWW2BAUWECqJGQYQ+cVltgQFGAkQOQ81thAstgBIA2A4EBkGECxpGQYRBNVlthBqtWW2BAUWEC2JGQYRClVltgQFGAkQOQ81thAulhBs1WW2BAUWEC9pGQYRDNVltgQFGAkQOQ81thAxlgBIA2A4EBkGEDFJGQYRG9VlthBtpWW2BAUWEDJpGQYRDNVltgQFGAkQOQ81thA0lgBIA2A4EBkGEDRJGQYRFqVlthB1xWWwBbYGBgA4BUYQNakGESKFZbgGAfAWAggJEEAmAgAWBAUZCBAWBAUoCSkZCBgVJgIAGCgFRhA4aQYRIoVluAFWED0VeAYB8QYQOoV2EBAICDVAQCg1KRYCABkWED0VZbggGRkF9SYCBfIJBbgVSBUpBgAQGQYCABgIMRYQO0V4KQA2AfFoIBkVtQUFBQUJBQkFZbX4BhA+VhB+BWW5BQYQPygYWFYQfnVltgAZFQUJKRUFBWW19gAlSQUJBWW1+AYQQQYQfgVluQUGEEHYWChWEH+VZbYQQohYWFYQiLVltgAZFQUJOSUFBQVltp08IbzsztoQAAAIFWW19gEpBQkFZbYQRSYQl7VlthBFyCgmEKAlZbUFBWW2EEaTNhBXtWWxVhBKlXYEBRfwjDeaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgVJgBAFhBKCQYRKiVltgQFGAkQOQ/VthBLwzaDY1ya3F3qAAAGEKAlZbYAFgBl8zc///////////////////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8gX2EBAAqBVIFg/wIZFpCDYAGBERVhBRxXYQUbYRLAVltbAheQVVBWW1+AX4Nz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBUkFCRkFBWW2EFcGEJe1ZbYQV5X2EKgVZbVltfYAGAgREVYQWPV2EFjmESwFZbW2AGX4Rz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBfkFSQYQEACpAEYP8WYAGBERVhBetXYQXqYRLAVltbFJBQkZBQVltfYAVfkFSQYQEACpAEc///////////////////////////FpBQkFZbYGBgBIBUYQYqkGESKFZbgGAfAWAggJEEAmAgAWBAUZCBAWBAUoCSkZCBgVJgIAGCgFRhBlaQYRIoVluAFWEGoVeAYB8QYQZ4V2EBAICDVAQCg1KRYCABkWEGoVZbggGRkF9SYCBfIJBbgVSBUpBgAQGQYCABgIMRYQaEV4KQA2AfFoIBkVtQUFBQUJBQkFZbX4BhBrVhB+BWW5BQYQbCgYWFYQiLVltgAZFQUJKRUFBWW2g2Ncmtxd6gAACBVltfYAFfhHP//////////////////////////xZz//////////////////////////8WgVJgIAGQgVJgIAFfIF+Dc///////////////////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8gVJBQkpFQUFZbYQdkYQl7Vltfc///////////////////////////FoFz//////////////////////////8WA2EH1FdfYEBRfx5PvfcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgVJgBAFhB8uRkGERpFZbYEBRgJEDkP1bYQfdgWEKgVZbUFZbXzOQUJBWW2EH9IODg2ABYQtEVltQUFBWW19hCASEhGEG2lZbkFB///////////////////////////////////////////+BFGEIhVeBgRAVYQh2V4KBg2BAUX/7j0GyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQhtk5KRkGES7VZbYEBRgJEDkP1bYQiEhISEhANfYQtEVltbUFBQUFZbX3P//////////////////////////xaDc///////////////////////////FgNhCPtXX2BAUX+Wxv0eAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQjykZBhEaRWW2BAUYCRA5D9W19z//////////////////////////8WgnP//////////////////////////xYDYQlrV19gQFF/7EQvBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUmAEAWEJYpGQYRGkVltgQFGAkQOQ/VthCXaDg4NhDRNWW1BQUFZbYQmDYQfgVltz//////////////////////////8WYQmhYQXzVltz//////////////////////////8WFGEKAFdhCcRhB+BWW2BAUX8RjNqnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQn3kZBhEaRWW2BAUYCRA5D9W1ZbX3P//////////////////////////xaCc///////////////////////////FgNhCnJXX2BAUX/sRC8FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQppkZBhEaRWW2BAUYCRA5D9W2EKfV+Dg2ENE1ZbUFBWW19gBV+QVJBhAQAKkARz//////////////////////////8WkFCBYAVfYQEACoFUgXP//////////////////////////wIZFpCDc///////////////////////////FgIXkFVQgXP//////////////////////////xaBc///////////////////////////Fn+L4AecUxZZFBNEzR/QpPKEGUl/lyKj2q/jtBhva2RX4GBAUWBAUYCRA5CjUFBWW19z//////////////////////////8WhHP//////////////////////////xYDYQu0V19gQFF/5gLfBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUmAEAWELq5GQYRGkVltgQFGAkQOQ/Vtfc///////////////////////////FoNz//////////////////////////8WA2EMJFdfYEBRf5QoDWIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgVJgBAFhDBuRkGERpFZbYEBRgJEDkP1bgWABX4Zz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBfhXP//////////////////////////xZz//////////////////////////8WgVJgIAGQgVJgIAFfIIGQVVCAFWENDVeCc///////////////////////////FoRz//////////////////////////8Wf4xb4eXr7H1b0U9xQn0ehPPdAxTA97IpHlsgCsjHw7klhGBAUWENBJGQYRDNVltgQFGAkQOQo1tQUFBQVltfc///////////////////////////FoNz//////////////////////////8WA2ENY1eAYAJfgoJUYQ1XkZBhE09WW5JQUIGQVVBhDjFWW1+AX4Vz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBUkFCBgRAVYQ3sV4OBg2BAUX/kUNOMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQ3jk5KRkGES7VZbYEBRgJEDkP1bgYEDX4CGc///////////////////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8ggZBVUFBbX3P//////////////////////////xaCc///////////////////////////FgNhDnhXgGACX4KCVAOSUFCBkFVQYQ7CVluAX4CEc///////////////////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8gX4KCVAGSUFCBkFVQW4Fz//////////////////////////8Wg3P//////////////////////////xZ/3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs++DYEBRYQ8fkZBhEM1WW2BAUYCRA5CjUFBQVltfgVGQUJGQUFZbX4KCUmAgggGQUJKRUFBWW4KBg15fg4MBUlBQUFZbX2AfGWAfgwEWkFCRkFBWW19hD26CYQ8sVlthD3iBhWEPNlZbk1BhD4iBhWAghgFhD0ZWW2EPkYFhD1RWW4QBkVBQkpFQUFZbX2AgggGQUIGBA1+DAVJhD7SBhGEPZFZbkFCSkVBQVltfgP1bX3P//////////////////////////4IWkFCRkFBWW19hD+mCYQ/AVluQUJGQUFZbYQ/5gWEP31ZbgRRhEANXX4D9W1BWW1+BNZBQYRAUgWEP8FZbkpFQUFZbX4GQUJGQUFZbYRAsgWEQGlZbgRRhEDZXX4D9W1BWW1+BNZBQYRBHgWEQI1ZbkpFQUFZbX4BgQIOFAxIVYRBjV2EQYmEPvFZbW19hEHCFgoYBYRAGVluSUFBgIGEQgYWChgFhEDlWW5FQUJJQkpBQVltfgRUVkFCRkFBWW2EQn4FhEItWW4JSUFBWW19gIIIBkFBhELhfgwGEYRCWVluSkVBQVlthEMeBYRAaVluCUlBQVltfYCCCAZBQYRDgX4MBhGEQvlZbkpFQUFZbX4BfYGCEhgMSFWEQ/VdhEPxhD7xWW1tfYREKhoKHAWEQBlZbk1BQYCBhERuGgocBYRAGVluSUFBgQGERLIaChwFhEDlWW5FQUJJQklCSVltfYP+CFpBQkZBQVlthEUuBYRE2VluCUlBQVltfYCCCAZBQYRFkX4MBhGERQlZbkpFQUFZbX2AggoQDEhVhEX9XYRF+YQ+8VltbX2ERjISChQFhEAZWW5FQUJKRUFBWW2ERnoFhD99WW4JSUFBWW19gIIIBkFBhEbdfgwGEYRGVVluSkVBQVltfgGBAg4UDEhVhEdNXYRHSYQ+8VltbX2ER4IWChgFhEAZWW5JQUGAgYRHxhYKGAWEQBlZbkVBQklCSkFBWW39OSHtxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF9SYCJgBFJgJF/9W19gAoIEkFBgAYIWgGESP1dgf4IWkVBbYCCCEIEDYRJSV2ESUWER+1ZbW1CRkFBWW39BbHJlYWR5IGNsYWltZWQAAAAAAAAAAAAAAAAAAAAAAF+CAVJQVltfYRKMYA+DYQ82VluRUGESl4JhElhWW2AgggGQUJGQUFZbX2AgggGQUIGBA1+DAVJhErmBYRKAVluQUJGQUFZbf05Ie3EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX1JgIWAEUmAkX/1bX2BgggGQUGETAF+DAYZhEZVWW2ETDWAggwGFYRC+VlthExpgQIMBhGEQvlZblJNQUFBQVlt/Tkh7cQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfUmARYARSYCRf/VtfYRNZgmEQGlZbkVBhE2SDYRAaVluSUIKCAZBQgIIRFWETfFdhE3thEyJWW1uSkVBQVv6iZGlwZnNYIhIgvFN3nEiPA5oFk9D4SJvhP06nZUVlgv5bF0tItgxH7Klkc29sY0MACBoAM8CAoIliRInkWtCMR8RiM7jLlrPAEOCi6LeKZ9PRnfdMg+CIoFO8UL7AIVpCbbR4iuMmtAHhmSbHIsvV5YwcHNACzyHiIAoSawpQCkYKHy9jb3Ntb3MuY3J5cHRvLnNlY3AyNTZrMS5QdWJLZXkSIwohA4Wtq7/RuEV02tWEwEsU0YiEi7ZVSRSVkCKVS8pJLShsEgQKAggBGAQSFwoRCgZ1ZWxkZXISBzE3MTg0NzAQ47g0GkBiOOB+qz3uFpYR7eizttzmeg++KVa2blzG0KcbayzukzeT4v2tARdi4ngx8E4KeTHQtNvQI0oRM1S6b+kkobR1")
	if err != nil {
		t.Fatalf("Failed to convert base64 string to bytes: %v", err)
	}

	elderInnerTx := &ElderInnerTx{
		ElderOuterTx: elderOuterTxBytes,
	}

	// Mock the Transaction
	tx := &Transaction{
		inner: elderInnerTx,
	}

	// Call the function
	address, err := ElderInnerTxSender(tx)

	// Assert no error
	assert.NoError(t, err, "Expected no error")

	// Assert the returned address is correct
	expectedAddress := "0x00816f8E1B177Ab540Be8c38c7d2c8EB55d56A79"
	assert.Equal(t, common.HexToAddress(expectedAddress), address, "Expected address to match")
}
