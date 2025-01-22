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
	elderOuterTxBytes, err := Base64toBytes("Cn4KfAodL2VsZGVyLnJvdXRlci5Nc2dTdWJtaXRSb2xsVHgSWwosZWxkZXIxZ2NzNnJ5MGVjcXl2OWd2dnBzMG40bHhrcXh0M242MDlmZzJ0OWsQARigwh4iJeSAhQJUC+QAglIIlO3wYZn42h8uJ6IV+WJQtmeboNm9ZICAgIASWApQCkYKHy9jb3Ntb3MuY3J5cHRvLnNlY3AyNTZrMS5QdWJLZXkSIwohA8XMSkrP6ntRndi9dSLOKXPrK0K/HrszIND4SlkJnhYAEgQKAggCGAMSBBDAmgwaQPIbBQFAHwgDumZKI1Vj9UofvfhFBzDPnPSHe1CbOXlfCS7B72PAeLPjvV0Yij/LlQBON6PlUaOqFxo6uF6wiC8=")
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
	expectedAddress := "0x45049FFB8457927CaD1d66FCf9B57dc69dE92724"
	assert.Equal(t, common.HexToAddress(expectedAddress), address, "Expected address to match")
}
