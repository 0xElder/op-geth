package types

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	elderutils "github.com/0xElder/elder/utils"
	routertypes "github.com/0xElder/elder/x/router/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

var (
	ErrElderBlockHeightLessThanStart  = errors.New("block height is less than start")
	ErrElderBlockHeighMoreThanCurrent = errors.New("block height is more than current")
	ErrRollupIDNotAvailable           = errors.New("rollup id not available")
	ErrElderRollAppNotEnabled         = errors.New("rollup app not enabled")
)

// ElderGetTxByBlockResponse represents response from Elcer when we query for transactions by block for a rollup
type ElderGetTxByBlockResponse struct {
	RollID string `json:"rollId"`
	Txs    struct {
		Block  string   `json:"block"`
		TxList []string `json:"txList"`
	} `json:"txs"`
	CurrentHeight string `json:"currentHeight"`
}

// ElderGetTxByBlockResponseInvalid represents response from Elcer when we query for transactions by block for a rollup and the response is invalid
type ElderGetTxByBlockResponseInvalid struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Details []interface{} `json:"details"`
}

// VerifyElderTxsSignature verifies the signature of the elder(cosmos) transactions
func VerifyElderTxsSignature(txs [][]byte, elderChainId string) error {
	for _, txBytes := range txs {
		tx, err := elderutils.BytesToCosmosTx(txBytes)
		if err != nil {
			return fmt.Errorf("unable to unmarshal tx %+v: %v", txBytes, err)
		}

		err = elderutils.VerifyRollMsgTxSignature(context.Background(), tx, elderChainId)
		if err != nil {
			return fmt.Errorf("tx signature verification failed %+v: %v", txs, err)
		}
	}

	return nil
}

// TxsBytesToTxs converts the bytes of the elder transactions to the ethereum ElderInnerTx transactions
func TxsBytesToElderInnerTxs(txs [][]byte, chainConfig *params.ChainConfig, elderChainId string) ([]*Transaction, error) {
	elderInnerTxs := make([]*Transaction, len(txs))
	for i, txBytes := range txs {
		elderInnerTx, err := ElderTxToElderInnerTx(txBytes, chainConfig)
		if err != nil {
			return []*Transaction{}, err
		}

		elderInnerTxs[i] = elderInnerTx
	}
	return elderInnerTxs, nil
}

// BytesToBase64 converts the bytes to base64 string
func Base64toBytes(in string) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return []byte{}, err
	}

	return out, nil
}

// ElderTxToEthTx converts the elder transaction to ethereum transaction
func ElderTxToEthTx(rawElderTxBytes []byte) (*Transaction, uint64, string, error) {
	elderTx, err := elderutils.BytesToCosmosTx(rawElderTxBytes)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid transaction1 %+v: %v", rawElderTxBytes, err)
	}

	signatures, msgs, err := elderutils.GetSigsAndMsgsFromTx(elderTx)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid transaction2 %+v: %v", elderTx, err)
	}

	// Validate there is exactly one signer and one signature
	if len(signatures) != 1 {
		return nil, 0, "", fmt.Errorf("invalid transaction3, length of signer and signatures must be 1, %+v: %v", elderTx, err)
	}

	accSeq := signatures[0].Sequence
	accPublicKey := signatures[0].PubKey
	accPublicKeyStr := hex.EncodeToString(accPublicKey.Bytes())

	if len(msgs) != 1 {
		return nil, 0, "", fmt.Errorf("invalid transaction3 %+v: %v", elderTx, err)
	}

	// Ensure the message is of type MsgSubmitRollTx
	rollMsg, ok := msgs[0].(*routertypes.MsgSubmitRollTx)
	if !ok {
		return nil, 0, "", errors.New("message is not of type MsgSubmitRollTx")
	}

	var tx Transaction
	if err := tx.UnmarshalBinary(rollMsg.TxData); err != nil {
		return nil, 0, "", fmt.Errorf("invalid transaction4 %+v: %v", elderTx, err)
	}

	fmt.Println("original txHash", tx.Hash().Hex())
	return &tx, accSeq, accPublicKeyStr, nil
}

// ElderTxToElderInnerTx converts the elder transaction to ethereum ElderInnerTx transaction
func ElderTxToElderInnerTx(rawElderTxBytes []byte, chainConfig *params.ChainConfig) (*Transaction, error) {
	tx, accSeq, accPublicKeyStr, err := ElderTxToEthTx(rawElderTxBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction2 %+v: %v", rawElderTxBytes, err)
	}

	elderInnerTx, err := LegacyTxToElderInnerTx(tx, rawElderTxBytes, accSeq, accPublicKeyStr, chainConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction5 %+v: %v", tx, err)
	}

	return elderInnerTx, nil
}

// LegacyTxToElderInnerTx converts the ethereum transaction to ethereum ElderInnerTx transaction
func LegacyTxToElderInnerTx(tx *Transaction, rawElderTxBytes []byte, accSeq uint64, accPublicKeyStr string, chainConfig *params.ChainConfig) (*Transaction, error) {
	v, r, s := tx.RawSignatureValues()
	nonce := tx.Nonce()

	// If the transaction is not signed, set the nonce to 0
	// keep nonce unchanged for double signed tx
	if r.Int64() == 0 || s.Int64() == 0 {
		nonce = 0
	}

	elderDoubleSigned := false

	signer := LatestSigner(chainConfig)
	originalAddr, err := signer.Sender(tx)
	if err == nil {
		elderTxAddr, _ := ElderTxSender(rawElderTxBytes)
		if elderTxAddr.Cmp(originalAddr) == 0 {
			elderDoubleSigned = true
		}
	}

	inner := NewTx(&ElderInnerTx{
		ChainID:              chainConfig.ChainID,
		Gas:                  tx.Gas(),
		To:                   tx.To(),
		Value:                tx.Value(),
		Data:                 tx.Data(),
		AccessList:           tx.AccessList(),
		Nonce:                nonce,
		V:                    v,
		R:                    r,
		S:                    s,
		ElderOuterTx:         rawElderTxBytes,
		ElderAccountSequence: accSeq,
		ElderPublicKey:       accPublicKeyStr,
		ElderStatus:          true,
		ElderDoubleSigned:    elderDoubleSigned,
	})

	fmt.Println("elder inner txHash", inner.Hash().Hex())
	return inner, nil
}

// CosmosPubKeyToEthPubkey converts the cosmos public key to ethereum public key
func CosmosPubKeyToEthPubkey(pubKey string) (string, error) {
	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %v", err)
	}

	// Generate the public key object
	publicKey, err := crypto.DecompressPubkey(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decompress public key: %v", err)
	}

	return hex.EncodeToString(crypto.FromECDSAPub(publicKey)), nil
}

// EthPubKeyToEthAddr converts the ethereum public key to ethereum address
func EthPubKeyToEthAddr(pubKey string) (string, error) {
	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %v", err)
	}

	// Generate the public key object
	publicKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate public key: %v", err)
	}

	// Generate the address
	address := crypto.PubkeyToAddress(*publicKey)
	return address.Hex(), nil
}

// ElderInnerTxSender returns the sender of the ethereum ElderInnerTx transaction
func ElderInnerTxSender(tx *Transaction) (common.Address, error) {
	elderInnerTx := tx.inner.(*ElderInnerTx)

	return ElderTxSender(elderInnerTx.ElderOuterTx)
}

// ElderTxSender returns the sender of the elder(cosmos) transaction
func ElderTxSender(elderTxBytes []byte) (common.Address, error) {
	elderOuterTx, err := elderutils.BytesToCosmosTx(elderTxBytes)
	if err != nil {
		return common.Address{}, err
	}

	signatures, _, err := elderutils.GetSigsAndMsgsFromTx(elderOuterTx)
	if err != nil {
		return common.Address{}, err
	}

	// Validate there is exactly one signer and one signature
	if len(signatures) != 1 {
		return common.Address{}, errors.New("invalid transaction, length of signer and signatures must be 1")
	}

	cosmosPubKey := signatures[0].PubKey
	cosmosPubKeyStr := hex.EncodeToString(cosmosPubKey.Bytes())

	ethPubKey, err := CosmosPubKeyToEthPubkey(cosmosPubKeyStr)
	if err != nil {
		panic(err)
	}

	ethAddr, err := EthPubKeyToEthAddr(ethPubKey)
	if err != nil {
		panic(err)
	}

	return common.HexToAddress(ethAddr), nil
}

// TODO : @anshalshukla - Refactor this function
func ExtractErrorFromQueryResponse(message string) error {
	if strings.Contains(message, fmt.Sprint(routertypes.ErrInvalidStartBlockHeight.ABCICode())) {
		return ErrElderBlockHeightLessThanStart
	} else if strings.Contains(message, fmt.Sprint(routertypes.ErrInvalidEndBlockHeight.ABCICode())) {
		return ErrElderBlockHeighMoreThanCurrent
	} else if strings.Contains(message, fmt.Sprint(routertypes.ErrRollNotEnabled.ABCICode())) {
		return ErrRollupIDNotAvailable
	} else {
		return fmt.Errorf("unknown error %v", message)
	}
}

// ConvertEcdsaToSecp256k1PrivKey converts the ECDSA private key to secp256k1 private key
func ConvertEcdsaToSecp256k1PrivKey(ecdsaKey *ecdsa.PrivateKey) *elderutils.Secp256k1PrivateKey {
	// Convert the D value of the ECDSA private key to a byte slice
	keyBytes := ecdsaKey.D.Bytes()

	// Ensure the key is 32 bytes (256 bits) long
	if len(keyBytes) < 32 {
		padding := make([]byte, 32-len(keyBytes))
		keyBytes = append(padding, keyBytes...)
	} else if len(keyBytes) > 32 {
		keyBytes = keyBytes[len(keyBytes)-32:]
	}

	// Create a new secp256k1 private key from the bytes
	privKey := &elderutils.Secp256k1PrivateKey{Key: keyBytes}

	return privKey
}
