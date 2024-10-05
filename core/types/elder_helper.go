package types

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"cosmossdk.io/api/cosmos/crypto/secp256k1"
	routertypes "github.com/0xElder/elder/x/router/types"
	eldertx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/gogoproto/proto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	ErrElderBlockHeightLessThanStart  = errors.New("block height is less than start")
	ErrElderBlockHeighMoreThanCurrent = errors.New("block height is more than current")
	ErrRollupIDNotAvailable           = errors.New("rollup id not available")
)

type ElderGetTxByBlockResponse struct {
	RollID string `json:"rollId"`
	Txs    struct {
		Block  string   `json:"block"`
		TxList []string `json:"txList"`
	} `json:"txs"`
	CurrentHeight string `json:"currentHeight"`
}

type ElderGetTxByBlockResponseInvalid struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Details []interface{} `json:"details"`
}

func TxsStringToTxs(txs []string) ([]*Transaction, error) {
	elderInnerTxs := make([]*Transaction, len(txs))
	for i, tx := range txs {
		txBytes, err := Base64toBytes(tx)
		if err != nil {
			return []*Transaction{}, err
		}

		elderInnerTx, err := ElderTxToElderInnerTx(txBytes)
		if err != nil {
			return []*Transaction{}, err
		}

		elderInnerTxs[i] = elderInnerTx
	}
	return elderInnerTxs, nil
}

func Base64toBytes(in string) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return []byte{}, err
	}

	return out, nil
}

func BytesToCosmosTx(rawTxBytes []byte) (*eldertx.Tx, error) {
	var tx eldertx.Tx

	err := tx.Unmarshal(rawTxBytes)
	if err != nil {
		return nil, err
	}

	return &tx, nil
}

func ElderTxToEthTx(rawElderTxBytes []byte) (*Transaction, uint64, string, error) {
	elderTx, err := BytesToCosmosTx(rawElderTxBytes)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid transaction1 %+v: %v", rawElderTxBytes, err)
	}

	accSeq := elderTx.AuthInfo.SignerInfos[0].Sequence
	accPublicKey := elderTx.AuthInfo.SignerInfos[0].PublicKey.Value
	accPublicKeyStr := hex.EncodeToString(accPublicKey)

	cosmMessage := &routertypes.MsgSubmitRollTx{}
	err = proto.Unmarshal(elderTx.Body.Messages[0].Value, cosmMessage)
	if err != nil {
		return nil, 0, "", fmt.Errorf("invalid transaction3 %+v: %v", elderTx, err)
	}

	var tx Transaction
	if err := tx.UnmarshalBinary(cosmMessage.TxData); err != nil {
		return nil, 0, "", fmt.Errorf("invalid transaction4 %+v: %v", elderTx, err)
	}

	fmt.Println("original txHash", tx.Hash().Hex())
	return &tx, accSeq, accPublicKeyStr, nil
}

func ElderTxToElderInnerTx(rawElderTxBytes []byte) (*Transaction, error) {
	tx, accSeq, accPublicKeyStr, err := ElderTxToEthTx(rawElderTxBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction2 %+v: %v", rawElderTxBytes, err)
	}

	elderInnerTx, err := LegacyTxToElderInnerTx(tx, rawElderTxBytes, accSeq, accPublicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction5 %+v: %v", tx, err)
	}

	return elderInnerTx, nil
}

func LegacyTxToElderInnerTx(tx *Transaction, rawElderTxBytes []byte, accSeq uint64, accPublicKeyStr string) (*Transaction, error) {
	v, r, s := tx.RawSignatureValues()
	nonce := tx.Nonce()
	if !tx.IsElderDoubleSignedInnerTx() {
		nonce = 0
	}

	inner := NewTx(&ElderInnerTx{
		ChainID:              tx.ChainId(),
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
	})

	fmt.Println("elder inner txHash", inner.Hash().Hex())
	return inner, nil
}

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

func ElderInnerTxSender(tx *Transaction) (common.Address, error) {
	elderInnerTx := tx.inner.(*ElderInnerTx)
	elderOuterTx, err := BytesToCosmosTx(elderInnerTx.ElderOuterTx)
	if err != nil {
		return common.Address{}, err
	}

	signerCosmos := elderOuterTx.GetAuthInfo()

	cosmosPubKey := &secp256k1.PubKey{}
	err = proto.Unmarshal(signerCosmos.SignerInfos[0].PublicKey.Value, cosmosPubKey)
	if err != nil {
		panic(err)
	}

	cosmosPubKeyStr := hex.EncodeToString(cosmosPubKey.Key)

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

func ExtractErrorFromQueryResponse(responseData []byte) error {
	elderInvalidResp := &ElderGetTxByBlockResponseInvalid{}
	err := json.Unmarshal(responseData, &elderInvalidResp)
	if err != nil {
		return err
	}

	elderErr := fmt.Errorf(elderInvalidResp.Message)
	if routertypes.ErrInvalidStartBlockHeight.Is(elderErr) {
		return ErrElderBlockHeightLessThanStart
	} else if routertypes.ErrInvalidEndBlockHeight.Is(elderErr) {
		return ErrElderBlockHeighMoreThanCurrent
	} else if routertypes.ErrRollNotEnabled.Is(elderErr) {
		return ErrRollupIDNotAvailable
	} else {
		return fmt.Errorf("unknown error %v", elderErr)
	}
}
