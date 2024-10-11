package types

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"strings"
	"time"

	registrationtypes "github.com/0xElder/elder/x/registration/types"
	"github.com/0xElder/elder/x/router/keeper"
	routertypes "github.com/0xElder/elder/x/router/types"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdktypes "github.com/cosmos/cosmos-sdk/types"
	eldertx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"golang.org/x/crypto/ripemd160"
	"google.golang.org/grpc"

	"github.com/cosmos/gogoproto/proto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	cosmosmath "cosmossdk.io/math"
	elderregistration "github.com/0xElder/elder/api/elder/registration"
	bech32 "github.com/btcsuite/btcutil/bech32"
	"github.com/ethereum/go-ethereum/log"
)

var (
	ErrElderBlockHeightLessThanStart  = errors.New("block height is less than start")
	ErrElderBlockHeighMoreThanCurrent = errors.New("block height is more than current")
	ErrRollupIDNotAvailable           = errors.New("rollup id not available")
	ErrElderRollAppNotEnabled         = errors.New("rollup app not enabled")
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

	// If the transaction is not signed, set the nonce to 0
	// keep nonce unchanged for double signed tx
	if v == nil || r == nil || s == nil {
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

	message := elderInvalidResp.Message
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

func BuildElderTxFromMsgAndBroadcast(conn *grpc.ClientConn, privateKey secp256k1.PrivKey, msg sdktypes.Msg) (string, error) {
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	cdc := codec.NewProtoCodec(interfaceRegistry)

	// Create a new transaction builder
	txConfig := authtx.NewTxConfig(cdc, authtx.DefaultSignModes)
	txBuilder := txConfig.NewTxBuilder()

	err := txBuilder.SetMsgs(msg)
	if err != nil {
		log.Warn("Failed to set message: %v\n", err)
		return "", err
	}

	// Sign the transaction
	txBytes, err := signTx(conn, privateKey, txConfig, txBuilder)
	if err != nil {
		log.Warn("Failed to sign the transaction: %v\n", err)
		return "", err
	}

	// Simulate the transaction to estimate gas
	gasEstimate, err := simulateElderTx(conn, txBytes)
	if err != nil {
		log.Warn("Failed to simulate the transaction: %v\n", err)
		return "", err
	}

	// Apply a gas adjustment (e.g., 1.5 to add 50% buffer)
	gasAdjustment := 1.5
	adjustedGas := uint64(float64(gasEstimate) * gasAdjustment)

	// Set gas price
	gp := os.Getenv("ELDER_GAS_PRICE")
	var gasPrice float64
	if gp == "" {
		// default gas price
		gasPrice = .01 * math.Pow(10, -6) // .01 uelder/gas
	}

	// Set a fee amount
	feeAmount := cosmosmath.NewInt(int64(math.Ceil((float64(adjustedGas) * gasPrice))))
	fee := sdktypes.NewCoin("elder", feeAmount)

	// Set the gas limit and fee amount in txBuilder
	txBuilder.SetGasLimit(adjustedGas)
	txBuilder.SetFeeAmount(sdktypes.NewCoins(fee))

	// Sign the transaction
	txBytes, err = signTx(conn, privateKey, txConfig, txBuilder)
	if err != nil {
		log.Warn("Failed to sign the transaction: %v\n", err)
		return "", err
	}

	// Broadcast the transaction
	txResponse, err := broadcastElderTx(conn, txBytes)
	if err != nil {
		log.Warn("Failed to broadcast the transaction: %v\n", err)
		return "", err
	}

	if txResponse.Code != 0 {
		log.Warn("Txn failed with status: %d\n", txResponse.Code)
	}

	var count = 0
	for {
		count++
		log.Info("Waiting for tx to be included in a block...")
		time.Sleep(2 * time.Second)
		tx, err := getElderTxFromHash(conn, txResponse.TxHash)
		if count > 10 && err != nil {
			return "", fmt.Errorf("Txn %s not found in elder block, err: %v", txResponse.TxHash, err)
		}
		if tx != nil {
			log.Info("Txn succeeded", "txHash", txResponse.TxHash)
			break
		}
	}

	return txResponse.TxHash, nil
}

func QueryElderForSeqencedBlock(conn *grpc.ClientConn, rollId, rollAppBlockNumber uint64) (*routertypes.QueryTxsByBlockResponse, error) {
	routerClient := routertypes.NewQueryClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Fetch the tx list
	blockReq := &routertypes.QueryTxsByBlockRequest{
		RollId: rollId,
		Block:  int64(rollAppBlockNumber),
	}

	blockRes, err := routerClient.TxsByBlock(ctx, blockReq)
	if err != nil {
		log.Warn("Failed to fetch account info: %v\n", err)
		return nil, err
	}

	return blockRes, nil
}

func QueryElderRollApp(conn *grpc.ClientConn, rollId uint64) (*registrationtypes.Roll, error) {
	registrationClient := registrationtypes.NewQueryClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	rollReq := &registrationtypes.QueryQueryRollRequest{
		Id: rollId,
	}

	// Fetch the roll app
	rollRes, err := registrationClient.QueryRoll(ctx, rollReq)
	if err != nil {
		log.Warn("Failed to fetch roll app: %v\n", err)
		return nil, err
	}

	return rollRes.Roll, nil
}

func QueryElderAccountBalance(conn *grpc.ClientConn, executorPk *secp256k1.PrivKey) (*big.Int, error) {
	bankClient := banktypes.NewQueryClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	address := CosmosPublicKeyToCosmosAddress("elder", hex.EncodeToString(executorPk.PubKey().Bytes()))
	req := banktypes.QueryBalanceRequest{
		Address: address,
		Denom:   "elder",
	}

	res, err := bankClient.Balance(ctx, &req)
	if err != nil {
		log.Warn("Failed to fetch balance: %v\n", err)
		return &big.Int{}, err
	}

	return res.Balance.Amount.BigInt(), nil
}

func signTx(conn *grpc.ClientConn, privateKey secp256k1.PrivKey, txConfig client.TxConfig, txBuilder client.TxBuilder) ([]byte, error) {
	elderAddress := CosmosPublicKeyToCosmosAddress("elder", hex.EncodeToString(privateKey.PubKey().Bytes()))
	// Account and sequence number: Fetch this from your chain (e.g., using gRPC)
	accountNumber, sequenceNumber, err := queryElderAccount(conn, elderAddress)
	if err != nil {
		log.Warn("Failed to fetch account info: %v\n", err)
		return []byte{}, err
	}

	chainId := queryElderChainID(conn)

	signerData := authsigning.SignerData{
		ChainID:       chainId,
		AccountNumber: accountNumber,
		Sequence:      sequenceNumber,
		PubKey:        privateKey.PubKey(),
		Address:       privateKey.PubKey().Address().String(),
	}

	signatureV2 := signing.SignatureV2{
		PubKey: privateKey.PubKey(),
		Data: &signing.SingleSignatureData{
			SignMode:  signing.SignMode(txConfig.SignModeHandler().DefaultMode()),
			Signature: nil,
		},
		Sequence: sequenceNumber,
	}
	err = txBuilder.SetSignatures(signatureV2)
	if err != nil {
		log.Warn("Failed to set signatures: %v\n", err)
		return []byte{}, err
	}

	// Sign the transaction
	signatureV2, err = tx.SignWithPrivKey(
		context.Background(),
		signing.SignMode(txConfig.SignModeHandler().DefaultMode()),
		signerData,
		txBuilder,
		&privateKey,
		txConfig,
		sequenceNumber,
	)
	if err != nil {
		log.Warn("Failed to sign the transaction: %v\n", err)
		return []byte{}, err
	}

	err = txBuilder.SetSignatures(signatureV2)
	if err != nil {
		log.Warn("Failed to set signatures: %v\n", err)
		return []byte{}, err
	}

	// Encode the transaction
	txBytes, err := txConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		log.Warn("Failed to encode the transaction: %v\n", err)
		return []byte{}, err
	}

	return txBytes, nil
}

func queryElderChainID(conn *grpc.ClientConn) string {
	// Create a client for querying the Tendermint chain
	tmClient := cmtservice.NewServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	status, err := tmClient.GetNodeInfo(ctx, &cmtservice.GetNodeInfoRequest{})
	if err != nil {
		log.Warn("Failed to fetch chain info: %v\n", err)
	}

	return status.DefaultNodeInfo.Network
}

func queryElderAccount(conn *grpc.ClientConn, address string) (uint64, uint64, error) {
	// Create a client for querying account data
	authClient := authtypes.NewQueryClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Fetch the account information
	accountReq := &authtypes.QueryAccountRequest{
		Address: address,
	}
	accountRes, err := authClient.Account(ctx, accountReq)
	if err != nil {
		log.Warn("Failed to fetch account info: %v\n", err)
		return 0, 0, err
	}

	// Unmarshal the account info
	var account authtypes.BaseAccount
	err = account.Unmarshal(accountRes.Account.Value)
	if err != nil {
		log.Warn("Failed to unmarshal account info: %v\n", err)
		return 0, 0, err
	}

	return account.AccountNumber, account.Sequence, nil
}

func queryElderRollMinTxFees(conn *grpc.ClientConn, rollId uint64) (uint64, error) {
	// Create a client for querying the roll registration
	registerClient := elderregistration.NewQueryClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Fetch the roll registration
	rollReq := &elderregistration.QueryQueryRollRequest{
		Id: rollId,
	}
	rollRes, err := registerClient.QueryRoll(ctx, rollReq)
	if err != nil {
		log.Warn("Failed to fetch roll registration: %v\n", err)
		return 0, err
	}

	return rollRes.Roll.MinTxFees, nil
}

func broadcastElderTx(conn *grpc.ClientConn, txBytes []byte) (*sdktypes.TxResponse, error) {
	// Broadcast the tx via gRPC. We create a new client for the Protobuf Tx
	// service.
	txClient := eldertx.NewServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// We then call the BroadcastTx method on this client.
	grpcRes, err := txClient.BroadcastTx(
		ctx,
		&eldertx.BroadcastTxRequest{
			Mode:    eldertx.BroadcastMode_BROADCAST_MODE_SYNC,
			TxBytes: txBytes, // Proto-binary of the signed transaction, see previous step.
		},
	)
	if err != nil {
		return &sdktypes.TxResponse{}, err
	}

	log.Info("Tx Broadcasted", "txHash", grpcRes.TxResponse.TxHash)
	return grpcRes.TxResponse, nil
}

func getElderTxFromHash(conn *grpc.ClientConn, txHash string) (*eldertx.Tx, error) {
	// Create a client for querying the Tendermint chain
	txClient := eldertx.NewServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Fetch the transaction
	grpcRes, err := txClient.GetTx(
		ctx,
		&eldertx.GetTxRequest{
			Hash: txHash, // Hash of the transaction
		},
	)
	if err != nil {
		return nil, err
	}

	var rollAppBlock string
	for _, event := range grpcRes.TxResponse.Events {
		if event.Type == "roll_tx_submitted" {
			rollAppBlock = event.Attributes[0].Value
			break
		}
	}

	log.Info("Tx Response Code", "responseCode", grpcRes.TxResponse.Code)
	log.Info("Tx will be included in block of the roll app", "rollAppBlock", rollAppBlock)
	return grpcRes.Tx, nil
}

func simulateElderTx(conn *grpc.ClientConn, txBytes []byte) (uint64, error) {
	// Simulate the tx via gRPC. We create a new client for the Protobuf Tx
	// service.
	txClient := eldertx.NewServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// We then call the SimulateTx method on this client.
	grpcRes, err := txClient.Simulate(
		ctx,
		&eldertx.SimulateRequest{
			TxBytes: txBytes, // Proto-binary of the signed transaction, see previous step.
		},
	)
	if err != nil {
		return 0, err
	}

	return grpcRes.GasInfo.GasUsed, nil
}

func calcTxFees(conn *grpc.ClientConn, txData []byte, rollId uint64) uint64 {
	// Fetch the fees per byte from the chain
	feesPerByte, err := queryElderRollMinTxFees(conn, rollId)
	if err != nil {
		return 0
	}

	return keeper.TxFees(txData, feesPerByte)
}

// PublicKeyToAddress converts secp256k1 public key to a bech32 Tendermint/Cosmos based address
func CosmosPublicKeyToCosmosAddress(addressPrefix, publicKeyString string) string {
	// Decode public key string
	pubKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		log.Warn("Failed to decode public key hex: %v\n", err)
	}

	// Hash pubKeyBytes as: RIPEMD160(SHA256(public_key_bytes))
	pubKeySha256Hash := sha256.Sum256(pubKeyBytes)
	ripemd160hash := ripemd160.New()
	ripemd160hash.Write(pubKeySha256Hash[:])
	addressBytes := ripemd160hash.Sum(nil)

	// Convert addressBytes into a bech32 string
	address := toBech32(addressPrefix, addressBytes)

	return address
}

// Code courtesy: https://github.com/cosmos/cosmos-sdk/blob/90c9c9a9eb4676d05d3f4b89d9a907bd3db8194f/types/bech32/bech32.go#L10
func toBech32(addrPrefix string, addrBytes []byte) string {
	converted, err := bech32.ConvertBits(addrBytes, 8, 5, true)
	if err != nil {
		panic(err)
	}

	addr, err := bech32.Encode(addrPrefix, converted)
	if err != nil {
		panic(err)
	}

	return addr
}
