package types

import (
	"context"
	"math/big"
	"time"

	"github.com/0xElder/elder/utils"
	registrationtypes "github.com/0xElder/elder/x/registration/types"
	routertypes "github.com/0xElder/elder/x/router/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/grpc"
)

type ElderClient struct {
	conn *grpc.ClientConn
}

// EnableRollApp implements IElderClient.
func (ec ElderClient) EnableRollApp(rollId uint64, rollStartBlock uint64, executorPk *secp256k1.PrivKey, elderEnableRollAppCh chan struct{}) {
	executorAddress := utils.CosmosPublicKeyToBech32Address("elder", executorPk.PubKey())
	msg := registrationtypes.MsgEnableRoll{
		Sender:         executorAddress,
		RollId:         rollId,
		RollStartBlock: rollStartBlock,
	}

	authClient := utils.AuthClient(ec.conn)
	tmClient := utils.TmClient(ec.conn)
	txClient := utils.TxClient(ec.conn)

	res, err := utils.BuildElderTxFromMsgAndBroadcast(authClient, tmClient, txClient, *executorPk, &msg, 3)
	if res == "" || err != nil {
		log.Crit("Failed to enable rollapp sequencing in elder", "err", err)
	}

	elderEnableRollAppCh <- struct{}{}
}

// QueryElderAccountBalance implements IElderClient.
func (ec ElderClient) QueryElderAccountBalance(executorPk *secp256k1.PrivKey) (*big.Int, error) {
	bankClient := banktypes.NewQueryClient(ec.conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	address := utils.CosmosPublicKeyToBech32Address("elder", executorPk.PubKey())
	req := banktypes.QueryBalanceRequest{
		Address: address,
		Denom:   "uelder",
	}

	res, err := bankClient.Balance(ctx, &req)
	if err != nil {
		log.Warn("Failed to fetch balance", "err", err)
		return &big.Int{}, err
	}

	return res.Balance.Amount.BigInt(), nil
}

// QueryElderForSeqencedBlock implements IElderClient.
func (ec ElderClient) QueryElderForSeqencedBlock(rollId uint64, rollAppBlockNumber uint64) (*routertypes.QueryTxsByBlockResponse, error) {
	routerClient := routertypes.NewQueryClient(ec.conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Fetch the tx list
	blockReq := &routertypes.QueryTxsByBlockRequest{
		RollId: rollId,
		Block:  int64(rollAppBlockNumber),
	}

	blockRes, err := routerClient.TxsByBlock(ctx, blockReq)
	if err != nil {
		return nil, err
	}

	return blockRes, nil
}

// QueryElderRollApp implements IElderClient.
func (ec ElderClient) QueryElderRollApp(rollId uint64) (*registrationtypes.Roll, error) {
	registrationClient := registrationtypes.NewQueryClient(ec.conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	rollReq := &registrationtypes.QueryQueryRollRequest{
		Id: rollId,
	}

	// Fetch the roll app
	rollRes, err := registrationClient.QueryRoll(ctx, rollReq)
	if err != nil {
		log.Warn("Failed to fetch roll app", "err", err)
		return nil, err
	}

	return rollRes.Roll, nil
}

// QueryFromElder implements IElderClient.
func (ec ElderClient) QueryFromElder(rollAppEnabled bool, currBlock uint64, rollId uint64) ([][]byte, error) {
	if !rollAppEnabled {
		return nil, ErrElderRollAppNotEnabled
	}

	response, err := ec.QueryElderForSeqencedBlock(rollId, currBlock)
	if err != nil {
		return nil, ExtractErrorFromQueryResponse(err.Error())
	}

	// elder yet to sequence block if
	// requested roll app block > last sequenced roll app block on elder
	if uint64(response.CurrentHeight) < currBlock {
		return nil, ErrElderBlockHeighMoreThanCurrent
	}

	return response.Txs.TxList, nil
}

// CloseElderClient closes the connection to the ElderClient.
func (ec ElderClient) CloseElderClient() error {
	return ec.conn.Close()

}

// Conn returns the connection to the ElderClient.
func (ec ElderClient) Conn() *grpc.ClientConn {
	return ec.conn
}

// Creates a new ElderClient.
func NewElderClient(conn *grpc.ClientConn) *ElderClient {
	return &ElderClient{
		conn: conn,
	}
}
