package types

import (
	"context"
	"math/big"
	"time"

	elderutils "github.com/0xElder/elder/utils"
	registrationtypes "github.com/0xElder/elder/x/registration/types"
	routertypes "github.com/0xElder/elder/x/router/types"
	"github.com/ethereum/go-ethereum/log"
	"google.golang.org/grpc"
)

type ElderClient struct {
	conn *grpc.ClientConn
}

// QueryElderAccountBalance implements IElderClient.
func (ec ElderClient) QueryElderAccountBalance(executorPk *elderutils.Secp256k1PrivateKey) (*big.Int, error) {
	return elderutils.QueryElderAccountBalance(elderutils.BankClient(ec.conn), executorPk)
}

// QueryElderRollApp implements IElderClient.
func (ec ElderClient) QueryElderRollApp(rollId uint64) (*registrationtypes.Roll, error) {
	return elderutils.QueryElderRollApp(registrationtypes.NewQueryClient(ec.conn), rollId)
}

// EnableRollApp implements IElderClient.
func (ec ElderClient) EnableRollApp(rollId uint64, rollStartBlock uint64, executorPk *elderutils.Secp256k1PrivateKey, elderEnableRollAppCh chan struct{}) {
	executorAddress := elderutils.CosmosPublicKeyToBech32Address("elder", executorPk.PubKey())
	msg := registrationtypes.MsgEnableRoll{
		Sender:         executorAddress,
		RollId:         rollId,
		RollStartBlock: rollStartBlock,
	}

	authClient := elderutils.AuthClient(ec.conn)
	tmClient := elderutils.TmClient(ec.conn)
	txClient := elderutils.TxClient(ec.conn)

	res, err := elderutils.BuildElderTxFromMsgAndBroadcast(authClient, tmClient, txClient, *executorPk, &msg, 3)
	if res == "" || err != nil {
		log.Crit("Failed to enable rollapp sequencing in elder", "err", err)
	}

	elderEnableRollAppCh <- struct{}{}
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
