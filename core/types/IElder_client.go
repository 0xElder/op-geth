package types

import (
	"math/big"

	elderutils "github.com/0xElder/elder/utils"
	registrationtypes "github.com/0xElder/elder/x/registration/types"
	routertypes "github.com/0xElder/elder/x/router/types"
	"google.golang.org/grpc"
)

type IElderClient interface {
	EnableRollApp(rollId uint64, rollStartBlock uint64, executorPk *elderutils.Secp256k1PrivateKey, elderEnableRollAppCh chan struct{})
	QueryElderChainID() string
	QueryFromElder(rollAppEnabled bool, currBlock uint64, rollId uint64) ([][]byte, error)
	QueryElderForSeqencedBlock(rollId, rollAppBlockNumber uint64) (*routertypes.QueryTxsByBlockResponse, error)
	QueryElderRollApp(rollId uint64) (*registrationtypes.Roll, error)
	QueryElderAccountBalance(executorPk *elderutils.Secp256k1PrivateKey) (*big.Int, error)
	Conn() *grpc.ClientConn
	CloseElderClient() error
}
