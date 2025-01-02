package types

import (
	"math/big"

	registrationtypes "github.com/0xElder/elder/x/registration/types"
	routertypes "github.com/0xElder/elder/x/router/types"
	"google.golang.org/grpc"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

type IElderClient interface {
	EnableRollApp(rollId uint64, rollStartBlock uint64, executorPk *secp256k1.PrivKey, elderEnableRollAppCh chan struct{})
	QueryFromElder(rollAppEnabled bool, currBlock uint64, rollId uint64) ([][]byte, error)
	QueryElderForSeqencedBlock(rollId, rollAppBlockNumber uint64) (*routertypes.QueryTxsByBlockResponse, error)
	QueryElderRollApp(rollId uint64) (*registrationtypes.Roll, error)
	QueryElderAccountBalance(executorPk *secp256k1.PrivKey) (*big.Int, error)
	Conn() *grpc.ClientConn
	CloseElderClient() error
}
