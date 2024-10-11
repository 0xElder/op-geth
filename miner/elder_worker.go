package miner

import (
	"encoding/hex"

	eldertypes "github.com/0xElder/elder/x/registration/types"
	elderhelper "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// Seperate worker file for easier upstream merges
func (w *worker) enableRollApp() {
	executorAddress := elderhelper.CosmosPublicKeyToCosmosAddress("elder", hex.EncodeToString(w.config.ElderExecutorPk.PubKey().Bytes()))
	msg := eldertypes.MsgEnableRoll{
		Sender:         executorAddress,
		RollID:         w.config.ElderRollID,
		RollStartBlock: w.config.ElderRollStartBlock,
	}

	res, err := elderhelper.BuildElderTxFromMsgAndBroadcast(w.config.ElderGrpcClientConn, w.config.ElderExecutorPk, &msg)
	if res == "" || err != nil {
		log.Crit("Failed to enable rollapp sequencing in elder", "err", err)
		w.elderEnableRollAppFailedCh <- struct{}{}
		return
	}

	w.elderEnableRollAppCh <- struct{}{}
}
