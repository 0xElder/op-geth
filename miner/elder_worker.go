package miner

import (
	"encoding/hex"
	"sync/atomic"

	eldertypes "github.com/0xElder/elder/x/registration/types"
	"github.com/ethereum/go-ethereum/core/types"
	elderhelper "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// seperate worker file for easier upstream merges

// enableRollApp enables the rollapp sequencing on the elder sequencer
// it assusmes that the rollapp is already registered with the elder
func (w *worker) enableRollApp() {
	executorAddress := elderhelper.CosmosPublicKeyToCosmosAddress("elder", hex.EncodeToString(w.config.ElderExecutorPk.PubKey().Bytes()))
	msg := eldertypes.MsgEnableRoll{
		Sender:         executorAddress,
		RollId:         w.config.ElderRollID,
		RollStartBlock: w.config.ElderRollStartBlock,
	}

	res, err := elderhelper.BuildElderTxFromMsgAndBroadcast(w.config.ElderGrpcClientConn, w.config.ElderExecutorPk, &msg)
	if res == "" || err != nil {
		log.Crit("Failed to enable rollapp sequencing in elder", "err", err)
	}

	w.elderEnableRollAppCh <- struct{}{}
}

// query the elder sequencer for the latest block
// if the elder sequencer is not available, the query will fail
func (w *worker) queryFromElder() ([][]byte, error) {
	if !w.config.ElderRollAppEnabled {
		return nil, types.ErrElderRollAppNotEnabled
	}
	currBlock := w.chain.CurrentBlock().Number.Uint64()

	response, err := elderhelper.QueryElderForSeqencedBlock(w.config.ElderGrpcClientConn, w.config.ElderRollID, currBlock)
	if err != nil {
		return nil, types.ExtractErrorFromQueryResponse(err.Error())
	}

	// elder yet to sequence block if
	// requested roll app block > last sequenced roll app block on elder
	if uint64(response.CurrentHeight) < currBlock {
		return nil, types.ErrElderBlockHeighMoreThanCurrent
	}

	return response.Txs.TxList, nil
}

// fillElderTransactions queries the transaction from elder sequencing after validation
// fills them into the given sealing block. The transaction selection and ordering strategy
// cannot be customized as the sequencing is done by the elder sequencer
// returns true if the elder sequencer should have sequenced the block, false otherwise
func (w *worker) fillElderTransactions(interrupt *atomic.Int32, env *environment) (bool, error) {
	currentBlock := w.chain.CurrentBlock().Number.Uint64()
	if !w.config.ElderRollAppEnabled && w.config.ElderSequencerEnabled {
		rollappStartBlock := w.config.ElderRollStartBlock

		if currentBlock == rollappStartBlock-1 {
			go w.enableRollApp()
		}

		if currentBlock == rollappStartBlock {
			select {
			case <-w.elderEnableRollAppCh:
				log.Info("Roll App sequencing enabled on elder")
				w.config.ElderRollAppEnabled = true
			}
		}
	}

	if w.config.ElderSequencerEnabled && !w.config.ElderSequencerEnabled && currentBlock >= w.config.ElderRollStartBlock {
		log.Crit("Roll app has passed start block, elder sequencer should be enabled")
	}

	// checking roll start block with current chain status is necessary as rollapp might be syncing even when the rollapp is enabled
	// enter into the statement even if w.config.ElderRollAppEnabled is false
	if w.config.ElderSequencerEnabled && w.config.ElderRollStartBlock <= currentBlock {
		resp, err := w.queryFromElder()
		if err != nil {
			switch err {
			case types.ErrElderBlockHeightLessThanStart:
				log.Info("Block height less than elder start block, building normal block")
				return false, nil
			case types.ErrRollupIDNotAvailable:
				log.Warn("Rollup ID not available")
				return false, nil
			case types.ErrElderBlockHeighMoreThanCurrent:
				return true, errBlockInterruptedByElder
			case types.ErrElderRollAppNotEnabled:
				return true, errRollAppNotEnabledOnElder
			default:
				return true, errUnableToQueryElder
			}
		}

		txs, err := types.TxsBytesToTxs(resp, w.chainConfig.ChainID)
		if err != nil {
			log.Crit("Failed to convert txs to bytes", "err", err)
		}
		log.Info("Filling elder transactions", "txs", len(txs))
		if err := w.commitElderTransactions(env, txs, interrupt); err != nil {
			log.Crit("Failed to commit elder transactions", "err", err)
		}
		return true, nil
	}
	return false, nil
}
