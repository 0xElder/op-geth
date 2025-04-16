package miner

import (
	"sync/atomic"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// seperate worker file for easier upstream merges

// enableRollApp enables the rollapp sequencing on the elder sequencer
// it assusmes that the rollapp is already registered with the elder
func (w *worker) enableRollApp() {
	w.config.ElderGrpcClient.EnableRollApp(w.config.ElderRollID, w.config.ElderRollStartBlock, &w.config.ElderExecutorPk, w.elderEnableRollAppCh)
}

// query the elder sequencer for the latest block
// if the elder sequencer is not available, the query will fail
func (w *worker) queryFromElder() ([][]byte, error) {
	// current block is the canonical block number. We need to fetch the current building block i.e. current_canon_block + 1
	blockNumberToFetch := w.chain.CurrentBlock().Number.Uint64() + 1
	return w.config.ElderGrpcClient.QueryFromElder(w.config.ElderRollAppEnabled, blockNumberToFetch, w.config.ElderRollID)
}

// fillElderTransactions queries the transaction from elder sequencing after validation
// fills them into the given sealing block. The transaction selection and ordering strategy
// cannot be customized as the sequencing is done by the elder sequencer
// returns true if the elder sequencer should have sequenced the block, false otherwise
func (w *worker) fillElderTransactions(interrupt *atomic.Int32, env *environment) (bool, error) {
	if !w.config.ElderSequencerEnabled {
		return false, nil
	}

	currentBlock := w.chain.CurrentBlock().Number.Uint64()
	if !w.config.ElderRollAppEnabled && w.config.ElderSequencerEnabled {
		rollappStartBlock := w.config.ElderRollStartBlock

		// enable sequencing on elder sequencer when the current building block is 1 block away from the elder start block. Current building block is current_canon_block + 1. Hence, the condition is current_canon_block == elder_start_block - 2
		if currentBlock == rollappStartBlock-2 {
			go w.enableRollApp()
		}

		// since the enable rollapp tx was sent in the previous block, we need to wait for the rollapp to be enabled on elder
		if currentBlock == rollappStartBlock-1 {
			<-w.elderEnableRollAppCh
			log.Info("Roll App sequencing enabled on elder")
			w.config.ElderRollAppEnabled = true
		}
	}

	if !w.config.ElderRollAppEnabled && currentBlock >= w.config.ElderRollStartBlock {
		log.Crit("Roll app has passed start block, elder sequencer should be enabled")
	}

	// current block is the canonical block number. We need to fetch the current building block i.e. current_canon_block + 1
	// checking roll start block with current chain status is necessary as rollapp might be syncing even when the rollapp is enabled
	// enter into the statement even if w.config.ElderRollAppEnabled is false
	if w.config.ElderRollStartBlock <= currentBlock+1 {
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

		// Verify the signatures of the txs
		err = types.VerifyElderTxsSignature(resp, w.config.ElderChainID)
		if err != nil {
			log.Crit("Failed to verify elder sigs", "err", err)
		}

		// Convert the txs to ElderInnerTx types.Transaction
		txs, err := types.TxsBytesToElderInnerTxs(resp, w.chainConfig, w.config.ElderChainID)
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
