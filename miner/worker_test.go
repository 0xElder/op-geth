// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"encoding/base64"
	"math/big"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/clique"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/golang/mock/gomock"
	"github.com/holiman/uint256"
	"google.golang.org/grpc"
)

const (
	// testCode is the testing contract binary code which will initialises some
	// variables in constructor
	testCode = "0x60806040527fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0060005534801561003457600080fd5b5060fc806100436000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80630c4dae8814603757806398a213cf146053575b600080fd5b603d607e565b6040518082815260200191505060405180910390f35b607c60048036036020811015606757600080fd5b81019080803590602001909291905050506084565b005b60005481565b806000819055507fe9e44f9f7da8c559de847a3232b57364adc0354f15a2cd8dc636d54396f9587a6000546040518082815260200191505060405180910390a15056fea265627a7a723058208ae31d9424f2d0bc2a3da1a5dd659db2d71ec322a17db8f87e19e209e3a1ff4a64736f6c634300050a0032"

	// testGas is the gas required for contract deployment.
	testGas = 144109
)

var (
	// Test chain configurations
	testTxPoolConfig  legacypool.Config
	ethashChainConfig *params.ChainConfig
	cliqueChainConfig *params.ChainConfig

	// Test accounts
	testBankKey, _  = crypto.GenerateKey()
	testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
	testBankFunds   = big.NewInt(1000000000000000000)

	testUserKey, _  = crypto.GenerateKey()
	testUserAddress = crypto.PubkeyToAddress(testUserKey.PublicKey)

	// Test transactions
	pendingTxs []*types.Transaction
	newTxs     []*types.Transaction

	testConfig = &Config{
		Recommit: time.Second,
		GasCeil:  params.GenesisGasLimit,
	}
)

func init() {
	testTxPoolConfig = legacypool.DefaultConfig
	testTxPoolConfig.Journal = ""
	ethashChainConfig = new(params.ChainConfig)
	*ethashChainConfig = *params.TestChainConfig
	cliqueChainConfig = new(params.ChainConfig)
	*cliqueChainConfig = *params.TestChainConfig
	cliqueChainConfig.Clique = &params.CliqueConfig{
		Period: 10,
		Epoch:  30000,
	}

	signer := types.LatestSigner(params.TestChainConfig)
	tx1 := types.MustSignNewTx(testBankKey, signer, &types.AccessListTx{
		ChainID:  params.TestChainConfig.ChainID,
		Nonce:    0,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	pendingTxs = append(pendingTxs, tx1)

	tx2 := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{
		Nonce:    1,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	newTxs = append(newTxs, tx2)
}

// testWorkerBackend implements worker.Backend interfaces and wraps all information needed during the testing.
type testWorkerBackend struct {
	db      ethdb.Database
	txPool  *txpool.TxPool
	chain   *core.BlockChain
	genesis *core.Genesis
}

func newTestWorkerBackend(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, n int) *testWorkerBackend {
	var gspec = &core.Genesis{
		Config: chainConfig,
		Alloc:  types.GenesisAlloc{testBankAddress: {Balance: testBankFunds}},
	}
	switch e := engine.(type) {
	case *clique.Clique:
		gspec.ExtraData = make([]byte, 32+common.AddressLength+crypto.SignatureLength)
		copy(gspec.ExtraData[32:32+common.AddressLength], testBankAddress.Bytes())
		e.Authorize(testBankAddress, func(account accounts.Account, s string, data []byte) ([]byte, error) {
			return crypto.Sign(crypto.Keccak256(data), testBankKey)
		})
	case *ethash.Ethash:
	default:
		t.Fatalf("unexpected consensus engine type: %T", engine)
	}
	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("core.NewBlockChain failed: %v", err)
	}
	pool := legacypool.New(testTxPoolConfig, chain)
	txpool, _ := txpool.New(testTxPoolConfig.PriceLimit, chain, []txpool.SubPool{pool})

	return &testWorkerBackend{
		db:      db,
		chain:   chain,
		txPool:  txpool,
		genesis: gspec,
	}
}

func (b *testWorkerBackend) BlockChain() *core.BlockChain { return b.chain }
func (b *testWorkerBackend) TxPool() *txpool.TxPool       { return b.txPool }

func (b *testWorkerBackend) newRandomTx(creation bool) *types.Transaction {
	var tx *types.Transaction
	gasPrice := big.NewInt(10 * params.InitialBaseFee)
	if creation {
		tx, _ = types.SignTx(types.NewContractCreation(b.txPool.Nonce(testBankAddress), big.NewInt(0), testGas, gasPrice, common.FromHex(testCode)), types.HomesteadSigner{}, testBankKey)
	} else {
		tx, _ = types.SignTx(types.NewTransaction(b.txPool.Nonce(testBankAddress), testUserAddress, big.NewInt(1000), params.TxGas, gasPrice, nil), types.HomesteadSigner{}, testBankKey)
	}
	return tx
}

func newTestWorker(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, blocks int) (*worker, *testWorkerBackend) {
	backend := newTestWorkerBackend(t, chainConfig, engine, db, blocks)
	backend.txPool.Add(pendingTxs, true, false)
	w := newWorker(testConfig, chainConfig, engine, backend, new(event.TypeMux), nil, false)
	w.setEtherbase(testBankAddress)
	return w, backend
}

func newTestWorkerElder(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, blocks int) (*worker, *testWorkerBackend) {
	chainConfig.ChainID = big.NewInt(77269)
	backend := newTestWorkerBackend(t, chainConfig, engine, db, blocks)
	backend.txPool.Add(pendingTxs, true, false)

	// Mock elder client
	ctrl := gomock.NewController(t)

	elderClientMock := types.NewMockIElderClient(ctrl)

	elderClientMock.EXPECT().Conn().Return(&grpc.ClientConn{}).AnyTimes()
	elderClientMock.EXPECT().CloseElderClient().Return(nil).AnyTimes()
	elderClientMock.EXPECT().EnableRollApp(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return().AnyTimes()

	testConfigElder := &Config{
		Recommit:              time.Second,
		GasCeil:               params.GenesisGasLimit,
		ElderSequencerEnabled: true,
		ElderRollID:           1,
		ElderRollStartBlock:   3,
		ElderExecutorPk:       *types.ConvertEcdsaToSecp256k1PrivKey(testBankKey),
		ElderGrpcClient:       elderClientMock,
		ElderChainID:          "elder_devnet_3",
	}

	w := newWorker(testConfigElder, chainConfig, engine, backend, new(event.TypeMux), nil, false)
	w.setEtherbase(testBankAddress)
	return w, backend
}

func TestGenerateAndImportBlock(t *testing.T) {
	// Added logging to stdout for debugging
	log.SetDefault(log.NewLogger(log.NewTerminalHandler(os.Stderr, true)))

	t.Parallel()
	var (
		db     = rawdb.NewMemoryDatabase()
		config = *params.AllCliqueProtocolChanges
	)
	config.Clique = &params.CliqueConfig{Period: 1, Epoch: 30000}
	engine := clique.New(config.Clique, db)

	w, b := newTestWorker(t, &config, engine, db, 0)
	defer w.close()

	// This test chain imports the mined blocks.
	chain, _ := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, b.genesis, nil, engine, vm.Config{}, nil, nil)
	defer chain.Stop()

	// Ignore empty commit here for less noise.
	w.skipSealHook = func(task *task) bool {
		return len(task.receipts) == 0
	}

	// Wait for mined blocks.
	sub := w.mux.Subscribe(core.NewMinedBlockEvent{})
	defer sub.Unsubscribe()

	// Start mining!
	w.start()

	for i := 0; i < 5; i++ {
		b.txPool.Add([]*types.Transaction{b.newRandomTx(true)}, true, false)
		b.txPool.Add([]*types.Transaction{b.newRandomTx(false)}, true, false)

		select {
		case ev := <-sub.Chan():
			block := ev.Data.(core.NewMinedBlockEvent).Block
			if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
				t.Fatalf("failed to insert new mined block %d: %v", block.NumberU64(), err)
			}
		case <-time.After(3 * time.Second): // Worker needs 1s to include new changes.
			t.Fatalf("timeout")
		}
	}
}

func txsBase64ToBytes(txsBase64 []string) ([][]byte, error) {
	txs := make([][]byte, len(txsBase64))
	for i, txBase64 := range txsBase64 {
		tx, err := base64.StdEncoding.DecodeString(txBase64)
		if err != nil {
			return nil, err
		}
		txs[i] = tx
	}
	return txs, nil
}

func TestGenerateAndImportBlockElder(t *testing.T) {
	// Added logging to stdout for debugging
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelInfo, true)))

	t.Parallel()
	var (
		db     = rawdb.NewMemoryDatabase()
		config = *params.AllCliqueProtocolChanges
	)
	config.Clique = &params.CliqueConfig{Period: 1, Epoch: 30000}
	engine := clique.New(config.Clique, db)

	w, b := newTestWorkerElder(t, &config, engine, db, 0)
	defer w.close()

	// This test chain imports the mined blocks.
	chain, _ := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, b.genesis, nil, engine, vm.Config{}, nil, nil)
	defer chain.Stop()

	// Wait for mined blocks.
	sub := w.mux.Subscribe(core.NewMinedBlockEvent{})
	defer sub.Unsubscribe()

	// Start mining!
	w.start()

	// Sending signal to channel to mimic rollup enabled on Elder
	w.elderEnableRollAppCh <- struct{}{}

	// Txlist derived from Elder response for the following request:

	// const tx = {
	// 	to: "0x000000000000000000000000000000000000dead",
	// 	value: 0
	//   };
	// cosmos signer = "elder1p50czqsrzstsu50q073f4upcfmadvknfrufzmz"
	// signer eth addy = "0x00816f8e1b177ab540be8c38c7d2c8eb55d56a79"

	// {
	// 	"roll_id": "2",
	// 	"txs": {
	// 	"block": "3843420",
	// 	"tx_list": [
	// 	"Cn0KewodL2VsZGVyLnJvdXRlci5Nc2dTdWJtaXRSb2xsVHgSWgosZWxkZXIxcDUwY3pxc3J6c3RzdTUwcTA3M2Y0dXBjZm1hZHZrbmZydWZ6bXoQAhoo54CFBKgXyACDD0JAlAAAAAAAAAAAAAAAAAAAAAAAAN6tgICCpxGAgBJqClAKRgofL2Nvc21vcy5jcnlwdG8uc2VjcDI1NmsxLlB1YktleRIjCiEDha2rv9G4RXTa1YTASxTRiISLtlVJFJWQIpVLykktKGwSBAoCCAEYIBIWChAKBnVlbGRlchIGMjUwMDAwEMCaDBpARDLc50ycOdw1ADFO4H5Fp/xH0O6S2AtD/cWKAHaN7s4RtXJkfTJ9njQyEBXXkln1pa6QDJlkdpVDtrHL/xxw2Q=="
	// 	]
	// 	},
	// 	"current_height": "3843430"
	// 	}

	txList := []string{"Crw6Crk6Ch0vZWxkZXIucm91dGVyLk1zZ1N1Ym1pdFJvbGxUeBKXOgosZWxkZXIxcDUwY3pxc3J6c3RzdTUwcTA3M2Y0dXBjZm1hZHZrbmZydWZ6bXoQARriOQL5HN6DAS3VgIRZaC8AhFloMC6DE9lrgIC5HIJggGBAUjSAFWEAD1dfgP1bUDNgQFGAYEABYEBSgGAKgVJgIAF/VHJlYXRUb2tlbgAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUlBgQFGAYEABYEBSgGAFgVJgIAF/VFJFQVQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUlCBYAOQgWEAjJGQYQbZVltQgGAEkIFhAJyRkGEG2VZbUFBQX3P//////////////////////////xaBc///////////////////////////FgNhAQ9XX2BAUX8eT733AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQEGkZBhB+dWW2BAUYCRA5D9W2EBHoFhAT5gIBtgIBxWW1BhATkzadPCG87M7aEAAABhAgFgIBtgIBxWW2EIvVZbX2AFX5BUkGEBAAqQBHP//////////////////////////xaQUIFgBV9hAQAKgVSBc///////////////////////////AhkWkINz//////////////////////////8WAheQVVCBc///////////////////////////FoFz//////////////////////////8Wf4vgB5xTFlkUE0TNH9Ck8oQZSX+XIqPar+O0GG9rZFfgYEBRYEBRgJEDkKNQUFZbX3P//////////////////////////xaCc///////////////////////////FgNhAnFXX2BAUX/sRC8FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQJokZBhB+dWW2BAUYCRA5D9W2ECgl+Dg2EChmAgG2AgHFZbUFBWW19z//////////////////////////8Wg3P//////////////////////////xYDYQLWV4BgAl+CglRhAsqRkGEILVZbklBQgZBVUGEDpFZbX4BfhXP//////////////////////////xZz//////////////////////////8WgVJgIAGQgVJgIAFfIFSQUIGBEBVhA19Xg4GDYEBRf+RQ04wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgVJgBAFhA1aTkpGQYQhvVltgQFGAkQOQ/VuBgQNfgIZz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyCBkFVQUFtfc///////////////////////////FoJz//////////////////////////8WA2ED61eAYAJfgoJUA5JQUIGQVVBhBDVWW4BfgIRz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBfgoJUAZJQUIGQVVBbgXP//////////////////////////xaDc///////////////////////////Fn/d8lKtG+LIm2nCsGj8N42qlSun8WPEoRYo9VpN9SOz74NgQFFhBJKRkGEIpFZbYEBRgJEDkKNQUFBWW1+BUZBQkZBQVlt/Tkh7cQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfUmBBYARSYCRf/Vt/Tkh7cQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfUmAiYARSYCRf/VtfYAKCBJBQYAGCFoBhBRpXYH+CFpFQW2AgghCBA2EFLVdhBSxhBNZWW1tQkZBQVltfgZBQgV9SYCBfIJBQkZBQVltfYCBgH4MBBJBQkZBQVltfgoIbkFCSkVBQVltfYAiDAmEFj3///////////////////////////////////////////4JhBVRWW2EFmYaDYQVUVluVUIAZhBaTUICGFoQXklBQUJOSUFBQVltfgZBQkZBQVltfgZBQkZBQVltfYQXdYQXYYQXThGEFsVZbYQW6VlthBbFWW5BQkZBQVltfgZBQkZBQVlthBfaDYQXDVlthBgphBgKCYQXkVluEhFRhBWBWW4JVUFBQUFZbX5BWW2EGHmEGElZbYQYpgYSEYQXtVltQUFBWW1uBgRAVYQZMV2EGQV+CYQYWVltgAYEBkFBhBi9WW1BQVltgH4IRFWEGkVdhBmKBYQUzVlthBmuEYQVFVluBAWAghRAVYQZ6V4GQUFthBo5hBoaFYQVFVluDAYJhBi5WW1BQ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////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8gX2EBAAqBVIFg/wIZFpCDYAGBERVhBRxXYQUbYRLAVltbAheQVVBWW1+AX4Nz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBUkFCRkFBWW2EFcGEJe1ZbYQV5X2EKgVZbVltfYAGAgREVYQWPV2EFjmESwFZbW2AGX4Rz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBfkFSQYQEACpAEYP8WYAGBERVhBetXYQXqYRLAVltbFJBQkZBQVltfYAVfkFSQYQEACpAEc///////////////////////////FpBQkFZbYGBgBIBUYQYqkGESKFZbgGAfAWAggJEEAmAgAWBAUZCBAWBAUoCSkZCBgVJgIAGCgFRhBlaQYRIoVluAFWEGoVeAYB8QYQZ4V2EBAICDVAQCg1KRYCABkWEGoVZbggGRkF9SYCBfIJBbgVSBUpBgAQGQYCABgIMRYQaEV4KQA2AfFoIBkVtQUFBQUJBQkFZbX4BhBrVhB+BWW5BQYQbCgYWFYQiLVltgAZFQUJKRUFBWW2g2Ncmtxd6gAACBVltfYAFfhHP//////////////////////////xZz//////////////////////////8WgVJgIAGQgVJgIAFfIF+Dc///////////////////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8gVJBQkpFQUFZbYQdkYQl7Vltfc///////////////////////////FoFz//////////////////////////8WA2EH1FdfYEBRfx5PvfcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgVJgBAFhB8uRkGERpFZbYEBRgJEDkP1bYQfdgWEKgVZbUFZbXzOQUJBWW2EH9IODg2ABYQtEVltQUFBWW19hCASEhGEG2lZbkFB///////////////////////////////////////////+BFGEIhVeBgRAVYQh2V4KBg2BAUX/7j0GyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQhtk5KRkGES7VZbYEBRgJEDkP1bYQiEhISEhANfYQtEVltbUFBQUFZbX3P//////////////////////////xaDc///////////////////////////FgNhCPtXX2BAUX+Wxv0eAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQjykZBhEaRWW2BAUYCRA5D9W19z//////////////////////////8WgnP//////////////////////////xYDYQlrV19gQFF/7EQvBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUmAEAWEJYpGQYRGkVltgQFGAkQOQ/VthCXaDg4NhDRNWW1BQUFZbYQmDYQfgVltz//////////////////////////8WYQmhYQXzVltz//////////////////////////8WFGEKAFdhCcRhB+BWW2BAUX8RjNqnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQn3kZBhEaRWW2BAUYCRA5D9W1ZbX3P//////////////////////////xaCc///////////////////////////FgNhCnJXX2BAUX/sRC8FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQppkZBhEaRWW2BAUYCRA5D9W2EKfV+Dg2ENE1ZbUFBWW19gBV+QVJBhAQAKkARz//////////////////////////8WkFCBYAVfYQEACoFUgXP//////////////////////////wIZFpCDc///////////////////////////FgIXkFVQgXP//////////////////////////xaBc///////////////////////////Fn+L4AecUxZZFBNEzR/QpPKEGUl/lyKj2q/jtBhva2RX4GBAUWBAUYCRA5CjUFBWW19z//////////////////////////8WhHP//////////////////////////xYDYQu0V19gQFF/5gLfBQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBUmAEAWELq5GQYRGkVltgQFGAkQOQ/Vtfc///////////////////////////FoNz//////////////////////////8WA2EMJFdfYEBRf5QoDWIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgVJgBAFhDBuRkGERpFZbYEBRgJEDkP1bgWABX4Zz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBfhXP//////////////////////////xZz//////////////////////////8WgVJgIAGQgVJgIAFfIIGQVVCAFWENDVeCc///////////////////////////FoRz//////////////////////////8Wf4xb4eXr7H1b0U9xQn0ehPPdAxTA97IpHlsgCsjHw7klhGBAUWENBJGQYRDNVltgQFGAkQOQo1tQUFBQVltfc///////////////////////////FoNz//////////////////////////8WA2ENY1eAYAJfgoJUYQ1XkZBhE09WW5JQUIGQVVBhDjFWW1+AX4Vz//////////////////////////8Wc///////////////////////////FoFSYCABkIFSYCABXyBUkFCBgRAVYQ3sV4OBg2BAUX/kUNOMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIFSYAQBYQ3jk5KRkGES7VZbYEBRgJEDkP1bgYEDX4CGc///////////////////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8ggZBVUFBbX3P//////////////////////////xaCc///////////////////////////FgNhDnhXgGACX4KCVAOSUFCBkFVQYQ7CVluAX4CEc///////////////////////////FnP//////////////////////////xaBUmAgAZCBUmAgAV8gX4KCVAGSUFCBkFVQW4Fz//////////////////////////8Wg3P//////////////////////////xZ/3fJSrRviyJtpwrBo/DeNqpUrp/FjxKEWKPVaTfUjs++DYEBRYQ8fkZBhEM1WW2BAUYCRA5CjUFBQVltfgVGQUJGQUFZbX4KCUmAgggGQUJKRUFBWW4KBg15fg4MBUlBQUFZbX2AfGWAfgwEWkFCRkFBWW19hD26CYQ8sVlthD3iBhWEPNlZbk1BhD4iBhWAghgFhD0ZWW2EPkYFhD1RWW4QBkVBQkpFQUFZbX2AgggGQUIGBA1+DAVJhD7SBhGEPZFZbkFCSkVBQVltfgP1bX3P//////////////////////////4IWkFCRkFBWW19hD+mCYQ/AVluQUJGQUFZbYQ/5gWEP31ZbgRRhEANXX4D9W1BWW1+BNZBQYRAUgWEP8FZbkpFQUFZbX4GQUJGQUFZbYRAsgWEQGlZbgRRhEDZXX4D9W1BWW1+BNZBQYRBHgWEQI1ZbkpFQUFZbX4BgQIOFAxIVYRBjV2EQYmEPvFZbW19hEHCFgoYBYRAGVluSUFBgIGEQgYWChgFhEDlWW5FQUJJQkpBQVltfgRUVkFCRkFBWW2EQn4FhEItWW4JSUFBWW19gIIIBkFBhELhfgwGEYRCWVluSkVBQVlthEMeBYRAaVluCUlBQVltfYCCCAZBQYRDgX4MBhGEQvlZbkpFQUFZbX4BfYGCEhgMSFWEQ/VdhEPxhD7xWW1tfYREKhoKHAWEQBlZbk1BQYCBhERuGgocBYRAGVluSUFBgQGERLIaChwFhEDlWW5FQUJJQklCSVltfYP+CFpBQkZBQVlthEUuBYRE2VluCUlBQVltfYCCCAZBQYRFkX4MBhGERQlZbkpFQUFZbX2AggoQDEhVhEX9XYRF+YQ+8VltbX2ERjISChQFhEAZWW5FQUJKRUFBWW2ERnoFhD99WW4JSUFBWW19gIIIBkFBhEbdfgwGEYRGVVluSkVBQVltfgGBAg4UDEhVhEdNXYRHSYQ+8VltbX2ER4IWChgFhEAZWW5JQUGAgYRHxhYKGAWEQBlZbkVBQklCSkFBWW39OSHtxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF9SYCJgBFJgJF/9W19gAoIEkFBgAYIWgGESP1dgf4IWkVBbYCCCEIEDYRJSV2ESUWER+1ZbW1CRkFBWW39BbHJlYWR5IGNsYWltZWQAAAAAAAAAAAAAAAAAAAAAAF+CAVJQVltfYRKMYA+DYQ82VluRUGESl4JhElhWW2AgggGQUJGQUFZbX2AgggGQUIGBA1+DAVJhErmBYRKAVluQUJGQUFZbf05Ie3EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX1JgIWAEUmAkX/1bX2BgggGQUGETAF+DAYZhEZVWW2ETDWAggwGFYRC+VlthExpgQIMBhGEQvlZblJNQUFBQVlt/Tkh7cQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABfUmARYARSYCRf/VtfYRNZgmEQGlZbkVBhE2SDYRAaVluSUIKCAZBQgIIRFWETfFdhE3thEyJWW1uSkVBQVv6iZGlwZnNYIhIgvFN3nEiPA5oFk9D4SJvhP06nZUVlgv5bF0tItgxH7Klkc29sY0MACBoAM8CAoIliRInkWtCMR8RiM7jLlrPAEOCi6LeKZ9PRnfdMg+CIoFO8UL7AIVpCbbR4iuMmtAHhmSbHIsvV5YwcHNACzyHiIAoSawpQCkYKHy9jb3Ntb3MuY3J5cHRvLnNlY3AyNTZrMS5QdWJLZXkSIwohA4Wtq7/RuEV02tWEwEsU0YiEi7ZVSRSVkCKVS8pJLShsEgQKAggBGAQSFwoRCgZ1ZWxkZXISBzE3MTg0NzAQ47g0GkBiOOB+qz3uFpYR7eizttzmeg++KVa2blzG0KcbayzukzeT4v2tARdi4ngx8E4KeTHQtNvQI0oRM1S6b+kkobR1"}

	// Convert base64 encoded transactions to bytes
	txListBytes, err := txsBase64ToBytes(txList)
	if err != nil {
		t.Fatalf("Error : %s", err)
	}
	// empty transactions response from Elder
	w.config.ElderGrpcClient.(*types.MockIElderClient).EXPECT().QueryFromElder(gomock.Any(), gomock.Any(), gomock.Any()).Return(txListBytes, nil).AnyTimes()

	for i := 0; i < 5; i++ {
		select {
		case ev := <-sub.Chan():
			block := ev.Data.(core.NewMinedBlockEvent).Block
			if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
				t.Fatalf("failed to insert new mined block %d: %v", block.NumberU64(), err)
			}
		case <-time.After(3 * time.Second): // Worker needs 1s to include new changes.
			t.Fatalf("timeout")
		}
	}
}

func TestGenerateAndImportBlockElderEmptyTxs(t *testing.T) {
	// Added logging to stdout for debugging
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelInfo, true)))

	t.Parallel()
	var (
		db     = rawdb.NewMemoryDatabase()
		config = *params.AllCliqueProtocolChanges
	)
	config.Clique = &params.CliqueConfig{Period: 1, Epoch: 30000}
	engine := clique.New(config.Clique, db)

	w, b := newTestWorkerElder(t, &config, engine, db, 0)
	defer w.close()

	// This test chain imports the mined blocks.
	chain, _ := core.NewBlockChain(rawdb.NewMemoryDatabase(), nil, b.genesis, nil, engine, vm.Config{}, nil, nil)
	defer chain.Stop()

	// Wait for mined blocks.
	sub := w.mux.Subscribe(core.NewMinedBlockEvent{})
	defer sub.Unsubscribe()

	// Start mining!
	w.start()

	// Sending signal to channel to mimic rollup enabled on Elder
	w.elderEnableRollAppCh <- struct{}{}

	// empty transactions response from Elder
	w.config.ElderGrpcClient.(*types.MockIElderClient).EXPECT().QueryFromElder(gomock.Any(), gomock.Any(), gomock.Any()).Return([][]byte{}, nil).AnyTimes()

	for i := 0; i < 5; i++ {
		select {
		case ev := <-sub.Chan():
			block := ev.Data.(core.NewMinedBlockEvent).Block
			if _, err := chain.InsertChain([]*types.Block{block}); err != nil {
				t.Fatalf("failed to insert new mined block %d: %v", block.NumberU64(), err)
			}
		case <-time.After(3 * time.Second): // Worker needs 1s to include new changes.
			t.Fatalf("timeout")
		}
	}
}

func TestEmptyWorkEthash(t *testing.T) {
	t.Parallel()
	testEmptyWork(t, ethashChainConfig, ethash.NewFaker())
}
func TestEmptyWorkClique(t *testing.T) {
	t.Parallel()
	testEmptyWork(t, cliqueChainConfig, clique.New(cliqueChainConfig.Clique, rawdb.NewMemoryDatabase()))
}

func testEmptyWork(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine) {
	defer engine.Close()

	w, _ := newTestWorker(t, chainConfig, engine, rawdb.NewMemoryDatabase(), 0)
	defer w.close()

	taskCh := make(chan struct{}, 2)
	checkEqual := func(t *testing.T, task *task) {
		// The work should contain 1 tx
		receiptLen, balance := 1, uint256.NewInt(1000)
		if len(task.receipts) != receiptLen {
			t.Fatalf("receipt number mismatch: have %d, want %d", len(task.receipts), receiptLen)
		}
		if task.state.GetBalance(testUserAddress).Cmp(balance) != 0 {
			t.Fatalf("account balance mismatch: have %d, want %d", task.state.GetBalance(testUserAddress), balance)
		}
	}
	w.newTaskHook = func(task *task) {
		if task.block.NumberU64() == 1 {
			checkEqual(t, task)
			taskCh <- struct{}{}
		}
	}
	w.skipSealHook = func(task *task) bool { return true }
	w.fullTaskHook = func() {
		time.Sleep(100 * time.Millisecond)
	}
	w.start() // Start mining!
	select {
	case <-taskCh:
	case <-time.NewTimer(3 * time.Second).C:
		t.Error("new task timeout")
	}
}

func TestAdjustIntervalEthash(t *testing.T) {
	t.Parallel()
	testAdjustInterval(t, ethashChainConfig, ethash.NewFaker())
}

func TestAdjustIntervalClique(t *testing.T) {
	t.Parallel()
	testAdjustInterval(t, cliqueChainConfig, clique.New(cliqueChainConfig.Clique, rawdb.NewMemoryDatabase()))
}

func testAdjustInterval(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine) {
	defer engine.Close()

	w, _ := newTestWorker(t, chainConfig, engine, rawdb.NewMemoryDatabase(), 0)
	defer w.close()

	w.skipSealHook = func(task *task) bool {
		return true
	}
	w.fullTaskHook = func() {
		time.Sleep(100 * time.Millisecond)
	}
	var (
		progress = make(chan struct{}, 10)
		result   = make([]float64, 0, 10)
		index    = 0
		start    atomic.Bool
	)
	w.resubmitHook = func(minInterval time.Duration, recommitInterval time.Duration) {
		// Short circuit if interval checking hasn't started.
		if !start.Load() {
			return
		}
		var wantMinInterval, wantRecommitInterval time.Duration

		switch index {
		case 0:
			wantMinInterval, wantRecommitInterval = 3*time.Second, 3*time.Second
		case 1:
			origin := float64(3 * time.Second.Nanoseconds())
			estimate := origin*(1-intervalAdjustRatio) + intervalAdjustRatio*(origin/0.8+intervalAdjustBias)
			wantMinInterval, wantRecommitInterval = 3*time.Second, time.Duration(estimate)*time.Nanosecond
		case 2:
			estimate := result[index-1]
			min := float64(3 * time.Second.Nanoseconds())
			estimate = estimate*(1-intervalAdjustRatio) + intervalAdjustRatio*(min-intervalAdjustBias)
			wantMinInterval, wantRecommitInterval = 3*time.Second, time.Duration(estimate)*time.Nanosecond
		case 3:
			// lower than upstream test, since enforced min recommit interval is lower
			wantMinInterval, wantRecommitInterval = 500*time.Millisecond, 500*time.Millisecond
		}

		// Check interval
		if minInterval != wantMinInterval {
			t.Errorf("resubmit min interval mismatch: have %v, want %v ", minInterval, wantMinInterval)
		}
		if recommitInterval != wantRecommitInterval {
			t.Errorf("resubmit interval mismatch: have %v, want %v", recommitInterval, wantRecommitInterval)
		}
		result = append(result, float64(recommitInterval.Nanoseconds()))
		index += 1
		progress <- struct{}{}
	}
	w.start()

	time.Sleep(time.Second) // Ensure two tasks have been submitted due to start opt
	start.Store(true)

	w.setRecommitInterval(3 * time.Second)
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}

	w.resubmitAdjustCh <- &intervalAdjust{inc: true, ratio: 0.8}
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}

	w.resubmitAdjustCh <- &intervalAdjust{inc: false}
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}

	w.setRecommitInterval(500 * time.Millisecond)
	select {
	case <-progress:
	case <-time.NewTimer(time.Second).C:
		t.Error("interval reset timeout")
	}
}

func TestGetSealingWorkEthash(t *testing.T) {
	t.Parallel()
	testGetSealingWork(t, ethashChainConfig, ethash.NewFaker())
}

func TestGetSealingWorkClique(t *testing.T) {
	t.Parallel()
	testGetSealingWork(t, cliqueChainConfig, clique.New(cliqueChainConfig.Clique, rawdb.NewMemoryDatabase()))
}

func TestGetSealingWorkPostMerge(t *testing.T) {
	t.Parallel()
	local := new(params.ChainConfig)
	*local = *ethashChainConfig
	local.TerminalTotalDifficulty = big.NewInt(0)
	testGetSealingWork(t, local, ethash.NewFaker())
}

func testGetSealingWork(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine) {
	defer engine.Close()

	w, b := newTestWorker(t, chainConfig, engine, rawdb.NewMemoryDatabase(), 0)
	defer w.close()

	w.setExtra([]byte{0x01, 0x02})

	w.skipSealHook = func(task *task) bool {
		return true
	}
	w.fullTaskHook = func() {
		time.Sleep(100 * time.Millisecond)
	}
	timestamp := uint64(time.Now().Unix())
	assertBlock := func(block *types.Block, number uint64, coinbase common.Address, random common.Hash) {
		if block.Time() != timestamp {
			// Sometime the timestamp will be mutated if the timestamp
			// is even smaller than parent block's. It's OK.
			t.Logf("Invalid timestamp, want %d, get %d", timestamp, block.Time())
		}
		_, isClique := engine.(*clique.Clique)
		if !isClique {
			if len(block.Extra()) != 2 {
				t.Error("Unexpected extra field")
			}
			if block.Coinbase() != coinbase {
				t.Errorf("Unexpected coinbase got %x want %x", block.Coinbase(), coinbase)
			}
		} else {
			if block.Coinbase() != (common.Address{}) {
				t.Error("Unexpected coinbase")
			}
		}
		if !isClique {
			if block.MixDigest() != random {
				t.Error("Unexpected mix digest")
			}
		}
		if block.Nonce() != 0 {
			t.Error("Unexpected block nonce")
		}
		if block.NumberU64() != number {
			t.Errorf("Mismatched block number, want %d got %d", number, block.NumberU64())
		}
	}
	var cases = []struct {
		parent       common.Hash
		coinbase     common.Address
		random       common.Hash
		expectNumber uint64
		expectErr    bool
	}{
		{
			b.chain.Genesis().Hash(),
			common.HexToAddress("0xdeadbeef"),
			common.HexToHash("0xcafebabe"),
			uint64(1),
			false,
		},
		{
			b.chain.CurrentBlock().Hash(),
			common.HexToAddress("0xdeadbeef"),
			common.HexToHash("0xcafebabe"),
			b.chain.CurrentBlock().Number.Uint64() + 1,
			false,
		},
		{
			b.chain.CurrentBlock().Hash(),
			common.Address{},
			common.HexToHash("0xcafebabe"),
			b.chain.CurrentBlock().Number.Uint64() + 1,
			false,
		},
		{
			b.chain.CurrentBlock().Hash(),
			common.Address{},
			common.Hash{},
			b.chain.CurrentBlock().Number.Uint64() + 1,
			false,
		},
		{
			common.HexToHash("0xdeadbeef"),
			common.HexToAddress("0xdeadbeef"),
			common.HexToHash("0xcafebabe"),
			0,
			true,
		},
	}

	// This API should work even when the automatic sealing is not enabled
	for _, c := range cases {
		r := w.getSealingBlock(&generateParams{
			parentHash:  c.parent,
			timestamp:   timestamp,
			coinbase:    c.coinbase,
			random:      c.random,
			withdrawals: nil,
			beaconRoot:  nil,
			noTxs:       false,
			forceTime:   true,
		})
		if c.expectErr {
			if r.err == nil {
				t.Error("Expect error but get nil")
			}
		} else {
			if r.err != nil {
				t.Errorf("Unexpected error %v", r.err)
			}
			assertBlock(r.block, c.expectNumber, c.coinbase, c.random)
		}
	}

	// This API should work even when the automatic sealing is enabled
	w.start()
	for _, c := range cases {
		r := w.getSealingBlock(&generateParams{
			parentHash:  c.parent,
			timestamp:   timestamp,
			coinbase:    c.coinbase,
			random:      c.random,
			withdrawals: nil,
			beaconRoot:  nil,
			noTxs:       false,
			forceTime:   true,
		})
		if c.expectErr {
			if r.err == nil {
				t.Error("Expect error but get nil")
			}
		} else {
			if r.err != nil {
				t.Errorf("Unexpected error %v", r.err)
			}
			assertBlock(r.block, c.expectNumber, c.coinbase, c.random)
		}
	}
}
