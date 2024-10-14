// Copyright 2021 The go-ethereum Authors
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

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

const ElderInnerTxType = 0x65

type ElderInnerTx struct {
	ChainID    *big.Int
	Nonce      uint64
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList AccessList

	// Signature values
	V *big.Int
	R *big.Int
	S *big.Int

	// ElderOuterTx contains the outer transaction that wraps this inner transaction. It is required to verify the signatures as outer tx is the signed tx.
	ElderOuterTx         []byte
	ElderAccountSequence uint64
	ElderPublicKey       string
	ElderStatus          bool // default true
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *ElderInnerTx) copy() TxData {
	cpy := &ElderInnerTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are copied below.
		AccessList:           make(AccessList, len(tx.AccessList)),
		Value:                new(big.Int),
		ChainID:              new(big.Int),
		V:                    new(big.Int),
		R:                    new(big.Int),
		S:                    new(big.Int),
		ElderOuterTx:         common.CopyBytes(tx.ElderOuterTx),
		ElderAccountSequence: tx.ElderAccountSequence,
		ElderPublicKey:       tx.ElderPublicKey,
		ElderStatus:          tx.ElderStatus,
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

// accessors for innerTx.
func (tx *ElderInnerTx) txType() byte           { return ElderInnerTxType }
func (tx *ElderInnerTx) chainID() *big.Int      { return tx.ChainID }
func (tx *ElderInnerTx) accessList() AccessList { return tx.AccessList }
func (tx *ElderInnerTx) data() []byte           { return tx.Data }
func (tx *ElderInnerTx) gas() uint64            { return tx.Gas }
func (tx *ElderInnerTx) gasFeeCap() *big.Int    { return common.Big0 }
func (tx *ElderInnerTx) gasTipCap() *big.Int    { return common.Big0 }
func (tx *ElderInnerTx) gasPrice() *big.Int     { return common.Big0 }
func (tx *ElderInnerTx) value() *big.Int        { return tx.Value }
func (tx *ElderInnerTx) nonce() uint64          { return tx.Nonce }
func (tx *ElderInnerTx) to() *common.Address    { return tx.To }
func (tx *ElderInnerTx) isSystemTx() bool       { return false }

func (tx *ElderInnerTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	return dst.Set(new(big.Int))
}

func (tx *ElderInnerTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *ElderInnerTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.V, tx.R, tx.S = v, r, s
}

func (tx *ElderInnerTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *ElderInnerTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
