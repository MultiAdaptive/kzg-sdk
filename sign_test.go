package kzg_sdk

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestEIP155FdSigning(t *testing.T) {
	key, _ := crypto.GenerateKey()
	subAddr := crypto.PubkeyToAddress(key.PublicKey)
	signer := NewEIP155FdSigner(big.NewInt(18))

	key1, _ := crypto.GenerateKey()
	senAddr := crypto.PubkeyToAddress(key1.PublicKey)

	index := 1
	length := 10
	gasPrice := 10
	commit := []byte("commit")

	//sign 
	signHash,signData,err := SignFd(senAddr,subAddr,uint64(index),uint64(length),uint64(gasPrice),commit,signer, key)
	if err != nil {
		t.Errorf("err-----1 %x",err.Error())
	}

	// verify
	from, err := FdSender(signer,signData,signHash)
	if err != nil {
		println("err----",err.Error())
	}
	if from != subAddr {
		t.Errorf("exected from and address to be equal. Got %x want %x", from, subAddr)
	}
}



func TestHomesteadFdSigner(t *testing.T) {
	key, _ := crypto.GenerateKey()
	subAddr := crypto.PubkeyToAddress(key.PublicKey)
	signer := HomesteadFdSigner{}

	key1, _ := crypto.GenerateKey()
	senAddr := crypto.PubkeyToAddress(key1.PublicKey)

	index := 1
	length := 10
	gasPrice := 10
	commit := []byte("commit")
	
	signHash,signData,err := SignFd(senAddr,subAddr,uint64(index),uint64(length),uint64(gasPrice),commit,signer, key)
	if err != nil {
		t.Errorf("err-----1 %x",err.Error())
	}

	from, err := FdSender(signer,signData,signHash)
	if err != nil {
		println("err----",err.Error())
	}

	if from != subAddr {
		t.Errorf("exected from and address to be equal. Got %x want %x", from, subAddr)
	}
}
