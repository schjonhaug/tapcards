package tapprotocol

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func (tapProtocol *TapProtocol) Unseal(cvc string) (string, error) {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.unseal(cvc)

}
func (tapProtocol *TapProtocol) unseal(cvc string) (string, error) {

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.status()
	}

	fmt.Println("----------------------------")
	fmt.Println("Unseal")
	fmt.Println("----------------------------")

	command := Command{Cmd: "unseal"}

	auth, err := tapProtocol.authenticate(cvc, command)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	unsealCommand := unsealCommand{
		Command: command,
		auth:    *auth,
		Slot:    tapProtocol.Satscard.ActiveSlot,
	}

	data, err := tapProtocol.sendReceive(unsealCommand)

	if err != nil {
		return "", err
	}

	unsealData, ok := data.(unsealData)

	if !ok {
		return "", errors.New("incorrect data type")
	}
	fmt.Println("##########")
	fmt.Println("# UNSEAL #")
	fmt.Println("##########")

	fmt.Println("Slot:             ", unsealData.Slot)
	fmt.Printf("Private Key:       %x\n", unsealData.PrivateKey)
	fmt.Printf("Public Key:        %x\n", unsealData.PublicKey)
	fmt.Printf("Master Public Key: %x\n", unsealData.MasterPublicKey)
	fmt.Printf("Chain Code:        %x\n", unsealData.ChainCode)
	fmt.Printf("Card Nonce:        %x\n", unsealData.CardNonce)

	tapProtocol.currentCardNonce = unsealData.CardNonce

	// Calculate and return private key as wif

	unencryptedPrivateKeyBytes := xor(unsealData.PrivateKey[:], tapProtocol.sessionKey[:])

	privateKey, _ := btcec.PrivKeyFromBytes(unencryptedPrivateKeyBytes)

	wif, err := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)

	if err != nil {
		return "", err
	}

	return wif.String(), nil

}
