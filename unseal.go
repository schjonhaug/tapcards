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

	command := command{Cmd: "unseal"}

	auth, err := tapProtocol.authenticate(cvc, command)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	unsealCommand := unsealCommand{
		command: command,
		auth:    *auth,
		Slot:    tapProtocol.activeSlot,
	}

	data, err := tapProtocol.sendReceive(unsealCommand)

	if err != nil {
		return "", err
	}

	switch data := data.(type) {
	case unsealData:

		fmt.Println("##########")
		fmt.Println("# UNSEAL #")
		fmt.Println("##########")

		fmt.Println("Slot:             ", data.Slot)
		fmt.Printf("Private Key:       %x\n", data.PrivateKey)
		fmt.Printf("Public Key:        %x\n", data.PublicKey)
		fmt.Printf("Master Public Key: %x\n", data.MasterPublicKey)
		fmt.Printf("Chain Code:        %x\n", data.ChainCode)
		fmt.Printf("Card Nonce:        %x\n", data.CardNonce)

		tapProtocol.currentCardNonce = data.CardNonce

		// Calculate and return private key as wif

		unencryptedPrivateKeyBytes := xor(data.PrivateKey[:], tapProtocol.sessionKey[:])

		privateKey, _ := btcec.PrivKeyFromBytes(unencryptedPrivateKeyBytes)

		wif, err := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)

		if err != nil {
			return "", err
		}

		return wif.String(), nil

	case errorData:
		return "", errors.New(data.Error)

	default:
		return "", errors.New("undefined error")

	}

}
