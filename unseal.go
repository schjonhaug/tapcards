package tapprotocol

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func (tapProtocol *TapProtocol) UnsealRequest(cvc string) ([]byte, error) {

	fmt.Println("----------------------------")
	fmt.Println("Unseal")
	fmt.Println("----------------------------")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.Queue.Enqueue("status")
	}

	tapProtocol.Queue.Enqueue("unseal")

	tapProtocol.cvc = cvc

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) unsealRequest() ([]byte, error) {

	command := Command{Cmd: "unseal"}

	auth, err := tapProtocol.authenticate(tapProtocol.cvc, command)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	unsealCommand := unsealCommand{
		Command: command,
		auth:    *auth,
		Slot:    tapProtocol.Satscard.ActiveSlot,
	}

	return tapProtocol.ApduWrap(unsealCommand)

}

func (tapProtocol *TapProtocol) parseUnsealData(unsealData unsealData) error {

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
		return err
	}

	tapProtocol.Satscard.ActiveSlotPrivateKey = wif.String()

	return nil

}
