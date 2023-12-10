package tapprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func (tapProtocol *TapProtocol) checkRequest() ([]byte, error) {

	nonce, err := tapProtocol.createNonce()

	if err != nil {
		return nil, err
	}

	checkCommand := checkCommand{
		Command: Command{Cmd: "check"},
		Nonce:   nonce,
	}

	return tapProtocol.ApduWrap(checkCommand)

}

func (tapProtocol *TapProtocol) parseCheckData(checkData checkData) error {

	fmt.Println("#########")
	fmt.Println("# CHECK #")
	fmt.Println("#########")

	fmt.Printf("Auth signature: %x\n", checkData.AuthSignature[:])
	fmt.Printf("Card Nonce: %x\n", checkData.CardNonce[:])

	message := append([]byte(openDime), tapProtocol.currentCardNonce[:]...)
	message = append(message, tapProtocol.appNonce[:]...)

	if tapProtocol.currentSlotPublicKey != [33]byte{} {
		fmt.Println("Adding current slot public key")
		message = append(message, tapProtocol.currentSlotPublicKey[:]...)
	}

	messageDigest := sha256.Sum256([]byte(message))

	r := new(btcec.ModNScalar)
	r.SetByteSlice(checkData.AuthSignature[0:32])

	s := new(btcec.ModNScalar)
	s.SetByteSlice(checkData.AuthSignature[32:64])

	signature := ecdsa.NewSignature(r, s)

	publicKey, err := btcec.ParsePubKey(tapProtocol.cardPublicKey[:])

	if err != nil {
		return err
	}

	verified := signature.Verify(messageDigest[:], publicKey)

	if !verified {
		return errors.New("invalid signature certs")
	}

	for i := 0; i < len(tapProtocol.certificateChain); i++ {

		publicKey, err = signatureToPublicKey(tapProtocol.certificateChain[i], publicKey)

		if err != nil {
			return err
		}

	}

	// Convert hex string to bytes
	factoryRootPublicKeyBytes, err := hex.DecodeString(factoryRootPublicKeyString)
	if err != nil {
		log.Fatal(err)
	}

	factoryRootPublicKey, err := btcec.ParsePubKey(factoryRootPublicKeyBytes)

	if err != nil {
		return err
	}

	fmt.Printf("factoryRootPublicKey: %x\n", factoryRootPublicKey.SerializeCompressed())
	fmt.Printf("publicKey:            %x\n", publicKey.SerializeCompressed())

	if !factoryRootPublicKey.IsEqual(publicKey) {
		return errors.New("counterfeit card: invalid factory root public key")

	} else {
		fmt.Println("factoryRootPublicKey matched")
	}

	tapProtocol.currentCardNonce = checkData.CardNonce

	return nil

}
