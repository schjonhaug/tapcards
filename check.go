package tapcards

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"

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

	return apduWrap(checkCommand)

}

func (tapProtocol *TapProtocol) parseCheckData(checkData checkData) error {

	slog.Debug("Parse check")

	slog.Debug("CHECK", "AuthSignature", fmt.Sprintf("%x", checkData.AuthSignature[:]))
	slog.Debug("CHECK", "CardNonce", fmt.Sprintf("%x", checkData.CardNonce[:]))

	message := append([]byte(openDime), tapProtocol.currentCardNonce[:]...)
	message = append(message, tapProtocol.appNonce[:]...)

	if tapProtocol.currentSlotPublicKey != [33]byte{} {
		slog.Debug("Adding current slot public key")
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

	if !factoryRootPublicKey.IsEqual(publicKey) {

		slog.Debug("CHECK", "FactoryRootPublicKey", fmt.Sprintf("%x", factoryRootPublicKey.SerializeCompressed()))
		slog.Debug("CHECK", "PublicKey", fmt.Sprintf("%x", publicKey.SerializeCompressed()))

		return errors.New("counterfeit card: invalid factory root public key")

	}

	tapProtocol.currentCardNonce = checkData.CardNonce

	return nil

}
