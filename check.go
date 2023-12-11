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

func (satscard *Satscard) checkRequest() ([]byte, error) {

	nonce, err := satscard.createNonce()

	if err != nil {
		return nil, err
	}

	checkCommand := checkCommand{
		command: command{Cmd: "check"},
		Nonce:   nonce,
	}

	return apduWrap(checkCommand)

}

func (satscard *Satscard) parseCheckData(checkData checkData) error {

	slog.Debug("Parse check")

	slog.Debug("CHECK", "AuthSignature", fmt.Sprintf("%x", checkData.AuthSignature[:]))
	slog.Debug("CHECK", "CardNonce", fmt.Sprintf("%x", checkData.CardNonce[:]))

	message := append([]byte(openDime), satscard.currentCardNonce[:]...)
	message = append(message, satscard.appNonce[:]...)

	if satscard.activeSlotPublicKey != [33]byte{} {
		slog.Debug("Adding current slot public key")
		message = append(message, satscard.activeSlotPublicKey[:]...)
	}

	messageDigest := sha256.Sum256([]byte(message))

	r := new(btcec.ModNScalar)
	r.SetByteSlice(checkData.AuthSignature[0:32])

	s := new(btcec.ModNScalar)
	s.SetByteSlice(checkData.AuthSignature[32:64])

	signature := ecdsa.NewSignature(r, s)

	publicKey, err := btcec.ParsePubKey(satscard.cardPublicKey[:])

	if err != nil {
		return err
	}

	verified := signature.Verify(messageDigest[:], publicKey)

	if !verified {
		return errors.New("invalid signature certs")
	}

	for i := 0; i < len(satscard.certificateChain); i++ {

		publicKey, err = signatureToPublicKey(satscard.certificateChain[i], publicKey)

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

	satscard.currentCardNonce = checkData.CardNonce

	return nil

}
