package cktap

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func (satscard *Satscard) ReadRequest() ([]byte, error) {

	slog.Debug("Request read")

	if satscard.currentCardNonce == [16]byte{} {

		satscard.queue.enqueue("status")
	}

	satscard.queue.enqueue("read")

	return satscard.nextCommand()

}

func (satscard *Satscard) readRequest() ([]byte, error) {

	command := command{Cmd: "read"}

	nonce, err := satscard.createNonce()

	if err != nil {
		return nil, err
	}

	readCommand := readCommand{
		command: command,
		Nonce:   nonce,
	}

	return apduWrap(readCommand)

}

// READ
// read a SATSCARD’s current payment address
func (satscard *Satscard) parseReadData(readData readData) error {

	slog.Debug("Parse read")

	slog.Debug("READ", "Signature", fmt.Sprintf("%x", readData.Signature))
	slog.Debug("READ", "PublicKey", fmt.Sprintf("%x", readData.PublicKey))

	// Verify public key with signature

	message := append([]byte(openDime), satscard.currentCardNonce[:]...)
	message = append(message, satscard.appNonce[:]...)
	message = append(message, []byte{byte(satscard.ActiveSlot)}...)

	messageDigest := sha256.Sum256([]byte(message))

	r := new(btcec.ModNScalar)
	r.SetByteSlice(readData.Signature[0:32])

	s := new(btcec.ModNScalar)
	s.SetByteSlice(readData.Signature[32:])

	signature := ecdsa.NewSignature(r, s)

	publicKey, err := btcec.ParsePubKey(readData.PublicKey[:])
	if err != nil {
		return err
	}

	verified := signature.Verify(messageDigest[:], publicKey)

	if !verified {
		return errors.New("invalid signature read")
	}

	// Save the current slot public key
	satscard.currentSlotPublicKey = readData.PublicKey

	satscard.currentCardNonce = readData.CardNonce

	paymentAddress, err := paymentAddress(readData.PublicKey)

	if err != nil {
		return err
	}

	satscard.PaymentAddress = paymentAddress

	return nil

}
