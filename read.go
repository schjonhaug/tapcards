package tapcards

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func (tapProtocol *TapProtocol) ReadRequest() ([]byte, error) {

	slog.Debug("Request read")

	if tapProtocol.currentCardNonce == [16]byte{} {

		tapProtocol.queue.Enqueue("status")
	}

	tapProtocol.queue.Enqueue("read")

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) readRequest() ([]byte, error) {

	command := command{Cmd: "read"}

	nonce, err := tapProtocol.createNonce()

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
func (tapProtocol *TapProtocol) parseReadData(readData readData) error {

	slog.Debug("Parse read")

	slog.Debug("READ", "Signature", fmt.Sprintf("%x", readData.Signature))
	slog.Debug("READ", "PublicKey", fmt.Sprintf("%x", readData.PublicKey))

	// Verify public key with signature

	message := append([]byte(openDime), tapProtocol.currentCardNonce[:]...)
	message = append(message, tapProtocol.appNonce[:]...)
	message = append(message, []byte{byte(tapProtocol.Satscard.ActiveSlot)}...)

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
	tapProtocol.currentSlotPublicKey = readData.PublicKey

	tapProtocol.currentCardNonce = readData.CardNonce

	paymentAddress, err := paymentAddress(readData.PublicKey)

	if err != nil {
		return err
	}

	tapProtocol.Satscard.PaymentAddress = paymentAddress

	return nil

}
