package tapprotocol

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func (tapProtocol *TapProtocol) ReadRequest() ([]byte, error) {

	fmt.Println("----------------------------")
	fmt.Println("Read ")
	fmt.Println("----------------------------")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.Stack.Push("status")
	}

	tapProtocol.Stack.Push("read")

	command := Command{Cmd: "read"}

	nonce, err := tapProtocol.createNonce()

	if err != nil {
		return nil, err
	}

	readCommand := readCommand{
		Command: command,
		Nonce:   nonce,
	}

	return tapProtocol.ApduWrap(readCommand)

}

// READ
// read a SATSCARD’s current payment address
func (tapProtocol *TapProtocol) parseReadData(readData readData) error {

	fmt.Println("########")
	fmt.Println("# READ #")
	fmt.Println("########")

	fmt.Printf("Signature: %x\n", readData.Signature)
	fmt.Printf("Public Key: %x\n", readData.PublicKey)

	// Verify public key with signature

	message := append([]byte("OPENDIME"), tapProtocol.currentCardNonce[:]...)
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

	paymentAddress, err := paymentAddress(&readData)

	if err != nil {
		return err
	}

	tapProtocol.Satscard.PaymentAddress = paymentAddress

	return nil

}

// Convert public key to address
func paymentAddress(readData *readData) (string, error) {
	hash160 := btcutil.Hash160(readData.PublicKey[:])

	convertedBits, err := bech32.ConvertBits(hash160, 8, 5, true)
	if err != nil {
		return "", err
	}

	zero := make([]byte, 1)

	encoded, err := bech32.Encode("bc", append(zero, convertedBits...))
	if err != nil {
		return "", err
	}

	return encoded, nil
}
