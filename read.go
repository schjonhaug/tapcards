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

// READ
// read a SATSCARD’s current payment address
func (tapProtocol *TapProtocol) Read() (string, error) {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.read()

}

// READ
// read a SATSCARD’s current payment address
func (tapProtocol *TapProtocol) read() (string, error) {

	fmt.Println("----------------------------")
	fmt.Println("Read current payment address")
	fmt.Println("----------------------------")

	tapProtocol.status()

	// READ

	command := command{Cmd: "read"}

	nonce, err := tapProtocol.createNonce()

	if err != nil {
		return "", err
	}

	readCommand := readCommand{
		command: command,
		Nonce:   nonce,
	}

	data, err := tapProtocol.sendReceive(readCommand)

	if err != nil {
		return "", err
	}

	switch data := data.(type) {
	case readData:

		fmt.Println("########")
		fmt.Println("# READ #")
		fmt.Println("########")

		fmt.Printf("Signature: %x\n", data.Signature)
		fmt.Printf("Public Key: %x\n", data.PublicKey)

		// Verify public key with signature

		message := append([]byte("OPENDIME"), tapProtocol.currentCardNonce[:]...)
		message = append(message, tapProtocol.nonce[:]...)
		message = append(message, []byte{byte(tapProtocol.activeSlot)}...)

		messageDigest := sha256.Sum256([]byte(message))

		r := new(btcec.ModNScalar)
		r.SetByteSlice(data.Signature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(data.Signature[32:])

		signature := ecdsa.NewSignature(r, s)

		publicKey, err := btcec.ParsePubKey(data.PublicKey[:])
		if err != nil {
			return "", err
		}

		verified := signature.Verify(messageDigest[:], publicKey)

		if !verified {
			return "", errors.New("invalid signature")
		}

		// Save the current slot public key

		tapProtocol.currentSlotPublicKey = data.PublicKey

		// Convert public key to address

		hash160 := btcutil.Hash160(data.PublicKey[:])

		convertedBits, err := bech32.ConvertBits(hash160, 8, 5, true)
		if err != nil {
			return "", err
		}

		zero := make([]byte, 1)

		encoded, err := bech32.Encode("bc", append(zero, convertedBits...))
		if err != nil {
			return "", err
		}

		// Show the encoded data.
		fmt.Println("Encoded Data:", encoded)

		tapProtocol.currentCardNonce = data.CardNonce

		return encoded, nil

	case ErrorData:
		return "", errors.New(data.Error)

	default:
		return "", errors.New("undefined error")

	}

}
