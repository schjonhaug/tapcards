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

	readData, err := tapProtocol.read()
	if err != nil {
		return "", err
	}

	// Convert public key to address

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

	// Show the encoded readData.
	fmt.Println("Encoded Data:", encoded)

	return encoded, nil

}

// READ
// read a SATSCARD’s current payment address
func (tapProtocol *TapProtocol) read() (*readData, error) {

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.status()
	}

	fmt.Println("----------------------------")
	fmt.Println("Read ")
	fmt.Println("----------------------------")

	command := command{Cmd: "read"}

	nonce, err := tapProtocol.createNonce()

	if err != nil {
		return nil, err
	}

	readCommand := readCommand{
		command: command,
		Nonce:   nonce,
	}

	data, err := tapProtocol.sendReceive(readCommand)

	if err != nil {
		return nil, err
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
		message = append(message, tapProtocol.appNonce[:]...)
		message = append(message, []byte{byte(tapProtocol.activeSlot)}...)

		messageDigest := sha256.Sum256([]byte(message))

		r := new(btcec.ModNScalar)
		r.SetByteSlice(data.Signature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(data.Signature[32:])

		signature := ecdsa.NewSignature(r, s)

		publicKey, err := btcec.ParsePubKey(data.PublicKey[:])
		if err != nil {
			return nil, err
		}

		verified := signature.Verify(messageDigest[:], publicKey)

		if !verified {
			return nil, errors.New("invalid signature")
		}

		// Save the current slot public key
		tapProtocol.currentSlotPublicKey = data.PublicKey

		tapProtocol.currentCardNonce = data.CardNonce

		return &data, nil

	case errorData:
		return nil, errors.New(data.Error)

	default:
		return nil, errors.New("undefined error")

	}

}
