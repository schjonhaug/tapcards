package tapprotocol

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"
)

// TAP PROTOCOL

type Satscard struct {
	ActiveSlot     int
	NumberOfSlots  int
	Identity       string
	PaymentAddress string
	Proto          int
	Birth          int
	Version        string
}

type TapProtocol struct {
	appNonce             []byte
	currentCardNonce     [16]byte
	cardPublicKey        [33]byte
	sessionKey           [32]byte
	currentSlotPublicKey [33]byte

	transport Transport

	Satscard

	Stack
}

func (tapProtocol *TapProtocol) authenticate(cvc string, command Command) (*auth, error) {

	fmt.Println("\n########")
	fmt.Println("# AUTH #")
	fmt.Println("########")

	fmt.Println("CVC:    ", cvc)
	fmt.Println("Command:", command.Cmd)

	cardPublicKey, err := btcec.ParsePubKey(tapProtocol.cardPublicKey[:])
	if err != nil {
		return nil, err
	}

	// Derive an ephemeral public/private keypair for performing ECDHE with
	// the recipient.

	ephemeralPrivateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {

		return nil, err
	}

	ephemeralPublicKey := ephemeralPrivateKey.PubKey().SerializeCompressed()

	fmt.Print("\n")
	fmt.Printf("Ephemeral Public Key: %x\n", ephemeralPublicKey)

	// Using ECDHE, derive a shared symmetric key for encryption of the plaintext.
	tapProtocol.sessionKey = sha256.Sum256(generateSharedSecret(ephemeralPrivateKey, cardPublicKey))

	fmt.Printf("Session Key:  %x\n", tapProtocol.sessionKey)
	fmt.Printf("CurrentCardNonce:  %x\n", tapProtocol.currentCardNonce)

	md := sha256.Sum256(append(tapProtocol.currentCardNonce[:], []byte(command.Cmd)...))

	mask := xor(tapProtocol.sessionKey[:], md[:])[:len(cvc)]

	xcvc := xor([]byte(cvc), mask)

	fmt.Printf("xcvc %x\n", xcvc)

	auth := auth{EphemeralPubKey: ephemeralPublicKey, XCVC: xcvc}

	return &auth, nil

}

// xor performs a bitwise XOR operation on two byte slices.
// It takes two byte slices, a and b, as input and returns a new byte slice, c,
// where each element of c is the result of XOR operation between the corresponding elements of a and b.
// If the input slices have different lengths, it panics.
func xor(a, b []byte) []byte {

	if len(a) != len(b) {
		panic("input slices have different lengths")
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// generateSharedSecret generates a shared secret based on a private key and a
// public key using Diffie-Hellman key exchange (ECDH) (RFC 5903).
// RFC5903 Section 9 states we should only return x.
//
// It is recommended to securely hash the result before using as a cryptographic
// key.
func generateSharedSecret(privateKey *secp256k1.PrivateKey, publicKey *secp256k1.PublicKey) []byte {

	var point, result secp256k1.JacobianPoint
	publicKey.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&privateKey.Key, &point, &result)
	result.ToAffine()
	xBytes := result.X.Bytes()

	y := new(big.Int)
	y.SetBytes(result.Y.Bytes()[:])

	// Perform a bitwise AND with 0x01
	andResult := new(big.Int).And(y, big.NewInt(0x01))

	// Perform a bitwise OR with 0x02
	orResult := new(big.Int).Or(andResult, big.NewInt(0x02))

	even := orResult.Bytes()

	sharedSecret := append(even, xBytes[:]...)

	return sharedSecret
}

func (tapProtocol *TapProtocol) createNonce() ([]byte, error) {

	// Create nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)

	if err != nil {
		return nil, err
	}
	fmt.Printf("\nCreated nonce: %x\n", nonce)

	tapProtocol.appNonce = nonce

	return nonce, nil

}

func (tapProtocol *TapProtocol) sendReceive(command any) (any, error) {

	channel := make(chan any)

	go tapProtocol.transport.Send(command, channel)

	data := <-channel

	switch data := data.(type) {

	case ErrorData:
		return nil, fmt.Errorf("%d: %v", data.Code, data.Error)

	default:
		return data, nil

	}

}

func (tapProtocol *TapProtocol) ParseResponse(response []byte) ([]byte, error) {

	bytes, err := tapProtocol.ApduUnwrap(response)

	if err != nil {
		return nil, err
	}

	decMode, _ := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()

	command, ok := tapProtocol.Stack.Pop()

	if !ok {
		return nil, fmt.Errorf("stack empty")
	}

	switch command {
	case "status":

		var v StatusData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		tapProtocol.parseStatusData(v)
	case "read":

		var v readData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		tapProtocol.parseReadData(v)

	default:

		return nil, errors.New("incorrect command")

	}

	// Check if there are more commands to run

	if !tapProtocol.Stack.IsEmpty() {

		switch command {
		case "read":
			return tapProtocol.ReadRequest()
		default:
			return nil, errors.New("incorrect command")
		}

	}

	return nil, nil

}
