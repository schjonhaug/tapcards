package tapprotocol

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"
)

const openDime = "OPENDIME"

var factoryRootPublicKeyString = "03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1"

// TAP PROTOCOL

type Satscard struct {
	ActiveSlot           int
	NumberOfSlots        int
	Identity             string
	PaymentAddress       string
	Proto                int
	Birth                int
	Version              string
	ActiveSlotPrivateKey string
}

type TapProtocol struct {
	appNonce             []byte
	currentCardNonce     [16]byte
	cardPublicKey        [33]byte
	sessionKey           [32]byte
	currentSlotPublicKey [33]byte
	certificateChain     [][65]byte

	cvc string

	Satscard

	Queue
}

func (tapProtocol *TapProtocol) authenticate(cvc string, command Command) (*auth, error) {

	slog.Debug("AUTH")

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

func (tapProtocol *TapProtocol) ParseResponse(response []byte) ([]byte, error) {

	bytes, err := tapProtocol.ApduUnwrap(response)

	if err != nil {
		return nil, err
	}

	decMode, _ := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()

	command := tapProtocol.Queue.Dequeue()

	fmt.Println("Dequeued command: ", command)

	if command == nil {
		return nil, fmt.Errorf("queue empty")
	}

	switch command {
	case "status":

		var v StatusData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			fmt.Println("Error1: ", err)

			var e ErrorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {

				fmt.Println("Error2: ", err)

				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseStatusData(v)

	case "read":

		var v readData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseReadData(v)
	case "unseal":

		var v unsealData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseUnsealData(v)
	case "certs":

		var v certsData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseCertsData(v)
	case "check":

		var v checkData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseCheckData(v)

	default:

		return nil, errors.New("incorrect command found in queue")

	}

	if err != nil {
		return nil, err

	}

	// Check if there are more commands to run

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) nextCommand() ([]byte, error) {

	command := tapProtocol.Queue.Peek()

	if command == nil {
		fmt.Println("No more commands")

		tapProtocol.cvc = ""

		return nil, nil
	}

	fmt.Println("nextCommand: ", command)

	switch command {

	case "status":
		return tapProtocol.statusRequest()
	case "read":
		return tapProtocol.readRequest()
	case "unseal":
		return tapProtocol.unsealRequest()
	case "certs":
		return tapProtocol.certsRequest()
	case "check":
		return tapProtocol.checkRequest()

	default:
		return nil, errors.New("incorrect command")

	}

}

func (TapProtocol *TapProtocol) EnableDebugLogging() {

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
}

func (TapProtocol *TapProtocol) UseEmulator() {

	factoryRootPublicKeyString = "022b6750a0c09f632df32afc5bef66568667e04b2e0f57cb8640ac5a040179442b"

}
