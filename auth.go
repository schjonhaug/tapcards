package tapprotocol

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

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
