package tapcards

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func (satscard *Satscard) authenticate(cvc string, command command) (*auth, error) {

	slog.Debug("AUTH", "CVC", cvc)
	slog.Debug("AUTH", "Command", command.Cmd)

	cardPublicKey, err := btcec.ParsePubKey(satscard.cardPublicKey[:])
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

	slog.Debug("AUTH", "EphemeralPublicKey", fmt.Sprintf("%x", ephemeralPublicKey))

	// Using ECDHE, derive a shared symmetric key for encryption of the plaintext.
	satscard.sessionKey = sha256.Sum256(generateSharedSecret(ephemeralPrivateKey, cardPublicKey))

	slog.Debug("AUTH", "SessionKey", fmt.Sprintf("%x", satscard.sessionKey))
	slog.Debug("AUTH", "CurrentCardNonce", fmt.Sprintf("%x", satscard.currentCardNonce))

	md := sha256.Sum256(append(satscard.currentCardNonce[:], []byte(command.Cmd)...))

	f, err := xor(satscard.sessionKey[:], md[:])
	if err != nil {
		return nil, err
	}

	mask := f[:len(cvc)]

	xcvc, err := xor([]byte(cvc), mask)

	if err != nil {
		return nil, err
	}

	slog.Debug("AUTH", "XCVC", fmt.Sprintf("%x", xcvc))

	auth := auth{EphemeralPubKey: ephemeralPublicKey, XCVC: xcvc}

	return &auth, nil

}
