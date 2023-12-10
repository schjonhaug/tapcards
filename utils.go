package tapprotocol

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Convert the card public key into a human readable identity
func identity(cardPublicKey []byte) (string, error) {
	// convert pubkey into a hash formatted for humans
	// - sha256(compressed-pubkey)
	// - skip first 8 bytes of that (because that's revealed in NFC URL)
	// - base32 and take first 20 chars in 4 groups of five
	// - insert dashes
	// - result is 23 chars long

	if len(cardPublicKey) != 33 {
		return "", errors.New("expecting compressed pubkey")
	}

	checksum := sha256.Sum256(cardPublicKey[:])

	base32String := base32.StdEncoding.EncodeToString(checksum[8:])

	// Only keep the first 20 characters
	s := base32String[:20]

	// Split the string into groups of 5 characters
	var groups []string
	for i := 0; i < len(s); i += 5 {
		end := i + 5
		if end > len(s) {
			end = len(s)
		}
		groups = append(groups, s[i:end])
	}

	// Join the groups with dashes
	return strings.Join(groups, "-"), nil

}

/*
*
The first byte of each signature has rec_id encoded according to BIP-137.
* If the value is between 39 to 42 [39, 42], subtract 39 to get rec_id within the range of 0 to 3 [0, 3].
* If the value is [27, 30], subtract 27 to get rec_id within the range of [0, 3].
* Other values should not occur.
*/
func recID(signature []byte) (byte, error) {
	if len(signature) == 0 {
		return 0, fmt.Errorf("empty signature")
	}

	firstByte := signature[0]
	fmt.Println("First byte before:", firstByte)

	//ecdsa.RecoverCompact subtracts 27 from the recID, so we need to offset it
	offset := 27

	switch {
	case firstByte >= 39 && firstByte <= 42:
		return firstByte - 39 + byte(offset), nil
	case firstByte >= 27 && firstByte <= 30:
		return firstByte - 27 + byte(offset), nil
	default:
		return firstByte, nil
	}

}

func signatureToPublicKey(signature [65]byte, publicKey *secp256k1.PublicKey) (*secp256k1.PublicKey, error) {

	slog.Debug(fmt.Sprint("Signature:", signature[:]))

	messageDigest := sha256.Sum256(publicKey.SerializeCompressed())

	recId, err := recID(signature[:])

	if err != nil {
		return nil, err
	}

	fmt.Println("RecID:", recId)

	newSig := append([]byte{recId}, signature[1:]...)

	pubKey, _, err := ecdsa.RecoverCompact(newSig[:], messageDigest[:])

	return pubKey, err

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
