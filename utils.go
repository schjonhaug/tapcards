package tapcards

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
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
		return "", errors.New("expecting compressed public key")
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

	messageDigest := sha256.Sum256(publicKey.SerializeCompressed())

	recId, err := recID(signature[:])

	if err != nil {
		return nil, err
	}

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

// xor performs a bitwise XOR operation on two byte slices.
// It takes two byte slices, a and b, as input and returns a new byte slice, c,
// where each element of c is the result of XOR operation between the corresponding elements of a and b.
// If the input slices have different lengths, it panics.
func xor(a, b []byte) ([]byte, error) {

	if len(a) != len(b) {
		return nil, errors.New("input slices have different lengths")
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c, nil
}

// Convert public key to address
func paymentAddress(publicKey [33]byte) (string, error) {
	hash160 := btcutil.Hash160(publicKey[:])

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
