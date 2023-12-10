package tapprotocol

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
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
