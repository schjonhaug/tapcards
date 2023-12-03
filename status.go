package tapprotocol

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// STATUS
func (tapProtocol *TapProtocol) Status() (string, error) {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	statusData, err := tapProtocol.status()

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	identity, err := tapProtocol.identity(statusData.PublicKey)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	return identity, nil

}

func (tapProtocol *TapProtocol) status() (*statusData, error) {

	fmt.Println("----------------------------")
	fmt.Println("Status")
	fmt.Println("----------------------------")

	statusCommand := statusCommand{command{Cmd: "status"}}

	data, err := tapProtocol.sendReceive(statusCommand)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	switch data := data.(type) {
	case statusData:

		fmt.Println("##########")
		fmt.Println("# STATUS #")
		fmt.Println("##########")

		fmt.Println("Proto:     ", data.Proto)
		fmt.Println("Birth:     ", data.Birth)
		fmt.Println("Slots:     ", data.Slots)
		fmt.Println("Addr:      ", data.Address)
		fmt.Println("Ver:       ", data.Version)
		fmt.Printf("Pubkey:     %x\n", data.PublicKey)
		fmt.Printf("Card Nonce: %x\n", data.CardNonce)

		tapProtocol.cardPublicKey = data.PublicKey
		tapProtocol.currentCardNonce = data.CardNonce
		tapProtocol.activeSlot = data.Slots[0]
		tapProtocol.numberOfSlots = data.Slots[1]

		return &data, nil

	case errorData:
		return nil, errors.New(data.Error)

	default:
		return nil, errors.New("undefined error")

	}

}

func (tapProtocol *TapProtocol) identity(cardPublicKey [33]byte) (string, error) {
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
