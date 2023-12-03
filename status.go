package tapprotocol

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// STATUS
func (tapProtocol *TapProtocol) Status() error {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.status()

}

func (tapProtocol *TapProtocol) status() error {

	fmt.Println("----------------------------")
	fmt.Println("Status")
	fmt.Println("----------------------------")

	statusCommand := statusCommand{command{Cmd: "status"}}

	data, err := tapProtocol.sendReceive(statusCommand)

	if err != nil {
		fmt.Println(err)
		return err
	}

	statusData, ok := data.(StatusData)

	if !ok {
		return errors.New("incorrect data type")
	}
	fmt.Println("##########")
	fmt.Println("# STATUS #")
	fmt.Println("##########")

	fmt.Printf("Pubkey:     %x\n", statusData.PublicKey)
	fmt.Printf("Card Nonce: %x\n", statusData.CardNonce)

	tapProtocol.cardPublicKey = statusData.PublicKey
	tapProtocol.currentCardNonce = statusData.CardNonce

	identity, err := tapProtocol.identity()

	if err != nil {
		return err
	}

	tapProtocol.Satscard = Satscard{

		ActiveSlot:     statusData.Slots[0],
		NumberOfSlots:  statusData.Slots[1],
		Identity:       identity,
		PaymentAddress: statusData.Address,
		Proto:          statusData.Proto,
		Birth:          statusData.Birth,
		Version:        statusData.Version,
	}

	return nil

}

func (tapProtocol *TapProtocol) identity() (string, error) {
	// convert pubkey into a hash formatted for humans
	// - sha256(compressed-pubkey)
	// - skip first 8 bytes of that (because that's revealed in NFC URL)
	// - base32 and take first 20 chars in 4 groups of five
	// - insert dashes
	// - result is 23 chars long

	if len(tapProtocol.cardPublicKey) != 33 {
		return "", errors.New("expecting compressed pubkey")
	}

	checksum := sha256.Sum256(tapProtocol.cardPublicKey[:])

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
