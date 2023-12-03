package tapprotocol

import (
	"errors"
	"fmt"
)

func (tapProtocol *TapProtocol) check(nonce []byte) (*checkData, error) {

	checkCommand := checkCommand{
		command: command{Cmd: "check"},
		Nonce:   nonce,
	}

	data, err := tapProtocol.sendReceive(checkCommand)

	if err != nil {
		return nil, err
	}

	checkData, ok := data.(checkData)

	if !ok {
		return nil, errors.New("incorrect data type")
	}
	fmt.Println("#########")
	fmt.Println("# CHECK #")
	fmt.Println("#########")

	fmt.Printf("Auth signature: %x\n", checkData.AuthSignature[:])
	fmt.Printf("Card Nonce: %x\n", checkData.CardNonce[:])

	return &checkData, nil

}
