package tapprotocol

import (
	"errors"
	"fmt"
)

func (tapProtocol *TapProtocol) check() (*checkData, error) {

	nonce, err := tapProtocol.createNonce()

	if err != nil {
		return nil, err
	}

	checkCommand := checkCommand{
		command: command{Cmd: "check"},
		Nonce:   nonce,
	}

	data, err := tapProtocol.sendReceive(checkCommand)

	if err != nil {
		return nil, err
	}

	switch data := data.(type) {

	case checkData:

		fmt.Println("#########")
		fmt.Println("# CHECK #")
		fmt.Println("#########")

		fmt.Printf("Auth signature: %x\n", data.AuthSignature[:])
		fmt.Printf("Card Nonce: %x\n", data.CardNonce[:])

		return &data, nil

	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return nil, errors.New(data.Error)

	default:
		return nil, errors.New("undefined error")

	}

}
