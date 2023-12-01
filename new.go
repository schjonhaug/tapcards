package tapprotocol

import (
	"errors"
	"fmt"
)

func (tapProtocol *TapProtocol) New(cvc string) (int, error) {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.new(cvc)

}

func (tapProtocol *TapProtocol) new(cvc string) (int, error) {

	tapProtocol.status()

	fmt.Println("------------")
	fmt.Println("New")
	fmt.Println("------------")

	command := command{Cmd: "new"}

	auth, err := tapProtocol.authenticate(cvc, command)

	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	newCommand := newCommand{
		command: command,
		Slot:    tapProtocol.activeSlot, //TODO check maximum
		auth:    *auth,
	}

	data, err := tapProtocol.sendReceive(newCommand)

	if err != nil {
		return 0, err
	}

	switch data := data.(type) {
	case NewData:

		fmt.Println("#######")
		fmt.Println("# NEW #")
		fmt.Println("#######")

		fmt.Println("Slot:             ", data.Slot)

		tapProtocol.currentCardNonce = data.CardNonce
		tapProtocol.activeSlot = data.Slot

		return data.Slot, nil
	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return 0, errors.New(data.Error)

	default:
		return 0, errors.New("undefined error")

	}

}
