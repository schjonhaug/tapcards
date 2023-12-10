package tapprotocol

import (
	"errors"
	"fmt"
	"log/slog"
)

func (tapProtocol *TapProtocol) NewRequest(cvc string) ([]byte, error) {

	slog.Debug("Request new")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.Queue.Enqueue("status")
	}

	tapProtocol.Queue.Enqueue("new")

	tapProtocol.cvc = cvc

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) newRequest() ([]byte, error) {

	// Check if we can open the next slot
	if tapProtocol.Satscard.ActiveSlot+1 >= tapProtocol.NumberOfSlots {

		return nil, errors.New("no more slots available")

	}

	command := Command{Cmd: "new"}

	auth, err := tapProtocol.authenticate(tapProtocol.cvc, command)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	newCommand := newCommand{
		Command: command,
		Slot:    tapProtocol.Satscard.ActiveSlot,
		auth:    *auth,
	}

	return tapProtocol.ApduWrap(newCommand)

}

func (tapProtocol *TapProtocol) parseNewData(newData newData) error {

	slog.Debug("Parse new")
	slog.Debug("NEW", "Slot", newData.Slot)

	tapProtocol.currentCardNonce = newData.CardNonce
	tapProtocol.Satscard.ActiveSlot = newData.Slot

	return nil

}
