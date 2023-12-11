package tapcards

import (
	"errors"
	"log/slog"
)

func (tapProtocol *TapProtocol) NewRequest(cvc string) ([]byte, error) {

	slog.Debug("Request new")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.queue.Enqueue("status")
	}

	tapProtocol.queue.Enqueue("new")

	tapProtocol.cvc = cvc

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) newRequest() ([]byte, error) {

	// Check if we can open the next slot
	if tapProtocol.Satscard.ActiveSlot+1 >= tapProtocol.Satscard.NumberOfSlots {

		return nil, errors.New("no more slots available")

	}

	command := command{Cmd: "new"}

	auth, err := tapProtocol.authenticate(tapProtocol.cvc, command)

	if err != nil {
		return nil, err
	}

	newCommand := newCommand{
		command: command,
		Slot:    tapProtocol.Satscard.ActiveSlot,
		auth:    *auth,
	}

	return apduWrap(newCommand)

}

func (tapProtocol *TapProtocol) parseNewData(newData newData) error {

	slog.Debug("Parse new")
	slog.Debug("NEW", "Slot", newData.Slot)

	tapProtocol.currentCardNonce = newData.CardNonce
	tapProtocol.Satscard.ActiveSlot = newData.Slot

	return nil

}
