package tapcards

import (
	"errors"
	"log/slog"
)

func (satscard *Satscard) NewRequest(cvc string) ([]byte, error) {

	slog.Debug("Request new")

	if satscard.currentCardNonce == [16]byte{} {
		satscard.queue.enqueue("status")
	}

	satscard.queue.enqueue("new")

	satscard.cvc = cvc

	return satscard.nextCommand()

}

func (satscard *Satscard) newRequest() ([]byte, error) {

	// Check if we can open the next slot
	if satscard.ActiveSlot+1 >= satscard.NumberOfSlots {

		return nil, errors.New("no more slots available")

	}

	command := command{Cmd: "new"}

	auth, err := satscard.authenticate(satscard.cvc, command)

	if err != nil {
		return nil, err
	}

	newCommand := newCommand{
		command: command,
		Slot:    satscard.ActiveSlot,
		auth:    *auth,
	}

	return apduWrap(newCommand)

}

func (satscard *Satscard) parseNewData(newData newData) error {

	slog.Debug("Parse new")
	slog.Debug("NEW", "Slot", newData.Slot)

	satscard.currentCardNonce = newData.CardNonce
	satscard.ActiveSlot = newData.Slot

	return nil

}
