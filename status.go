package tapcards

import (
	"fmt"
	"log/slog"
)

func (satscard *Satscard) StatusRequest() ([]byte, error) {

	satscard.queue.enqueue("status")

	return satscard.nextCommand()

}

func (satscard *Satscard) statusRequest() ([]byte, error) {

	slog.Debug("Request status")

	statusCommand := statusCommand{command{Cmd: "status"}}

	return apduWrap(statusCommand)

}

func (satscard *Satscard) parseStatusData(statusData statusData) error {

	slog.Debug("Parse status")

	slog.Debug("STATUS", "PublicKey", fmt.Sprintf("%x", statusData.PublicKey))
	slog.Debug("STATUS", "CardNonce", fmt.Sprintf("%x", statusData.CardNonce))
	slog.Debug("STATUS", "AuthDelay", statusData.AuthDelay)

	satscard.cardPublicKey = statusData.PublicKey
	satscard.currentCardNonce = statusData.CardNonce

	identity, err := identity(satscard.cardPublicKey[:])

	if err != nil {
		return err
	}

	satscard.ActiveSlot = statusData.Slots[0]
	satscard.NumberOfSlots = statusData.Slots[1]
	satscard.Identity = identity
	satscard.PaymentAddress = statusData.Address
	satscard.Proto = statusData.Proto
	satscard.Birth = statusData.Birth
	satscard.Version = statusData.Version
	satscard.AuthDelay = statusData.AuthDelay

	return nil

}
