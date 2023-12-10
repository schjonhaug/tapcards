package tapcards

import (
	"fmt"
	"log/slog"
)

func (tapProtocol *TapProtocol) StatusRequest() ([]byte, error) {

	tapProtocol.Queue.Enqueue("status")

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) statusRequest() ([]byte, error) {

	slog.Debug("Request status")

	statusCommand := statusCommand{Command{Cmd: "status"}}

	return tapProtocol.ApduWrap(statusCommand)

}

func (tapProtocol *TapProtocol) parseStatusData(statusData StatusData) error {

	slog.Debug("Parse status")

	slog.Debug("STATUS", "PublicKey", fmt.Sprintf("%x", statusData.PublicKey))
	slog.Debug("STATUS", "CardNonce", fmt.Sprintf("%x", statusData.CardNonce))
	slog.Debug("STATUS", "AuthDelay", statusData.AuthDelay)

	tapProtocol.cardPublicKey = statusData.PublicKey
	tapProtocol.currentCardNonce = statusData.CardNonce

	identity, err := identity(tapProtocol.cardPublicKey[:])

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
		AuthDelay:      statusData.AuthDelay,
	}

	return nil

}
