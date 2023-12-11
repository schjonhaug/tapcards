package tapcards

import (
	"log/slog"
)

func (tapProtocol *TapProtocol) WaitRequest() ([]byte, error) {

	slog.Debug("Request wait")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.queue.Enqueue("status")
	}

	tapProtocol.queue.Enqueue("wait")

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) waitRequest() ([]byte, error) {

	waitCommand := waitCommand{command{Cmd: "wait"}}

	return apduWrap(waitCommand)

}

func (tapProtocol *TapProtocol) parseWaitData(waitData waitData) error {

	slog.Debug("Parse wait")

	slog.Debug("WAIT", "Success", waitData.Success)
	slog.Debug("WAIT", "AuthDelay", waitData.AuthDelay)

	tapProtocol.Satscard.AuthDelay = waitData.AuthDelay

	return nil

}
