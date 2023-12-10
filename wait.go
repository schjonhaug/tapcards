package tapcards

import (
	"log/slog"
)

func (tapProtocol *TapProtocol) WaitRequest() ([]byte, error) {

	slog.Debug("Request wait")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.Queue.Enqueue("status")
	}

	tapProtocol.Queue.Enqueue("wait")

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) waitRequest() ([]byte, error) {

	waitCommand := waitCommand{Command{Cmd: "wait"}}

	return tapProtocol.ApduWrap(waitCommand)

}

func (tapProtocol *TapProtocol) parseWaitData(waitData waitData) error {

	slog.Debug("Parse wait")

	slog.Debug("WAIT", "Success", waitData.Success)
	slog.Debug("WAIT", "AuthDelay", waitData.AuthDelay)

	tapProtocol.Satscard.AuthDelay = waitData.AuthDelay

	return nil

}
