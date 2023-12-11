package tapcards

import (
	"log/slog"
)

func (satscard *Satscard) WaitRequest() ([]byte, error) {

	slog.Debug("Request wait")

	if satscard.currentCardNonce == [16]byte{} {
		satscard.queue.enqueue("status")
	}

	satscard.queue.enqueue("wait")

	return satscard.nextCommand()

}

func (satscard *Satscard) waitRequest() ([]byte, error) {

	waitCommand := waitCommand{command{Cmd: "wait"}}

	return apduWrap(waitCommand)

}

func (satscard *Satscard) parseWaitData(waitData waitData) error {

	slog.Debug("Parse wait")

	slog.Debug("WAIT", "Success", waitData.Success)
	slog.Debug("WAIT", "AuthDelay", waitData.AuthDelay)

	satscard.AuthDelay = waitData.AuthDelay

	return nil

}
