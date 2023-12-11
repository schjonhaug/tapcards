package tapcards

import (
	"log/slog"
)

func (satscard *Satscard) CertsRequest() ([]byte, error) {

	slog.Debug("Request certs")

	if satscard.currentCardNonce == [16]byte{} {
		satscard.queue.enqueue("status")
	}

	satscard.queue.enqueue("certs")
	satscard.queue.enqueue("read")
	satscard.queue.enqueue("check")

	return satscard.nextCommand()

}

func (satscard *Satscard) certsRequest() ([]byte, error) {

	certsCommand := certsCommand{
		command{Cmd: "certs"},
	}

	return apduWrap(certsCommand)
}

func (satscard *Satscard) parseCertsData(certsData certsData) error {

	slog.Debug("Parse certs")

	satscard.certificateChain = certsData.CertificateChain

	return nil

}
