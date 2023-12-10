package tapcards

import (
	"log/slog"
)

func (tapProtocol *TapProtocol) CertsRequest() ([]byte, error) {

	slog.Debug("Request certs")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.queue.Enqueue("status")
	}

	tapProtocol.queue.Enqueue("certs")
	tapProtocol.queue.Enqueue("read")
	tapProtocol.queue.Enqueue("check")

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) certsRequest() ([]byte, error) {

	certsCommand := certsCommand{
		Command{Cmd: "certs"},
	}

	return tapProtocol.ApduWrap(certsCommand)
}

func (tapProtocol *TapProtocol) parseCertsData(certsData certsData) error {

	slog.Debug("Parse certs")

	tapProtocol.certificateChain = certsData.CertificateChain

	return nil

}
