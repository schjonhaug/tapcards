package tapprotocol

import (
	"log/slog"
)

func (tapProtocol *TapProtocol) CertsRequest() ([]byte, error) {

	slog.Debug("Request certs")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.Queue.Enqueue("status")
	}

	tapProtocol.Queue.Enqueue("certs")
	tapProtocol.Queue.Enqueue("read")
	tapProtocol.Queue.Enqueue("check")

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
